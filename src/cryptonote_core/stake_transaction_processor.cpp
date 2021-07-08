#include <string_tools.h>

#include "stake_transaction_processor.h"
#include "../graft_rta_config.h"

#include <mutex>



#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "staketransaction.processor"

using namespace cryptonote;

namespace
{

const char* STAKE_TRANSACTION_STORAGE_FILE_NAME = "stake_transactions.v2.bin";
const char* BLOCKCHAIN_BASED_LIST_FILE_NAME     = "blockchain_based_list.v5.bin";

}

bool stake_transaction::is_valid(uint64_t block_index) const
{
  uint64_t stake_first_valid_block = block_height + config::graft::STAKE_VALIDATION_PERIOD,
           stake_last_valid_block  = block_height + unlock_time + config::graft::TRUSTED_RESTAKING_PERIOD;

  if (block_index < stake_first_valid_block)
    return false;

  if (block_index >= stake_last_valid_block)
    return false;

  return true;
}

StakeTransactionProcessor::StakeTransactionProcessor(Blockchain& blockchain)
  : m_blockchain(blockchain)
  , m_stakes_need_update(true)
  , m_blockchain_based_list_need_update(true)
{
}

const supernode_stake* StakeTransactionProcessor::find_supernode_stake(uint64_t block_number, const std::string& supernode_public_id) const
{
  CRITICAL_REGION_LOCAL1(m_storage_lock);

  if (!m_storage)
    return nullptr;

  return m_storage->find_supernode_stake(block_number, supernode_public_id);
}

namespace
{

uint64_t get_transaction_amount(const transaction& tx, const account_public_address& address, const crypto::secret_key& tx_key)
{
  crypto::key_derivation derivation;

  if (!crypto::generate_key_derivation(address.m_view_public_key, tx_key, derivation))
  {
    MWARNING("failed to generate key derivation from supplied parameters");
    return 0;
  }

  uint64_t received = 0;

  for (size_t n = 0; n < tx.vout.size(); ++n)
  {
    if (typeid(cryptonote::txout_to_key) != tx.vout[n].target.type())
      continue;

    const cryptonote::txout_to_key tx_out_to_key = boost::get<cryptonote::txout_to_key>(tx.vout[n].target);

    crypto::public_key pubkey;
    derive_public_key(derivation, n, address.m_spend_public_key, pubkey);

    if (pubkey == tx_out_to_key.key)
    {
      uint64_t amount;
      if (tx.version == 1)
      {
        amount = tx.vout[n].amount;
      }
      else
      {
        try
        {
          rct::key Ctmp;
          //rct::key amount_key = rct::hash_to_scalar(rct::scalarmultKey(rct::pk2rct(address.m_view_public_key), rct::sk2rct(tx_key)));
          crypto::key_derivation derivation;
          bool r = crypto::generate_key_derivation(address.m_view_public_key, tx_key, derivation);
          if (!r)
          {
            LOG_ERROR("Failed to generate key derivation to decode rct output " << n);
            amount = 0;
          }
          else
          {
            crypto::secret_key scalar1;
            crypto::derivation_to_scalar(derivation, n, scalar1);
            rct::ecdhTuple ecdh_info = tx.rct_signatures.ecdhInfo[n];
            rct::ecdhDecode(ecdh_info, rct::sk2rct(scalar1));
            rct::key C = tx.rct_signatures.outPk[n].mask;
            rct::addKeys2(Ctmp, ecdh_info.mask, ecdh_info.amount, rct::H);
            if (rct::equalKeys(C, Ctmp))
              amount = rct::h2d(ecdh_info.amount);
            else
              amount = 0;
          }
        }
        catch (...) { amount = 0; }
      }
      received += amount;
    }
  }

  return received;
}

}

void StakeTransactionProcessor::init_storages(const std::string& config_dir)
{
  CRITICAL_REGION_LOCAL1(m_storage_lock);

  if (m_storage || m_blockchain_based_list)
    throw std::runtime_error("StakeTransactionProcessor storages have been already initialized");

  m_config_dir = config_dir;
}

void StakeTransactionProcessor::init_storages_impl()
{
  if (m_storage || m_blockchain_based_list)
    throw std::runtime_error("StakeTransactionProcessor storages have been already initialized");

  uint64_t first_block_number = m_enabled ? m_blockchain.get_earliest_ideal_height_for_version(config::graft::STAKE_TRANSACTION_PROCESSING_DB_VERSION)
                                          : std::numeric_limits<uint64_t>().max();

  if (first_block_number)
    first_block_number--;

  MDEBUG("Initialize stake processing storages. First block height is " << first_block_number);

  m_storage.reset(new StakeTransactionStorage(m_config_dir + "/" + STAKE_TRANSACTION_STORAGE_FILE_NAME, first_block_number));
  m_blockchain_based_list.reset(new BlockchainBasedList(m_config_dir + "/" + BLOCKCHAIN_BASED_LIST_FILE_NAME, first_block_number));
}

void StakeTransactionProcessor::process_block_stake_transaction(uint64_t block_index, const block& block, const crypto::hash& block_hash, bool update_storage)
{
  if (block_index <= m_storage->get_last_processed_block_index())
    return;

  if (m_blockchain.get_hard_fork_version(block_index) >= config::graft::STAKE_TRANSACTION_PROCESSING_DB_VERSION)
  {
      //analyze block transactions and add new stake transactions if exist

    stake_transaction stake_tx;

    std::vector<transaction> txs;
    std::vector<crypto::hash> missed_txs;
    
    if (!m_blockchain.get_transactions(block.tx_hashes, txs, missed_txs))
    {
      MWARNING("Unable to get transactions for block #" << block_index);
      return;
    }

    if (!missed_txs.empty())
    {
      MWARNING("Some transactions for block #" << block_index << " have been missed:");

      for (const crypto::hash& tx_hash : missed_txs)
        MWARNING("  " << tx_hash);
    }

    for (const transaction& tx : txs)
    {
      const crypto::hash tx_hash = get_transaction_prefix_hash(tx);

      try
      {
        if (!get_graft_stake_tx_extra_from_extra(tx, stake_tx.supernode_public_id, stake_tx.supernode_public_address, stake_tx.supernode_signature, stake_tx.tx_secret_key))
          continue;

        crypto::public_key W;
        if (!epee::string_tools::hex_to_pod(stake_tx.supernode_public_id, W) || !check_key(W))
        {
          MWARNING("Ignore stake transaction at block #" << block_index << ", tx_hash=" << tx_hash
            << " because of invalid supernode public identifier '" << stake_tx.supernode_public_id << "'");
          continue;
        }

        const bool is_subaddress = false;
        std::string supernode_public_address_str = cryptonote::get_account_address_as_str(m_blockchain.nettype(), is_subaddress, stake_tx.supernode_public_address);
        std::string data = supernode_public_address_str + ":" + stake_tx.supernode_public_id;
        crypto::hash hash;
        crypto::cn_fast_hash(data.data(), data.size(), hash);

        if (!crypto::check_signature(hash, W, stake_tx.supernode_signature))
        {
          MWARNING("Ignore stake transaction at block #" << block_index << ", tx_hash=" << tx_hash << ", supernode_public_id '" << stake_tx.supernode_public_id << "'"
            << " because of invalid supernode signature (mismatch)");
          continue;
        }

        uint64_t unlock_time = tx.unlock_time - block_index;

        if (unlock_time < config::graft::STAKE_MIN_UNLOCK_TIME)
        {
          MWARNING("Ignore stake transaction at block #" << block_index << ", tx_hash=" << tx_hash << ", supernode_public_id '" << stake_tx.supernode_public_id << "'"
            << " because unlock time " << unlock_time << " is less than minimum allowed " << config::graft::STAKE_MIN_UNLOCK_TIME);
          continue;
        }
        const auto CURRENT_STAKE_MAX_UNLOCK_TIME = m_blockchain.get_current_hard_fork_version() < 16 ? config::graft::STAKE_MAX_UNLOCK_TIME_V15
                                                                                                     : config::graft::STAKE_MAX_UNLOCK_TIME;
        if (unlock_time > CURRENT_STAKE_MAX_UNLOCK_TIME)
        {
          MWARNING("Ignore stake transaction at block #" << block_index << ", tx_hash=" << tx_hash << ", supernode_public_id '" << stake_tx.supernode_public_id << "'"
            << " because unlock time " << unlock_time << " is greater than maximum allowed " << CURRENT_STAKE_MAX_UNLOCK_TIME);
          continue;
        }

        uint64_t amount = get_transaction_amount(tx, stake_tx.supernode_public_address, stake_tx.tx_secret_key);

        if (!amount)
        {
          MWARNING("Ignore stake transaction at block #" << block_index << ", tx_hash=" << tx_hash << ", supernode_public_id '" << stake_tx.supernode_public_id << "'"
            << " because of error at parsing amount");
          continue;
        }

        stake_tx.amount = amount;
        stake_tx.block_height = block_index;
        stake_tx.hash = tx_hash;
        stake_tx.unlock_time = unlock_time;

        m_storage->add_tx(stake_tx);

        MDEBUG("New stake transaction found at block #" << block_index << ", tx_hash=" << tx_hash << ", supernode_public_id '" << stake_tx.supernode_public_id
          << "', amount=" << amount / double(COIN));
      }
      catch (std::exception& e)
      {
        MWARNING("Ignore transaction at block #" << block_index << ", tx_hash=" << tx_hash << " because of error at parsing: " << e.what());
      }
      catch (...)
      {
        MWARNING("Ignore transaction at block #" << block_index << ", tx_hash=" << tx_hash << " because of unknown error at parsing");
      }
    }

    m_stakes_need_update = true; //TODO: cache for stakes

      //update supernode stakes

    m_storage->update_supernode_stakes(block_index);
  }

    //update cache entries and save storage

  m_storage->add_last_processed_block(block_index, block_hash);

  if (update_storage)
    m_storage->store();
}

void StakeTransactionProcessor::process_block_blockchain_based_list(uint64_t block_index, const block& block, const crypto::hash& block_hash, bool update_storage)
{
  uint64_t prev_block_height = m_blockchain_based_list->block_height();

  m_blockchain_based_list->apply_block(block_index, block_hash, *m_storage);

  if (m_blockchain_based_list->need_store() || prev_block_height != m_blockchain_based_list->block_height())
  {
    m_blockchain_based_list_need_update = true;

    if (update_storage)
      m_blockchain_based_list->store();
  }
}

void StakeTransactionProcessor::process_block(uint64_t block_index, const block& block, const crypto::hash& block_hash, bool update_storage)
{
  process_block_stake_transaction(block_index, block, block_hash, update_storage);
  process_block_blockchain_based_list(block_index, block, block_hash, update_storage);
}

void StakeTransactionProcessor::synchronize()
{
  std::unique_lock<epee::critical_section> storage_lock{m_storage_lock, std::defer_lock};
  std::unique_lock<Blockchain> blockchain_lock{m_blockchain, std::defer_lock};
  std::lock(storage_lock, blockchain_lock);

  uint64_t height = m_blockchain.get_current_blockchain_height();

  if (!height || m_blockchain.get_hard_fork_version(height - 1) < config::graft::STAKE_TRANSACTION_PROCESSING_DB_VERSION)
    return;

  if (!m_storage || !m_blockchain_based_list)
  {
    init_storages_impl();
  }

    //unroll already processed blocks for alternative chains
  
  try
  {
    while (m_storage->has_last_processed_block())
    {
      size_t   stake_tx_count = m_storage->get_tx_count();
      uint64_t last_processed_block_index = m_storage->get_last_processed_block_index();

      if (last_processed_block_index < height)
      {
        try
        {
          const crypto::hash& last_processed_block_hash  = m_storage->get_last_processed_block_hash();
          crypto::hash        last_blockchain_block_hash = m_blockchain.get_block_id_by_height(last_processed_block_index);

          if (!memcmp(&last_processed_block_hash.data[0], &last_blockchain_block_hash.data[0], sizeof(last_blockchain_block_hash.data)))
            break; //latest block hash is the same as processed
        }
        catch (BLOCK_DNE&)
        {
          //block does not exist, waiting until it will be received
          return;
        }
      }
      
      MWARNING("Stake transactions processing: unroll block " << last_processed_block_index << " (height=" << height << ")");

      m_storage->remove_last_processed_block();

      if (stake_tx_count != m_storage->get_tx_count())
        m_storage->clear_supernode_stakes();

      if (m_blockchain_based_list->block_height() == last_processed_block_index)
        m_blockchain_based_list->remove_latest_block();
    }

    //apply new blocks

    uint64_t first_block_index = m_storage->get_last_processed_block_index() + 1;

    if (first_block_index > m_blockchain_based_list->block_height() + 1)
      first_block_index = m_blockchain_based_list->block_height() + 1;

    static const uint64_t SYNC_DEBUG_LOG_STEP  = 10000;
    static const uint64_t MAX_ITERATIONS_COUNT = 10000;

    uint64_t last_block_index = first_block_index,
             last_block_index_for_sync = height;

    if (last_block_index_for_sync - last_block_index > MAX_ITERATIONS_COUNT)
      last_block_index_for_sync = first_block_index + MAX_ITERATIONS_COUNT;

    for (; last_block_index<last_block_index_for_sync; last_block_index++)
    {
      if (last_block_index % SYNC_DEBUG_LOG_STEP == 0 || last_block_index == height - 1)
        MDEBUG("RTA block sync " << last_block_index << "/" << (height - 1));

      try
      {
        crypto::hash block_hash = m_blockchain.get_block_id_by_height(last_block_index);
        block block;

        if (!m_blockchain.get_block_by_hash(block_hash, block))
        {
          MWARNING("Block with hash " << block_hash << " has not been found");
          throw std::runtime_error("Error at parsing blockchain. Block hash has not been found");
        }

        process_block(last_block_index, block, block_hash, false);
      }
      catch (BLOCK_DNE&)
      {
        //block does not exist, waiting until it will be received
        break;
      }
    }

    if (m_blockchain_based_list->need_store())
      m_blockchain_based_list->store();

    if (m_storage->need_store())
      m_storage->store();

    if (last_block_index == height)
    {
      if (m_stakes_need_update && m_on_stakes_update)
        invoke_update_stakes_handler_impl(last_block_index - 1);

      if (m_blockchain_based_list_need_update && m_on_blockchain_based_list_update)
        invoke_update_blockchain_based_list_handler_impl(last_block_index - first_block_index);

      if (first_block_index != last_block_index)
        MDEBUG("Stake transactions sync OK");
    }
  }
  catch (const std::exception &e)
  {
    MWARNING(e.what());
  }
}

void StakeTransactionProcessor::set_on_update_stakes_handler(const supernode_stakes_update_handler& handler)
{
  CRITICAL_REGION_LOCAL1(m_storage_lock);
  m_on_stakes_update = handler;
}

void StakeTransactionProcessor::invoke_update_stakes_handler_impl(uint64_t block_index)
{
  try
  {
    if (!m_storage)
      return;

    m_on_stakes_update(block_index, m_storage->get_supernode_stakes(block_index));

    m_stakes_need_update = false;
  }
  catch (std::exception& e)
  {
    MCLOG(el::Level::Error, MONERO_DEFAULT_LOG_CATEGORY, "exception in StakeTransactionProcessor stake transactions update handler: " << e.what());
  }
}

void StakeTransactionProcessor::invoke_update_stakes_handler(bool force)
{
  CRITICAL_REGION_LOCAL1(m_storage_lock);

  if (!m_on_stakes_update)
    return;
  
  if (!m_stakes_need_update && !force)
    return;

  invoke_update_stakes_handler_impl(m_blockchain.get_db().height() - 1);
}

void StakeTransactionProcessor::set_on_update_blockchain_based_list_handler(const blockchain_based_list_update_handler& handler)
{
  CRITICAL_REGION_LOCAL1(m_storage_lock);
  m_on_blockchain_based_list_update = handler;
}

void StakeTransactionProcessor::invoke_update_blockchain_based_list_handler_impl(size_t depth)
{
  try
  {
    if (!m_blockchain_based_list)
      return;

    if (!m_blockchain_based_list->block_height())
      return; //empty blockchain based list

    if (depth > m_blockchain_based_list->history_depth())
      depth = m_blockchain_based_list->history_depth();

    if (depth > config::graft::SUPERNODE_HISTORY_SIZE)
      depth = config::graft::SUPERNODE_HISTORY_SIZE;

    uint64_t height = m_blockchain_based_list->block_height();

    for (size_t i=0; i<depth; i++)
    {
      uint64_t     block_height = height - i;
      crypto::hash block_hash   = m_blockchain.get_block_id_by_height(block_height);

      m_on_blockchain_based_list_update(block_height, block_hash, m_blockchain_based_list->tiers(i));
    }

    m_blockchain_based_list_need_update = false;
  }
  catch (std::exception& e)
  {
    MCLOG(el::Level::Error, MONERO_DEFAULT_LOG_CATEGORY, "exception in StakeTransactionProcessor blockchain based list update handler: " << e.what());
  }
}

void StakeTransactionProcessor::invoke_update_blockchain_based_list_handler(bool force, size_t depth)
{
  CRITICAL_REGION_LOCAL1(m_storage_lock);

  if (!m_on_blockchain_based_list_update)
    return;

  if (depth > 1)
    force = true;

  if (!m_blockchain_based_list_need_update && !force)
    return;

  invoke_update_blockchain_based_list_handler_impl(depth);
}

void StakeTransactionProcessor::set_enabled(bool arg)
{
  m_enabled = arg;
}

bool StakeTransactionProcessor::is_enabled() const
{
  return m_enabled;
}
