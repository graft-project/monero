// Copyright (c) 2014-2018, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once
#include <boost/thread.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/serialization/version.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/serialization/map.hpp>

#include "cryptonote_config.h"
#include "warnings.h"
#include "net/levin_server_cp2.h"
#include "net/http_client.h"
#include "p2p_protocol_defs.h"
#include "storages/levin_abstract_invoke2.h"
#include "net_peerlist.h"
#include "math_helper.h"
#include "net_node_common.h"
#include "common/command_line.h"
#include "net/jsonrpc_structs.h"
#include "storages/http_abstract_invoke.h"

#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <iomanip>

PUSH_WARNINGS
DISABLE_VS_WARNINGS(4355)

namespace nodetool
{
  using Uuid = boost::uuids::uuid;
  using Clock = std::chrono::steady_clock;
  using SupernodeId = std::string;

  struct SupernodeItem
  {
    std::chrono::steady_clock::time_point expiry_time; // expiry time of this struct
    std::string uri; // base URI (here it is URL without host and port) for forwarding requests to supernode
    std::string redirect_uri; //special uri for UDHT protocol redirection mechanism
    uint32_t redirect_timeout_ms;
    epee::net_utils::http::http_simple_client client;
  };

  struct redirect_record_t
  {
    typename std::map<SupernodeId, SupernodeItem>::iterator it_local_sn;
    Clock::time_point expiry_time; // expiry time of this record
  };

  using redirect_records_t = std::vector<redirect_record_t>;

  template<class base_type>
  struct p2p_connection_context_t: base_type //t_payload_net_handler::connection_context //public net_utils::connection_context_base
  {
    p2p_connection_context_t(): peer_id(0), support_flags(0), m_in_timedsync(false) {}

    peerid_type peer_id;
    uint32_t support_flags;
    bool m_in_timedsync;
  };

  template<class t_payload_net_handler>
  class node_server: public epee::levin::levin_commands_handler<p2p_connection_context_t<typename t_payload_net_handler::connection_context> >,
                     public i_p2p_endpoint<typename t_payload_net_handler::connection_context>,
                     public epee::net_utils::i_connection_filter
  {
    struct by_conn_id{};
    struct by_peer_id{};
    struct by_addr{};

    typedef p2p_connection_context_t<typename t_payload_net_handler::connection_context> p2p_connection_context;

    typedef COMMAND_HANDSHAKE_T<typename t_payload_net_handler::payload_type> COMMAND_HANDSHAKE;
    typedef COMMAND_TIMED_SYNC_T<typename t_payload_net_handler::payload_type> COMMAND_TIMED_SYNC;

  public:
    typedef t_payload_net_handler payload_net_handler;

    node_server(t_payload_net_handler& payload_handler)
      :m_payload_handler(payload_handler),
    m_current_number_of_out_peers(0),
    m_current_number_of_in_peers(0),
    m_allow_local_ip(false),
    m_hide_my_port(false),
    m_no_igd(false),
    m_offline(false),
    m_save_graph(false),
    is_closing(false),
    m_net_server( epee::net_utils::e_connection_type_P2P ) // this is a P2P connection of the main p2p node server, because this is class node_server<>
    {}
    virtual ~node_server()
    {}

    static void init_options(boost::program_options::options_description& desc);

    bool run();
    bool init(const boost::program_options::variables_map& vm);
    bool deinit();
    bool send_stop_signal();
    uint32_t get_this_peer_port(){return m_listening_port;}
    t_payload_net_handler& get_payload_object();

    template <class Archive, class t_version_type>
    void serialize(Archive &a,  const t_version_type ver)
    {
      a & m_peerlist;
      if (ver == 0)
      {
        // from v1, we do not store the peer id anymore
        peerid_type peer_id = AUTO_VAL_INIT (peer_id);
        a & peer_id;
      }
    }
    // debug functions
    bool log_peerlist();
    bool log_connections();
    virtual uint64_t get_connections_count();
    size_t get_outgoing_connections_count();
    size_t get_incoming_connections_count();
    peerlist_manager& get_peerlist_manager(){return m_peerlist;}
    void delete_out_connections(size_t count);
    void delete_in_connections(size_t count);
    virtual bool block_host(const epee::net_utils::network_address &adress, time_t seconds = P2P_IP_BLOCKTIME);
    virtual bool unblock_host(const epee::net_utils::network_address &address);
    virtual std::map<std::string, time_t> get_blocked_hosts() { CRITICAL_REGION_LOCAL(m_blocked_hosts_lock); return m_blocked_hosts; }

    // Graft/RTA methods to be called from RPC handlers


    void do_send_rta_message(const cryptonote::COMMAND_RPC_BROADCAST::request &req);

    std::vector<cryptonote::route_data> get_tunnels() const;
    void do_broadcast(const cryptonote::COMMAND_RPC_BROADCAST::request &req, uint64_t hop = 0);

  private:

    const std::vector<std::string> m_seed_nodes_list =
    {
    };

    bool islimitup=false;
    bool islimitdown=false;

    typedef COMMAND_REQUEST_STAT_INFO_T<typename t_payload_net_handler::stat_info> COMMAND_REQUEST_STAT_INFO;

    CHAIN_LEVIN_INVOKE_MAP2(p2p_connection_context); //move levin_commands_handler interface invoke(...) callbacks into invoke map
    CHAIN_LEVIN_NOTIFY_MAP2(p2p_connection_context); //move levin_commands_handler interface notify(...) callbacks into nothing

    BEGIN_INVOKE_MAP2(node_server)
      HANDLE_NOTIFY_T2(COMMAND_BROADCAST, &node_server::handle_broadcast)
      HANDLE_INVOKE_T2(COMMAND_HANDSHAKE, &node_server::handle_handshake)
      HANDLE_INVOKE_T2(COMMAND_TIMED_SYNC, &node_server::handle_timed_sync)
      HANDLE_INVOKE_T2(COMMAND_PING, &node_server::handle_ping)
#ifdef ALLOW_DEBUG_COMMANDS
      HANDLE_INVOKE_T2(COMMAND_REQUEST_STAT_INFO, &node_server::handle_get_stat_info)
      HANDLE_INVOKE_T2(COMMAND_REQUEST_NETWORK_STATE, &node_server::handle_get_network_state)
      HANDLE_INVOKE_T2(COMMAND_REQUEST_PEER_ID, &node_server::handle_get_peer_id)
#endif
      HANDLE_INVOKE_T2(COMMAND_REQUEST_SUPPORT_FLAGS, &node_server::handle_get_support_flags)
      CHAIN_INVOKE_MAP_TO_OBJ_FORCE_CONTEXT(m_payload_handler, typename t_payload_net_handler::connection_context&)
    END_INVOKE_MAP2()

    enum PeerType { anchor = 0, white, gray };

    //----------------- helper functions ------------------------------------------------

    // sometimes supernode gets very busy so it doesn't respond within 1 second, increasing timeout to 3s
    static constexpr size_t SUPERNODE_HTTP_TIMEOUT_MILLIS = 3 * 1000;
    template<class request_struct>
    int post_request_to_supernode(SupernodeItem &local_sn, const std::string &method, const typename request_struct::request &body,
                                  const std::string &endpoint = std::string())
    {
        // TODO: Why it needs to be json-rpc??
        boost::value_initialized<epee::json_rpc::request<typename request_struct::request> > init_req;
        epee::json_rpc::request<typename request_struct::request>& req = static_cast<epee::json_rpc::request<typename request_struct::request> &>(init_req);
        req.jsonrpc = "2.0";
        req.id = 0;
        req.method = method;
        req.params = body;

        std::string uri = "/" + method;
        // TODO: What is this for?
        if (!endpoint.empty())
        {
            uri = endpoint;
        }
        typename request_struct::response resp = AUTO_VAL_INIT(resp);
        bool r = epee::net_utils::invoke_http_json(local_sn.uri + uri,
                                                   req, resp, local_sn.client,
                                                   std::chrono::milliseconds(size_t(SUPERNODE_HTTP_TIMEOUT_MILLIS)), "POST");
        if (!r || resp.status == 0)
        {
            return 0;
        }
        return 1;
    }

    template<typename request_struct>
    int post_request_to_supernodes(const std::string &method, const typename request_struct::request &body,
                                   const std::string &endpoint = std::string())
    {
      boost::lock_guard<boost::recursive_mutex> guard(m_supernodes_lock);
      int ret = 0;
      for(auto& sn : m_local_sns)
        ret += post_request_to_supernode<request_struct>(sn.second, method, body, endpoint);
      return ret;
    }

    template<typename request_struct>
    int post_request_to_supernode_receivers(const std::string &method, const typename request_struct::request &body,
                                   const std::string &endpoint = std::string())
    {
      boost::lock_guard<boost::recursive_mutex> guard(m_supernodes_lock);
      int ret = 0;
      if(body.receiver_addresses.empty())
      {
        for(auto& sn : m_local_sns)
          ret += post_request_to_supernode<request_struct>(sn.second, method, body, endpoint);
      }
      else
      {
        for(auto& id : body.receiver_addresses)
        {
          auto it = m_local_sns.find(id);
          if(it == m_local_sns.end()) continue;
          ret += post_request_to_supernode<request_struct>(it->second, method, body, endpoint);
        }
      }
      return ret;
    }

    void remove_old_request_cache();

    //----------------- commands handlers ----------------------------------------------
    int handle_broadcast(int command, typename COMMAND_BROADCAST::request &arg, p2p_connection_context &context);
    int handle_handshake(int command, typename COMMAND_HANDSHAKE::request& arg, typename COMMAND_HANDSHAKE::response& rsp, p2p_connection_context& context);
    int handle_timed_sync(int command, typename COMMAND_TIMED_SYNC::request& arg, typename COMMAND_TIMED_SYNC::response& rsp, p2p_connection_context& context);
    int handle_ping(int command, COMMAND_PING::request& arg, COMMAND_PING::response& rsp, p2p_connection_context& context);
#ifdef ALLOW_DEBUG_COMMANDS
    int handle_get_stat_info(int command, typename COMMAND_REQUEST_STAT_INFO::request& arg, typename COMMAND_REQUEST_STAT_INFO::response& rsp, p2p_connection_context& context);
    int handle_get_network_state(int command, COMMAND_REQUEST_NETWORK_STATE::request& arg, COMMAND_REQUEST_NETWORK_STATE::response& rsp, p2p_connection_context& context);
    int handle_get_peer_id(int command, COMMAND_REQUEST_PEER_ID::request& arg, COMMAND_REQUEST_PEER_ID::response& rsp, p2p_connection_context& context);
#endif
    int handle_get_support_flags(int command, COMMAND_REQUEST_SUPPORT_FLAGS::request& arg, COMMAND_REQUEST_SUPPORT_FLAGS::response& rsp, p2p_connection_context& context);
    bool init_config();
    bool make_default_peer_id();
    bool make_default_config();
    bool store_config();
    bool check_trust(const proof_of_trust& tr);
    //----------------- levin_commands_handler -------------------------------------------------------------
    virtual void on_connection_new(p2p_connection_context& context);
    virtual void on_connection_close(p2p_connection_context& context);
    virtual void callback(p2p_connection_context& context);
    //----------------- i_p2p_endpoint -------------------------------------------------------------
    virtual bool relay_notify_to_list(int command, const std::string& data_buff, const std::list<boost::uuids::uuid> &connections);
    virtual bool relay_notify_to_all(int command, const std::string& data_buff, const epee::net_utils::connection_context_base& context);
    virtual bool invoke_command_to_peer(int command, const std::string& req_buff, std::string& resp_buff, const epee::net_utils::connection_context_base& context);
    virtual bool invoke_notify_to_peer(int command, const std::string& req_buff, const epee::net_utils::connection_context_base& context);
    virtual bool drop_connection(const epee::net_utils::connection_context_base& context);
    virtual void request_callback(const epee::net_utils::connection_context_base& context);
    virtual void for_each_connection(std::function<bool(typename t_payload_net_handler::connection_context&, peerid_type, uint32_t)> f);
    virtual bool for_connection(const boost::uuids::uuid&, std::function<bool(typename t_payload_net_handler::connection_context&, peerid_type, uint32_t)> f);
    virtual bool add_host_fail(const epee::net_utils::network_address &address);
    // added, non virtual
    /*!
     * \brief relay_notify    - send command to remote connection
     * \param command         - command
     * \param data_buff       - data buffer to send
     * \param connection_id   - connection id
     * \return                - true on success
     */
    bool relay_notify(int command, const std::string& data_buff, const boost::uuids::uuid& connection_id);
    //----------------- i_connection_filter  --------------------------------------------------------
    virtual bool is_remote_host_allowed(const epee::net_utils::network_address &address);
    //-----------------------------------------------------------------------------------------------
    bool parse_peer_from_string(epee::net_utils::network_address& pe, const std::string& node_addr, uint16_t default_port = 0);
    bool handle_command_line(
        const boost::program_options::variables_map& vm
      );
    bool idle_worker();
    bool handle_remote_peerlist(const std::list<peerlist_entry>& peerlist, time_t local_time, const epee::net_utils::connection_context_base& context);
    bool get_local_node_data(basic_node_data& node_data);
    // bool get_local_handshake_data(handshake_data& hshd);

    bool merge_peerlist_with_local(const std::list<peerlist_entry>& bs);
    bool fix_time_delta(std::list<peerlist_entry>& local_peerlist, time_t local_time, int64_t& delta);

    bool connections_maker();
    bool peer_sync_idle_maker();
    bool do_handshake_with_peer(peerid_type& pi, p2p_connection_context& context, bool just_take_peerlist = false);
    bool do_peer_timed_sync(const epee::net_utils::connection_context_base& context, peerid_type peer_id);

    bool make_new_connection_from_anchor_peerlist(const std::vector<anchor_peerlist_entry>& anchor_peerlist);
    bool make_new_connection_from_peerlist(bool use_white_list);
    bool try_to_connect_and_handshake_with_new_peer(const epee::net_utils::network_address& na, bool just_take_peerlist = false, uint64_t last_seen_stamp = 0, PeerType peer_type = white, uint64_t first_seen_stamp = 0);
    size_t get_random_index_with_fixed_probability(size_t max_index);
    bool is_peer_used(const peerlist_entry& peer);
    bool is_peer_used(const anchor_peerlist_entry& peer);
    bool is_addr_connected(const epee::net_utils::network_address& peer);
    void add_upnp_port_mapping(uint32_t port);
    void delete_upnp_port_mapping(uint32_t port);
    template<class t_callback>
    bool try_ping(basic_node_data& node_data, p2p_connection_context& context, const t_callback &cb);
    bool try_get_support_flags(const p2p_connection_context& context, std::function<void(p2p_connection_context&, const uint32_t&)> f);
    bool make_expected_connections_count(PeerType peer_type, size_t expected_connections);
    void cache_connect_fail_info(const epee::net_utils::network_address& addr);
    bool is_addr_recently_failed(const epee::net_utils::network_address& addr);
    bool is_priority_node(const epee::net_utils::network_address& na);
    std::set<std::string> get_seed_nodes(cryptonote::network_type nettype) const;
    bool connect_to_seed();
    bool find_connection_id_by_peer(const peerlist_entry &pe, boost::uuids::uuid &conn_id);
    template <class Container>
    bool connect_to_peerlist(const Container& peers);

    template <class Container>
    bool parse_peers_and_add_to_container(const boost::program_options::variables_map& vm, const command_line::arg_descriptor<std::vector<std::string> > & arg, Container& container);

    bool set_max_out_peers(const boost::program_options::variables_map& vm, int64_t max);
    bool set_max_in_peers(const boost::program_options::variables_map& vm, int64_t max);
    bool set_tos_flag(const boost::program_options::variables_map& vm, int limit);

    bool set_rate_up_limit(const boost::program_options::variables_map& vm, int64_t limit);
    bool set_rate_down_limit(const boost::program_options::variables_map& vm, int64_t limit);
    bool set_rate_limit(const boost::program_options::variables_map& vm, int64_t limit);

    bool has_too_many_connections(const epee::net_utils::network_address &address);

    bool check_connection_and_handshake_with_peer(const epee::net_utils::network_address& na, uint64_t last_seen_stamp);
    bool gray_peerlist_housekeeping();
    bool check_incoming_connections();

    void kill() { ///< will be called e.g. from deinit()
      _info("Killing the net_node");
      is_closing = true;
      if(mPeersLoggerThread != nullptr)
        mPeersLoggerThread->join(); // make sure the thread finishes
      _info("Joined extra background net_node threads");
    }


    //debug functions
    std::string print_connections_container();


    typedef epee::net_utils::boosted_tcp_server<epee::levin::async_protocol_handler<p2p_connection_context> > net_server;

    struct config
    {
      network_config m_net_config;
      uint64_t m_peer_id;
      uint32_t m_support_flags;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(m_net_config)
        KV_SERIALIZE(m_peer_id)
        KV_SERIALIZE(m_support_flags)
      END_KV_SERIALIZE_MAP()
    };

  public:
    config m_config; // TODO was private, add getters?
    std::atomic<unsigned int> m_current_number_of_out_peers;
    std::atomic<unsigned int> m_current_number_of_in_peers;

    void set_save_graph(bool save_graph)
    {
      m_save_graph = save_graph;
      epee::net_utils::connection_basic::set_save_graph(save_graph);
    }

    template<typename C>
    std::string join(const C& c, const std::string &joiner = " ") {
        std::ostringstream s;
        bool first = true;
        for (const auto& addr : c) {
            if (first) first = false;
            else s << joiner;
            s << addr;
        }
        return s.str();
    }

    bool notify_peer_list(int command, const std::string& buf, const std::vector<peerlist_entry>& peers_to_send, bool try_connect = false);

    void send_stakes_to_supernode();
    void send_blockchain_based_list_to_supernode(uint64_t last_received_block_height);

    uint64_t get_broadcast_bytes_in() const { return m_broadcast_bytes_in; }
    uint64_t get_broadcast_bytes_out() const { return m_broadcast_bytes_out; }
    uint64_t get_rta_p2p_msg_count() const { return m_rta_msg_p2p_counter; }
    uint64_t get_rta_jump_list_local_msg_count() const { return m_rta_msg_jump_list_local_counter; }
    uint64_t get_rta_jump_list_remote_msg_count() const { return m_rta_msg_jump_list_remote_counter; }

    //returns empty if sn is not found or dead
    SupernodeId check_supernode_id(const SupernodeId& local_sn)
    {
      if (local_sn.empty()) {
        MERROR("Invalid input: empty id passed");
        return local_sn;
      }
      boost::lock_guard<boost::recursive_mutex> guard(m_supernodes_lock);
      auto it = m_local_sns.find(local_sn);
      if (it == m_local_sns.end())  {
        MERROR("Unable to find local supernode with id: " << local_sn);
        return SupernodeId();
      }
      SupernodeItem& l_sn = it->second;
      if(l_sn.expiry_time < Clock::now())
      {
        //erase all l_sn references from m_redirect_supernode_ids
        for(auto rit = m_redirect_supernode_ids.begin(), erit = m_redirect_supernode_ids.end(); rit != erit;)
        {
          redirect_records_t& recs = rit->second;
          assert(!recs.empty());
          recs.erase(std::remove_if(recs.begin(), recs.end(), [it](redirect_record_t& v)->bool{ return v.it_local_sn == it; } ), recs.end());
          if(recs.empty())
          {
            rit = m_redirect_supernode_ids.erase(rit);
          }
          else ++rit;
        }
        //erase l_sn
        m_local_sns.erase(it);
        return SupernodeId();
      }
      return local_sn;
    }

    void register_supernode(const cryptonote::COMMAND_RPC_REGISTER_SUPERNODE::request& req)
    {
      if (req.supernode_id.empty()) {
        MERROR("Failed to register supernode: empty id");
        return;
      }
      MDEBUG("registering supernode: " << req.supernode_id << ", url: " << req.supernode_url);

      boost::lock_guard<boost::recursive_mutex> guard(m_supernodes_lock);

      SupernodeItem& sn = m_local_sns[req.supernode_id];
      sn.redirect_uri = req.redirect_uri;
      sn.redirect_timeout_ms = req.redirect_timeout_ms;
      sn.expiry_time = get_expiry_time(req.supernode_id);

      {//set sn.client & sn.uri
        epee::net_utils::http::url_content parsed{};
        bool ret = epee::net_utils::parse_url(req.supernode_url, parsed);
        sn.uri = std::move(parsed.uri);
        if (sn.client.is_connected()) sn.client.disconnect();
        sn.client.set_server(parsed.host, std::to_string(parsed.port), {});
      }
    }
    // TODO: Why cryptonode can't just forward message directly to a supernode?
    void add_rta_route(const std::string& id, const std::string& my_id)
    {
        boost::lock_guard<boost::recursive_mutex> guard(m_supernodes_lock);
        auto it = m_local_sns.find(my_id);
        if(it == m_local_sns.end()) {
          MERROR("Failed to add route: " << my_id << " is unknown supernode"); 
          return;
        }
        auto expiry_time = get_expiry_time(my_id);
        redirect_records_t& recs = m_redirect_supernode_ids[id];
        auto it2 = std::find_if(recs.begin(), recs.end(), [it](const redirect_record_t& r)->bool { return r.it_local_sn == it; });
        if(it2 == recs.end())
        {
          recs.emplace_back(redirect_record_t{it, expiry_time});
        }
        else
        {
          assert( it2->it_local_sn == it );
          it2->expiry_time = expiry_time;
        }
    }

    Clock::time_point get_expiry_time(const SupernodeId& local_sn)
    {
      boost::lock_guard<boost::recursive_mutex> guard(m_supernodes_lock);
      auto it = m_local_sns.find(local_sn);
      assert(it != m_local_sns.end());
      return Clock::now() + std::chrono::milliseconds(it->second.redirect_timeout_ms);
    }

  private:
    void handle_stakes_update(uint64_t block_number, const cryptonote::StakeTransactionProcessor::supernode_stake_array& stakes);
    void handle_blockchain_based_list_update(uint64_t block_number, const cryptonote::StakeTransactionProcessor::supernode_tier_array& tiers);

  private:
    std::multimap<int, std::string> m_supernode_requests_timestamps;
    std::set<std::string> m_supernode_requests_cache;
    boost::recursive_mutex m_request_cache_lock;
    std::vector<epee::net_utils::network_address> m_custom_seed_nodes;

    std::map<SupernodeId, SupernodeItem> m_local_sns;
    std::map<SupernodeId, redirect_records_t> m_redirect_supernode_ids; //recipients ids to redirect to the supernode
    boost::recursive_mutex m_supernodes_lock;

    std::string m_config_folder;

    bool m_have_address;
    bool m_first_connection_maker_call;
    uint32_t m_listening_port;
    uint32_t m_external_port;
    uint32_t m_ip_address;
    bool m_allow_local_ip;
    bool m_hide_my_port;
    bool m_no_igd;
    bool m_offline;
    std::atomic<bool> m_save_graph;
    std::atomic<bool> is_closing;
    std::unique_ptr<boost::thread> mPeersLoggerThread;
    //critical_section m_connections_lock;
    //connections_indexed_container m_connections;

    t_payload_net_handler& m_payload_handler;
    peerlist_manager m_peerlist;

    epee::math_helper::once_a_time_seconds<P2P_DEFAULT_HANDSHAKE_INTERVAL> m_peer_handshake_idle_maker_interval;
    epee::math_helper::once_a_time_seconds<1> m_connections_maker_interval;
    epee::math_helper::once_a_time_seconds<60*30, false> m_peerlist_store_interval;
    epee::math_helper::once_a_time_seconds<60> m_gray_peerlist_housekeeping_interval;
    epee::math_helper::once_a_time_seconds<900, false> m_incoming_connections_interval;

    std::string m_bind_ip;
    std::string m_port;
#ifdef ALLOW_DEBUG_COMMANDS
    uint64_t m_last_stat_request_time;
#endif
    std::list<epee::net_utils::network_address>   m_priority_peers;
    std::vector<epee::net_utils::network_address> m_exclusive_peers;
    std::vector<epee::net_utils::network_address> m_seed_nodes;
    bool m_fallback_seed_nodes_added;
    std::list<nodetool::peerlist_entry> m_command_line_peers;
    uint64_t m_peer_livetime;
    //keep connections to initiate some interactions
    net_server m_net_server;
    Uuid m_network_id;

    std::map<epee::net_utils::network_address, time_t> m_conn_fails_cache;
    epee::critical_section m_conn_fails_cache_lock;

    epee::critical_section m_blocked_hosts_lock;
    std::map<std::string, time_t> m_blocked_hosts;

    epee::critical_section m_host_fails_score_lock;
    std::map<std::string, uint64_t> m_host_fails_score;

    cryptonote::network_type m_nettype;
    // traffic counters
    std::atomic<uint64_t> m_broadcast_bytes_in {0};
    std::atomic<uint64_t> m_broadcast_bytes_out {0};
    
    // number of RTA messages/requests transferred over p2p
    std::atomic<uint64_t> m_rta_msg_p2p_counter {0};
    // number of RTA messages/requests transferred to local supernodes vim pubkey -> network address mapping
    std::atomic<uint64_t> m_rta_msg_jump_list_local_counter {0};
    // number of RTA messages/requests transferred to supernodes vim pubkey -> network address mapping
    std::atomic<uint64_t> m_rta_msg_jump_list_remote_counter {0};
  };

  const int64_t default_limit_up = 2048;    // kB/s
  const int64_t default_limit_down = 8192;  // kB/s

  extern const command_line::arg_descriptor<int64_t>     arg_in_peers;
  extern const command_line::arg_descriptor<std::string, false, true, 2> arg_p2p_bind_port;
}

POP_WARNINGS
