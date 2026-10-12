// A VPN session is one tunnel connection from a phone. It owns the flows
// (TCP connections, UDP and ICMP "conversations") opened by that phone.
//
// All objects here live on exactly one worker thread of the reactor server
// (the worker that owns the tunnel connection; the outbound sockets of the
// flows are created by the same worker and therefore report to it as well),
// so no locking is needed.
#ifndef SIMPLEVPN_VPN_SESSION_H
#define SIMPLEVPN_VPN_SESSION_H

#include <cstdint>
#include <memory>
#include <random>
#include <string>
#include <unordered_map>
#include <vector>

#include "inspector.h"
#include "packet.h"
#include "pcap_writer.h"
#include "server_api.h"

namespace vpn {

// Global options (vpn_* keys of the server config), read-only after start
struct VpnConfig {
    std::string token;                     // vpn_token: shared secret clients must present
    int hello_timeout_ms = 10000;          // vpn_hello_timeout_ms
    int tcp_idle_timeout_s = 3600;         // vpn_tcp_idle_timeout
    int tcp_half_close_timeout_s = 120;    // vpn_tcp_half_close_timeout
    int udp_idle_timeout_s = 120;          // vpn_udp_idle_timeout
    int dns_idle_timeout_s = 20;           // vpn_dns_idle_timeout
    int icmp_idle_timeout_s = 30;          // vpn_icmp_idle_timeout
    int max_flows_per_session = 4096;      // vpn_max_flows
    uint32_t tcp_window = 512 * 1024;      // vpn_tcp_window: receive window advertised to the phone
    size_t tcp_flow_buffer = 1024 * 1024;  // vpn_tcp_flow_buffer: pause reading the server above this
    std::string pcap_dir;                  // vpn_pcap_dir: capture every session to a pcap file
    size_t pcap_max_bytes = 100 << 20;     // vpn_pcap_max_mb
    bool block_private_targets = false;    // vpn_block_private: refuse loopback/private destinations
    bool block_quic = false;               // vpn_block_quic: reject UDP 443 so apps fall back to TCP + TLS
    int stats_interval_s = 60;             // vpn_stats_interval
    size_t session_inflight = 4 << 20;     // vpn_session_inflight: unacknowledged bytes per tunnel
};
extern VpnConfig g_vpn_config;

struct FlowKey {
    uint8_t protocol = 0;
    IpAddr src;           // phone side
    IpAddr dst;           // internet side
    uint16_t src_port = 0; // ICMP: echo identifier
    uint16_t dst_port = 0;

    bool operator==(const FlowKey& o) const {
        return protocol == o.protocol && src_port == o.src_port && dst_port == o.dst_port && src == o.src &&
               dst == o.dst;
    }
};

struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const {
        return k.src.hash() * 31 + k.dst.hash() * 17 + (static_cast<size_t>(k.src_port) << 16) + k.dst_port +
               k.protocol;
    }
};

class Session;

// Base class of the TCP / UDP / ICMP flows
class Flow {
public:
    Flow(Session* session, const FlowKey& key, uint64_t id);
    virtual ~Flow();

    // A packet from the phone that belongs to this flow
    virtual void on_packet(const ParsedPacket& packet) = 0;
    // Events of the outbound socket (see handle_server_* in server_api.h)
    virtual void on_upstream_open(int error) = 0;
    virtual void on_upstream_data(const char* data, int len) = 0; // data == nullptr: EOF
    virtual void on_upstream_close(int error) = 0;
    virtual void on_upstream_write_blocked(bool /*blocked*/) {}
    // The tunnel to the phone has room again
    virtual void on_tunnel_writable() {}
    virtual void on_timer(int64_t now_ms) = 0;

    uint64_t id() const { return id_; }
    const FlowKey& key() const { return key_; }
    const std::string& name() const { return name_; }
    bool dead() const { return dead_; }
    Session* session() const { return session_; }

protected:
    // Mark the flow for deletion; closes (or aborts) the outbound socket
    void finish(bool abort_upstream, const char* reason);
    void touch();

    Session* session_;
    FlowKey key_;
    uint64_t id_;
    std::string name_;            // e.g. "S1 TCP#12 172.19.0.2:40000 -> 1.2.3.4:443"
    SocketInfo upstream_{};
    bool has_upstream_ = false;
    bool dead_ = false;
    int64_t created_ms_;
    int64_t last_activity_ms_;
    uint64_t bytes_up_ = 0;       // phone -> internet payload bytes
    uint64_t bytes_down_ = 0;     // internet -> phone payload bytes
    FlowInspectState inspect_;
};

class Session {
public:
    Session(const SocketInfo& tunnel, uint64_t session_id);
    ~Session();

    // A complete frame from the phone
    void on_frame(uint8_t type, const uint8_t* payload, size_t len);
    void on_tunnel_write_blocked(bool blocked);
    void on_timer(int64_t now_ms);

    // Send a raw IP packet to the phone
    void send_packet(const std::string& packet);
    bool tunnel_blocked() const { return tunnel_blocked_; }

    // Close the tunnel (optionally with an ERROR frame)
    void close(const char* reason);

    // Delete flows that finished
    void reap();
    void mark_dead(const FlowKey& key) { dead_keys_.push_back(key); }

    // Session wide budget of bytes sent to the phone but not yet acknowledged,
    // so that one tunnel never buffers more than that (latency!)
    void add_inflight(long delta);
    size_t inflight_room() const {
        return inflight_ < g_vpn_config.session_inflight ? g_vpn_config.session_inflight - inflight_ : 0;
    }
    void wait_for_budget(uint64_t flow_id);
    size_t inflight() const { return inflight_; }

    // Flow bookkeeping
    uint64_t allocate_flow_id();
    void register_flow(Flow* flow);
    void unregister_flow(Flow* flow);

    const std::string& tag() const { return tag_; }
    int mtu() const { return mtu_; }
    uint32_t random32();

private:
    void handle_hello(const uint8_t* payload, size_t len);
    void handle_packet(const uint8_t* data, size_t len);
    void dispatch_packet(const ParsedPacket& p);
    void handle_tcp(const ParsedPacket& p);
    void handle_udp(const ParsedPacket& p);
    void handle_icmp(const ParsedPacket& p);
    void send_frame(uint8_t type, const void* data, size_t len);
    void send_tcp_reset_for(const ParsedPacket& p);
    bool target_allowed(const IpAddr& dst) const;
    void log_stats(const char* prefix) const;

    SocketInfo tunnel_;
    uint64_t session_id_;
    std::string tag_;               // "S<id>" used in log lines
    bool authenticated_ = false;
    bool closing_ = false;
    bool tunnel_blocked_ = false;
    int mtu_ = 1500;
    std::string client_name_;
    int64_t created_ms_;
    int64_t last_stats_ms_;
    PcapWriter pcap_;
    FragmentReassembler reassembler_;
    uint32_t next_ip_id_ = 1;

    std::unordered_map<FlowKey, std::unique_ptr<Flow>, FlowKeyHash> flows_;
    std::vector<FlowKey> dead_keys_;
    size_t inflight_ = 0;
    std::vector<uint64_t> starved_flows_; // flows waiting for inflight budget
    bool budget_released_ = false;

    // statistics
    uint64_t packets_in_ = 0, packets_out_ = 0, bytes_in_ = 0, bytes_out_ = 0;
    uint64_t dropped_ = 0, flows_created_ = 0;
};

// Per worker thread state of the plugin
struct WorkerState {
    std::unordered_map<uint64_t, std::unique_ptr<Session>> sessions; // by tunnel conn_id
    std::unordered_map<uint64_t, Flow*> flows;                       // by flow id (= upstream user_tag)
    uint64_t next_flow_id = 1;
    std::mt19937 rng;
};
extern thread_local WorkerState* t_worker;

int64_t now_ms();

} // namespace vpn

#endif // SIMPLEVPN_VPN_SESSION_H
