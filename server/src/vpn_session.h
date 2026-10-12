/**
 * @file vpn_session.h
 * @brief Session (one phone's tunnel), Flow (one TCP connection / UDP or ICMP
 *        "conversation" of that phone), the global VPN configuration and the
 *        per-worker state of the plugin.
 *
 * Overview
 * --------
 * A VPN session is one tunnel connection from a phone. The phone sends raw
 * IP packets; the session parses them and sorts them by FlowKey (protocol +
 * addresses + ports) into flows. Each flow owns one outbound socket to the
 * real destination (created through the reactor engine with srv_connect()),
 * i.e. the server acts as a user-space NAT / transparent proxy:
 *   phone app -> TUN -> tunnel -> Session -> Flow -> outbound socket -> internet
 * and the answers travel the same way back, rebuilt into IP packets by the
 * flow and sent to the phone with Session::send_packet().
 *
 * Threading: all objects here live on exactly one worker thread of the
 * reactor server (the worker that owns the tunnel connection; the outbound
 * sockets of the flows are created by the same worker and therefore report
 * to it as well), so no locking is needed. The only shared object,
 * g_vpn_config, is written once at start up and read-only afterwards.
 *
 * Reading guide: VpnConfig (the knobs), FlowKey, Flow (the interface every
 * flow implements, see flows.h for TCP/UDP/ICMP), Session (packet dispatch,
 * flow table, back pressure), WorkerState. The implementation is in
 * vpn_session.cpp, the callbacks that drive it in vpn_plugin.cpp.
 */
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

/**
 * @brief Global options (vpn_* keys of the server config file).
 *
 * Filled by load_config() in vpn_plugin.cpp on the MAIN thread before the
 * workers start; read-only afterwards, so workers read it without locks.
 * The initializers are the defaults used when a key is missing.
 */
struct VpnConfig {
    std::string token;                     // vpn_token: shared secret clients must present
    int hello_timeout_ms = 10000;          // vpn_hello_timeout_ms: close tunnels that do not authenticate in time
    int tcp_idle_timeout_s = 3600;         // vpn_tcp_idle_timeout: drop silent TCP flows
    int tcp_half_close_timeout_s = 120;    // vpn_tcp_half_close_timeout: same, once one side sent FIN
    int udp_idle_timeout_s = 120;          // vpn_udp_idle_timeout: forget silent UDP "conversations"
    int dns_idle_timeout_s = 20;           // vpn_dns_idle_timeout: shorter, DNS is one query + one answer
    int icmp_idle_timeout_s = 30;          // vpn_icmp_idle_timeout: ping flows
    int max_flows_per_session = 4096;      // vpn_max_flows: protects the server from one runaway phone
    uint32_t tcp_window = 512 * 1024;      // vpn_tcp_window: receive window advertised to the phone
    size_t tcp_flow_buffer = 1024 * 1024;  // vpn_tcp_flow_buffer: pause reading the server above this
    std::string pcap_dir;                  // vpn_pcap_dir: capture every session to a pcap file
    size_t pcap_max_bytes = 100 << 20;     // vpn_pcap_max_mb: size limit of one pcap file (stored in bytes)
    int capture_port = 0;                  // vpn_capture_port: live pcap stream port (also in the bind file), 0 = off
    bool capture_allow_remote = false;     // vpn_capture_allow_remote: accept capture clients that are not on loopback
    bool block_private_targets = false;    // vpn_block_private: refuse loopback/private destinations
    bool block_quic = false;               // vpn_block_quic: reject UDP 443 so apps fall back to TCP + TLS
    int stats_interval_s = 60;             // vpn_stats_interval: log session statistics this often, 0 = never
    size_t session_inflight = 4 << 20;     // vpn_session_inflight: unacknowledged bytes per tunnel
};
/// The one global configuration instance (defined in vpn_session.cpp).
extern VpnConfig g_vpn_config;

/**
 * @brief Identity of a flow, as seen in the packets coming FROM the phone.
 *
 * Packets in the other direction are built by the flow itself, so only the
 * phone-to-internet orientation is ever looked up. For TCP and UDP this is
 * the classic 5-tuple; for ICMP echo the identifier takes the place of the
 * source port (that is how ping programs tell their replies apart) and
 * dst_port stays 0.
 */
struct FlowKey {
    uint8_t protocol = 0;  // kProtoTcp, kProtoUdp, kProtoIcmp or kProtoIcmpV6
    IpAddr src;            // phone side
    IpAddr dst;            // internet side
    uint16_t src_port = 0; // ICMP: echo identifier
    uint16_t dst_port = 0; // ICMP: 0

    /// Field-wise equality, required by std::unordered_map.
    bool operator==(const FlowKey& o) const {
        // cheap integer comparisons first, the 16-byte addresses last
        return protocol == o.protocol && src_port == o.src_port && dst_port == o.dst_port && src == o.src &&
               dst == o.dst;
    }
};

/**
 * @brief Hash function object for FlowKey (std::unordered_map key).
 */
struct FlowKeyHash {
    /**
     * @param k Key to hash.
     * @return A hash mixing addresses, ports and protocol (multipliers spread the bits).
     */
    size_t operator()(const FlowKey& k) const {
        return k.src.hash() * 31 + k.dst.hash() * 17 + (static_cast<size_t>(k.src_port) << 16) + k.dst_port +
               k.protocol;
    }
};

class Session;

/**
 * @brief Base class of the TCP / UDP / ICMP flows (implementations in flows.h).
 *
 * A flow connects one "conversation" of the phone with one outbound socket.
 * Its life cycle: created by the Session when the first packet arrives
 * (registers itself in the worker's flow table under its id), receives
 * packets from the phone (on_packet) and events of its outbound socket
 * (on_upstream_*), and ends by calling finish(). finish() only MARKS the flow
 * dead; the Session deletes it later in reap(), because a flow must never be
 * deleted while one of its own methods is still running.
 */
class Flow {
public:
    /**
     * @param session Owning session (outlives the flow).
     * @param key     The flow's identity.
     * @param id      Unique id on this worker; also used as the user_tag of
     *                the outbound socket, so engine events find the flow again.
     */
    Flow(Session* session, const FlowKey& key, uint64_t id);
    /// Aborts the outbound socket if still open and unregisters the flow.
    virtual ~Flow();

    /// A packet from the phone that belongs to this flow.
    virtual void on_packet(const ParsedPacket& packet) = 0;
    // Events of the outbound socket (see handle_server_* in server_api.h)
    /// srv_connect() finished; @p error is 0 or an errno value.
    virtual void on_upstream_open(int error) = 0;
    virtual void on_upstream_data(const char* data, int len) = 0; // data == nullptr: EOF
    /// The outbound socket is closed; @p error is the errno that caused it (0 = normal).
    virtual void on_upstream_close(int error) = 0;
    /// The outbound socket's send queue is full (true) or drained (false).
    virtual void on_upstream_write_blocked(bool /*blocked*/) {}
    /// The tunnel to the phone has room again (or in-flight budget was released).
    virtual void on_tunnel_writable() {}
    /// Periodic tick (timeouts, retransmissions); @p now_ms from now_ms().
    virtual void on_timer(int64_t now_ms) = 0;

    uint64_t id() const { return id_; }
    const FlowKey& key() const { return key_; }
    const std::string& name() const { return name_; }
    bool dead() const { return dead_; }        // finished, waiting for Session::reap()
    Session* session() const { return session_; }

protected:
    /**
     * @brief Mark the flow for deletion; closes (or aborts) the outbound socket.
     * @param abort_upstream true = discard unsent data (TCP RST), false = close gracefully.
     * @param reason         Logged at INFO level if not nullptr.
     */
    void finish(bool abort_upstream, const char* reason);
    /// Record activity now (resets the idle timeout).
    void touch();

    Session* session_;            // owner; valid for the whole life of the flow
    FlowKey key_;                 // identity (phone side orientation)
    uint64_t id_;                 // unique per worker, = user_tag of upstream_
    std::string name_;            // e.g. "S1 TCP#12 172.19.0.2:40000 -> 1.2.3.4:443"
    SocketInfo upstream_{};       // the outbound socket to the real destination
    bool has_upstream_ = false;   // upstream_ is open and must be closed by us
    bool dead_ = false;           // finish() was called
    int64_t created_ms_;          // creation time (monotonic ms), for statistics
    int64_t last_activity_ms_;    // last touch(), for idle timeouts
    uint64_t bytes_up_ = 0;       // phone -> internet payload bytes
    uint64_t bytes_down_ = 0;     // internet -> phone payload bytes
    FlowInspectState inspect_;    // what the Inspector learned (protocol, host name ...)
};

/**
 * @brief One phone's tunnel connection and all of its flows.
 *
 * Responsibilities: the HELLO handshake (authentication), turning PACKET
 * frames into parsed packets (with fragment reassembly) and dispatching them
 * to flows, sending packets back to the phone (with fragmentation if they
 * exceed the phone's MTU), answering PINGs, pcap / live capture, back
 * pressure towards the flows, and periodic housekeeping.
 */
class Session {
public:
    /**
     * @param tunnel     Snapshot of the accepted tunnel connection (used for srv_send()).
     * @param session_id Id shown in logs as "S<id>" (the tunnel's conn_id).
     */
    Session(const SocketInfo& tunnel, uint64_t session_id);
    /// Logs final statistics, deletes all flows (aborting their sockets), closes the pcap file.
    ~Session();

    /**
     * @brief A complete frame from the phone.
     * @param type    Frame type (tunnel::FrameType).
     * @param payload Payload after the 8-byte header.
     * @param len     Payload length.
     */
    void on_frame(uint8_t type, const uint8_t* payload, size_t len);
    /// Tunnel send queue crossed the high (true) / low (false) watermark.
    void on_tunnel_write_blocked(bool blocked);
    /// Periodic tick from handle_timer().
    void on_timer(int64_t now_ms);

    /**
     * @brief Send a raw IP packet to the phone (wrapped in a PACKET frame).
     * @param packet Complete IPv4/IPv6 packet built by a flow.
     */
    void send_packet(const std::string& packet);
    /// true while the tunnel's send queue is above the high watermark.
    bool tunnel_blocked() const { return tunnel_blocked_; }

    /**
     * @brief Close the tunnel (optionally with an ERROR frame) and drop all flows.
     * @param reason Sent to the phone in an ERROR frame and logged; nullptr = silent close.
     */
    void close(const char* reason);

    /// Delete flows that finished and resume flows waiting for in-flight budget.
    void reap();
    /// Called by Flow::finish(): remember the key so reap() can delete the flow.
    void mark_dead(const FlowKey& key) { dead_keys_.push_back(key); }

    // Session wide budget of bytes sent to the phone but not yet acknowledged,
    // so that one tunnel never buffers more than that (latency!)
    /// Add (or with a negative @p delta release) unacknowledged bytes.
    void add_inflight(long delta);
    /// How many more unacknowledged bytes the flows may send right now.
    size_t inflight_room() const {
        return inflight_ < g_vpn_config.session_inflight ? g_vpn_config.session_inflight - inflight_ : 0;
    }
    /// A flow found no budget: call its on_tunnel_writable() once budget is released (FIFO).
    void wait_for_budget(uint64_t flow_id);
    size_t inflight() const { return inflight_; }

    // Flow bookkeeping (the worker wide id -> flow table used by the engine callbacks)
    /// @return A new flow id, unique on this worker.
    uint64_t allocate_flow_id();
    void register_flow(Flow* flow);
    void unregister_flow(Flow* flow);

    const std::string& tag() const { return tag_; }
    /// MTU of the phone's TUN device (from HELLO): the largest packet we may send it.
    int mtu() const { return mtu_; }
    /// @return 32 random bits from the worker's generator (TCP initial sequence numbers).
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

    SocketInfo tunnel_;             // the tunnel connection (target of srv_send / srv_close)
    uint64_t session_id_;           // numeric id (the tunnel's conn_id)
    std::string tag_;               // "S<id>" used in log lines
    bool authenticated_ = false;    // a valid HELLO was received
    bool closing_ = false;          // close() was called; ignore everything from now on
    bool tunnel_blocked_ = false;   // tunnel send queue above the high watermark
    int mtu_ = 1500;                // phone's TUN MTU (from HELLO, 576..65535)
    std::string client_name_;       // "client" key of HELLO (e.g. "android"), for logs
    int64_t created_ms_;            // creation time, for the HELLO timeout and statistics
    int64_t last_stats_ms_;         // last periodic statistics line
    int64_t last_flush_ms_ = 0;     // last pcap flush
    PcapWriter pcap_;               // per session capture file (if vpn_pcap_dir is set)
    FragmentReassembler reassembler_; // joins IP fragments sent by the phone
    uint32_t next_ip_id_ = 1;       // IP identification for packets we fragment

    std::unordered_map<FlowKey, std::unique_ptr<Flow>, FlowKeyHash> flows_; // owns the flows
    std::vector<FlowKey> dead_keys_;      // flows marked dead, deleted by reap()
    size_t inflight_ = 0;                 // unacknowledged bytes of all TCP flows towards the phone
    std::vector<uint64_t> starved_flows_; // flows waiting for inflight budget
    bool budget_released_ = false;        // budget was released while flows were waiting

    // statistics
    uint64_t packets_in_ = 0, packets_out_ = 0, bytes_in_ = 0, bytes_out_ = 0; // in = from phone, out = to phone
    uint64_t dropped_ = 0, flows_created_ = 0;
};

/**
 * @brief Per worker thread state of the plugin (one instance per worker, see t_worker).
 */
struct WorkerState {
    std::unordered_map<uint64_t, std::unique_ptr<Session>> sessions; // by tunnel conn_id
    std::unordered_map<uint64_t, Flow*> flows;                       // by flow id (= upstream user_tag); not owning
    uint64_t next_flow_id = 1;                                       // id allocator for flows
    std::mt19937 rng;                                                // random numbers (TCP ISN), seeded in handle_init
};
/// This worker thread's state; created in handle_init(SRV_THREAD_WORK), nullptr on other threads.
extern thread_local WorkerState* t_worker;

/// @return Monotonic time in milliseconds (steady clock; not affected by wall clock changes).
int64_t now_ms();

} // namespace vpn

#endif // SIMPLEVPN_VPN_SESSION_H
