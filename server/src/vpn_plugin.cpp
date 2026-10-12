/**
 * @file vpn_plugin.cpp
 * @brief Entry points of the SimpleVPN server plugin for the multithread
 *        reactor server (the handle_* callbacks of server_api.h).
 *
 * Overview
 * --------
 * The reactor engine ("mulserver", git submodule in server/reactor) owns all
 * sockets and threads; this plugin is a shared library it loads with
 * dlopen() and calls back into. Each phone connects with ONE TCP tunnel
 * connection and sends raw IP packets inside frames (see
 * common/tunnel_protocol.h). For every tunnel the plugin creates a Session
 * (vpn_session.h); the session terminates the TCP / UDP / ICMP flows found in
 * those packets (flows.h), logs (and optionally rewrites) what goes through
 * (inspector.h), records it to pcap (pcap_writer.h) and forwards everything to
 * the real destinations with ordinary outbound sockets that are also owned by
 * the reactor engine (srv_connect()).
 *
 * Thread model (see the comment at the top of server_api.h):
 *   - MAIN thread: handle_init(SRV_THREAD_MAIN) reads the configuration once.
 *   - CONN thread: the single network thread. It only calls
 *     handle_input_from_client() here, to cut the byte stream into frames.
 *     It must not touch per-worker state.
 *   - WORK threads: every other callback. The engine binds each connection
 *     to one worker (tunnel connections are spread round robin; outbound
 *     connections created with srv_connect() stay on the worker that created
 *     them). So a session and all of its flows and outbound sockets live on
 *     the same worker thread, and the per-worker WorkerState (t_worker) needs
 *     no locks at all. This "worker affinity" is the key design decision.
 *
 * How events are routed back to the right object:
 *   - tunnel connection events carry si->conn_id -> t_worker->sessions
 *   - outbound socket events carry si->user_tag, which the flow set to its
 *     flow id in srv_connect() -> t_worker->flows
 *
 * handle_input_from_server() is deliberately not implemented: the flows open
 * their sockets with SRV_CONNECT_RAW, so every read from the real server is
 * delivered as it is (the plugin forwards a byte stream, it has no messages
 * to cut out of it).
 *
 * A second kind of client may connect: the live capture port
 * (vpn_capture_port). Such a connection receives a pcap stream for Wireshark
 * and is not a VPN tunnel; is_capture_client() tells them apart.
 *
 * Reading guide: handle_init -> handle_client_open -> handle_input_from_client
 * -> handle_message_from_client (-> Session::on_frame in vpn_session.cpp) ->
 * handle_server_open / handle_message_from_server (-> Flow callbacks in
 * flows.cpp) -> handle_timer -> handle_client_close. See also
 * docs/en/architecture.md.
 */
#include <cerrno>
#include <cstring>
#include <memory>
#include <random>
#include <sys/socket.h>
#include <sys/stat.h>

#include "flows.h"
#include "inspector.h"
#include "server_api.h"
#include "tunnel_protocol.h"
#include "vpn_session.h"

using namespace vpn;

namespace {

/**
 * @brief Look up the session of a tunnel connection on the current worker.
 * @param conn_id Connection id of the tunnel (SocketInfo::conn_id).
 * @return The session, or nullptr if there is none (e.g. a capture client,
 *         or not called on a worker thread).
 */
Session* find_session(uint64_t conn_id) {
    if (t_worker == nullptr) {
        return nullptr; // not a worker thread
    }
    auto it = t_worker->sessions.find(conn_id);
    return it == t_worker->sessions.end() ? nullptr : it->second.get();
}

/**
 * @brief Is this connection a client of the live capture port (not a VPN tunnel)?
 *
 * Both kinds of connection arrive through the same callbacks, so they are
 * told apart by the local port they were accepted on.
 *
 * @param si Connection snapshot from the engine.
 * @return true for a live capture (Wireshark) client.
 */
bool is_capture_client(const SocketInfo* si) {
    return g_vpn_config.capture_port != 0 && si->local_addr.port == g_vpn_config.capture_port;
}

/**
 * @brief Is the address a loopback address (127.0.0.0/8, ::1 or ::ffff:127.x.x.x)?
 *
 * Used to accept live capture clients only from the server machine itself,
 * because the capture stream contains all the users' traffic.
 *
 * @param addr Address to test (IPv4 or IPv6).
 * @return true if the address is loopback.
 */
bool is_loopback(const NetAddr& addr) {
    static const uint8_t kV6Loopback[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}; // ::1
    static const uint8_t kV4Mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};          // ::ffff:0:0/96 prefix
    if (addr.family == AF_INET) {
        return addr.ip[0] == 127;
    }
    // IPv6: ::1, or an IPv4-mapped 127.x.x.x (dual stack listeners report IPv4 peers like that)
    return std::memcmp(addr.ip, kV6Loopback, 16) == 0 ||
           (std::memcmp(addr.ip, kV4Mapped, 12) == 0 && addr.ip[12] == 127);
}

/**
 * @brief Look up a flow by its id on the current worker.
 *
 * The flow id is what the flow passed as user_tag to srv_connect(), so the
 * engine reports it back in si->user_tag of every outbound socket event.
 *
 * @param flow_id Flow id (= SocketInfo::user_tag of an outbound socket).
 * @return The flow, or nullptr if it was already deleted.
 */
Flow* find_flow(uint64_t flow_id) {
    if (t_worker == nullptr) {
        return nullptr;
    }
    auto it = t_worker->flows.find(flow_id);
    return it == t_worker->flows.end() ? nullptr : it->second;
}

/**
 * @brief Create a directory and all its parents, like "mkdir -p".
 *
 * Errors (most often EEXIST) are ignored; if the directory really cannot be
 * created, opening the pcap file later fails and is logged there.
 *
 * @param path Directory path, absolute or relative to the working directory.
 */
void make_dirs(const std::string& path) {
    std::string current;
    for (size_t i = 0; i < path.size(); ++i) {
        current += path[i];
        if (path[i] == '/' || i + 1 == path.size()) {
            mkdir(current.c_str(), 0755); // each prefix ending in '/' plus the full path
        }
    }
}

/**
 * @brief Read all vpn_* keys of the server config file into g_vpn_config.
 *
 * Called once on the MAIN thread before any worker starts, so the workers can
 * read g_vpn_config afterwards without locking. Values that would break the
 * TCP implementation are clamped to sane ranges.
 */
void load_config() {
    VpnConfig& c = g_vpn_config;
    c.token = srv_conf_string("vpn_token", "");
    // The current value of each field (its default from VpnConfig) is the fallback
    c.hello_timeout_ms = srv_conf_int("vpn_hello_timeout_ms", c.hello_timeout_ms);
    c.tcp_idle_timeout_s = srv_conf_int("vpn_tcp_idle_timeout", c.tcp_idle_timeout_s);
    c.tcp_half_close_timeout_s = srv_conf_int("vpn_tcp_half_close_timeout", c.tcp_half_close_timeout_s);
    c.udp_idle_timeout_s = srv_conf_int("vpn_udp_idle_timeout", c.udp_idle_timeout_s);
    c.dns_idle_timeout_s = srv_conf_int("vpn_dns_idle_timeout", c.dns_idle_timeout_s);
    c.icmp_idle_timeout_s = srv_conf_int("vpn_icmp_idle_timeout", c.icmp_idle_timeout_s);
    c.max_flows_per_session = srv_conf_int("vpn_max_flows", c.max_flows_per_session);
    // TCP receive window advertised to the phone: clamp to 4 KB .. 16 MB
    int window = srv_conf_int("vpn_tcp_window", static_cast<int>(c.tcp_window));
    c.tcp_window = static_cast<uint32_t>(window < 4096 ? 4096 : (window > (1 << 24) ? (1 << 24) : window));
    // Per flow buffer of server data not yet delivered to the phone: at least 64 KB
    int flow_buffer = srv_conf_int("vpn_tcp_flow_buffer", static_cast<int>(c.tcp_flow_buffer));
    c.tcp_flow_buffer = static_cast<size_t>(flow_buffer < 65536 ? 65536 : flow_buffer);
    c.pcap_dir = srv_conf_string("vpn_pcap_dir", "");
    c.pcap_max_bytes = static_cast<size_t>(srv_conf_int("vpn_pcap_max_mb", 100)) << 20; // MB -> bytes
    c.capture_port = srv_conf_int("vpn_capture_port", 0);
    c.capture_allow_remote = srv_conf_int("vpn_capture_allow_remote", 0) != 0;
    c.block_private_targets = srv_conf_int("vpn_block_private", 0) != 0;
    c.block_quic = srv_conf_int("vpn_block_quic", 0) != 0;
    c.stats_interval_s = srv_conf_int("vpn_stats_interval", c.stats_interval_s);
    // Session wide in-flight budget towards the phone: at least 64 KB
    int inflight = srv_conf_int("vpn_session_inflight", static_cast<int>(c.session_inflight));
    c.session_inflight = static_cast<size_t>(inflight < 65536 ? 65536 : inflight);
}

} // namespace

// The engine finds the callbacks with dlsym() by their plain C names
extern "C" {

/**
 * @brief Plugin start up, called once in every thread of the engine.
 *
 * MAIN thread: load and validate the configuration (shared, read-only later).
 * WORK thread: create this worker's private WorkerState, including a random
 * generator for TCP initial sequence numbers.
 *
 * @param argc        Unused (command line of the server).
 * @param argv        Unused.
 * @param thread_type SRV_THREAD_MAIN, SRV_THREAD_CONN or SRV_THREAD_WORK.
 * @return 0 on success; -1 aborts the server start (bad configuration).
 */
int handle_init(int /*argc*/, char** /*argv*/, int thread_type) {
    if (thread_type == SRV_THREAD_MAIN) {
        load_config();
        g_inspector.load_config(); // vpn_log_packets, blocked domains, rewrite rules ...
        if (!g_vpn_config.pcap_dir.empty()) {
            make_dirs(g_vpn_config.pcap_dir);
        }
        if (g_vpn_config.token.empty()) {
            LOG_WARN("vpn_token is empty: anyone who can reach this server can use it as a proxy!");
        }
        // One whole frame is one engine "package": the engine must accept the largest possible frame
        if (srv_max_packet_size() < static_cast<int>(tunnel::kHeaderSize + tunnel::kMaxPayload)) {
            LOG_ERR("max_packet_size must be at least %u for the VPN tunnel",
                    static_cast<unsigned>(tunnel::kHeaderSize + tunnel::kMaxPayload));
            return -1;
        }
        if (g_vpn_config.capture_port != 0) {
            LOG_INFO("Live capture on port %d: nc 127.0.0.1 %d | wireshark -k -i -   (the port must be in the bind "
                     "file)",
                     g_vpn_config.capture_port, g_vpn_config.capture_port);
        }
        LOG_INFO("SimpleVPN plugin ready: tcp window %u, pcap %s, block private targets %s", g_vpn_config.tcp_window,
                 g_vpn_config.pcap_dir.empty() ? "off" : g_vpn_config.pcap_dir.c_str(),
                 g_vpn_config.block_private_targets ? "yes" : "no");
    } else if (thread_type == SRV_THREAD_WORK) {
        t_worker = new WorkerState(); // thread_local: each worker has its own sessions and flows
        std::random_device rd;
        // Mix in the worker id so that workers started at the same moment get different sequences
        t_worker->rng.seed(rd() ^ static_cast<unsigned>(srv_worker_id() * 7919));
    }
    return 0;
}

/**
 * @brief Plugin shutdown, called once in every thread.
 *
 * On a worker thread all remaining sessions are destroyed (which aborts
 * their flows' outbound sockets and closes their pcap files), then the
 * worker state itself is freed.
 *
 * @param thread_type SRV_THREAD_MAIN, SRV_THREAD_CONN or SRV_THREAD_WORK.
 */
void handle_fini(int thread_type) {
    if (thread_type == SRV_THREAD_WORK && t_worker != nullptr) {
        t_worker->sessions.clear(); // sessions first: their flows unregister from t_worker->flows
        delete t_worker;
        t_worker = nullptr;
    }
}

/**
 * @brief [CONN thread] Find the frame boundaries in the tunnel byte stream.
 *
 * The engine calls this with all bytes received so far that do not yet form
 * a package. Returning the total frame length lets the engine wait until the
 * whole frame has arrived and then deliver it in one piece to
 * handle_message_from_client() on the connection's worker. This runs on the
 * single network thread, so it only parses the 8-byte header and does
 * nothing else (no worker state, no logging on the hot path).
 *
 * @param data Buffered bytes of the connection, starting at a frame boundary.
 * @param len  Number of buffered bytes.
 * @param si   Connection snapshot.
 * @return Total frame length (may exceed @p len: the engine reads more),
 *         0 if the header is incomplete, -1 to close a connection that does
 *         not speak the tunnel protocol.
 */
int handle_input_from_client(const char* data, int len, const SocketInfo* si) {
    if (is_capture_client(si)) {
        return len; // capture clients only read; whatever they send is ignored
    }
    long total = tunnel::parse_header(reinterpret_cast<const uint8_t*>(data), static_cast<size_t>(len), nullptr,
                                      nullptr);
    if (total < 0) {
        char addr[64];
        LOG_WARN("Invalid tunnel frame from %s", srv_addr_to_string(&si->remote_addr, addr, sizeof(addr)));
        return -1; // the stream cannot be resynchronized: drop the connection
    }
    return static_cast<int>(total);
}

/**
 * @brief [WORK thread] A TCP client connected (a phone, or a capture client).
 *
 * For a tunnel a new, not yet authenticated Session is created; it expects a
 * HELLO frame within vpn_hello_timeout_ms. For a capture client the pcap
 * stream subscription starts (loopback only unless vpn_capture_allow_remote).
 *
 * @param send_data Unused: no greeting is sent (the client speaks first).
 * @param send_len  Unused.
 * @param si        Snapshot of the accepted connection.
 * @return 0 to accept, -1 to reject (close) the connection.
 */
int handle_client_open(char** /*send_data*/, int* /*send_len*/, const SocketInfo* si) {
    char addr[64];
    if (is_capture_client(si)) {
        srv_addr_to_string(&si->remote_addr, addr, sizeof(addr));
        if (!g_vpn_config.capture_allow_remote && !is_loopback(si->remote_addr)) {
            LOG_WARN("Live capture client %s rejected (not loopback, see vpn_capture_allow_remote)", addr);
            return -1;
        }
        g_live_capture.add_subscriber(*si); // sends the pcap file header, then every packet
        LOG_INFO("Live capture client %s connected", addr);
        return 0;
    }
    // Keyed by conn_id (fds are reused by the OS, conn_ids are unique for the process lifetime)
    t_worker->sessions[si->conn_id].reset(new Session(*si, si->conn_id));
    return 0;
}

/**
 * @brief [WORK thread] One complete frame from a phone.
 *
 * The frame boundaries were found by handle_input_from_client(), so @p data
 * is exactly one frame including its 8-byte header. The session handles it
 * (HELLO, PACKET, PING ...). Replies are not returned through send_data but
 * sent asynchronously by the session with srv_send(), because one incoming
 * packet may produce any number of outgoing packets (or none).
 *
 * @param data      One whole frame (header + payload).
 * @param len       Frame length in bytes.
 * @param send_data Unused.
 * @param send_len  Unused (left at 0: no direct reply).
 * @param si        Snapshot of the tunnel connection.
 * @return 0 normally, -1 to close the connection (no session / short frame).
 */
int handle_message_from_client(const char* data, int len, char** /*send_data*/, int* /*send_len*/,
                               const SocketInfo* si) {
    if (is_capture_client(si)) {
        return 0; // already discarded by handle_input_from_client
    }
    Session* session = find_session(si->conn_id);
    if (session == nullptr || len < static_cast<int>(tunnel::kHeaderSize)) {
        return -1;
    }
    const uint8_t* frame = reinterpret_cast<const uint8_t*>(data);
    // frame[3] is the frame type; the payload starts right after the header
    session->on_frame(frame[3], frame + tunnel::kHeaderSize, static_cast<size_t>(len) - tunnel::kHeaderSize);
    // Flows cannot delete themselves while their own method runs, they are only
    // marked dead; every callback ends by deleting those flows (deferred deletion)
    session->reap();
    return 0;
}

/**
 * @brief [WORK thread] A client connection is gone (called once per accepted connection).
 *
 * For a tunnel the Session is destroyed, which aborts all of its outbound
 * sockets (the phone is gone, nobody would receive their data) and closes
 * its pcap file. Capture clients are just unsubscribed.
 *
 * @param si Snapshot of the closed connection; si->last_error is the errno
 *           that caused the close (0 = orderly close).
 * @return Always 0.
 */
int handle_client_close(const SocketInfo* si) {
    char addr[64];
    if (is_capture_client(si)) {
        g_live_capture.remove_subscriber(si->conn_id);
        LOG_INFO("Live capture client %s disconnected", srv_addr_to_string(&si->remote_addr, addr, sizeof(addr)));
        return 0;
    }
    LOG_INFO("Tunnel from %s closed%s%s", srv_addr_to_string(&si->remote_addr, addr, sizeof(addr)),
             si->last_error ? ": " : "", si->last_error ? strerror(si->last_error) : "");
    t_worker->sessions.erase(si->conn_id); // ~Session() deletes all flows
    return 0;
}

/**
 * @brief [WORK thread] Result of a flow's srv_connect() to the real destination.
 *
 * For TCP this is when the server finally answers the phone's SYN with a
 * SYN-ACK (or with a RST if the connect failed), so the phone sees the real
 * outcome of its connection attempt.
 *
 * @param si    Snapshot of the outbound socket; si->user_tag is the flow id.
 * @param error 0 if connected, else the errno of the failed connect (no
 *              further callback follows for that socket).
 * @return Always 0.
 */
int handle_server_open(const SocketInfo* si, int error) {
    Flow* flow = find_flow(si->user_tag);
    if (flow != nullptr) {
        Session* session = flow->session(); // take it now: the session outlives the flow
        flow->on_upstream_open(error);
        session->reap(); // delete the flow if it finished (e.g. connect failed)
    }
    return 0;
}

/**
 * @brief [WORK thread] Data from the real destination for a flow.
 *
 * The flow wraps the bytes into IP packets (TCP segments, UDP datagrams,
 * ICMP replies) addressed to the phone and sends them through the tunnel.
 *
 * @param data Received bytes; nullptr with len 0 means EOF (the outbound TCP
 *             sockets use SRV_CONNECT_HALF_CLOSE, so a FIN from the server is
 *             reported here instead of closing the socket).
 * @param len  Number of bytes.
 * @param si   Snapshot of the outbound socket; si->user_tag is the flow id.
 * @return 0, or -1 if the flow no longer exists (the engine closes the socket).
 */
int handle_message_from_server(const char* data, int len, const SocketInfo* si) {
    Flow* flow = find_flow(si->user_tag);
    if (flow == nullptr) {
        return -1; // the flow is gone: close the socket
    }
    Session* session = flow->session();
    flow->on_upstream_data(data, len);
    session->reap();
    return 0;
}

/**
 * @brief [WORK thread] An outbound socket of a flow is gone.
 *
 * Usually the flow already knows (it closed the socket itself), in which
 * case it has been deleted and find_flow() returns nullptr. Otherwise the
 * flow reacts, e.g. a TCP flow resets the phone's connection after an error,
 * or sends a FIN to the phone after an orderly close.
 *
 * @param si Snapshot of the outbound socket; si->last_error tells why.
 * @return Always 0.
 */
int handle_server_close(const SocketInfo* si) {
    Flow* flow = find_flow(si->user_tag);
    if (flow != nullptr) {
        Session* session = flow->session();
        flow->on_upstream_close(si->last_error);
        session->reap();
    }
    return 0;
}

/**
 * @brief [WORK thread] Flow control notification from the engine.
 *
 * The engine queues data per connection. When a connection's queue crosses
 * the high watermark it reports blocked = 1, when it drains below the low
 * watermark it reports 0. This is the back pressure that keeps memory and
 * latency bounded:
 *   - tunnel connection blocked: the phone (or its network) is slower than
 *     the internet; the session stops sending TCP data to it until it drains.
 *   - outbound socket blocked: a real server reads slower than the phone
 *     uploads; the TCP flow advertises a zero window to the phone.
 *
 * @param si      Snapshot of the connection whose send queue changed.
 * @param blocked 1 = above the high watermark, 0 = drained again.
 * @return Always 0.
 */
int handle_write_blocked(const SocketInfo* si, int blocked) {
    if (si->conn_kind == SRV_CONN_TCP_CLIENT) {
        // An accepted connection: a tunnel (capture clients have no session and are ignored)
        Session* session = find_session(si->conn_id);
        if (session != nullptr) {
            session->on_tunnel_write_blocked(blocked != 0);
            session->reap();
        }
    } else {
        // An outbound socket created by a flow
        Flow* flow = find_flow(si->user_tag);
        if (flow != nullptr) {
            Session* session = flow->session();
            flow->on_upstream_write_blocked(blocked != 0);
            session->reap();
        }
    }
    return 0;
}

/**
 * @brief [WORK thread] Periodic timer, called in every worker (default every 100 ms,
 *        engine option timer_interval_ms).
 *
 * Drives everything time based of the sessions on this worker: HELLO
 * timeout, TCP retransmissions, idle timeouts of flows, fragment reassembly
 * expiry, pcap flushing and statistics.
 *
 * @param milliseconds In: time since the last call. Not changed, so the
 *                     engine keeps its configured interval.
 * @return Always 0.
 */
int handle_timer(int* /*milliseconds*/) {
    if (t_worker == nullptr) {
        return 0;
    }
    int64_t now = now_ms(); // one timestamp for all sessions of this tick
    for (auto& item : t_worker->sessions) {
        item.second->on_timer(now); // also reaps finished flows
    }
    return 0;
}

} // extern "C"
