// SimpleVPN server plugin for the multithread reactor server.
//
// Each phone connects with one TCP tunnel connection and sends raw IP
// packets (see common/tunnel_protocol.h). The plugin terminates the TCP / UDP
// / ICMP flows inside those packets, logs (and optionally rewrites) what goes
// through, and forwards everything to the real destinations with ordinary
// sockets owned by the reactor engine.
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

Session* find_session(uint64_t conn_id) {
    if (t_worker == nullptr) {
        return nullptr;
    }
    auto it = t_worker->sessions.find(conn_id);
    return it == t_worker->sessions.end() ? nullptr : it->second.get();
}

// A connection to the live capture port (not a VPN tunnel)
bool is_capture_client(const SocketInfo* si) {
    return g_vpn_config.capture_port != 0 && si->local_addr.port == g_vpn_config.capture_port;
}

bool is_loopback(const NetAddr& addr) {
    static const uint8_t kV6Loopback[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    static const uint8_t kV4Mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    if (addr.family == AF_INET) {
        return addr.ip[0] == 127;
    }
    return std::memcmp(addr.ip, kV6Loopback, 16) == 0 ||
           (std::memcmp(addr.ip, kV4Mapped, 12) == 0 && addr.ip[12] == 127);
}

Flow* find_flow(uint64_t flow_id) {
    if (t_worker == nullptr) {
        return nullptr;
    }
    auto it = t_worker->flows.find(flow_id);
    return it == t_worker->flows.end() ? nullptr : it->second;
}

void make_dirs(const std::string& path) {
    std::string current;
    for (size_t i = 0; i < path.size(); ++i) {
        current += path[i];
        if (path[i] == '/' || i + 1 == path.size()) {
            mkdir(current.c_str(), 0755);
        }
    }
}

void load_config() {
    VpnConfig& c = g_vpn_config;
    c.token = srv_conf_string("vpn_token", "");
    c.hello_timeout_ms = srv_conf_int("vpn_hello_timeout_ms", c.hello_timeout_ms);
    c.tcp_idle_timeout_s = srv_conf_int("vpn_tcp_idle_timeout", c.tcp_idle_timeout_s);
    c.tcp_half_close_timeout_s = srv_conf_int("vpn_tcp_half_close_timeout", c.tcp_half_close_timeout_s);
    c.udp_idle_timeout_s = srv_conf_int("vpn_udp_idle_timeout", c.udp_idle_timeout_s);
    c.dns_idle_timeout_s = srv_conf_int("vpn_dns_idle_timeout", c.dns_idle_timeout_s);
    c.icmp_idle_timeout_s = srv_conf_int("vpn_icmp_idle_timeout", c.icmp_idle_timeout_s);
    c.max_flows_per_session = srv_conf_int("vpn_max_flows", c.max_flows_per_session);
    int window = srv_conf_int("vpn_tcp_window", static_cast<int>(c.tcp_window));
    c.tcp_window = static_cast<uint32_t>(window < 4096 ? 4096 : (window > (1 << 24) ? (1 << 24) : window));
    int flow_buffer = srv_conf_int("vpn_tcp_flow_buffer", static_cast<int>(c.tcp_flow_buffer));
    c.tcp_flow_buffer = static_cast<size_t>(flow_buffer < 65536 ? 65536 : flow_buffer);
    c.pcap_dir = srv_conf_string("vpn_pcap_dir", "");
    c.pcap_max_bytes = static_cast<size_t>(srv_conf_int("vpn_pcap_max_mb", 100)) << 20;
    c.capture_port = srv_conf_int("vpn_capture_port", 0);
    c.capture_allow_remote = srv_conf_int("vpn_capture_allow_remote", 0) != 0;
    c.block_private_targets = srv_conf_int("vpn_block_private", 0) != 0;
    c.block_quic = srv_conf_int("vpn_block_quic", 0) != 0;
    c.stats_interval_s = srv_conf_int("vpn_stats_interval", c.stats_interval_s);
    int inflight = srv_conf_int("vpn_session_inflight", static_cast<int>(c.session_inflight));
    c.session_inflight = static_cast<size_t>(inflight < 65536 ? 65536 : inflight);
}

} // namespace

extern "C" {

int handle_init(int /*argc*/, char** /*argv*/, int thread_type) {
    if (thread_type == SRV_THREAD_MAIN) {
        load_config();
        g_inspector.load_config();
        if (!g_vpn_config.pcap_dir.empty()) {
            make_dirs(g_vpn_config.pcap_dir);
        }
        if (g_vpn_config.token.empty()) {
            LOG_WARN("vpn_token is empty: anyone who can reach this server can use it as a proxy!");
        }
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
        t_worker = new WorkerState();
        std::random_device rd;
        t_worker->rng.seed(rd() ^ static_cast<unsigned>(srv_worker_id() * 7919));
    }
    return 0;
}

void handle_fini(int thread_type) {
    if (thread_type == SRV_THREAD_WORK && t_worker != nullptr) {
        t_worker->sessions.clear();
        delete t_worker;
        t_worker = nullptr;
    }
}

// [CONN thread] frame boundaries of the tunnel stream
int handle_input_from_client(const char* data, int len, const SocketInfo* si) {
    if (is_capture_client(si)) {
        return len; // capture clients only read; whatever they send is ignored
    }
    long total = tunnel::parse_header(reinterpret_cast<const uint8_t*>(data), static_cast<size_t>(len), nullptr,
                                      nullptr);
    if (total < 0) {
        char addr[64];
        LOG_WARN("Invalid tunnel frame from %s", srv_addr_to_string(&si->remote_addr, addr, sizeof(addr)));
        return -1;
    }
    return static_cast<int>(total);
}

int handle_client_open(char** /*send_data*/, int* /*send_len*/, const SocketInfo* si) {
    char addr[64];
    if (is_capture_client(si)) {
        srv_addr_to_string(&si->remote_addr, addr, sizeof(addr));
        if (!g_vpn_config.capture_allow_remote && !is_loopback(si->remote_addr)) {
            LOG_WARN("Live capture client %s rejected (not loopback, see vpn_capture_allow_remote)", addr);
            return -1;
        }
        g_live_capture.add_subscriber(*si);
        LOG_INFO("Live capture client %s connected", addr);
        return 0;
    }
    t_worker->sessions[si->conn_id].reset(new Session(*si, si->conn_id));
    return 0;
}

int handle_message_from_client(const char* data, int len, char** /*send_data*/, int* /*send_len*/,
                               const SocketInfo* si) {
    if (is_capture_client(si)) {
        return 0;
    }
    Session* session = find_session(si->conn_id);
    if (session == nullptr || len < static_cast<int>(tunnel::kHeaderSize)) {
        return -1;
    }
    const uint8_t* frame = reinterpret_cast<const uint8_t*>(data);
    session->on_frame(frame[3], frame + tunnel::kHeaderSize, static_cast<size_t>(len) - tunnel::kHeaderSize);
    session->reap();
    return 0;
}

int handle_client_close(const SocketInfo* si) {
    char addr[64];
    if (is_capture_client(si)) {
        g_live_capture.remove_subscriber(si->conn_id);
        LOG_INFO("Live capture client %s disconnected", srv_addr_to_string(&si->remote_addr, addr, sizeof(addr)));
        return 0;
    }
    LOG_INFO("Tunnel from %s closed%s%s", srv_addr_to_string(&si->remote_addr, addr, sizeof(addr)),
             si->last_error ? ": " : "", si->last_error ? strerror(si->last_error) : "");
    t_worker->sessions.erase(si->conn_id);
    return 0;
}

int handle_server_open(const SocketInfo* si, int error) {
    Flow* flow = find_flow(si->user_tag);
    if (flow != nullptr) {
        Session* session = flow->session();
        flow->on_upstream_open(error);
        session->reap();
    }
    return 0;
}

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

int handle_server_close(const SocketInfo* si) {
    Flow* flow = find_flow(si->user_tag);
    if (flow != nullptr) {
        Session* session = flow->session();
        flow->on_upstream_close(si->last_error);
        session->reap();
    }
    return 0;
}

int handle_write_blocked(const SocketInfo* si, int blocked) {
    if (si->conn_kind == SRV_CONN_TCP_CLIENT) {
        Session* session = find_session(si->conn_id);
        if (session != nullptr) {
            session->on_tunnel_write_blocked(blocked != 0);
            session->reap();
        }
    } else {
        Flow* flow = find_flow(si->user_tag);
        if (flow != nullptr) {
            Session* session = flow->session();
            flow->on_upstream_write_blocked(blocked != 0);
            session->reap();
        }
    }
    return 0;
}

int handle_timer(int* /*milliseconds*/) {
    if (t_worker == nullptr) {
        return 0;
    }
    int64_t now = now_ms();
    for (auto& item : t_worker->sessions) {
        item.second->on_timer(now);
    }
    return 0;
}

} // extern "C"
