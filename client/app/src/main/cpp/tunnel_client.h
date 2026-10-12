// Portable VPN tunnel client core, used by the Android app (through JNI) and
// by the Linux test client (tools/linux_client).
//
// It moves raw IP packets between a TUN file descriptor and one TCP
// connection to the VPN server, nothing else: every packet the system routes
// into the TUN device is sent to the server, every packet the server sends
// back is written into the TUN device. It reconnects automatically.
#ifndef SIMPLEVPN_TUNNEL_CLIENT_H
#define SIMPLEVPN_TUNNEL_CLIENT_H

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>

namespace simplevpn {

enum class TunnelState : int {
    Idle = 0,
    Connecting = 1,
    Connected = 2,
    Reconnecting = 3,
    Stopped = 4,
    AuthFailed = 5
};

enum LogLevel { kLogError = 0, kLogWarn = 1, kLogInfo = 2, kLogDebug = 3 };

struct TunnelClientConfig {
    std::string server_host;           // IP literal or host name
    uint16_t server_port = 9443;
    std::string token;                 // must match vpn_token of the server
    int tun_fd = -1;                   // owned by the client, closed when run() returns
    int mtu = 1500;
    std::string client_name = "simplevpn";
    std::string tun_ipv4;              // informational, sent in HELLO
    std::string tun_ipv6;
    int connect_timeout_ms = 10000;
    int keepalive_interval_ms = 15000; // PING interval
    int keepalive_timeout_ms = 45000;  // reconnect if nothing was received for this long
    int max_backoff_ms = 30000;
    size_t max_send_buffer = 4 * 1024 * 1024; // stop reading the TUN above this

    // Called with every new socket before connect(); Android must call
    // VpnService.protect() here so the tunnel itself bypasses the VPN.
    std::function<bool(int fd)> protect_socket;
    std::function<void(int level, const std::string& message)> log;
    std::function<void(TunnelState state, const std::string& message)> on_state;
};

struct TunnelStats {
    std::atomic<uint64_t> tx_packets{0}; // TUN -> server
    std::atomic<uint64_t> tx_bytes{0};
    std::atomic<uint64_t> rx_packets{0}; // server -> TUN
    std::atomic<uint64_t> rx_bytes{0};
    std::atomic<uint64_t> dropped{0};
    std::atomic<uint64_t> reconnects{0};
    std::atomic<int> state{0};
    std::atomic<int64_t> connected_since_ms{0}; // wall clock, 0 = not connected
};

class TunnelClient {
public:
    explicit TunnelClient(TunnelClientConfig config);
    ~TunnelClient();

    TunnelClient(const TunnelClient&) = delete;
    TunnelClient& operator=(const TunnelClient&) = delete;

    // Blocks until stop() is called. Closes the TUN fd before returning.
    void run();

    // Thread safe, may be called from any thread
    void stop();

    const TunnelStats& stats() const { return stats_; }
    std::string last_message() const;

private:
    enum class SessionEnd { Stopped, Disconnected, AuthFailed };

    int connect_server();
    SessionEnd run_session(int sock);
    bool wait_backoff(int ms);
    void drain_tun();
    void set_state(TunnelState state, const std::string& message);
    void log(int level, const std::string& message) const;

    TunnelClientConfig config_;
    TunnelStats stats_;
    std::atomic<bool> stop_requested_{false};
    int wake_pipe_[2] = {-1, -1};
    mutable std::mutex message_mutex_;
    std::string last_message_;
};

} // namespace simplevpn

#endif // SIMPLEVPN_TUNNEL_CLIENT_H
