/**
 * @file tunnel_client.h
 * @brief Portable VPN tunnel client core, used by the Android app (through
 *        JNI, see native-lib.cpp) and by the Linux test client
 *        (tools/linux_client/main.cpp).
 *
 * Overview
 * --------
 * It moves raw IP packets between a TUN file descriptor and one TCP
 * connection to the VPN server, nothing else: every packet the system routes
 * into the TUN device is sent to the server, every packet the server sends
 * back is written into the TUN device. All the hard work (TCP termination,
 * NAT, inspection) happens on the server; the client stays small and
 * platform independent (plain POSIX: sockets, poll(), pipes).
 *
 * Life cycle: construct with a TunnelClientConfig, call run() on a thread of
 * its own (it blocks), call stop() from any other thread to end it. run()
 * connects, performs the HELLO handshake, pumps packets, sends keepalive
 * PINGs and reconnects automatically (with exponential back off) whenever
 * the connection breaks. reconnect() forces a fresh connection right away,
 * which Android uses when the phone switches networks.
 *
 * Reading guide: TunnelClientConfig (inputs and callbacks), TunnelState (what
 * the UI shows), then TunnelClient::run() and run_session() in
 * tunnel_client.cpp. The wire format is in common/tunnel_protocol.h.
 */
#ifndef SIMPLEVPN_TUNNEL_CLIENT_H
#define SIMPLEVPN_TUNNEL_CLIENT_H

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>

namespace simplevpn {

/**
 * @brief Connection state reported to the UI (on_state callback and TunnelStats::state).
 *
 * The numeric values are part of the JNI contract: MyVpnService.kt has the
 * same constants (STATE_*), so do not renumber them.
 */
enum class TunnelState : int {
    Idle = 0,         ///< not started yet
    Connecting = 1,   ///< first connection attempt in progress
    Connected = 2,    ///< HELLO_ACK received, packets are flowing
    Reconnecting = 3, ///< connection lost or failed, waiting / retrying
    Stopped = 4,      ///< run() has returned (stop() or invalid TUN fd)
    AuthFailed = 5    ///< the server rejected the token (still retries, slowly)
};

/// Log levels of the log callback (lower = more important).
enum LogLevel { kLogError = 0, kLogWarn = 1, kLogInfo = 2, kLogDebug = 3 };

/**
 * @brief Everything the tunnel client needs: server, TUN device, timeouts
 *        and the platform callbacks.
 */
struct TunnelClientConfig {
    std::string server_host;           // IP literal or host name
    uint16_t server_port = 9443;       // TCP port of the server's tunnel listener
    std::string token;                 // must match vpn_token of the server
    int tun_fd = -1;                   // owned by the client, closed when run() returns
    int mtu = 1500;                    // MTU of the TUN device, told to the server in HELLO
    std::string client_name = "simplevpn"; // shown in the server log ("android", "linux-client")
    std::string tun_ipv4;              // informational, sent in HELLO
    std::string tun_ipv6;              // informational, sent in HELLO (empty = no IPv6)
    int connect_timeout_ms = 10000;    // TCP connect timeout, also the HELLO_ACK deadline
    int keepalive_interval_ms = 15000; // PING interval
    int keepalive_timeout_ms = 45000;  // reconnect if nothing was received for this long
    int max_backoff_ms = 30000;        // upper limit of the reconnect delay (starts at 1 s, doubles)
    size_t max_send_buffer = 4 * 1024 * 1024; // stop reading the TUN above this

    // Called with every new socket before connect(); Android must call
    // VpnService.protect() here so the tunnel itself bypasses the VPN.
    // (Without it the tunnel's own packets would be routed into the TUN,
    // i.e. back into the tunnel: an endless loop.) Return false to skip the socket.
    std::function<bool(int fd)> protect_socket;
    // Optional log sink (level = LogLevel). Called on the tunnel thread.
    std::function<void(int level, const std::string& message)> log;
    // Optional state change notification. Called on the tunnel thread; must not block.
    std::function<void(TunnelState state, const std::string& message)> on_state;
};

/**
 * @brief Counters of the tunnel. Written by the tunnel thread, read by any
 *        thread (UI, JNI) without locks, hence std::atomic.
 */
struct TunnelStats {
    std::atomic<uint64_t> tx_packets{0}; // TUN -> server
    std::atomic<uint64_t> tx_bytes{0};
    std::atomic<uint64_t> rx_packets{0}; // server -> TUN
    std::atomic<uint64_t> rx_bytes{0};
    std::atomic<uint64_t> dropped{0};    // packets lost locally (TUN full, read while disconnected)
    std::atomic<uint64_t> reconnects{0}; // tunnel sessions that ended other than by stop()
    std::atomic<int> state{0};           // current TunnelState as int
    std::atomic<int64_t> connected_since_ms{0}; // wall clock, 0 = not connected
};

/**
 * @brief The tunnel client: one instance per VPN connection.
 *
 * Threading: run() executes on one dedicated thread (the "tunnel thread");
 * every callback of the config is invoked on that thread. stop(),
 * reconnect(), stats() and last_message() may be called from any thread.
 * Cross-thread wake ups use the "self-pipe trick": the caller sets an atomic
 * flag and writes one byte into a pipe whose read end is part of the tunnel
 * thread's poll() set, so the blocked poll() returns immediately.
 */
class TunnelClient {
public:
    /// @param config Settings and callbacks; the client takes ownership of config.tun_fd.
    explicit TunnelClient(TunnelClientConfig config);
    /// Closes the TUN fd (if run() did not already) and the wake pipe.
    ~TunnelClient();

    // Not copyable: it owns file descriptors
    TunnelClient(const TunnelClient&) = delete;
    TunnelClient& operator=(const TunnelClient&) = delete;

    // Blocks until stop() is called. Closes the TUN fd before returning.
    void run();

    // Thread safe, may be called from any thread
    // (also from a signal handler: it only stores an atomic and calls write()).
    void stop();

    // Drop the current server connection and connect again right away, e.g.
    // after the phone switched between Wi-Fi and mobile data. Thread safe.
    void reconnect();

    /// @return Live counters (atomics, safe to read from any thread).
    const TunnelStats& stats() const { return stats_; }
    /// @return The last state / error message (thread safe copy).
    std::string last_message() const;

private:
    /// Why run_session() returned; decides the next step in run().
    enum class SessionEnd { Stopped, Disconnected, AuthFailed, NetworkChanged };

    int connect_server();
    SessionEnd run_session(int sock);
    bool wait_backoff(int ms);
    void drain_tun();
    void set_state(TunnelState state, const std::string& message);
    void log(int level, const std::string& message) const;

    TunnelClientConfig config_;                  // settings, callbacks and the TUN fd
    TunnelStats stats_;                          // counters for the UI
    std::atomic<bool> stop_requested_{false};    // set by stop()
    std::atomic<bool> reconnect_requested_{false}; // set by reconnect()
    int wake_pipe_[2] = {-1, -1};                // self-pipe: [0] polled by the tunnel thread, [1] written by stop/reconnect
    mutable std::mutex message_mutex_;           // guards last_message_ (read from other threads)
    std::string last_message_;                   // last state / error text
};

} // namespace simplevpn

#endif // SIMPLEVPN_TUNNEL_CLIENT_H
