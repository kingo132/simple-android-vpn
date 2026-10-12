/**
 * @file tunnel_client.cpp
 * @brief Implementation of the portable tunnel client: connect, handshake,
 *        packet pump between the TUN fd and the server socket, keepalive and
 *        automatic reconnect.
 *
 * Overview
 * --------
 * Everything runs on ONE thread (the caller of run()) with non-blocking file
 * descriptors and a single poll() loop, instead of one thread per direction:
 * no locks are needed around the buffers, and stop() / reconnect() wake the
 * loop through a pipe (self-pipe trick, see tunnel_client.h).
 *
 * Outer loop, run():   connect_server() -> run_session() -> back off -> repeat
 * Inner loop, run_session(), per poll() wake up:
 *   1. wake pipe readable: stop or network change requested
 *   2. socket readable: read bytes, cut them into frames (process_frames),
 *      write PACKET payloads into the TUN
 *   3. TUN readable: read packets, append them as PACKET frames to the
 *      output buffer (pump_tun)
 *   4. timers: handshake deadline, keepalive PING, keepalive timeout
 *   5. flush the output buffer to the socket as far as it accepts it
 *
 * Reading guide: run() first, then run_session() and its three lambdas
 * (flush, pump_tun, process_frames), then connect_server() and wait_backoff().
 */
#include "tunnel_client.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "tunnel_protocol.h"

namespace simplevpn {

namespace {

/// @return Monotonic milliseconds (for timeouts; never jumps with the wall clock).
int64_t mono_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

/// @return Wall clock milliseconds since 1970 (for "connected since" shown in the UI).
int64_t wall_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

/**
 * @brief Switch a file descriptor to non-blocking mode (O_NONBLOCK).
 *
 * Needed for the single-thread poll() design: a read/write/connect must
 * never block the loop, it returns EAGAIN / EINPROGRESS instead.
 *
 * @param fd File descriptor to change; errors are ignored.
 */
void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
}

/**
 * @brief Byte buffer with a read offset (cheap consume from the front).
 *
 * Used for the outgoing frames: send() often accepts only part of the
 * buffer, and erasing the sent bytes from the front of a std::string every
 * time would copy the rest again and again. Instead the offset moves and the
 * memory is compacted only occasionally.
 */
class Buffer {
public:
    /// @return Number of unconsumed bytes.
    size_t size() const { return data_.size() - offset_; }
    bool empty() const { return size() == 0; }
    /// @return Pointer to the first unconsumed byte.
    const char* data() const { return data_.data() + offset_; }
    /// @return The underlying string, to append new data at the end.
    std::string& raw() { return data_; }
    /**
     * @brief Drop @p n bytes from the front (they were sent).
     * @param n Number of bytes, at most size().
     */
    void consume(size_t n) {
        offset_ += n;
        if (offset_ >= data_.size()) {
            // everything sent: reset for free
            data_.clear();
            offset_ = 0;
        } else if (offset_ > 65536 && offset_ * 2 > data_.size()) {
            // more than half (and > 64 KB) is dead space: compact once
            data_.erase(0, offset_);
            offset_ = 0;
        }
    }

private:
    std::string data_;  // consumed bytes [0, offset_) followed by pending bytes
    size_t offset_ = 0; // start of the pending bytes
};

} // namespace

/**
 * @brief Store the config and create the wake pipe.
 *
 * Both pipe ends are non-blocking (a full pipe must never block stop(), and
 * draining must stop when it is empty) and close-on-exec (child processes,
 * e.g. the "ip" commands of the Linux client, must not inherit them).
 */
TunnelClient::TunnelClient(TunnelClientConfig config) : config_(std::move(config)) {
    if (pipe(wake_pipe_) == 0) {
        set_nonblocking(wake_pipe_[0]);
        set_nonblocking(wake_pipe_[1]);
        fcntl(wake_pipe_[0], F_SETFD, FD_CLOEXEC);
        fcntl(wake_pipe_[1], F_SETFD, FD_CLOEXEC);
    }
}

/**
 * @brief Release the file descriptors (the TUN fd only if run() never ran or failed early).
 */
TunnelClient::~TunnelClient() {
    if (config_.tun_fd >= 0) {
        close(config_.tun_fd);
        config_.tun_fd = -1;
    }
    for (int fd : wake_pipe_) {
        if (fd >= 0) {
            close(fd);
        }
    }
}

/**
 * @brief Ask run() to finish. Returns immediately; run() returns soon after.
 *
 * Only an atomic store and write() are used, both async-signal-safe, so the
 * Linux client may call this from its SIGINT handler.
 */
void TunnelClient::stop() {
    stop_requested_ = true;
    if (wake_pipe_[1] >= 0) {
        char c = 1;
        ssize_t r = write(wake_pipe_[1], &c, 1); // wakes the poll() of the tunnel thread
        (void)r; // a full pipe is fine: it is already readable
    }
}

/**
 * @brief Ask the tunnel thread to drop the current connection and connect
 *        again immediately (also cuts short a running back off wait).
 */
void TunnelClient::reconnect() {
    reconnect_requested_ = true;
    if (wake_pipe_[1] >= 0) {
        char c = 1;
        ssize_t r = write(wake_pipe_[1], &c, 1);
        (void)r;
    }
}

/**
 * @return A copy of the last state / error message (taken under the mutex,
 *         because the tunnel thread may change it concurrently).
 */
std::string TunnelClient::last_message() const {
    std::lock_guard<std::mutex> lock(message_mutex_);
    return last_message_;
}

/**
 * @brief Forward a message to the optional log callback.
 * @param level   LogLevel.
 * @param message Text.
 */
void TunnelClient::log(int level, const std::string& message) const {
    if (config_.log) {
        config_.log(level, message);
    }
}

/**
 * @brief Publish a new state: stats (for polling UIs), last message, log
 *        and the on_state callback (Android: MyVpnService.onNativeState).
 * @param state   New state.
 * @param message Human readable explanation shown in the UI.
 */
void TunnelClient::set_state(TunnelState state, const std::string& message) {
    stats_.state = static_cast<int>(state);
    {
        std::lock_guard<std::mutex> lock(message_mutex_);
        last_message_ = message;
    }
    log(kLogInfo, message);
    if (config_.on_state) {
        config_.on_state(state, message);
    }
}

/**
 * @brief Read and discard packets waiting in the TUN device (at most 256 per call).
 *
 * While there is no server connection the system keeps routing packets into
 * the TUN. Throwing them away (counted as dropped) keeps the TUN queue from
 * filling up; the apps see lost packets and time out / retry normally.
 */
void TunnelClient::drain_tun() {
    char buffer[65536]; // one IP packet is at most 64 KB
    for (int i = 0; i < 256; ++i) {
        ssize_t n = read(config_.tun_fd, buffer, sizeof(buffer));
        if (n <= 0) {
            break; // EAGAIN: the queue is empty
        }
        ++stats_.dropped;
    }
}

/**
 * @brief Wait before the next connection attempt, interruptible by stop()
 *        and reconnect().
 *
 * @param ms Delay in milliseconds.
 * @return true to try connecting now (delay over, or a network change was
 *         signalled), false if stop() was called.
 */
bool TunnelClient::wait_backoff(int ms) {
    int64_t deadline = mono_ms() + ms;
    while (!stop_requested_) {
        int64_t left = deadline - mono_ms();
        if (left <= 0) {
            return true;
        }
        // Keep draining the TUN device so applications fail fast instead of
        // waiting on a full queue while we are disconnected
        pollfd fds[2] = {{wake_pipe_[0], POLLIN, 0}, {config_.tun_fd, POLLIN, 0}};
        int n = poll(fds, 2, static_cast<int>(std::min<int64_t>(left, 1000)));
        if (n > 0 && (fds[1].revents & POLLIN)) {
            drain_tun();
        }
        if (n > 0 && (fds[0].revents & POLLIN)) {
            char buf[64];
            while (read(wake_pipe_[0], buf, sizeof(buf)) > 0) {
                // empty the pipe so the next poll() blocks again
            }
            if (reconnect_requested_.exchange(false)) {
                return !stop_requested_; // a new network: try right away
            }
        }
    }
    return false;
}

/**
 * @brief Resolve the server and open a connected, non-blocking TCP socket.
 *
 * Every address returned by getaddrinfo() (IPv6 and IPv4) is tried in turn.
 * Each socket is passed to protect_socket BEFORE connect(), so on Android
 * its packets leave through the physical network instead of the VPN itself.
 * The connect is non-blocking with poll(), so it has a timeout and can be
 * interrupted by stop() through the wake pipe.
 *
 * Note: getaddrinfo() itself blocks; the Android app therefore passes an IP
 * address that it resolved before the VPN came up.
 *
 * @return A connected socket, or -1 (the state was set to Reconnecting with
 *         the reason, unless stop() was requested).
 */
int TunnelClient::connect_server() {
    addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;     // IPv4 or IPv6, whatever the name resolves to
    hints.ai_socktype = SOCK_STREAM; // TCP
    addrinfo* result = nullptr;
    std::string port = std::to_string(config_.server_port);
    int rc = getaddrinfo(config_.server_host.c_str(), port.c_str(), &hints, &result);
    if (rc != 0 || result == nullptr) {
        set_state(TunnelState::Reconnecting,
                  "cannot resolve " + config_.server_host + ": " + gai_strerror(rc));
        return -1;
    }

    int sock = -1;
    std::string error = "no address"; // reason reported if every address fails
    for (addrinfo* ai = result; ai != nullptr && !stop_requested_; ai = ai->ai_next) {
        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0) {
            error = strerror(errno);
            continue;
        }
        fcntl(sock, F_SETFD, FD_CLOEXEC);
        // Must happen before connect(): VpnService.protect() binds the socket to the underlying network
        if (config_.protect_socket && !config_.protect_socket(sock)) {
            error = "protect() failed";
            close(sock);
            sock = -1;
            continue;
        }
        set_nonblocking(sock);
        // Non-blocking connect: returns at once with EINPROGRESS, completion is signalled by POLLOUT
        if (connect(sock, ai->ai_addr, ai->ai_addrlen) != 0 && errno != EINPROGRESS) {
            error = strerror(errno);
            close(sock);
            sock = -1;
            continue;
        }
        pollfd fds[2] = {{sock, POLLOUT, 0}, {wake_pipe_[0], POLLIN, 0}};
        int n = poll(fds, 2, config_.connect_timeout_ms);
        int err = 0;
        socklen_t len = sizeof(err);
        if (n <= 0 || !(fds[0].revents & (POLLOUT | POLLERR | POLLHUP))) {
            // timeout, or woken by stop()/reconnect() through the pipe
            err = n == 0 ? ETIMEDOUT : EINTR;
        } else if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) != 0) {
            // SO_ERROR holds the result of the asynchronous connect (0 = success)
            err = errno;
        }
        if (err != 0) {
            error = strerror(err);
            close(sock);
            sock = -1;
            continue; // try the next address
        }
        int on = 1;
        // Disable Nagle: each frame is one IP packet that should leave immediately
        // (delaying small packets such as ACKs or DNS queries would add latency)
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
        break;
    }
    freeaddrinfo(result);
    if (sock < 0 && !stop_requested_) {
        set_state(TunnelState::Reconnecting, "cannot connect to " + config_.server_host + ":" + port + ": " + error);
    }
    return sock;
}

/**
 * @brief Run one tunnel session on a connected socket until it ends.
 *
 * Sends HELLO, waits for HELLO_ACK (only then the TUN is read, so no packet
 * is sent before the server accepted us), then pumps packets in both
 * directions, answers PINGs, sends its own PINGs every keepalive interval and
 * gives up if nothing at all was received for keepalive_timeout_ms (a dead
 * TCP connection, e.g. after the phone lost its network, may otherwise stay
 * "open" for many minutes).
 *
 * @param sock Connected socket from connect_server(); closed before returning.
 * @return Why the session ended (Stopped, Disconnected, AuthFailed, NetworkChanged).
 */
TunnelClient::SessionEnd TunnelClient::run_session(int sock) {
    Buffer out;                       // frames waiting to be sent to the server
    std::string in;                   // bytes received from the server, not yet a complete frame
    std::vector<char> packet(65536);  // TUN read buffer (max IP packet size)

    // The HELLO frame is the first thing in the output buffer
    std::map<std::string, std::string> hello;
    hello["version"] = "1";
    hello["token"] = config_.token;
    hello["client"] = config_.client_name;
    hello["mtu"] = std::to_string(config_.mtu);
    hello["ipv4"] = config_.tun_ipv4;
    hello["ipv6"] = config_.tun_ipv6;
    std::string hello_text = tunnel::encode_kv(hello);
    tunnel::append_frame(out.raw(), tunnel::kHello, hello_text.data(), hello_text.size());

    bool authenticated = false;                              // HELLO_ACK received
    int64_t now = mono_ms();
    int64_t hello_deadline = now + config_.connect_timeout_ms; // HELLO_ACK must arrive before this
    int64_t last_rx = now;                                   // last time any byte came from the server
    int64_t last_ping = now;                                 // last PING we sent
    std::string end_message = "disconnected";
    SessionEnd end = SessionEnd::Disconnected;

    // Send as much of `out` as the socket accepts; false = fatal socket error
    auto flush = [&]() -> bool {
        while (!out.empty()) {
            // MSG_NOSIGNAL: a closed connection must give EPIPE, not kill the process with SIGPIPE
            ssize_t n = send(sock, out.data(), out.size(), MSG_NOSIGNAL);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                    return true; // socket buffer full: retry when poll() reports POLLOUT
                }
                end_message = std::string("send failed: ") + strerror(errno);
                return false;
            }
            out.consume(static_cast<size_t>(n));
        }
        return true;
    };

    // Read packets from the TUN and queue them as frames
    // (at most max_packets, and never beyond max_send_buffer: if the server is
    // slower than the apps, we stop reading, the TUN queue fills up and the
    // apps' TCP stacks slow down - that is the back pressure towards the phone)
    auto pump_tun = [&](int max_packets) {
        for (int i = 0; i < max_packets && out.size() < config_.max_send_buffer; ++i) {
            ssize_t r = read(config_.tun_fd, packet.data(), packet.size()); // one read = one IP packet
            if (r <= 0) {
                break; // EAGAIN: no more packets right now
            }
            tunnel::append_frame(out.raw(), tunnel::kPacket, packet.data(), static_cast<size_t>(r));
            ++stats_.tx_packets;
            stats_.tx_bytes += static_cast<uint64_t>(r);
        }
    };

    // Handle the complete frames in `in`; false ends the session
    auto process_frames = [&]() -> bool {
        size_t offset = 0; // start of the next unprocessed frame in `in`
        bool keep_going = true;
        while (keep_going) {
            uint8_t type = 0;
            uint32_t payload_len = 0;
            long total = tunnel::parse_header(reinterpret_cast<const uint8_t*>(in.data()) + offset,
                                              in.size() - offset, &type, &payload_len);
            if (total < 0) {
                end_message = "protocol error from server";
                keep_going = false;
                break;
            }
            if (total == 0 || in.size() - offset < static_cast<size_t>(total)) {
                break; // incomplete frame: wait for more bytes
            }
            const char* payload = in.data() + offset + tunnel::kHeaderSize;
            switch (type) {
            case tunnel::kHelloAck: {
                authenticated = true; // from now on the TUN is read
                std::map<std::string, std::string> ack = tunnel::decode_kv(payload, payload_len);
                stats_.connected_since_ms = wall_ms();
                set_state(TunnelState::Connected, "connected to " + config_.server_host + " (" + ack["server"] +
                                                      ", session " + ack["session"] + ")");
                break;
            }
            case tunnel::kPacket: {
                // One write = one packet injected into the system's network stack
                ssize_t w = write(config_.tun_fd, payload, payload_len);
                if (w < 0) {
                    ++stats_.dropped;
                    // a full TUN queue is normal under load (the packet is lost, TCP recovers)
                    if (errno != EAGAIN && errno != EWOULDBLOCK && errno != ENOBUFS) {
                        log(kLogWarn, std::string("write to TUN failed: ") + strerror(errno));
                    }
                } else {
                    ++stats_.rx_packets;
                    stats_.rx_bytes += payload_len;
                }
                break;
            }
            case tunnel::kPing:
                tunnel::append_frame(out.raw(), tunnel::kPong, payload, payload_len); // echo the payload
                break;
            case tunnel::kPong:
                break; // receiving anything already updated last_rx
            case tunnel::kError:
                end_message = "server error: " + std::string(payload, payload_len);
                if (end_message.find("authentication") != std::string::npos) {
                    end = SessionEnd::AuthFailed; // wrong token: retry only slowly
                }
                keep_going = false;
                break;
            default:
                break; // unknown frame types are ignored (forward compatibility)
            }
            offset += static_cast<size_t>(total);
        }
        in.erase(0, offset); // drop the processed frames, keep a partial one
        return keep_going;
    };

    while (true) {
        if (stop_requested_) {
            end = SessionEnd::Stopped;
            break;
        }
        // Read the TUN only after the handshake and while the output buffer has room
        bool read_tun = authenticated && out.size() < config_.max_send_buffer;
        pollfd fds[3];
        // Ask for POLLOUT only when there is something to send, otherwise poll() would return at once forever
        fds[0] = {sock, static_cast<short>(POLLIN | (out.empty() ? 0 : POLLOUT)), 0};
        fds[1] = {wake_pipe_[0], POLLIN, 0};
        fds[2] = {config_.tun_fd, static_cast<short>(read_tun ? POLLIN : 0), 0}; // events 0 = ignored
        int n = poll(fds, 3, 1000); // wake at least once a second for the timers
        if (n < 0 && errno != EINTR) {
            end_message = std::string("poll failed: ") + strerror(errno);
            break;
        }
        now = mono_ms();

        if (fds[1].revents & POLLIN) {
            char buf[64];
            while (read(wake_pipe_[0], buf, sizeof(buf)) > 0) {
                // empty the wake pipe
            }
            if (stop_requested_) {
                end = SessionEnd::Stopped;
                break;
            }
            if (reconnect_requested_.exchange(false)) {
                end_message = "network changed";
                end = SessionEnd::NetworkChanged;
                break;
            }
        }

        // Server -> TUN. Work in small batches and drain the TUN in between:
        // writing packets into the TUN makes the system generate ACKs, and
        // the TUN transmit queue (500 packets on Linux/Android) must not overflow.
        bool session_over = false;
        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            for (int i = 0; i < 16 && !session_over; ++i) { // at most 16 reads, then let the TUN side run
                size_t old = in.size();
                in.resize(old + 65536); // read directly behind the pending bytes
                ssize_t r = recv(sock, &in[old], 65536, 0);
                in.resize(old + (r > 0 ? static_cast<size_t>(r) : 0)); // keep only what was received
                if (r == 0) {
                    end_message = "server closed the connection";
                    session_over = true;
                } else if (r < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                        end_message = std::string("receive failed: ") + strerror(errno);
                        session_over = true;
                    }
                } else {
                    last_rx = now; // any data proves the connection is alive
                }
                if (!process_frames()) {
                    session_over = true;
                }
                if (authenticated) {
                    pump_tun(64);
                }
                if (r <= 0) {
                    break; // socket drained (or closed)
                }
            }
        }
        if (session_over) {
            break;
        }

        // TUN -> server
        if (read_tun && (fds[2].revents & POLLIN)) {
            pump_tun(256);
        }

        // Timers
        if (!authenticated && now > hello_deadline) {
            end_message = "handshake timeout";
            break;
        }
        if (authenticated && now - last_ping >= config_.keepalive_interval_ms) {
            int64_t stamp = now; // payload: our timestamp, echoed back in the PONG
            tunnel::append_frame(out.raw(), tunnel::kPing, &stamp, sizeof(stamp));
            last_ping = now;
        }
        if (now - last_rx > config_.keepalive_timeout_ms) {
            // Not even a PONG for several PING intervals: the connection is dead
            end_message = "keepalive timeout";
            break;
        }

        if (!flush()) {
            break;
        }
    }

    close(sock);
    stats_.connected_since_ms = 0;
    if (end != SessionEnd::Stopped) {
        log(kLogWarn, "tunnel ended: " + end_message);
        std::lock_guard<std::mutex> lock(message_mutex_);
        last_message_ = end_message; // run() includes it in the next state message
    }
    return end;
}

/**
 * @brief Main loop of the tunnel thread: connect, run a session, back off,
 *        repeat until stop().
 *
 * Reconnect policy: the delay starts at 1 s and doubles up to
 * max_backoff_ms, so an unreachable server is not hammered. A network
 * change reconnects immediately with the delay reset; a session that lasted
 * more than 10 s also resets it; an authentication failure waits the maximum
 * (retrying fast with a wrong token is pointless).
 *
 * Before returning, the TUN fd is closed. On Android that is what tears the
 * VPN interface down.
 */
void TunnelClient::run() {
    if (config_.tun_fd < 0) {
        set_state(TunnelState::Stopped, "invalid TUN fd");
        return;
    }
    set_nonblocking(config_.tun_fd); // Android's setBlocking(false) already did it; Linux needs it
    int backoff = 1000;
    set_state(TunnelState::Connecting, "connecting to " + config_.server_host);

    while (!stop_requested_) {
        int sock = connect_server();
        if (sock < 0) {
            if (!wait_backoff(backoff)) {
                break; // stopped
            }
            backoff = std::min(backoff * 2, config_.max_backoff_ms);
            continue;
        }
        int64_t started = mono_ms();
        SessionEnd end = run_session(sock);
        if (end == SessionEnd::Stopped) {
            break;
        }
        ++stats_.reconnects;
        if (end == SessionEnd::NetworkChanged) {
            set_state(TunnelState::Reconnecting, "network changed, reconnecting");
            backoff = 1000;
            continue; // no waiting: the new network is up
        }
        if (end == SessionEnd::AuthFailed) {
            set_state(TunnelState::AuthFailed, last_message());
            backoff = config_.max_backoff_ms;
        } else {
            set_state(TunnelState::Reconnecting, last_message() + ", reconnecting");
            // A session that lasted a while resets the back off
            if (mono_ms() - started > 10000) {
                backoff = 1000;
            }
        }
        if (!wait_backoff(backoff)) {
            break;
        }
        backoff = std::min(backoff * 2, config_.max_backoff_ms);
    }

    close(config_.tun_fd);
    config_.tun_fd = -1; // so the destructor does not close it again
    set_state(TunnelState::Stopped, "stopped");
}

} // namespace simplevpn
