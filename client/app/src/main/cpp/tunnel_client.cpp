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

int64_t mono_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

int64_t wall_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
}

// Byte buffer with a read offset (cheap consume from the front)
class Buffer {
public:
    size_t size() const { return data_.size() - offset_; }
    bool empty() const { return size() == 0; }
    const char* data() const { return data_.data() + offset_; }
    std::string& raw() { return data_; }
    void consume(size_t n) {
        offset_ += n;
        if (offset_ >= data_.size()) {
            data_.clear();
            offset_ = 0;
        } else if (offset_ > 65536 && offset_ * 2 > data_.size()) {
            data_.erase(0, offset_);
            offset_ = 0;
        }
    }

private:
    std::string data_;
    size_t offset_ = 0;
};

} // namespace

TunnelClient::TunnelClient(TunnelClientConfig config) : config_(std::move(config)) {
    if (pipe(wake_pipe_) == 0) {
        set_nonblocking(wake_pipe_[0]);
        set_nonblocking(wake_pipe_[1]);
        fcntl(wake_pipe_[0], F_SETFD, FD_CLOEXEC);
        fcntl(wake_pipe_[1], F_SETFD, FD_CLOEXEC);
    }
}

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

void TunnelClient::stop() {
    stop_requested_ = true;
    if (wake_pipe_[1] >= 0) {
        char c = 1;
        ssize_t r = write(wake_pipe_[1], &c, 1);
        (void)r;
    }
}

void TunnelClient::reconnect() {
    reconnect_requested_ = true;
    if (wake_pipe_[1] >= 0) {
        char c = 1;
        ssize_t r = write(wake_pipe_[1], &c, 1);
        (void)r;
    }
}

std::string TunnelClient::last_message() const {
    std::lock_guard<std::mutex> lock(message_mutex_);
    return last_message_;
}

void TunnelClient::log(int level, const std::string& message) const {
    if (config_.log) {
        config_.log(level, message);
    }
}

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

void TunnelClient::drain_tun() {
    char buffer[65536];
    for (int i = 0; i < 256; ++i) {
        ssize_t n = read(config_.tun_fd, buffer, sizeof(buffer));
        if (n <= 0) {
            break;
        }
        ++stats_.dropped;
    }
}

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
            }
            if (reconnect_requested_.exchange(false)) {
                return !stop_requested_; // a new network: try right away
            }
        }
    }
    return false;
}

int TunnelClient::connect_server() {
    addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* result = nullptr;
    std::string port = std::to_string(config_.server_port);
    int rc = getaddrinfo(config_.server_host.c_str(), port.c_str(), &hints, &result);
    if (rc != 0 || result == nullptr) {
        set_state(TunnelState::Reconnecting,
                  "cannot resolve " + config_.server_host + ": " + gai_strerror(rc));
        return -1;
    }

    int sock = -1;
    std::string error = "no address";
    for (addrinfo* ai = result; ai != nullptr && !stop_requested_; ai = ai->ai_next) {
        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0) {
            error = strerror(errno);
            continue;
        }
        fcntl(sock, F_SETFD, FD_CLOEXEC);
        if (config_.protect_socket && !config_.protect_socket(sock)) {
            error = "protect() failed";
            close(sock);
            sock = -1;
            continue;
        }
        set_nonblocking(sock);
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
            err = n == 0 ? ETIMEDOUT : EINTR;
        } else if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) != 0) {
            err = errno;
        }
        if (err != 0) {
            error = strerror(err);
            close(sock);
            sock = -1;
            continue;
        }
        int on = 1;
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
        break;
    }
    freeaddrinfo(result);
    if (sock < 0 && !stop_requested_) {
        set_state(TunnelState::Reconnecting, "cannot connect to " + config_.server_host + ":" + port + ": " + error);
    }
    return sock;
}

TunnelClient::SessionEnd TunnelClient::run_session(int sock) {
    Buffer out;
    std::string in;
    std::vector<char> packet(65536);

    std::map<std::string, std::string> hello;
    hello["version"] = "1";
    hello["token"] = config_.token;
    hello["client"] = config_.client_name;
    hello["mtu"] = std::to_string(config_.mtu);
    hello["ipv4"] = config_.tun_ipv4;
    hello["ipv6"] = config_.tun_ipv6;
    std::string hello_text = tunnel::encode_kv(hello);
    tunnel::append_frame(out.raw(), tunnel::kHello, hello_text.data(), hello_text.size());

    bool authenticated = false;
    int64_t now = mono_ms();
    int64_t hello_deadline = now + config_.connect_timeout_ms;
    int64_t last_rx = now;
    int64_t last_ping = now;
    std::string end_message = "disconnected";
    SessionEnd end = SessionEnd::Disconnected;

    auto flush = [&]() -> bool {
        while (!out.empty()) {
            ssize_t n = send(sock, out.data(), out.size(), MSG_NOSIGNAL);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                    return true;
                }
                end_message = std::string("send failed: ") + strerror(errno);
                return false;
            }
            out.consume(static_cast<size_t>(n));
        }
        return true;
    };

    // Read packets from the TUN and queue them as frames
    auto pump_tun = [&](int max_packets) {
        for (int i = 0; i < max_packets && out.size() < config_.max_send_buffer; ++i) {
            ssize_t r = read(config_.tun_fd, packet.data(), packet.size());
            if (r <= 0) {
                break;
            }
            tunnel::append_frame(out.raw(), tunnel::kPacket, packet.data(), static_cast<size_t>(r));
            ++stats_.tx_packets;
            stats_.tx_bytes += static_cast<uint64_t>(r);
        }
    };

    // Handle the complete frames in `in`; false ends the session
    auto process_frames = [&]() -> bool {
        size_t offset = 0;
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
                break;
            }
            const char* payload = in.data() + offset + tunnel::kHeaderSize;
            switch (type) {
            case tunnel::kHelloAck: {
                authenticated = true;
                std::map<std::string, std::string> ack = tunnel::decode_kv(payload, payload_len);
                stats_.connected_since_ms = wall_ms();
                set_state(TunnelState::Connected, "connected to " + config_.server_host + " (" + ack["server"] +
                                                      ", session " + ack["session"] + ")");
                break;
            }
            case tunnel::kPacket: {
                ssize_t w = write(config_.tun_fd, payload, payload_len);
                if (w < 0) {
                    ++stats_.dropped;
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
                tunnel::append_frame(out.raw(), tunnel::kPong, payload, payload_len);
                break;
            case tunnel::kPong:
                break;
            case tunnel::kError:
                end_message = "server error: " + std::string(payload, payload_len);
                if (end_message.find("authentication") != std::string::npos) {
                    end = SessionEnd::AuthFailed;
                }
                keep_going = false;
                break;
            default:
                break;
            }
            offset += static_cast<size_t>(total);
        }
        in.erase(0, offset);
        return keep_going;
    };

    while (true) {
        if (stop_requested_) {
            end = SessionEnd::Stopped;
            break;
        }
        bool read_tun = authenticated && out.size() < config_.max_send_buffer;
        pollfd fds[3];
        fds[0] = {sock, static_cast<short>(POLLIN | (out.empty() ? 0 : POLLOUT)), 0};
        fds[1] = {wake_pipe_[0], POLLIN, 0};
        fds[2] = {config_.tun_fd, static_cast<short>(read_tun ? POLLIN : 0), 0};
        int n = poll(fds, 3, 1000);
        if (n < 0 && errno != EINTR) {
            end_message = std::string("poll failed: ") + strerror(errno);
            break;
        }
        now = mono_ms();

        if (fds[1].revents & POLLIN) {
            char buf[64];
            while (read(wake_pipe_[0], buf, sizeof(buf)) > 0) {
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
            for (int i = 0; i < 16 && !session_over; ++i) {
                size_t old = in.size();
                in.resize(old + 65536);
                ssize_t r = recv(sock, &in[old], 65536, 0);
                in.resize(old + (r > 0 ? static_cast<size_t>(r) : 0));
                if (r == 0) {
                    end_message = "server closed the connection";
                    session_over = true;
                } else if (r < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                        end_message = std::string("receive failed: ") + strerror(errno);
                        session_over = true;
                    }
                } else {
                    last_rx = now;
                }
                if (!process_frames()) {
                    session_over = true;
                }
                if (authenticated) {
                    pump_tun(64);
                }
                if (r <= 0) {
                    break;
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
            int64_t stamp = now;
            tunnel::append_frame(out.raw(), tunnel::kPing, &stamp, sizeof(stamp));
            last_ping = now;
        }
        if (now - last_rx > config_.keepalive_timeout_ms) {
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
        last_message_ = end_message;
    }
    return end;
}

void TunnelClient::run() {
    if (config_.tun_fd < 0) {
        set_state(TunnelState::Stopped, "invalid TUN fd");
        return;
    }
    set_nonblocking(config_.tun_fd);
    int backoff = 1000;
    set_state(TunnelState::Connecting, "connecting to " + config_.server_host);

    while (!stop_requested_) {
        int sock = connect_server();
        if (sock < 0) {
            if (!wait_backoff(backoff)) {
                break;
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
            continue;
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
    config_.tun_fd = -1;
    set_state(TunnelState::Stopped, "stopped");
}

} // namespace simplevpn
