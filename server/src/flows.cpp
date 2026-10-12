#include "flows.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>

namespace vpn {

namespace {

constexpr int kInitialRtoMs = 1000;
constexpr int kMinRtoMs = 300;
constexpr int kMaxRtoMs = 30000;
constexpr int kMaxRetries = 10;
constexpr int kMaxSynAckRetries = 5;
constexpr size_t kMaxInFlight = 2 * 1024 * 1024;

std::string endpoint(const IpAddr& ip, uint16_t port) {
    if (ip.version == 6) {
        return "[" + ip.to_string() + "]:" + std::to_string(port);
    }
    return ip.to_string() + ":" + std::to_string(port);
}

} // namespace

// ---------------------------------------------------------------------------
// TcpFlow
// ---------------------------------------------------------------------------

TcpFlow::TcpFlow(Session* session, const FlowKey& key, uint64_t id, const ParsedPacket& syn)
    : Flow(session, key, id) {
    name_ = session->tag() + " TCP#" + std::to_string(id) + " " + endpoint(key.src, key.src_port) + " -> " +
            endpoint(key.dst, key.dst_port);

    irs_ = syn.seq;
    rcv_nxt_ = syn.seq + 1;
    iss_ = session->random32();
    snd_una_ = iss_;
    snd_nxt_ = iss_;
    snd_max_ = iss_;
    snd_wnd_ = syn.window; // the window of a SYN is never scaled

    if (syn.tcp_options.wscale >= 0) {
        wscale_ok_ = true;
        snd_wscale_ = syn.tcp_options.wscale;
        while (rcv_wscale_ < 14 && (g_vpn_config.tcp_window >> rcv_wscale_) > 65535) {
            ++rcv_wscale_;
        }
    }

    int header_overhead = key.src.version == 4 ? 40 : 60;
    int our_mss = std::max(536, session->mtu() - header_overhead);
    int peer_mss = syn.tcp_options.mss != 0 ? syn.tcp_options.mss : (key.src.version == 4 ? 536 : 1220);
    mss_ = static_cast<uint16_t>(std::min(our_mss, peer_mss));
}

TcpFlow::~TcpFlow() {
    if (reported_inflight_ > 0) {
        session_->add_inflight(-static_cast<long>(reported_inflight_));
    }
}

// Keep the session wide count of unacknowledged bytes up to date
void TcpFlow::account_inflight() {
    size_t now = dead_ ? 0 : in_flight();
    if (now != reported_inflight_) {
        session_->add_inflight(static_cast<long>(now) - static_cast<long>(reported_inflight_));
        reported_inflight_ = now;
    }
}

bool TcpFlow::start() {
    NetAddr remote = key_.dst.to_netaddr(key_.dst_port);
    int ret = srv_connect(SOCK_STREAM, 0, &remote, SRV_CONNECT_HALF_CLOSE | SRV_CONNECT_RAW, id_, &upstream_);
    if (ret != 0) {
        LOG_INFO("%s connect failed: %s", name_.c_str(), strerror(-ret));
        send_segment(kTcpRst | kTcpAck, 0, nullptr, 0);
        finish(false, nullptr);
        return false;
    }
    has_upstream_ = true;
    LOG_DEBUG("%s SYN (mss %u, wscale %d), connecting to server", name_.c_str(), mss_,
              wscale_ok_ ? snd_wscale_ : -1);
    return true;
}

bool TcpFlow::is_new_connection(const ParsedPacket& syn) const {
    return syn.seq != irs_;
}

uint16_t TcpFlow::advertised_window() const {
    if (upstream_blocked_) {
        return 0;
    }
    uint32_t window = g_vpn_config.tcp_window >> rcv_wscale_;
    return static_cast<uint16_t>(std::min<uint32_t>(window, 65535));
}

void TcpFlow::send_segment(uint8_t flags, uint32_t seq, const uint8_t* data, size_t len, bool syn_options) {
    uint8_t options[8];
    size_t options_len = 0;
    uint16_t window = advertised_window();
    if (syn_options) {
        options[0] = 2; // MSS
        options[1] = 4;
        write_be16(options + 2, mss_);
        options_len = 4;
        if (wscale_ok_) {
            options[4] = 1; // NOP
            options[5] = 3; // window scale
            options[6] = 3;
            options[7] = static_cast<uint8_t>(rcv_wscale_);
            options_len = 8;
        }
        // the window field of a SYN is not scaled
        window = upstream_blocked_ ? 0 : static_cast<uint16_t>(std::min<uint32_t>(g_vpn_config.tcp_window, 65535));
    }
    uint32_t ack = (flags & kTcpAck) ? rcv_nxt_ : 0;
    build_tcp_packet(scratch_, key_.dst, key_.dst_port, key_.src, key_.src_port, seq, ack, flags, window, options,
                     options_len, data, len);
    session_->send_packet(scratch_);
    if (flags & kTcpAck) {
        zero_window_sent_ = window == 0;
    }
}

void TcpFlow::send_ack() {
    send_segment(kTcpAck, snd_max_, nullptr, 0);
}

void TcpFlow::send_syn_ack() {
    send_segment(kTcpSyn | kTcpAck, iss_, nullptr, 0, true);
}

void TcpFlow::arm_rto() {
    rto_deadline_ = now_ms() + rto_ms_;
}

void TcpFlow::update_rtt(int64_t sample) {
    if (sample < 1) {
        sample = 1;
    }
    if (srtt_ms_ == 0) {
        srtt_ms_ = sample;
        rttvar_ms_ = sample / 2;
    } else {
        int64_t diff = srtt_ms_ > sample ? srtt_ms_ - sample : sample - srtt_ms_;
        rttvar_ms_ = (3 * rttvar_ms_ + diff) / 4;
        srtt_ms_ = (7 * srtt_ms_ + sample) / 8;
    }
    int64_t rto = srtt_ms_ + std::max<int64_t>(10, 4 * rttvar_ms_);
    rto_ms_ = static_cast<int>(std::min<int64_t>(kMaxRtoMs, std::max<int64_t>(kMinRtoMs, rto)));
}

void TcpFlow::abort(const char* reason, bool reset_phone) {
    if (dead_) {
        return;
    }
    if (reason != nullptr) {
        LOG_INFO("%s aborted: %s (up %llu bytes, down %llu bytes)", name_.c_str(), reason,
                 static_cast<unsigned long long>(bytes_up_), static_cast<unsigned long long>(bytes_down_));
    }
    if (reset_phone && state_ != State::Connecting) {
        send_segment(kTcpRst | kTcpAck, state_ == State::Established ? snd_max_ : snd_nxt_, nullptr, 0);
    }
    finish(true, nullptr);
    account_inflight();
}

void TcpFlow::on_upstream_open(int error) {
    if (dead_) {
        return;
    }
    if (error != 0) {
        has_upstream_ = false; // a failed connect is not followed by a close event
        LOG_INFO("%s connect to server failed: %s", name_.c_str(), strerror(error));
        send_segment(kTcpRst | kTcpAck, 0, nullptr, 0);
        finish(false, nullptr);
        return;
    }
    upstream_open_ = true;
    char local[64];
    LOG_INFO("%s connected (server side local address %s)", name_.c_str(),
             srv_addr_to_string(&upstream_.local_addr, local, sizeof(local)));
    // Now that the real server accepted, complete the handshake with the phone
    state_ = State::SynAckSent;
    snd_una_ = iss_;
    snd_nxt_ = iss_ + 1;
    snd_max_ = snd_nxt_;
    send_syn_ack();
    arm_rto();
}

void TcpFlow::on_packet(const ParsedPacket& p) {
    if (dead_) {
        return;
    }
    touch();
    uint8_t flags = p.tcp_flags;

    if (flags & kTcpRst) {
        LOG_INFO("%s reset by client (up %llu bytes, down %llu bytes)", name_.c_str(),
                 static_cast<unsigned long long>(bytes_up_), static_cast<unsigned long long>(bytes_down_));
        abort(nullptr, false);
        return;
    }
    if (state_ == State::Connecting) {
        return; // SYN retransmission while we are still connecting to the server
    }
    if (flags & kTcpSyn) {
        if (state_ == State::SynAckSent && !(flags & kTcpAck) && p.seq == irs_) {
            send_syn_ack(); // our SYN-ACK got lost
        } else {
            send_ack(); // challenge ACK
        }
        return;
    }
    if (!(flags & kTcpAck)) {
        return;
    }

    process_ack(p);
    if (dead_) {
        return;
    }
    process_data(p);
    if (dead_) {
        return;
    }
    transmit();
    maybe_finish();
}

void TcpFlow::process_ack(const ParsedPacket& p) {
    uint32_t ack = p.ack;
    if (state_ == State::SynAckSent) {
        if (ack != iss_ + 1) {
            // Not an ACK of our SYN-ACK
            send_segment(kTcpRst, ack, nullptr, 0);
            return;
        }
        state_ = State::Established;
        snd_una_ = iss_ + 1;
        retries_ = 0;
        rto_deadline_ = 0;
        rto_ms_ = kInitialRtoMs;
        LOG_DEBUG("%s established", name_.c_str());
    }

    uint32_t window = static_cast<uint32_t>(p.window) << (wscale_ok_ ? snd_wscale_ : 0);
    if (seq_gt(ack, snd_una_) && seq_le(ack, snd_max_)) {
        uint32_t acked = ack - snd_una_;
        size_t data_acked = std::min<size_t>(acked, send_buf_.size());
        if (acked > send_buf_.size()) {
            // Everything beyond the data is the FIN (ack <= snd_max_ proves we sent it)
            fin_acked_ = true;
            fin_sent_ = true;
        }
        send_buf_.erase(0, data_acked);
        snd_una_ = ack;
        if (seq_lt(snd_nxt_, snd_una_)) {
            snd_nxt_ = snd_una_; // data sent before a rewind arrived after all
        }
        dupacks_ = 0;
        retries_ = 0;
        if (rtt_timing_ && seq_le(rtt_seq_, ack)) {
            update_rtt(now_ms() - rtt_start_ms_);
            rtt_timing_ = false;
        } else if (srtt_ms_ == 0) {
            rto_ms_ = kInitialRtoMs;
        } else {
            update_rtt(srtt_ms_); // recompute the RTO without the back off
        }
        rto_deadline_ = 0;
        if (in_flight() > 0) {
            arm_rto();
        }
        if (upstream_paused_ && send_buf_.size() < g_vpn_config.tcp_flow_buffer / 2) {
            srv_pause_read(&upstream_, 0);
            upstream_paused_ = false;
        }
        account_inflight();
    } else if (ack == snd_una_ && p.payload_len == 0 && !(p.tcp_flags & kTcpFin) && in_flight() > 0 &&
               window == snd_wnd_) {
        if (++dupacks_ == 3) {
            // Fast retransmit of the first unacknowledged segment
            size_t len = std::min<size_t>(mss_, send_buf_.size());
            if (len > 0) {
                send_segment(kTcpAck | kTcpPsh, snd_una_, reinterpret_cast<const uint8_t*>(send_buf_.data()), len);
            } else if (upstream_eof_ && !fin_acked_) {
                send_segment(kTcpFin | kTcpAck, snd_una_, nullptr, 0);
            }
            rtt_timing_ = false;
            ++retransmits_;
        }
    } else if (seq_gt(ack, snd_max_)) {
        send_ack(); // acknowledges data we never sent
        return;
    }
    snd_wnd_ = window;
}

void TcpFlow::deliver_upstream(const uint8_t* data, size_t len) {
    std::string chunk(reinterpret_cast<const char*>(data), len);
    if (g_inspector.inspect_tcp(name_, key_.dst_port, true, inspect_, chunk) == Inspector::kBlock) {
        abort("blocked by rule", true);
        return;
    }
    if (!chunk.empty()) {
        srv_send(&upstream_, chunk.data(), static_cast<int>(chunk.size()));
    }
}

void TcpFlow::process_data(const ParsedPacket& p) {
    bool fin = (p.tcp_flags & kTcpFin) != 0;
    const uint8_t* data = p.payload;
    size_t len = p.payload_len;
    uint32_t seq = p.seq;
    if ((len == 0 && !fin) || state_ != State::Established) {
        return;
    }
    if (phone_fin_) {
        send_ack(); // retransmission after the FIN
        return;
    }

    if (seq_lt(seq, rcv_nxt_)) {
        uint32_t overlap = rcv_nxt_ - seq;
        if (overlap > len || (overlap == len && !fin)) {
            send_ack(); // complete duplicate
            return;
        }
        data += overlap;
        len -= overlap;
        seq = rcv_nxt_;
    }
    if (seq != rcv_nxt_) {
        send_ack(); // out of order (a hole): the phone will retransmit
        return;
    }

    if (len > 0) {
        if (upstream_closed_) {
            abort("data from client after the server closed", true);
            return;
        }
        bytes_up_ += len;
        rcv_nxt_ += static_cast<uint32_t>(len);
        deliver_upstream(data, len);
        if (dead_) {
            return;
        }
    }
    if (fin) {
        rcv_nxt_ += 1;
        phone_fin_ = true;
        LOG_DEBUG("%s FIN from client", name_.c_str());
        if (!upstream_closed_) {
            srv_shutdown_write(&upstream_);
        }
    }
    send_ack();
}

void TcpFlow::transmit(bool force_one) {
    if (dead_ || state_ != State::Established) {
        return;
    }
    if (session_->tunnel_blocked() && !force_one) {
        return;
    }
    bool sent_any = false;
    while (!fin_sent_) {
        size_t sent = snd_nxt_ - snd_una_; // position in send_buf_
        size_t unsent = send_buf_.size() > sent ? send_buf_.size() - sent : 0;
        if (unsent == 0) {
            if (upstream_eof_) {
                send_segment(kTcpFin | kTcpAck, snd_nxt_, nullptr, 0);
                snd_nxt_ += 1;
                fin_sent_ = true;
                if (seq_gt(snd_nxt_, snd_max_)) {
                    snd_max_ = snd_nxt_;
                }
                if (rto_deadline_ == 0) {
                    arm_rto();
                }
                LOG_DEBUG("%s FIN to client", name_.c_str());
            }
            break;
        }
        size_t window = std::min<size_t>(snd_wnd_, kMaxInFlight);
        size_t room = window > sent ? window - sent : 0;
        bool new_data = snd_nxt_ == snd_max_;
        if (new_data && room > 0) {
            // Share the tunnel fairly: limit the unacknowledged bytes of the whole session
            size_t session_room = session_->inflight_room();
            if (session_room == 0 && !force_one) {
                session_->wait_for_budget(id_);
                break;
            }
            room = std::min(room, std::max<size_t>(session_room, mss_));
        }
        if (room == 0) {
            if (!force_one || sent_any) {
                if (rto_deadline_ == 0) {
                    arm_rto(); // persist timer: probe the zero window later
                }
                break;
            }
            room = 1; // zero window probe
        }
        size_t len = std::min(std::min(unsent, room), static_cast<size_t>(mss_));
        uint8_t flags = kTcpAck | (len == unsent ? kTcpPsh : 0);
        send_segment(flags, snd_nxt_, reinterpret_cast<const uint8_t*>(send_buf_.data()) + sent, len);
        if (!rtt_timing_ && !force_one && new_data) {
            rtt_timing_ = true;
            rtt_seq_ = snd_nxt_ + static_cast<uint32_t>(len);
            rtt_start_ms_ = now_ms();
        }
        if (!new_data) {
            ++retransmits_;
        }
        snd_nxt_ += static_cast<uint32_t>(len);
        if (seq_gt(snd_nxt_, snd_max_)) {
            snd_max_ = snd_nxt_;
        }
        account_inflight();
        sent_any = true;
        if (rto_deadline_ == 0) {
            arm_rto();
        }
        if (force_one || session_->tunnel_blocked()) {
            break;
        }
    }
    account_inflight();
}

void TcpFlow::maybe_finish() {
    if (dead_ || !phone_fin_ || !fin_acked_) {
        return;
    }
    LOG_INFO("%s closed (up %llu bytes, down %llu bytes, %lld ms, %llu retransmits%s%s)", name_.c_str(),
             static_cast<unsigned long long>(bytes_up_), static_cast<unsigned long long>(bytes_down_),
             static_cast<long long>(now_ms() - created_ms_), static_cast<unsigned long long>(retransmits_),
             inspect_.protocol.empty() ? "" : (", " + inspect_.protocol).c_str(),
             inspect_.host.empty() ? "" : (" " + inspect_.host).c_str());
    finish(false, nullptr);
    account_inflight();
}

void TcpFlow::on_upstream_data(const char* data, int len) {
    if (dead_) {
        return;
    }
    touch();
    if (data == nullptr) {
        upstream_eof_ = true;
        LOG_DEBUG("%s FIN from server", name_.c_str());
        transmit();
        maybe_finish();
        return;
    }
    std::string chunk(data, static_cast<size_t>(len));
    if (g_inspector.inspect_tcp(name_, key_.dst_port, false, inspect_, chunk) == Inspector::kBlock) {
        abort("blocked by rule", true);
        return;
    }
    bytes_down_ += static_cast<uint64_t>(len);
    send_buf_.append(chunk);
    if (!upstream_paused_ && send_buf_.size() > g_vpn_config.tcp_flow_buffer) {
        srv_pause_read(&upstream_, 1);
        upstream_paused_ = true;
    }
    transmit();
}

void TcpFlow::on_upstream_close(int error) {
    has_upstream_ = false;
    upstream_closed_ = true;
    if (dead_) {
        return;
    }
    if (error != 0) {
        LOG_INFO("%s server connection error: %s", name_.c_str(), strerror(error));
        abort(nullptr, true);
        return;
    }
    if (!upstream_eof_) {
        upstream_eof_ = true;
        transmit();
    }
    maybe_finish();
}

void TcpFlow::on_upstream_write_blocked(bool blocked) {
    upstream_blocked_ = blocked;
    if (dead_ || state_ != State::Established || phone_fin_) {
        return;
    }
    if (blocked || zero_window_sent_) {
        send_ack(); // advertise the zero window / the reopened window right away
    }
}

void TcpFlow::on_tunnel_writable() {
    transmit();
}

void TcpFlow::on_timer(int64_t now) {
    if (dead_) {
        return;
    }
    int timeout_s = (phone_fin_ || upstream_eof_) ? g_vpn_config.tcp_half_close_timeout_s
                                                   : g_vpn_config.tcp_idle_timeout_s;
    if (now - last_activity_ms_ > timeout_s * 1000LL) {
        abort("idle timeout", true);
        return;
    }
    if (rto_deadline_ == 0 || now < rto_deadline_) {
        return;
    }
    rto_deadline_ = 0;

    if (state_ == State::SynAckSent) {
        if (++retries_ > kMaxSynAckRetries) {
            abort("handshake timeout", true);
            return;
        }
        rto_ms_ = std::min(rto_ms_ * 2, kMaxRtoMs);
        send_syn_ack();
        arm_rto();
        return;
    }
    if (state_ != State::Established) {
        return;
    }

    bool zero_window = snd_wnd_ == 0;
    if (in_flight() == 0 && !(zero_window && !send_buf_.empty())) {
        return; // nothing outstanding
    }
    if (!zero_window && ++retries_ > kMaxRetries) {
        abort("too many retransmissions", true);
        return;
    }
    rto_ms_ = std::min(rto_ms_ * 2, kMaxRtoMs);
    // Go back N: resend from the oldest unacknowledged byte. ACKs for data
    // sent before (up to snd_max_) are still accepted and skip ahead again.
    snd_nxt_ = snd_una_;
    if (fin_sent_ && !fin_acked_) {
        fin_sent_ = false;
    }
    rtt_timing_ = false;
    LOG_DEBUG("%s retransmission timeout (%s), rto %d ms, in flight %zu, window %u, srtt %lld ms, session in flight %zu",
              name_.c_str(), zero_window ? "zero window probe" : "data", rto_ms_, in_flight(), snd_wnd_,
              static_cast<long long>(srtt_ms_), session_->inflight());
    transmit(true);
    if (rto_deadline_ == 0) {
        arm_rto();
    }
}

// ---------------------------------------------------------------------------
// UdpFlow
// ---------------------------------------------------------------------------

UdpFlow::UdpFlow(Session* session, const FlowKey& key, uint64_t id) : Flow(session, key, id) {
    name_ = session->tag() + " UDP#" + std::to_string(id) + " " + endpoint(key.src, key.src_port) + " -> " +
            endpoint(key.dst, key.dst_port);
}

bool UdpFlow::start() {
    NetAddr remote = key_.dst.to_netaddr(key_.dst_port);
    int ret = srv_connect(SOCK_DGRAM, 0, &remote, SRV_CONNECT_RAW, id_, &upstream_);
    if (ret != 0) {
        LOG_INFO("%s cannot open socket: %s", name_.c_str(), strerror(-ret));
        finish(false, nullptr);
        return false;
    }
    has_upstream_ = true;
    LOG_DEBUG("%s new", name_.c_str());
    return true;
}

void UdpFlow::on_packet(const ParsedPacket& p) {
    if (dead_) {
        return;
    }
    touch();
    ++packets_up_;
    bytes_up_ += p.payload_len;
    last_header_.assign(reinterpret_cast<const char*>(p.ip_header), p.ip_header_len + 8);

    std::string reply;
    if (g_inspector.inspect_udp(name_, key_.dst_port, true, p.payload, p.payload_len, &reply) == Inspector::kBlock) {
        if (!reply.empty()) {
            build_udp_packet(scratch_, key_.dst, key_.dst_port, key_.src, key_.src_port,
                             reinterpret_cast<const uint8_t*>(reply.data()), reply.size());
            session_->send_packet(scratch_);
        }
        return;
    }
    if (p.payload_len > 0) {
        srv_send(&upstream_, p.payload, static_cast<int>(p.payload_len));
    }
}

void UdpFlow::on_upstream_open(int error) {
    if (error != 0) {
        has_upstream_ = false;
        LOG_INFO("%s failed: %s", name_.c_str(), strerror(error));
        finish(false, nullptr);
    }
}

void UdpFlow::on_upstream_data(const char* data, int len) {
    if (dead_ || data == nullptr) {
        return;
    }
    touch();
    ++packets_down_;
    bytes_down_ += static_cast<uint64_t>(len);
    if (session_->tunnel_blocked()) {
        return; // tunnel congested: drop, the application protocol copes with UDP loss
    }
    g_inspector.inspect_udp(name_, key_.dst_port, false, reinterpret_cast<const uint8_t*>(data),
                            static_cast<size_t>(len), nullptr);
    build_udp_packet(scratch_, key_.dst, key_.dst_port, key_.src, key_.src_port,
                     reinterpret_cast<const uint8_t*>(data), static_cast<size_t>(len));
    session_->send_packet(scratch_);
}

void UdpFlow::on_upstream_close(int error) {
    has_upstream_ = false;
    if (dead_) {
        return;
    }
    if ((error == ECONNREFUSED || error == EHOSTUNREACH || error == ENETUNREACH) && !last_header_.empty()) {
        // Tell the phone like a router would: ICMP destination unreachable
        bool v6 = key_.src.version == 6;
        uint8_t type = v6 ? 1 : 3;
        uint8_t code = error == ECONNREFUSED ? (v6 ? 4 : 3) : (v6 ? 0 : 1);
        build_icmp_packet(scratch_, key_.dst, key_.src, type, code, 0,
                          reinterpret_cast<const uint8_t*>(last_header_.data()), last_header_.size());
        session_->send_packet(scratch_);
        LOG_INFO("%s %s, ICMP unreachable sent to client", name_.c_str(), strerror(error));
    } else if (error != 0) {
        LOG_INFO("%s socket error: %s", name_.c_str(), strerror(error));
    }
    finish(false, nullptr);
}

void UdpFlow::on_timer(int64_t now) {
    if (dead_) {
        return;
    }
    int timeout_s = key_.dst_port == 53 ? g_vpn_config.dns_idle_timeout_s : g_vpn_config.udp_idle_timeout_s;
    if (now - last_activity_ms_ > timeout_s * 1000LL) {
        if (key_.dst_port == 53) {
            LOG_DEBUG("%s closed (%llu/%llu packets up/down)", name_.c_str(),
                      static_cast<unsigned long long>(packets_up_), static_cast<unsigned long long>(packets_down_));
        } else {
            LOG_INFO("%s closed: %llu packets (%llu bytes) up, %llu packets (%llu bytes) down", name_.c_str(),
                     static_cast<unsigned long long>(packets_up_), static_cast<unsigned long long>(bytes_up_),
                     static_cast<unsigned long long>(packets_down_), static_cast<unsigned long long>(bytes_down_));
        }
        finish(false, nullptr);
    }
}

// ---------------------------------------------------------------------------
// IcmpFlow (echo request / reply)
// ---------------------------------------------------------------------------

IcmpFlow::IcmpFlow(Session* session, const FlowKey& key, uint64_t id) : Flow(session, key, id) {
    name_ = session->tag() + " ICMP#" + std::to_string(id) + " " + key.src.to_string() + " -> " +
            key.dst.to_string() + " id=" + std::to_string(key.src_port);
}

bool IcmpFlow::start() {
    NetAddr remote = key_.dst.to_netaddr(0);
    int protocol = key_.dst.version == 4 ? static_cast<int>(IPPROTO_ICMP) : static_cast<int>(IPPROTO_ICMPV6);
    // Unprivileged ping socket first (net.ipv4.ping_group_range), raw socket as root otherwise
    int ret = srv_connect(SOCK_DGRAM, protocol, &remote, SRV_CONNECT_RAW, id_, &upstream_);
    if (ret == -EACCES || ret == -EPERM || ret == -EPROTONOSUPPORT) {
        ret = srv_connect(SOCK_RAW, protocol, &remote, SRV_CONNECT_RAW, id_, &upstream_);
        raw_ = ret == 0;
    }
    if (ret != 0) {
        LOG_INFO("%s cannot open ICMP socket: %s (allow ping sockets with sysctl net.ipv4.ping_group_range or "
                 "run as root)",
                 name_.c_str(), strerror(-ret));
        finish(false, nullptr);
        return false;
    }
    has_upstream_ = true;
    LOG_DEBUG("%s new (%s socket)", name_.c_str(), raw_ ? "raw" : "ping");
    return true;
}

void IcmpFlow::on_packet(const ParsedPacket& p) {
    if (dead_) {
        return;
    }
    touch();
    ++requests_;
    bytes_up_ += p.payload_len;
    bool v4 = key_.dst.version == 4;
    // ICMP echo request without IP header; the kernel fills in the IPv6 checksum
    scratch_.assign(8 + p.payload_len, '\0');
    uint8_t* icmp = reinterpret_cast<uint8_t*>(&scratch_[0]);
    icmp[0] = v4 ? 8 : 128;
    icmp[1] = 0;
    write_be16(icmp + 4, key_.src_port);
    write_be16(icmp + 6, p.icmp_seq);
    if (p.payload_len > 0) {
        std::memcpy(icmp + 8, p.payload, p.payload_len);
    }
    if (v4) {
        write_be16(icmp + 2, checksum_finish(checksum_add(0, icmp, scratch_.size())));
    }
    LOG_DEBUG("%s echo request seq=%u", name_.c_str(), p.icmp_seq);
    srv_send(&upstream_, scratch_.data(), static_cast<int>(scratch_.size()));
}

void IcmpFlow::on_upstream_open(int error) {
    if (error != 0) {
        has_upstream_ = false;
        finish(false, nullptr);
    }
}

void IcmpFlow::on_upstream_data(const char* data, int len) {
    if (dead_ || data == nullptr) {
        return;
    }
    const uint8_t* icmp = reinterpret_cast<const uint8_t*>(data);
    size_t n = static_cast<size_t>(len);
    bool v4 = key_.dst.version == 4;
    if (raw_ && v4) {
        // IPv4 raw sockets deliver the IP header too
        if (n < 20) {
            return;
        }
        size_t ihl = static_cast<size_t>(icmp[0] & 0x0f) * 4;
        if (n < ihl) {
            return;
        }
        icmp += ihl;
        n -= ihl;
    }
    if (n < 8) {
        return;
    }
    uint8_t reply_type = v4 ? 0 : 129;
    if (icmp[0] != reply_type) {
        return;
    }
    if (raw_ && read_be16(icmp + 4) != key_.src_port) {
        return; // a raw socket sees the replies of every flow to this host
    }
    uint16_t seq = read_be16(icmp + 6);
    touch();
    ++replies_;
    bytes_down_ += n - 8;
    // Ping sockets rewrite the identifier, restore the phone's one
    uint32_t rest = (static_cast<uint32_t>(key_.src_port) << 16) | seq;
    build_icmp_packet(scratch_, key_.dst, key_.src, reply_type, 0, rest, icmp + 8, n - 8);
    LOG_DEBUG("%s echo reply seq=%u", name_.c_str(), seq);
    session_->send_packet(scratch_);
}

void IcmpFlow::on_upstream_close(int error) {
    has_upstream_ = false;
    if (!dead_) {
        if (error != 0) {
            LOG_INFO("%s socket error: %s", name_.c_str(), strerror(error));
        }
        finish(false, nullptr);
    }
}

void IcmpFlow::on_timer(int64_t now) {
    if (!dead_ && now - last_activity_ms_ > g_vpn_config.icmp_idle_timeout_s * 1000LL) {
        LOG_INFO("%s closed: %llu requests, %llu replies", name_.c_str(), static_cast<unsigned long long>(requests_),
                 static_cast<unsigned long long>(replies_));
        finish(false, nullptr);
    }
}

} // namespace vpn
