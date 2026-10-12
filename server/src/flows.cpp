/**
 * @file flows.cpp
 * @brief Implementation of TcpFlow (user-space TCP endpoint), UdpFlow (UDP
 *        NAT) and IcmpFlow (ping forwarding). See flows.h for the overview
 *        and the reading guide, and docs/en/architecture.md for diagrams.
 *
 * TCP in one paragraph (what the code below relies on): every byte of a TCP
 * stream has a 32 bit sequence number; SYN and FIN also occupy one sequence
 * number each. The receiver acknowledges cumulatively ("I have everything
 * before ACK") and advertises a receive window ("you may send WINDOW more
 * bytes after ACK"). The sender keeps unacknowledged data and resends it
 * after a retransmission timeout (RTO) or after three duplicate ACKs (fast
 * retransmit). Relevant RFCs: 9293 (TCP, replaces 793), 6298 (RTO), 5681
 * (duplicate ACKs / fast retransmit), 7323 (window scale), 5961 (challenge
 * ACK), 1122 (zero window probing).
 */
#include "flows.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>

namespace vpn {

namespace {

// Retransmission timer limits. RFC 6298 suggests 1 s initially and a minimum
// of 1 s; like Linux (200 ms) we allow a smaller minimum because the phone is
// usually only a few tens of milliseconds away and a 1 s floor would make
// every loss very expensive.
constexpr int kInitialRtoMs = 1000;   // RTO before the first RTT sample (RFC 6298 2.1)
constexpr int kMinRtoMs = 300;        // lower bound of the computed RTO
constexpr int kMaxRtoMs = 30000;      // upper bound, also caps the exponential back off
constexpr int kMaxRetries = 10;       // consecutive data timeouts before the connection is aborted
constexpr int kMaxSynAckRetries = 5;  // SYN-ACK retransmissions before giving up the handshake
// Per-flow cap on unacknowledged bytes, even if the phone's window is bigger
constexpr size_t kMaxInFlight = 2 * 1024 * 1024;

/**
 * @brief Format an address and port for log lines.
 * @param ip   IPv4 or IPv6 address.
 * @param port Port number.
 * @return "1.2.3.4:80" or "[2001:db8::1]:80" (IPv6 in brackets, so the port
 *         colon is unambiguous).
 */
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

/**
 * Sets up the sequence numbers and negotiates the TCP options from the
 * phone's SYN. Nothing is sent here: the SYN-ACK is only sent once the real
 * server accepted (on_upstream_open()).
 */
TcpFlow::TcpFlow(Session* session, const FlowKey& key, uint64_t id, const ParsedPacket& syn)
    : Flow(session, key, id) {
    // e.g. "S1 TCP#12 172.19.0.2:40000 -> 1.2.3.4:443"
    name_ = session->tag() + " TCP#" + std::to_string(id) + " " + endpoint(key.src, key.src_port) + " -> " +
            endpoint(key.dst, key.dst_port);

    irs_ = syn.seq;
    rcv_nxt_ = syn.seq + 1; // the SYN itself occupies one sequence number
    // A random ISN (RFC 6528 spirit): makes our segments hard to guess and
    // unlikely to be confused with segments of an earlier connection.
    iss_ = session->random32();
    // Nothing sent yet: all three send pointers start at the ISN
    snd_una_ = iss_;
    snd_nxt_ = iss_;
    snd_max_ = iss_;
    snd_wnd_ = syn.window; // the window of a SYN is never scaled

    // Window scaling (RFC 7323) is only used if BOTH SYNs carry the option,
    // so we may only offer it in our SYN-ACK when the phone offered it.
    if (syn.tcp_options.wscale >= 0) {
        wscale_ok_ = true;
        snd_wscale_ = syn.tcp_options.wscale;
        // Smallest shift that makes our configured window fit into the 16 bit
        // window field (14 is the maximum allowed by RFC 7323)
        while (rcv_wscale_ < 14 && (g_vpn_config.tcp_window >> rcv_wscale_) > 65535) {
            ++rcv_wscale_;
        }
    }

    // MSS = largest payload per segment. Ours follows from the tunnel MTU
    // minus IP + TCP headers (20 + 20 for IPv4, 40 + 20 for IPv6). If the
    // phone sent no MSS option the RFC defaults apply: 536 for IPv4 (RFC
    // 1122), 1220 for IPv6 (minimum IPv6 MTU 1280 - 60). We use the smaller
    // of both, so our segments never need IP fragmentation on the TUN side.
    int header_overhead = key.src.version == 4 ? 40 : 60;
    int our_mss = std::max(536, session->mtu() - header_overhead);
    int peer_mss = syn.tcp_options.mss != 0 ? syn.tcp_options.mss : (key.src.version == 4 ? 536 : 1220);
    mss_ = static_cast<uint16_t>(std::min(our_mss, peer_mss));
}

/**
 * Gives our share of the in-flight budget back to the session (a flow that
 * is deleted without going through abort()/maybe_finish(), e.g. when the
 * session is closed, may still have unacknowledged data).
 */
TcpFlow::~TcpFlow() {
    if (reported_inflight_ > 0) {
        session_->add_inflight(-static_cast<long>(reported_inflight_));
    }
}

/**
 * Keep the session wide count of unacknowledged bytes up to date. Each flow
 * remembers what it last reported and sends only the difference, so the
 * session total always equals the sum of all flows. A dead flow reports 0:
 * its data will never be acknowledged, so it must not block other flows.
 * Releasing budget (a negative delta) lets the session wake flows that are
 * waiting for budget (Session::reap()).
 */
// Keep the session wide count of unacknowledged bytes up to date
void TcpFlow::account_inflight() {
    size_t now = dead_ ? 0 : in_flight();
    if (now != reported_inflight_) {
        session_->add_inflight(static_cast<long>(now) - static_cast<long>(reported_inflight_));
        reported_inflight_ = now;
    }
}

/**
 * Starts the non-blocking connect to the real destination. Flags:
 * SRV_CONNECT_HALF_CLOSE delivers the server's FIN as on_upstream_data(NULL)
 * instead of closing the socket, so we can still send the phone's remaining
 * data (TCP half-close); SRV_CONNECT_RAW delivers every read as-is (no
 * message framing), which is what a byte stream relay wants.
 */
bool TcpFlow::start() {
    NetAddr remote = key_.dst.to_netaddr(key_.dst_port);
    int ret = srv_connect(SOCK_STREAM, 0, &remote, SRV_CONNECT_HALF_CLOSE | SRV_CONNECT_RAW, id_, &upstream_);
    if (ret != 0) {
        LOG_INFO("%s connect failed: %s", name_.c_str(), strerror(-ret));
        // Answer the SYN with RST+ACK (seq 0, ack = SYN + 1), what a host
        // without a listener does: the app sees "connection refused".
        send_segment(kTcpRst | kTcpAck, 0, nullptr, 0);
        finish(false, nullptr);
        return false;
    }
    has_upstream_ = true; // from now on the Flow destructor/finish() must close the socket
    LOG_DEBUG("%s SYN (mss %u, wscale %d), connecting to server", name_.c_str(), mss_,
              wscale_ok_ ? snd_wscale_ : -1);
    return true;
}

/**
 * A retransmitted SYN repeats the phone's ISN; a SYN with a different ISN
 * belongs to a new connection that reuses the same ports (Session then drops
 * this flow and creates a new one).
 */
bool TcpFlow::is_new_connection(const ParsedPacket& syn) const {
    return syn.seq != irs_;
}

/**
 * The receive window we announce to the phone. It is constant: received data
 * is handed to srv_send() immediately, so we never hold a reassembly buffer
 * that could fill up. The real limit is the outbound socket's send queue;
 * when the reactor reports it as blocked we announce 0 so the phone stops
 * sending (back pressure from the internet server to the phone app).
 */
uint16_t TcpFlow::advertised_window() const {
    if (upstream_blocked_) {
        return 0;
    }
    uint32_t window = g_vpn_config.tcp_window >> rcv_wscale_; // the phone multiplies it by 2^rcv_wscale_ again
    return static_cast<uint16_t>(std::min<uint32_t>(window, 65535));
}

/**
 * Every segment we send to the phone goes through here. The packet is built
 * with swapped addresses (source = real server, destination = phone), so to
 * the phone it looks like the server answered directly.
 */
void TcpFlow::send_segment(uint8_t flags, uint32_t seq, const uint8_t* data, size_t len, bool syn_options) {
    uint8_t options[8];
    size_t options_len = 0;
    uint16_t window = advertised_window();
    if (syn_options) {
        // TCP options are kind/length/value; the option area must be a
        // multiple of 4 bytes, hence the NOP padding before window scale.
        // SACK and timestamps are not offered, which keeps the receiver and
        // the RTT logic simple (the phone then does not use them either).
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
    // Segments with the ACK flag (all except a bare RST) acknowledge everything
    // received so far; without the flag the ACK field is meaningless (0)
    uint32_t ack = (flags & kTcpAck) ? rcv_nxt_ : 0;
    build_tcp_packet(scratch_, key_.dst, key_.dst_port, key_.src, key_.src_port, seq, ack, flags, window, options,
                     options_len, data, len);
    session_->send_packet(scratch_);
    if (flags & kTcpAck) {
        // Remember whether the phone currently believes our window is closed;
        // on_upstream_write_blocked() sends a window update when it reopens.
        zero_window_sent_ = window == 0;
    }
}

/**
 * Pure ACK. It carries no data, so its sequence number is just "the next one
 * after everything we sent": snd_max_ (not snd_nxt_, which may be rewound
 * during a retransmission and would then look like an old segment).
 */
void TcpFlow::send_ack() {
    send_segment(kTcpAck, snd_max_, nullptr, 0);
}

/** SYN-ACK: sequence number iss_, with the MSS / window scale options. */
void TcpFlow::send_syn_ack() {
    send_segment(kTcpSyn | kTcpAck, iss_, nullptr, 0, true);
}

/**
 * One timer per flow is enough (RFC 6298 section 5): it is armed when data
 * is outstanding and restarted when an ACK makes progress. While the phone's
 * window is zero the same timer serves as the persist timer. It is checked
 * by on_timer(), so its resolution is the reactor timer interval.
 */
void TcpFlow::arm_rto() {
    rto_deadline_ = now_ms() + rto_ms_;
}

/**
 * RTT estimator of RFC 6298 section 2 (Jacobson/Karels):
 *   first sample R:  SRTT = R, RTTVAR = R / 2
 *   later samples:   RTTVAR = 3/4 RTTVAR + 1/4 |SRTT - R|
 *                    SRTT   = 7/8 SRTT   + 1/8 R
 *   RTO = SRTT + max(G, 4 * RTTVAR), G = clock granularity (10 ms here),
 * then clamped to [kMinRtoMs, kMaxRtoMs]. RTTVAR is updated before SRTT
 * because it must use the old SRTT. Setting rto_ms_ also removes any
 * exponential back off applied by on_timer().
 */
void TcpFlow::update_rtt(int64_t sample) {
    if (sample < 1) {
        sample = 1; // a 0 ms sample (same timer tick) would make SRTT look like "no sample yet"
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

/**
 * Hard close of both connections. Used for errors, idle timeouts, Inspector
 * blocks and resets from either side. finish(true) aborts the outbound
 * socket, which makes the server's kernel send a RST to the real server too.
 */
void TcpFlow::abort(const char* reason, bool reset_phone) {
    if (dead_) {
        return;
    }
    if (reason != nullptr) {
        LOG_INFO("%s aborted: %s (up %llu bytes, down %llu bytes)", name_.c_str(), reason,
                 static_cast<unsigned long long>(bytes_up_), static_cast<unsigned long long>(bytes_down_));
    }
    // In Connecting the phone has not heard from us yet, so there is nothing
    // to reset; if it retransmits its SYN, Session simply starts a new flow.
    // The RST carries the next sequence number the phone expects from us
    // (after everything sent), so the phone accepts it.
    if (reset_phone && state_ != State::Connecting) {
        send_segment(kTcpRst | kTcpAck, state_ == State::Established ? snd_max_ : snd_nxt_, nullptr, 0);
    }
    finish(true, nullptr);
    account_inflight(); // dead now: releases our whole in-flight share
}

/**
 * Result of the outbound connect. Only now do we complete the handshake with
 * the phone, so the phone's connect() succeeds exactly when the real one did.
 */
void TcpFlow::on_upstream_open(int error) {
    if (dead_) {
        return;
    }
    if (error != 0) {
        has_upstream_ = false; // a failed connect is not followed by a close event
        LOG_INFO("%s connect to server failed: %s", name_.c_str(), strerror(error));
        // Refused, unreachable or timed out: refuse the phone's SYN (RST+ACK)
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
    snd_nxt_ = iss_ + 1; // our SYN occupies one sequence number
    snd_max_ = snd_nxt_;
    send_syn_ack();
    arm_rto(); // the SYN-ACK is retransmitted from on_timer() until the phone ACKs it
}

/**
 * Entry point for every segment from the phone. Order follows RFC 9293
 * "SEGMENT ARRIVES": RST first, then SYN, then the ACK field, then the data
 * and FIN, then we send what became possible and check for the end.
 */
void TcpFlow::on_packet(const ParsedPacket& p) {
    if (dead_) {
        return;
    }
    touch(); // any segment from the phone counts as activity for the idle timeout
    uint8_t flags = p.tcp_flags;

    if (flags & kTcpRst) {
        // The phone gave up the connection. Never answer a RST with a RST.
        // (No RFC 5961 sequence check: the tunnel is authenticated, so blind
        // RST injection by third parties is not a concern here.)
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
            // Unexpected SYN on a synchronized connection (RFC 5961 section
            // 4): do not reset, just tell the phone where we are. If the
            // phone really lost its state it answers with a RST.
            send_ack(); // challenge ACK
        }
        return;
    }
    if (!(flags & kTcpAck)) {
        return; // after the SYN every valid segment has ACK set (RFC 9293): drop
    }

    // Each step can kill the flow (e.g. an Inspector block), so check dead_
    process_ack(p);
    if (dead_) {
        return;
    }
    process_data(p);
    if (dead_) {
        return;
    }
    transmit(); // the ACK may have freed window / budget for more data
    maybe_finish();
}

/**
 * Sender side of the phone's segment: what did the phone acknowledge, and
 * how big is its window now?
 */
void TcpFlow::process_ack(const ParsedPacket& p) {
    uint32_t ack = p.ack;
    if (state_ == State::SynAckSent) {
        if (ack != iss_ + 1) {
            // Not an ACK of our SYN-ACK
            // RFC 9293: answer an unacceptable ACK in SYN-RECEIVED with a RST
            // whose sequence number is the segment's ACK value.
            send_segment(kTcpRst, ack, nullptr, 0);
            return;
        }
        // Handshake complete. The SYN-ACK is not used as an RTT sample
        // (it may have been retransmitted, see Karn's algorithm below).
        state_ = State::Established;
        snd_una_ = iss_ + 1;
        retries_ = 0;
        rto_deadline_ = 0;
        rto_ms_ = kInitialRtoMs;
        LOG_DEBUG("%s established", name_.c_str());
    }

    // The window field is in units of 2^snd_wscale_ bytes (RFC 7323)
    uint32_t window = static_cast<uint32_t>(p.window) << (wscale_ok_ ? snd_wscale_ : 0);
    if (seq_gt(ack, snd_una_) && seq_le(ack, snd_max_)) {
        // New data acknowledged (snd_una_ < ack <= snd_max_). Accepting up to
        // snd_max_ (not just snd_nxt_) matters after a go-back-N rewind: the
        // original transmissions may still arrive and be acknowledged.
        uint32_t acked = ack - snd_una_;
        size_t data_acked = std::min<size_t>(acked, send_buf_.size());
        if (acked > send_buf_.size()) {
            // Everything beyond the data is the FIN (ack <= snd_max_ proves we sent it)
            fin_acked_ = true;
            fin_sent_ = true; // may have been cleared by a rewind in on_timer()
        }
        send_buf_.erase(0, data_acked); // send_buf_ always starts at snd_una_
        snd_una_ = ack;
        if (seq_lt(snd_nxt_, snd_una_)) {
            snd_nxt_ = snd_una_; // data sent before a rewind arrived after all
        }
        dupacks_ = 0;
        retries_ = 0; // progress: the connection is alive
        // Karn's algorithm: only segments sent exactly once are timed
        // (rtt_timing_ is cleared on every retransmission), otherwise we
        // could not tell which transmission the ACK belongs to.
        if (rtt_timing_ && seq_le(rtt_seq_, ack)) {
            update_rtt(now_ms() - rtt_start_ms_);
            rtt_timing_ = false;
        } else if (srtt_ms_ == 0) {
            rto_ms_ = kInitialRtoMs; // no sample yet: undo any back off
        } else {
            update_rtt(srtt_ms_); // recompute the RTO without the back off
        }
        // RFC 6298 5.2 / 5.3: stop the timer when everything is acknowledged,
        // otherwise restart it for the remaining data
        rto_deadline_ = 0;
        if (in_flight() > 0) {
            arm_rto();
        }
        // Resume reading from the server once half of the buffer limit has
        // drained (hysteresis, so we do not toggle pause/resume constantly)
        if (upstream_paused_ && send_buf_.size() < g_vpn_config.tcp_flow_buffer / 2) {
            srv_pause_read(&upstream_, 0);
            upstream_paused_ = false;
        }
        account_inflight();
    } else if (ack == snd_una_ && p.payload_len == 0 && !(p.tcp_flags & kTcpFin) && in_flight() > 0 &&
               window == snd_wnd_) {
        // A duplicate ACK as defined by RFC 5681: no new ACK, no data, no
        // window change, while data is outstanding. The phone sends one for
        // every segment that arrives after a hole, so three in a row mean a
        // segment was most likely lost (not just reordered).
        if (++dupacks_ == 3) {
            // Fast retransmit of the first unacknowledged segment
            // (no fast recovery / cwnd reduction: there is no congestion
            // window here, see the TcpFlow class comment)
            size_t len = std::min<size_t>(mss_, send_buf_.size());
            if (len > 0) {
                send_segment(kTcpAck | kTcpPsh, snd_una_, reinterpret_cast<const uint8_t*>(send_buf_.data()), len);
            } else if (upstream_eof_ && !fin_acked_) {
                send_segment(kTcpFin | kTcpAck, snd_una_, nullptr, 0); // only the FIN is missing
            }
            rtt_timing_ = false; // Karn: a retransmission invalidates the running sample
            ++retransmits_;
        }
    } else if (seq_gt(ack, snd_max_)) {
        send_ack(); // acknowledges data we never sent
        return;     // RFC 9293: drop the segment (and ignore its window)
    }
    // Otherwise (an old ACK or a pure window update) only the window is taken.
    // Simplification: no SND.WL1/WL2 check against reordered old window
    // updates; the tunnel delivers packets in order, so this is rare.
    snd_wnd_ = window;
}

/**
 * Phone -> server bytes. The Inspector may log, rewrite (also change the
 * length; the two TCP connections have independent sequence numbers) or
 * block the data. srv_send() queues it on the outbound socket; if that queue
 * grows too large the reactor reports write_blocked and we close the window.
 */
void TcpFlow::deliver_upstream(const uint8_t* data, size_t len) {
    std::string chunk(reinterpret_cast<const char*>(data), len); // modifiable copy for the Inspector
    if (g_inspector.inspect_tcp(name_, key_.dst_port, true, inspect_, chunk) == Inspector::kBlock) {
        abort("blocked by rule", true);
        return;
    }
    if (!chunk.empty()) {
        srv_send(&upstream_, chunk.data(), static_cast<int>(chunk.size()));
    }
}

/**
 * Receiver side: accept the phone's payload and FIN strictly in order.
 * There is no out-of-order queue: a segment beyond rcv_nxt_ is dropped and
 * the duplicate ACK makes the phone retransmit. That is acceptable because
 * the tunnel is a TCP connection itself, so packets arrive in order and are
 * lost only rarely (e.g. a full queue on the phone side). Every accepted
 * segment is acknowledged immediately (no delayed ACKs, for simplicity).
 */
void TcpFlow::process_data(const ParsedPacket& p) {
    bool fin = (p.tcp_flags & kTcpFin) != 0;
    const uint8_t* data = p.payload;
    size_t len = p.payload_len;
    uint32_t seq = p.seq;
    if ((len == 0 && !fin) || state_ != State::Established) {
        return; // a pure ACK: nothing to receive (and no ACK for an ACK)
    }
    if (phone_fin_) {
        send_ack(); // retransmission after the FIN
        return;
    }

    if (seq_lt(seq, rcv_nxt_)) {
        // The segment starts before rcv_nxt_: part (or all) of it was
        // received already (e.g. our ACK got lost and the phone resent it)
        uint32_t overlap = rcv_nxt_ - seq;
        if (overlap > len || (overlap == len && !fin)) {
            send_ack(); // complete duplicate
            return;
        }
        // Partial overlap: cut off the old bytes, keep the new tail
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
            // The server socket is gone, the bytes cannot be delivered. A
            // real TCP stack answers data for a closed socket with a RST too.
            abort("data from client after the server closed", true);
            return;
        }
        // Note: data is accepted even if it exceeds the window we advertised
        // (e.g. it was in flight when the window closed); srv_send() queues it.
        bytes_up_ += len;
        rcv_nxt_ += static_cast<uint32_t>(len);
        deliver_upstream(data, len);
        if (dead_) {
            return;
        }
    }
    if (fin) {
        // The phone finished sending (half-close). Pass that on with
        // shutdown(SHUT_WR) after the queued data; the server can keep
        // sending to the phone until it closes its side too.
        rcv_nxt_ += 1; // the FIN occupies one sequence number
        phone_fin_ = true;
        LOG_DEBUG("%s FIN from client", name_.c_str());
        if (!upstream_closed_) {
            srv_shutdown_write(&upstream_);
        }
    }
    send_ack();
}

/**
 * The sender. Cuts the unsent part of send_buf_ into segments of at most
 * mss_ bytes and sends them while all of these allow it:
 *   - the phone's receive window (flow control), capped at kMaxInFlight,
 *   - the session wide in-flight budget (fairness between flows and bounded
 *     latency: a bulk download must not fill the tunnel for everybody),
 *   - the tunnel itself (Session::tunnel_blocked(), back pressure of the
 *     tunnel's TCP connection).
 * When everything is sent and the server closed its side, the FIN follows.
 * Blocked flows are resumed by on_tunnel_writable() (tunnel drained or
 * budget released) or by the next ACK from the phone.
 *
 * Positions: send_buf_[0] has sequence number snd_una_, so the offset of
 * snd_nxt_ in the buffer is snd_nxt_ - snd_una_ ("sent" below). Bytes before
 * snd_max_ that are sent again (after a rewind) are retransmissions.
 */
void TcpFlow::transmit(bool force_one) {
    if (dead_ || state_ != State::Established) {
        return;
    }
    if (session_->tunnel_blocked() && !force_one) {
        return; // the tunnel is congested; on_tunnel_writable() calls us again
    }
    bool sent_any = false;
    while (!fin_sent_) {
        size_t sent = snd_nxt_ - snd_una_; // position in send_buf_
        size_t unsent = send_buf_.size() > sent ? send_buf_.size() - sent : 0;
        if (unsent == 0) {
            if (upstream_eof_) {
                // All data is out and the server closed: send our FIN, which
                // needs no window space (it carries no data)
                send_segment(kTcpFin | kTcpAck, snd_nxt_, nullptr, 0);
                snd_nxt_ += 1; // the FIN occupies one sequence number
                fin_sent_ = true;
                if (seq_gt(snd_nxt_, snd_max_)) {
                    snd_max_ = snd_nxt_;
                }
                if (rto_deadline_ == 0) {
                    arm_rto(); // the FIN is retransmitted like data
                }
                LOG_DEBUG("%s FIN to client", name_.c_str());
            }
            break;
        }
        // Usable window = window - bytes already in flight from snd_una_
        size_t window = std::min<size_t>(snd_wnd_, kMaxInFlight);
        size_t room = window > sent ? window - sent : 0;
        bool new_data = snd_nxt_ == snd_max_; // false while resending after a rewind
        if (new_data && room > 0) {
            // Share the tunnel fairly: limit the unacknowledged bytes of the whole session
            // (Only new data is charged: retransmitted bytes are already
            // counted, because in_flight() is measured up to snd_max_.)
            size_t session_room = session_->inflight_room();
            if (session_room == 0 && !force_one) {
                session_->wait_for_budget(id_); // queue up; Session::reap() wakes us in FIFO order
                break;
            }
            // At least one full segment, so a flow is never stuck on a tiny
            // remainder (the budget may be exceeded by less than one MSS)
            room = std::min(room, std::max<size_t>(session_room, mss_));
        }
        if (room == 0) {
            // The phone's window is full (or zero). Normally we just wait for
            // its next ACK. If that ACK (the window update) gets lost, both
            // sides would wait forever, so the RTO timer doubles as the
            // persist timer and on_timer() then sends a probe.
            if (!force_one || sent_any) {
                if (rto_deadline_ == 0) {
                    arm_rto(); // persist timer: probe the zero window later
                }
                break;
            }
            // Forced by the timer: send one byte beyond the window. The phone
            // either accepts it or answers with an ACK carrying its current
            // window (RFC 1122 4.2.2.17).
            room = 1; // zero window probe
        }
        size_t len = std::min(std::min(unsent, room), static_cast<size_t>(mss_));
        // PSH on the segment that empties the buffer ("deliver to the app now")
        uint8_t flags = kTcpAck | (len == unsent ? kTcpPsh : 0);
        send_segment(flags, snd_nxt_, reinterpret_cast<const uint8_t*>(send_buf_.data()) + sent, len);
        // Time one segment per round trip (no TCP timestamps here). Only new
        // data that is sent for the first time, never retransmissions or
        // probes (Karn's algorithm).
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
        account_inflight(); // keep the session budget exact for the next iteration / other flows
        sent_any = true;
        if (rto_deadline_ == 0) {
            arm_rto(); // RFC 6298 5.1: start the timer if it is not running
        }
        // A forced send is exactly one segment; and stop as soon as the
        // tunnel became congested by what we just queued
        if (force_one || session_->tunnel_blocked()) {
            break;
        }
    }
    account_inflight();
}

/**
 * Graceful end: both directions are finished when the phone sent its FIN
 * (phone_fin_) and acknowledged ours (fin_acked_). There is no TIME-WAIT
 * state: the flow disappears at once. A late retransmission from the phone
 * would get a RST from Session::handle_tcp(), which is harmless now.
 */
void TcpFlow::maybe_finish() {
    if (dead_ || !phone_fin_ || !fin_acked_) {
        return;
    }
    LOG_INFO("%s closed (up %llu bytes, down %llu bytes, %lld ms, %llu retransmits%s%s)", name_.c_str(),
             static_cast<unsigned long long>(bytes_up_), static_cast<unsigned long long>(bytes_down_),
             static_cast<long long>(now_ms() - created_ms_), static_cast<unsigned long long>(retransmits_),
             inspect_.protocol.empty() ? "" : (", " + inspect_.protocol).c_str(),
             inspect_.host.empty() ? "" : (" " + inspect_.host).c_str());
    finish(false, nullptr); // srv_close(): orderly close of the outbound socket
    account_inflight();
}

/**
 * Server -> phone bytes. They are appended to send_buf_ and kept there until
 * the phone acknowledges them (they may have to be retransmitted). If the
 * buffer grows beyond vpn_tcp_flow_buffer (the phone reads slower than the
 * server sends), we stop reading the outbound socket; the server's kernel
 * window then fills up and slows the real server down (back pressure).
 */
void TcpFlow::on_upstream_data(const char* data, int len) {
    if (dead_) {
        return;
    }
    touch();
    if (data == nullptr) {
        // EOF = the server sent FIN. Forward it after the buffered data.
        upstream_eof_ = true;
        LOG_DEBUG("%s FIN from server", name_.c_str());
        transmit();
        maybe_finish();
        return;
    }
    std::string chunk(data, static_cast<size_t>(len)); // modifiable copy for the Inspector
    if (g_inspector.inspect_tcp(name_, key_.dst_port, false, inspect_, chunk) == Inspector::kBlock) {
        abort("blocked by rule", true);
        return;
    }
    bytes_down_ += static_cast<uint64_t>(len); // counted as received from the server (before rewriting)
    send_buf_.append(chunk);
    if (!upstream_paused_ && send_buf_.size() > g_vpn_config.tcp_flow_buffer) {
        srv_pause_read(&upstream_, 1);
        upstream_paused_ = true; // resumed in process_ack() once the phone caught up
    }
    transmit();
}

/**
 * The outbound socket is closed for good. An error (e.g. ECONNRESET, the
 * server sent a RST) is passed on as a RST to the phone. A normal close
 * without a separate EOF event is treated as the server's FIN; data still
 * in send_buf_ is delivered to the phone first.
 */
void TcpFlow::on_upstream_close(int error) {
    has_upstream_ = false; // the socket no longer exists: nothing to close later
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

/**
 * Back pressure phone -> server. The reactor calls this when the unsent data
 * queued on the outbound socket crosses its high watermark (blocked) or
 * drains below the low watermark (unblocked). advertised_window() then
 * returns 0 or the normal window; the ACK sent here tells the phone right
 * away instead of waiting for the next segment.
 */
void TcpFlow::on_upstream_write_blocked(bool blocked) {
    upstream_blocked_ = blocked;
    // After the phone's FIN no more data comes, so its window does not matter
    if (dead_ || state_ != State::Established || phone_fin_) {
        return;
    }
    if (blocked || zero_window_sent_) {
        send_ack(); // advertise the zero window / the reopened window right away
    }
}

/**
 * Called by Session when the tunnel drained or in-flight budget was released
 * (Session::reap() wakes flows that called wait_for_budget()).
 */
void TcpFlow::on_tunnel_writable() {
    transmit();
}

/**
 * Called from Session::on_timer() on every reactor timer tick.
 * 1. Idle timeout (shorter once one side has closed, so half-closed
 *    connections whose other side never finishes do not linger for an hour).
 * 2. Retransmission timer: resend the SYN-ACK, or go back N and resend from
 *    snd_una_, or send a zero window probe; with exponential back off.
 */
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
        return; // timer not running or not yet expired
    }
    rto_deadline_ = 0;

    if (state_ == State::SynAckSent) {
        // The phone did not ACK our SYN-ACK: resend it with back off
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

    // A zero window with data waiting: the timer works as persist timer
    bool zero_window = snd_wnd_ == 0;
    if (in_flight() == 0 && !(zero_window && !send_buf_.empty())) {
        return; // nothing outstanding
    }
    // Probes do not count as retries: a receiver may legitimately keep its
    // window closed for a long time as long as it answers (RFC 1122
    // 4.2.2.17); the idle timeout still bounds a dead peer.
    if (!zero_window && ++retries_ > kMaxRetries) {
        abort("too many retransmissions", true);
        return;
    }
    rto_ms_ = std::min(rto_ms_ * 2, kMaxRtoMs); // exponential back off (RFC 6298 5.5)
    // Go back N: resend from the oldest unacknowledged byte. ACKs for data
    // sent before (up to snd_max_) are still accepted and skip ahead again.
    snd_nxt_ = snd_una_;
    if (fin_sent_ && !fin_acked_) {
        fin_sent_ = false; // the FIN is resent after the data again
    }
    rtt_timing_ = false; // Karn's algorithm
    LOG_DEBUG("%s retransmission timeout (%s), rto %d ms, in flight %zu, window %u, srtt %lld ms, session in flight %zu",
              name_.c_str(), zero_window ? "zero window probe" : "data", rto_ms_, in_flight(), snd_wnd_,
              static_cast<long long>(srtt_ms_), session_->inflight());
    // Only one segment now (RFC 6298 5.4: the earliest unacknowledged one);
    // the phone's ACK for it triggers transmit() for the rest
    transmit(true);
    if (rto_deadline_ == 0) {
        arm_rto(); // keep the timer running even if transmit() sent nothing
    }
}

// ---------------------------------------------------------------------------
// UdpFlow
// ---------------------------------------------------------------------------

/** Only sets the log name; the socket is opened by start(). */
UdpFlow::UdpFlow(Session* session, const FlowKey& key, uint64_t id) : Flow(session, key, id) {
    name_ = session->tag() + " UDP#" + std::to_string(id) + " " + endpoint(key.src, key.src_port) + " -> " +
            endpoint(key.dst, key.dst_port);
}

/**
 * A connected UDP socket: the kernel chooses a local port (our "NAT port"),
 * send() needs no address, and only datagrams from the target are delivered.
 * It also makes the kernel report ICMP errors for this destination as socket
 * errors (see on_upstream_close()). SRV_CONNECT_RAW: one read = one datagram.
 */
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

/** Phone -> target datagram. */
void UdpFlow::on_packet(const ParsedPacket& p) {
    if (dead_) {
        return;
    }
    touch();
    ++packets_up_;
    bytes_up_ += p.payload_len;
    // An ICMP error must quote the offending packet's IP header plus at least
    // the first 8 bytes of its payload (= the UDP header), RFC 792 / 4443.
    last_header_.assign(reinterpret_cast<const char*>(p.ip_header), p.ip_header_len + 8);

    std::string reply;
    if (g_inspector.inspect_udp(name_, key_.dst_port, true, p.payload, p.payload_len, &reply) == Inspector::kBlock) {
        // Blocked (e.g. a DNS query for a blocked domain). The Inspector may
        // provide an answer (NXDOMAIN), which we send back "from the target".
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

/** For UDP "connecting" cannot really fail later; just handle an error. */
void UdpFlow::on_upstream_open(int error) {
    if (error != 0) {
        has_upstream_ = false; // a failed connect is not followed by a close event
        LOG_INFO("%s failed: %s", name_.c_str(), strerror(error));
        finish(false, nullptr);
    }
}

/**
 * Target -> phone datagram: wrap it into an IP/UDP packet with the target as
 * source. Session::send_packet() fragments it if it exceeds the tunnel MTU.
 */
void UdpFlow::on_upstream_data(const char* data, int len) {
    if (dead_ || data == nullptr) {
        return;
    }
    touch();
    ++packets_down_;
    bytes_down_ += static_cast<uint64_t>(len);
    // Unlike TCP there is nothing to retransmit, and queueing would only add
    // latency (bufferbloat), so a congested tunnel simply drops the datagram.
    if (session_->tunnel_blocked()) {
        return; // tunnel congested: drop, the application protocol copes with UDP loss
    }
    // Downstream inspection only logs (no reply, the verdict is ignored)
    g_inspector.inspect_udp(name_, key_.dst_port, false, reinterpret_cast<const uint8_t*>(data),
                            static_cast<size_t>(len), nullptr);
    build_udp_packet(scratch_, key_.dst, key_.dst_port, key_.src, key_.src_port,
                     reinterpret_cast<const uint8_t*>(data), static_cast<size_t>(len));
    session_->send_packet(scratch_);
}

/**
 * The socket reported an error or was closed. On Linux an ICMP error that
 * the target (or a router) sent for our datagram shows up as an errno on the
 * connected socket: port unreachable -> ECONNREFUSED, host / network
 * unreachable -> EHOSTUNREACH / ENETUNREACH. We translate it back into the
 * ICMP message the phone would have received without the VPN, so e.g. a
 * traceroute or a UDP client gets its fast "unreachable" answer.
 */
void UdpFlow::on_upstream_close(int error) {
    has_upstream_ = false;
    if (dead_) {
        return;
    }
    if ((error == ECONNREFUSED || error == EHOSTUNREACH || error == ENETUNREACH) && !last_header_.empty()) {
        // Tell the phone like a router would: ICMP destination unreachable
        // IPv4: type 3, code 3 = port unreachable, code 1 = host unreachable.
        // IPv6: type 1, code 4 = port unreachable, code 0 = no route.
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

/**
 * UDP has no close handshake, so a flow ends after a period without traffic.
 * DNS (port 53) gets a much shorter timeout: one query, one answer, and apps
 * use a new source port per query, so those flows are many and short.
 */
void UdpFlow::on_timer(int64_t now) {
    if (dead_) {
        return;
    }
    int timeout_s = key_.dst_port == 53 ? g_vpn_config.dns_idle_timeout_s : g_vpn_config.udp_idle_timeout_s;
    if (now - last_activity_ms_ > timeout_s * 1000LL) {
        if (key_.dst_port == 53) {
            // Debug level: DNS flows would flood the log at INFO
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

/** Only sets the log name (src_port holds the echo identifier). */
IcmpFlow::IcmpFlow(Session* session, const FlowKey& key, uint64_t id) : Flow(session, key, id) {
    name_ = session->tag() + " ICMP#" + std::to_string(id) + " " + key.src.to_string() + " -> " +
            key.dst.to_string() + " id=" + std::to_string(key.src_port);
}

/**
 * Two ways to send ICMP from user space:
 *   - Ping socket (socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)): no root needed
 *     if the process's group is within net.ipv4.ping_group_range (that sysctl
 *     also covers IPv6). The kernel assigns its own echo identifier (like a
 *     local port), fills in the checksum and only delivers matching replies.
 *   - Raw socket (SOCK_RAW): needs root / CAP_NET_RAW, sends our bytes as
 *     they are and receives every ICMP message for the protocol.
 * connect() fixes the destination, so srv_send() needs no address.
 */
bool IcmpFlow::start() {
    NetAddr remote = key_.dst.to_netaddr(0); // ICMP has no ports
    int protocol = key_.dst.version == 4 ? static_cast<int>(IPPROTO_ICMP) : static_cast<int>(IPPROTO_ICMPV6);
    // Unprivileged ping socket first (net.ipv4.ping_group_range), raw socket as root otherwise
    int ret = srv_connect(SOCK_DGRAM, protocol, &remote, SRV_CONNECT_RAW, id_, &upstream_);
    if (ret == -EACCES || ret == -EPERM || ret == -EPROTONOSUPPORT) {
        // Ping sockets not allowed for our group (or not supported)
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
    LOG_INFO("%s new (%s socket)", name_.c_str(), raw_ ? "raw" : "ping");
    return true;
}

/**
 * Phone -> target echo request. The ICMP message is rebuilt (without the IP
 * header, the kernel adds that):
 *   byte 0 type (8 = IPv4 echo request, 128 = ICMPv6 echo request),
 *   byte 1 code 0, bytes 2..3 checksum, bytes 4..5 identifier,
 *   bytes 6..7 sequence number, then the payload.
 */
void IcmpFlow::on_packet(const ParsedPacket& p) {
    if (dead_) {
        return;
    }
    touch();
    ++requests_;
    bytes_up_ += p.payload_len;
    bool v4 = key_.dst.version == 4;
    // ICMP echo request without IP header; the kernel fills in the IPv6 checksum
    // (the ICMPv6 checksum covers a pseudo header with the source address,
    // which only the kernel knows; the checksum bytes stay 0 here)
    scratch_.assign(8 + p.payload_len, '\0');
    uint8_t* icmp = reinterpret_cast<uint8_t*>(&scratch_[0]);
    icmp[0] = v4 ? 8 : 128;
    icmp[1] = 0;
    write_be16(icmp + 4, key_.src_port); // the phone's identifier (a ping socket replaces it with its own)
    write_be16(icmp + 6, p.icmp_seq);
    if (p.payload_len > 0) {
        std::memcpy(icmp + 8, p.payload, p.payload_len);
    }
    if (v4) {
        // An IPv4 raw socket sends the bytes unchanged, so the checksum must
        // be right (a ping socket recomputes it anyway)
        write_be16(icmp + 2, checksum_finish(checksum_add(0, icmp, scratch_.size())));
    }
    LOG_DEBUG("%s echo request seq=%u", name_.c_str(), p.icmp_seq);
    srv_send(&upstream_, scratch_.data(), static_cast<int>(scratch_.size()));
}

/** Only an error matters (the flow ends; the phone's ping just times out). */
void IcmpFlow::on_upstream_open(int error) {
    if (error != 0) {
        has_upstream_ = false; // a failed connect is not followed by a close event
        finish(false, nullptr);
    }
}

/**
 * An ICMP message from the socket. Filter for our echo replies (a raw socket
 * also sees other ICMP types and the replies of other flows), then rebuild
 * the reply as an IP packet from the target to the phone.
 */
void IcmpFlow::on_upstream_data(const char* data, int len) {
    if (dead_ || data == nullptr) {
        return;
    }
    const uint8_t* icmp = reinterpret_cast<const uint8_t*>(data);
    size_t n = static_cast<size_t>(len);
    bool v4 = key_.dst.version == 4;
    // kernel_demux: does the kernel already deliver only the replies that
    // match our socket's identifier?
#ifdef __APPLE__
    // macOS ICMP datagram sockets behave like raw ones: IP header included,
    // identifier not rewritten, every echo reply from the host delivered
    const bool kernel_demux = false;
#else
    const bool kernel_demux = !raw_; // Linux ping sockets
#endif
    if (v4 && n >= 20 && (icmp[0] >> 4) == 4) {
        // IPv4 raw sockets deliver the IP header too (an ICMP header never starts with 0x4X here)
        // (IPv6 raw sockets never include the IPv6 header.) The header
        // length is IHL (low nibble of the first byte) in 4 byte words.
        size_t ihl = static_cast<size_t>(icmp[0] & 0x0f) * 4;
        if (n < ihl) {
            return;
        }
        icmp += ihl;
        n -= ihl;
    }
    if (n < 8) {
        return; // shorter than an ICMP echo header
    }
    uint8_t reply_type = v4 ? 0 : 129; // echo reply: 0 (ICMP) / 129 (ICMPv6)
    if (icmp[0] != reply_type) {
        return; // other ICMP messages (unreachable, our own requests seen by a raw socket, ...)
    }
    if (!kernel_demux && read_be16(icmp + 4) != key_.src_port) {
        return; // a raw socket sees the replies of every flow to this host
    }
    uint16_t seq = read_be16(icmp + 6);
    touch();
    ++replies_;
    bytes_down_ += n - 8;
    // Ping sockets rewrite the identifier, restore the phone's one
    // header_rest = bytes 4..7 of the ICMP header: identifier << 16 | sequence
    uint32_t rest = (static_cast<uint32_t>(key_.src_port) << 16) | seq;
    build_icmp_packet(scratch_, key_.dst, key_.src, reply_type, 0, rest, icmp + 8, n - 8);
    LOG_DEBUG("%s echo reply seq=%u", name_.c_str(), seq);
    session_->send_packet(scratch_);
}

/** The socket is gone (error or close): finish the flow. */
void IcmpFlow::on_upstream_close(int error) {
    has_upstream_ = false;
    if (!dead_) {
        if (error != 0) {
            LOG_INFO("%s socket error: %s", name_.c_str(), strerror(error));
        }
        finish(false, nullptr);
    }
}

/** A ping flow ends after icmp_idle_timeout without requests or replies. */
void IcmpFlow::on_timer(int64_t now) {
    if (!dead_ && now - last_activity_ms_ > g_vpn_config.icmp_idle_timeout_s * 1000LL) {
        LOG_INFO("%s closed: %llu requests, %llu replies", name_.c_str(), static_cast<unsigned long long>(requests_),
                 static_cast<unsigned long long>(replies_));
        finish(false, nullptr);
    }
}

} // namespace vpn
