/**
 * @file flows.h
 * @brief TCP, UDP and ICMP flows of a VPN session: the part of the server that
 *        turns raw IP packets from the phone into ordinary sockets towards the
 *        internet and back.
 *
 * Overview
 * --------
 * The phone sends every IP packet through the tunnel (one TCP connection, see
 * common/tunnel_protocol.h). Session (vpn_session.h) parses the packets and
 * sorts them into "flows" by their 5-tuple (FlowKey). Each flow object owns
 * one outbound socket on the server (the "upstream", created with
 * srv_connect() of the reactor engine) and translates between the two worlds:
 *
 *   - TcpFlow implements a small user-space TCP endpoint. Towards the phone it
 *     impersonates the real server: it answers the SYN, acknowledges data,
 *     retransmits, does flow control. Towards the internet it uses an
 *     ordinary TCP socket, so the kernel of the server does the "real" TCP.
 *     Because the connection is terminated in the middle (a "split TCP" or
 *     transparent proxy design), the application byte stream is visible (and
 *     modifiable) in between, see Inspector. The two TCP connections have
 *     independent sequence numbers, windows and retransmissions.
 *   - UdpFlow is a simple NAT: every UDP 4-tuple of the phone gets its own
 *     connected UDP socket on the server; datagrams are copied in both
 *     directions, socket errors are turned back into ICMP errors.
 *   - IcmpFlow forwards ICMP echo (ping) through an unprivileged Linux "ping
 *     socket", or a raw socket when running as root.
 *
 * Data path (see docs/en/architecture.md for diagrams):
 *   phone -> tunnel -> Session::handle_packet -> Flow::on_packet -> srv_send
 *   to the upstream socket; and upstream data -> Flow::on_upstream_data ->
 *   build an IP packet -> Session::send_packet -> tunnel -> phone.
 *
 * All flows of a session live on one reactor worker thread, so nothing here
 * needs locking. Flows are never deleted directly: they call finish(), which
 * marks them dead, and Session::reap() deletes them later, when no callback
 * of the flow is on the stack any more.
 *
 * Reading guide: start with the TcpFlow member variables (the classic TCP
 * sequence variables of RFC 9293 / RFC 793), then in flows.cpp follow one
 * connection: constructor -> start() -> on_upstream_open() (SYN-ACK) ->
 * on_packet() -> process_ack() / process_data() -> transmit(), then the
 * close path (maybe_finish(), abort()) and the timer (on_timer()). UdpFlow
 * and IcmpFlow are much shorter and can be read independently.
 */
#ifndef SIMPLEVPN_FLOWS_H
#define SIMPLEVPN_FLOWS_H

#include <string>

#include "vpn_session.h"

namespace vpn {

/**
 * @brief One TCP connection of the phone, terminated in user space.
 *
 * Lifecycle: Session::handle_tcp() creates the flow for a SYN and calls
 * start(), which opens the outbound connection. Only when the real server
 * has accepted (on_upstream_open()) do we answer the phone with a SYN-ACK.
 * That way the phone sees the true outcome: a refused connection becomes a
 * RST, an unreachable server simply never answers (the phone's own SYN
 * timeout applies), exactly as without the VPN.
 *
 * After the handshake data is relayed in both directions:
 *   - phone -> server: process_data() accepts in-order segments, passes them
 *     to the Inspector and srv_send()s them to the upstream socket. The
 *     window we advertise to the phone closes when the upstream socket's
 *     send queue is full (back pressure, on_upstream_write_blocked()).
 *   - server -> phone: on_upstream_data() appends to send_buf_ and
 *     transmit() cuts it into MSS sized segments, limited by the phone's
 *     receive window, a per-flow cap and the session wide in-flight budget.
 *     Unacknowledged data stays in send_buf_ until process_ack() removes it;
 *     on_timer() retransmits on a timeout (RTO, RFC 6298).
 *
 * There is deliberately no congestion control (no cwnd, slow start, ...):
 * the path to the phone is the tunnel, which is itself a TCP connection with
 * its own congestion control. Its back pressure reaches us as
 * Session::tunnel_blocked(), and the session in-flight budget keeps the
 * amount of queued data (and therefore latency) bounded.
 */
class TcpFlow : public Flow {
public:
    /**
     * @brief Create the flow from the phone's SYN (nothing is sent yet).
     *
     * Records the phone's initial sequence number, chooses our own random
     * one, and negotiates the TCP options (window scale, MSS) from the SYN.
     * @param session Session (tunnel) the flow belongs to.
     * @param key     5-tuple; src = phone side, dst = internet side.
     * @param id      Unique flow id, also the user_tag of the upstream socket.
     * @param syn     The parsed SYN packet from the phone.
     */
    TcpFlow(Session* session, const FlowKey& key, uint64_t id, const ParsedPacket& syn);

    /**
     * @brief Open the outbound connection to the real server (non-blocking).
     *
     * The result arrives later in on_upstream_open().
     * @return true if the connect was started; false if that failed
     *         immediately (a RST was sent to the phone and the flow is dead).
     */
    bool start();

    /**
     * @brief Does this SYN start a different connection on the same 4-tuple?
     *
     * A retransmitted SYN carries the same initial sequence number as the
     * original one; a different ISN means the phone reuses the ports for a
     * new connection, so Session replaces this flow.
     * @param syn A SYN (without ACK) from the phone for this flow's key.
     * @return true if syn.seq differs from the ISN this flow was created with.
     */
    bool is_new_connection(const ParsedPacket& syn) const;

    /**
     * @brief A TCP segment from the phone that belongs to this flow.
     *
     * Handles RST and SYN, then ACK processing, data processing, sending
     * whatever the ACK made possible and the close check.
     * @param packet Parsed segment (already checked to match this flow's key).
     */
    void on_packet(const ParsedPacket& packet) override;
    /**
     * @brief Result of the outbound connect().
     * @param error 0 = connected (we now send the SYN-ACK), otherwise an
     *              errno value (we send a RST to the phone).
     */
    void on_upstream_open(int error) override;
    /**
     * @brief Bytes from the real server (or EOF), to be sent to the phone.
     * @param data Received bytes, or nullptr for EOF (the server's FIN; the
     *             socket was opened with SRV_CONNECT_HALF_CLOSE).
     * @param len  Number of bytes in data.
     */
    void on_upstream_data(const char* data, int len) override;
    /**
     * @brief The outbound socket is gone.
     * @param error 0 = orderly close, otherwise an errno value (e.g.
     *              ECONNRESET), which is passed on to the phone as a RST.
     */
    void on_upstream_close(int error) override;
    /**
     * @brief Flow control of the outbound socket's send queue.
     * @param blocked true: the queue crossed the high watermark, advertise a
     *                zero window to the phone; false: it drained, reopen.
     */
    void on_upstream_write_blocked(bool blocked) override;
    /**
     * @brief The tunnel (or the session in-flight budget) has room again:
     *        continue sending buffered data to the phone.
     */
    void on_tunnel_writable() override;
    /**
     * @brief Periodic timer: idle timeouts, SYN-ACK retransmission, RTO
     *        retransmission and zero window probes.
     * @param now_ms Current time in milliseconds (now_ms()).
     */
    void on_timer(int64_t now_ms) override;

private:
    // Our side of the TCP state machine. Much smaller than the full RFC 9293
    // state diagram: the closing states are expressed by the phone_fin_ /
    // fin_sent_ / fin_acked_ flags below instead.
    //   Connecting:  SYN received, waiting for the real server to accept (no SYN-ACK sent yet)
    //   SynAckSent:  SYN-ACK sent to the phone, waiting for its ACK (like SYN-RECEIVED)
    //   Established: handshake complete, data flows (also while half closed)
    enum class State { Connecting, SynAckSent, Established };

    /**
     * @brief Build one TCP/IP packet towards the phone and send it through
     *        the tunnel. Source address/port are the real server's, so the
     *        phone believes it talks to the server directly.
     * @param flags       TCP flags (kTcpSyn, kTcpAck, ...).
     * @param seq         Sequence number of the segment.
     * @param data        Payload, or nullptr.
     * @param len         Payload length.
     * @param syn_options true for the SYN-ACK: add the MSS / window scale
     *                    options and use the unscaled window field.
     */
    void send_segment(uint8_t flags, uint32_t seq, const uint8_t* data, size_t len, bool syn_options = false);
    /** @brief Send a pure ACK (no data) with the current rcv_nxt_ and window. */
    void send_ack();
    /** @brief Send (or resend) our SYN-ACK, which carries iss_ and the options. */
    void send_syn_ack();
    /**
     * @brief Kill the connection: optionally RST the phone, abort (RST) the
     *        server socket and mark the flow dead.
     * @param reason      Logged if not nullptr.
     * @param reset_phone true to send a RST to the phone as well.
     */
    void abort(const char* reason, bool reset_phone);
    /**
     * @brief Send as much of send_buf_ (and finally the FIN) to the phone as
     *        the windows, the session budget and the tunnel allow.
     * @param force_one true from the retransmission timer: send exactly one
     *                  segment even if the tunnel is congested or the window
     *                  is zero (then it is a 1 byte zero window probe).
     */
    void transmit(bool force_one = false);
    /**
     * @brief Process the ACK field and window of a segment from the phone:
     *        complete the handshake, release acknowledged data, take RTT
     *        samples, detect duplicate ACKs (fast retransmit).
     * @param p Segment from the phone (has the ACK flag).
     */
    void process_ack(const ParsedPacket& p);
    /**
     * @brief Process the payload and FIN of a segment from the phone: accept
     *        in-order data, forward it upstream, acknowledge it.
     * @param p Segment from the phone.
     */
    void process_data(const ParsedPacket& p);
    /**
     * @brief Pass phone -> server bytes through the Inspector and queue them
     *        on the outbound socket.
     * @param data Payload bytes (in order, not yet delivered).
     * @param len  Number of bytes.
     */
    void deliver_upstream(const uint8_t* data, size_t len);
    /**
     * @brief Finish the flow gracefully once both directions are closed
     *        (phone's FIN received and our FIN acknowledged).
     */
    void maybe_finish();
    /** @brief (Re)start the retransmission timer: deadline = now + rto_ms_. */
    void arm_rto();
    /**
     * @brief Feed one round trip time measurement into the RFC 6298
     *        estimator and recompute rto_ms_.
     * @param sample_ms Measured RTT in milliseconds.
     */
    void update_rtt(int64_t sample_ms);
    /**
     * @brief Value for the 16 bit window field of segments to the phone.
     * @return The receive window scaled down by rcv_wscale_, or 0 while the
     *         outbound socket is write blocked (back pressure).
     */
    uint16_t advertised_window() const;
    /**
     * @brief Report changes of this flow's unacknowledged byte count to the
     *        session wide in-flight budget (Session::add_inflight()).
     */
    void account_inflight();
    /**
     * @brief Bytes sent to the phone and not yet acknowledged.
     * @return snd_max_ - snd_una_ (uses snd_max_, not snd_nxt_, so data
     *         sent before a go-back-N rewind still counts).
     */
    size_t in_flight() const { return snd_max_ - snd_una_; }

    State state_ = State::Connecting; // where we are in the handshake
    // Sequence space phone -> us. All sequence numbers are 32 bit and wrap
    // around, so they are compared with seq_lt() / seq_gt() (packet.h).
    uint32_t irs_ = 0;      // phone's initial sequence number
    uint32_t rcv_nxt_ = 0;  // next byte expected from the phone
    // Sequence space us -> phone (RFC 9293 names SND.UNA, SND.NXT, SND.WND;
    // snd_max_ is the classic BSD extension). Invariant (in sequence space):
    // snd_una_ <= snd_nxt_ <= snd_max_.
    uint32_t iss_ = 0;      // our initial sequence number
    uint32_t snd_una_ = 0;  // oldest unacknowledged byte
    uint32_t snd_nxt_ = 0;  // next byte to send (rewound to snd_una_ on a timeout)
    uint32_t snd_max_ = 0;  // highest sequence number sent so far + 1
    uint32_t snd_wnd_ = 0;  // phone's receive window (bytes, scaled)
    int snd_wscale_ = 0;    // phone's window scale
    int rcv_wscale_ = 0;    // our window scale
    bool wscale_ok_ = false; // window scaling in use (only if the phone's SYN offered it, RFC 7323)
    uint16_t mss_ = 536;    // segment size towards the phone
    std::string send_buf_;  // bytes from the server not yet acknowledged by the phone, starting at snd_una_

    // Connection close / flow control flags
    bool phone_fin_ = false;        // FIN received from the phone (and forwarded as shutdown)
    bool upstream_eof_ = false;     // server sent FIN, we must send FIN to the phone
    bool fin_sent_ = false;         // our FIN is out (cleared again on a timeout rewind if not yet acked)
    bool fin_acked_ = false;        // the phone acknowledged our FIN: server -> phone direction done
    bool upstream_open_ = false;    // the outbound connect() succeeded
    bool upstream_closed_ = false;  // the outbound socket is gone; data from the phone can no longer be delivered
    bool upstream_blocked_ = false; // server socket send buffer full -> zero window to the phone
    bool upstream_paused_ = false;  // we paused reading from the server
    bool zero_window_sent_ = false; // the last ACK we sent advertised window 0 (a window update is due when it reopens)

    // retransmission
    int64_t rto_deadline_ = 0;  // when the retransmission timer fires (ms), 0 = timer not running
    int rto_ms_ = 1000;         // current retransmission timeout (doubled on every timeout = back off)
    int retries_ = 0;           // consecutive timeouts without progress; the flow is aborted after too many
    int dupacks_ = 0;           // consecutive duplicate ACKs (3 trigger a fast retransmit)
    int64_t srtt_ms_ = 0;       // smoothed round trip time (RFC 6298 SRTT), 0 = no sample yet
    int64_t rttvar_ms_ = 0;     // round trip time variation (RFC 6298 RTTVAR)
    bool rtt_timing_ = false;   // a segment is currently being timed for an RTT sample
    uint32_t rtt_seq_ = 0;      // the sample completes when the phone acknowledges this sequence number
    int64_t rtt_start_ms_ = 0;  // when the timed segment was sent
    uint64_t retransmits_ = 0;  // statistics: segments sent again (logged when the flow closes)
    size_t reported_inflight_ = 0; // our share of the session's in-flight bytes
    std::string scratch_;   // packet building buffer

public:
    /** @brief Returns this flow's share of the session in-flight budget. */
    ~TcpFlow() override;
};

/**
 * @brief One UDP "conversation" (phone address/port <-> target address/port),
 *        relayed like a NAT router would.
 *
 * Each flow owns a connected UDP socket on the server, so the kernel picks a
 * local port for it and only delivers datagrams that come from the target
 * (endpoint dependent filtering, like a port restricted NAT). UDP has no
 * connection state, so the flow simply ends after an idle timeout.
 */
class UdpFlow : public Flow {
public:
    /**
     * @brief Create the flow (no socket yet, see start()).
     * @param session Session the flow belongs to.
     * @param key     src = phone address/port, dst = target address/port.
     * @param id      Unique flow id (user_tag of the upstream socket).
     */
    UdpFlow(Session* session, const FlowKey& key, uint64_t id);
    /**
     * @brief Open the connected UDP socket towards the target.
     * @return true on success; false if the socket could not be created
     *         (the flow is then dead and the first datagram is dropped).
     */
    bool start();
    /**
     * @brief A datagram from the phone: inspect it and send its payload to
     *        the target (or answer it directly if the Inspector blocks it).
     * @param packet Parsed UDP packet from the phone.
     */
    void on_packet(const ParsedPacket& packet) override;
    /**
     * @brief Result of srv_connect(); only an error matters for UDP.
     * @param error 0 or an errno value.
     */
    void on_upstream_open(int error) override;
    /**
     * @brief A datagram from the target: wrap it into IP/UDP and send it to
     *        the phone.
     * @param data Datagram payload (nullptr is ignored, UDP has no EOF).
     * @param len  Payload length.
     */
    void on_upstream_data(const char* data, int len) override;
    /**
     * @brief The socket failed or was closed; ICMP errors reported by the
     *        kernel are passed on to the phone as ICMP unreachable.
     * @param error errno value (ECONNREFUSED = ICMP port unreachable, ...).
     */
    void on_upstream_close(int error) override;
    /**
     * @brief Ends the flow after the UDP (or shorter DNS) idle timeout.
     * @param now_ms Current time in milliseconds.
     */
    void on_timer(int64_t now_ms) override;

private:
    std::string last_header_; // IP + UDP header of the last packet from the phone (for ICMP errors)
    uint64_t packets_up_ = 0;   // datagrams phone -> target (statistics)
    uint64_t packets_down_ = 0; // datagrams target -> phone (statistics)
    std::string scratch_;       // packet building buffer
};

/**
 * @brief ICMP echo (ping) of the phone towards one target and identifier.
 *
 * FlowKey::src_port holds the phone's echo identifier. The requests are sent
 * through an unprivileged "ping socket" (Linux SOCK_DGRAM + IPPROTO_ICMP,
 * allowed by net.ipv4.ping_group_range), or a raw socket when that is not
 * available and the server runs as root. Only echo request/reply is
 * supported; other ICMP messages from the phone are dropped by Session.
 */
class IcmpFlow : public Flow {
public:
    /**
     * @brief Create the flow (no socket yet, see start()).
     * @param session Session the flow belongs to.
     * @param key     src/dst addresses; src_port = echo identifier, dst_port = 0.
     * @param id      Unique flow id (user_tag of the upstream socket).
     */
    IcmpFlow(Session* session, const FlowKey& key, uint64_t id);
    /**
     * @brief Open a ping socket, falling back to a raw socket.
     * @return true on success; false if neither socket type is permitted.
     */
    bool start();
    /**
     * @brief An echo request from the phone: rebuild the ICMP message and
     *        send it to the target.
     * @param packet Parsed ICMP / ICMPv6 echo request.
     */
    void on_packet(const ParsedPacket& packet) override;
    /**
     * @brief Result of srv_connect(); only an error matters.
     * @param error 0 or an errno value.
     */
    void on_upstream_open(int error) override;
    /**
     * @brief An ICMP message received by the socket: if it is our echo
     *        reply, rebuild it as an IP packet for the phone.
     * @param data ICMP message (raw IPv4 sockets: with IP header in front).
     * @param len  Length of data.
     */
    void on_upstream_data(const char* data, int len) override;
    /**
     * @brief The socket is gone: finish the flow.
     * @param error 0 or an errno value (logged).
     */
    void on_upstream_close(int error) override;
    /**
     * @brief Ends the flow after the ICMP idle timeout.
     * @param now_ms Current time in milliseconds.
     */
    void on_timer(int64_t now_ms) override;

private:
    bool raw_ = false;      // SOCK_RAW (root) instead of an unprivileged ping socket
    uint64_t requests_ = 0; // echo requests forwarded (statistics)
    uint64_t replies_ = 0;  // echo replies delivered to the phone (statistics)
    std::string scratch_;   // packet building buffer
};

} // namespace vpn

#endif // SIMPLEVPN_FLOWS_H
