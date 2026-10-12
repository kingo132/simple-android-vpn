// TCP, UDP and ICMP flows of a VPN session.
//
// TcpFlow implements a small user-space TCP endpoint: towards the phone it
// impersonates the real server (it answers the SYN, acknowledges data,
// retransmits, does flow control), and towards the internet it uses an
// ordinary socket. That makes the application byte stream visible (and
// modifiable) in between, see Inspector.
#ifndef SIMPLEVPN_FLOWS_H
#define SIMPLEVPN_FLOWS_H

#include <string>

#include "vpn_session.h"

namespace vpn {

class TcpFlow : public Flow {
public:
    TcpFlow(Session* session, const FlowKey& key, uint64_t id, const ParsedPacket& syn);

    // Open the outbound connection; false if that failed immediately (a RST was sent)
    bool start();

    // A new SYN for this 4-tuple that starts a different connection
    bool is_new_connection(const ParsedPacket& syn) const;

    void on_packet(const ParsedPacket& packet) override;
    void on_upstream_open(int error) override;
    void on_upstream_data(const char* data, int len) override;
    void on_upstream_close(int error) override;
    void on_upstream_write_blocked(bool blocked) override;
    void on_tunnel_writable() override;
    void on_timer(int64_t now_ms) override;

private:
    enum class State { Connecting, SynAckSent, Established };

    void send_segment(uint8_t flags, uint32_t seq, const uint8_t* data, size_t len, bool syn_options = false);
    void send_ack();
    void send_syn_ack();
    void abort(const char* reason, bool reset_phone);
    void transmit(bool force_one = false);
    void process_ack(const ParsedPacket& p);
    void process_data(const ParsedPacket& p);
    void deliver_upstream(const uint8_t* data, size_t len);
    void maybe_finish();
    void arm_rto();
    void update_rtt(int64_t sample_ms);
    uint16_t advertised_window() const;
    void account_inflight();
    // Bytes sent and not yet acknowledged (including data sent before a rewind)
    size_t in_flight() const { return snd_max_ - snd_una_; }

    State state_ = State::Connecting;
    // phone -> us
    uint32_t irs_ = 0;      // phone's initial sequence number
    uint32_t rcv_nxt_ = 0;  // next byte expected from the phone
    // us -> phone
    uint32_t iss_ = 0;      // our initial sequence number
    uint32_t snd_una_ = 0;  // oldest unacknowledged byte
    uint32_t snd_nxt_ = 0;  // next byte to send (rewound to snd_una_ on a timeout)
    uint32_t snd_max_ = 0;  // highest sequence number sent so far + 1
    uint32_t snd_wnd_ = 0;  // phone's receive window (bytes, scaled)
    int snd_wscale_ = 0;    // phone's window scale
    int rcv_wscale_ = 0;    // our window scale
    bool wscale_ok_ = false;
    uint16_t mss_ = 536;    // segment size towards the phone
    std::string send_buf_;  // bytes from the server not yet acknowledged by the phone, starting at snd_una_

    bool phone_fin_ = false;        // FIN received from the phone (and forwarded as shutdown)
    bool upstream_eof_ = false;     // server sent FIN, we must send FIN to the phone
    bool fin_sent_ = false;
    bool fin_acked_ = false;
    bool upstream_open_ = false;
    bool upstream_closed_ = false;
    bool upstream_blocked_ = false; // server socket send buffer full -> zero window to the phone
    bool upstream_paused_ = false;  // we paused reading from the server
    bool zero_window_sent_ = false;

    // retransmission
    int64_t rto_deadline_ = 0;
    int rto_ms_ = 1000;
    int retries_ = 0;
    int dupacks_ = 0;
    int64_t srtt_ms_ = 0;
    int64_t rttvar_ms_ = 0;
    bool rtt_timing_ = false;
    uint32_t rtt_seq_ = 0;
    int64_t rtt_start_ms_ = 0;
    uint64_t retransmits_ = 0;
    size_t reported_inflight_ = 0; // our share of the session's in-flight bytes
    std::string scratch_;   // packet building buffer

public:
    ~TcpFlow() override;
};

class UdpFlow : public Flow {
public:
    UdpFlow(Session* session, const FlowKey& key, uint64_t id);
    bool start();
    void on_packet(const ParsedPacket& packet) override;
    void on_upstream_open(int error) override;
    void on_upstream_data(const char* data, int len) override;
    void on_upstream_close(int error) override;
    void on_timer(int64_t now_ms) override;

private:
    std::string last_header_; // IP + UDP header of the last packet from the phone (for ICMP errors)
    uint64_t packets_up_ = 0;
    uint64_t packets_down_ = 0;
    std::string scratch_;
};

class IcmpFlow : public Flow {
public:
    IcmpFlow(Session* session, const FlowKey& key, uint64_t id);
    bool start();
    void on_packet(const ParsedPacket& packet) override;
    void on_upstream_open(int error) override;
    void on_upstream_data(const char* data, int len) override;
    void on_upstream_close(int error) override;
    void on_timer(int64_t now_ms) override;

private:
    bool raw_ = false;      // SOCK_RAW (root) instead of an unprivileged ping socket
    uint64_t requests_ = 0;
    uint64_t replies_ = 0;
    std::string scratch_;
};

} // namespace vpn

#endif // SIMPLEVPN_FLOWS_H
