/**
 * @file vpn_session.cpp
 * @brief Implementation of Flow (common part) and Session: handshake, packet
 *        dispatch to flows, sending packets to the phone, back pressure and
 *        housekeeping.
 *
 * Overview
 * --------
 * Data path phone -> internet: handle_message_from_client() (vpn_plugin.cpp)
 * calls Session::on_frame() with one frame. A PACKET frame goes to
 * handle_packet() (capture, parse, reassemble fragments), then
 * dispatch_packet() picks handle_tcp / handle_udp / handle_icmp, which find
 * or create the Flow for the packet's FlowKey and hand the packet to it.
 *
 * Data path internet -> phone: a flow builds an IP packet and calls
 * Session::send_packet(), which captures it, fragments it if it is larger
 * than the phone's MTU and queues it as a PACKET frame on the tunnel with
 * srv_send().
 *
 * Back pressure: if the phone cannot keep up, the engine reports the tunnel
 * as blocked (on_tunnel_write_blocked) and TCP flows stop sending; in
 * addition the session limits the total number of unacknowledged bytes of
 * all its TCP flows (in-flight budget), so a single big download cannot fill
 * the tunnel with megabytes of queued data and add seconds of latency to
 * everything else (e.g. DNS answers) of the same phone.
 *
 * Reading guide: Session::on_frame -> handle_hello -> handle_packet ->
 * dispatch_packet -> handle_tcp (the most interesting) -> send_packet ->
 * reap / add_inflight -> on_timer.
 */
#include "vpn_session.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <ctime>
#include <sys/socket.h>

#include "flows.h"
#include "tunnel_protocol.h"

namespace vpn {

VpnConfig g_vpn_config;                     // filled by load_config() in vpn_plugin.cpp
thread_local WorkerState* t_worker = nullptr; // one per worker thread, see handle_init()

/**
 * @brief Monotonic milliseconds, used for every timeout of the plugin.
 * @return Milliseconds since an arbitrary fixed point (steady_clock never jumps,
 *         unlike the wall clock which NTP or the admin may change).
 */
int64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

// ---------------------------------------------------------------------------
// Flow
// ---------------------------------------------------------------------------

/**
 * @brief Common flow construction: remember identity and times, and register
 *        in the worker's id -> flow table so engine events can find the flow.
 */
Flow::Flow(Session* session, const FlowKey& key, uint64_t id)
    : session_(session), key_(key), id_(id), created_ms_(now_ms()), last_activity_ms_(created_ms_) {
    session_->register_flow(this);
}

/**
 * @brief Destroy a flow: abort a still open outbound socket (nobody will
 *        read its data any more) and remove the flow from the id table, so
 *        late engine events for that socket find nothing and are ignored.
 */
Flow::~Flow() {
    if (has_upstream_) {
        srv_abort(&upstream_);
    }
    session_->unregister_flow(this);
}

/**
 * @brief End the flow: close its outbound socket and mark it dead.
 *
 * The flow is not deleted here (we are usually inside one of its own
 * methods); Session::reap() deletes it at the end of the current engine
 * callback.
 *
 * @param abort_upstream true = srv_abort (drop unsent data, RST for TCP),
 *                       false = srv_close (send what is queued, then close).
 * @param reason         Logged with the flow name if not nullptr.
 */
void Flow::finish(bool abort_upstream, const char* reason) {
    if (reason != nullptr) {
        LOG_INFO("%s %s", name_.c_str(), reason);
    }
    if (has_upstream_) {
        if (abort_upstream) {
            srv_abort(&upstream_);
        } else {
            srv_close(&upstream_);
        }
        has_upstream_ = false;
    }
    if (!dead_) {
        dead_ = true;
        session_->mark_dead(key_); // only once, so reap() sees each key once
    }
}

/**
 * @brief Note activity on the flow (resets its idle timeout).
 */
void Flow::touch() {
    last_activity_ms_ = now_ms();
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/**
 * @brief Create the session for a freshly accepted tunnel connection.
 *
 * The session starts unauthenticated: until a valid HELLO arrives, any other
 * frame closes the tunnel, and on_timer() closes it after vpn_hello_timeout_ms.
 */
Session::Session(const SocketInfo& tunnel, uint64_t session_id)
    : tunnel_(tunnel), session_id_(session_id), tag_("S" + std::to_string(session_id)), created_ms_(now_ms()),
      last_stats_ms_(created_ms_) {
    char addr[64];
    LOG_INFO("%s tunnel connection from %s", tag_.c_str(),
             srv_addr_to_string(&tunnel.remote_addr, addr, sizeof(addr)));
}

/**
 * @brief Tear the session down (tunnel closed or server shutdown).
 */
Session::~Session() {
    if (authenticated_) {
        log_stats("closed");
    }
    flows_.clear(); // aborts the outbound sockets
    pcap_.close();
}

/**
 * @return A new flow id, unique among all flows of this worker (it is also
 *         the user_tag of the flow's outbound socket).
 */
uint64_t Session::allocate_flow_id() {
    return t_worker->next_flow_id++;
}

/**
 * @brief Enter a flow into the worker wide id table (called by Flow's constructor).
 * @param flow The new flow.
 */
void Session::register_flow(Flow* flow) {
    t_worker->flows[flow->id()] = flow;
}

/**
 * @brief Remove a flow from the worker wide id table (called by Flow's destructor).
 * @param flow The flow being destroyed.
 */
void Session::unregister_flow(Flow* flow) {
    t_worker->flows.erase(flow->id());
}

/**
 * @return 32 random bits; used for the TCP initial sequence numbers we send
 *         to the phone (predictable ISNs would allow spoofing attacks).
 */
uint32_t Session::random32() {
    return static_cast<uint32_t>(t_worker->rng());
}

/**
 * @brief Update the session wide count of unacknowledged bytes towards the phone.
 *
 * TCP flows report their change here whenever they send data (positive) or
 * get it acknowledged by the phone (negative). If budget is released while
 * flows are waiting, reap() will wake them up.
 *
 * @param delta Change in bytes; negative values release budget.
 */
void Session::add_inflight(long delta) {
    if (delta < 0 && static_cast<size_t>(-delta) > inflight_) {
        inflight_ = 0; // never underflow (defensive)
    } else {
        inflight_ = static_cast<size_t>(static_cast<long>(inflight_) + delta);
    }
    if (delta < 0 && !starved_flows_.empty()) {
        budget_released_ = true; // handled in reap(), not here: we may be deep inside a flow's method
    }
}

/**
 * @brief Queue a flow that wanted to send but found no in-flight budget.
 * @param flow_id The waiting flow (by id, it may be deleted while waiting).
 */
void Session::wait_for_budget(uint64_t flow_id) {
    if (std::find(starved_flows_.begin(), starved_flows_.end(), flow_id) == starved_flows_.end()) {
        starved_flows_.push_back(flow_id); // each flow at most once, in arrival order
    }
}

/**
 * @brief Deferred work after every engine callback: wake flows waiting for
 *        in-flight budget, then delete the flows that finished.
 *
 * Doing this at a well defined point (instead of inside the flow methods)
 * avoids deleting an object while its own code is still on the call stack.
 */
void Session::reap() {
    // Let flows that waited for the in-flight budget continue (FIFO)
    if (budget_released_ && !tunnel_blocked_) {
        budget_released_ = false;
        std::vector<uint64_t> waiting;
        waiting.swap(starved_flows_); // flows that block again re-queue themselves via wait_for_budget()
        for (size_t i = 0; i < waiting.size(); ++i) {
            if (inflight_room() == 0) {
                // still no room: keep the rest waiting, in order
                starved_flows_.insert(starved_flows_.begin(), waiting.begin() + static_cast<long>(i), waiting.end());
                break;
            }
            // Look the id up again: the flow may have been deleted while waiting
            auto it = t_worker->flows.find(waiting[i]);
            if (it != t_worker->flows.end() && it->second->session() == this && !it->second->dead()) {
                it->second->on_tunnel_writable();
            }
        }
    }

    for (const FlowKey& key : dead_keys_) {
        auto it = flows_.find(key);
        // Check dead(): the key may already belong to a new flow (4-tuple reuse)
        if (it != flows_.end() && it->second->dead()) {
            flows_.erase(it); // runs ~Flow()
        }
    }
    dead_keys_.clear();
}

/**
 * @brief Queue one frame on the tunnel connection.
 *
 * srv_send() only queues the bytes for the CONN thread; it never blocks.
 * The queue length is what the engine watches for handle_write_blocked().
 *
 * @param type Frame type (tunnel::FrameType).
 * @param data Payload.
 * @param len  Payload length.
 */
void Session::send_frame(uint8_t type, const void* data, size_t len) {
    std::string frame;
    frame.reserve(tunnel::kHeaderSize + len);
    tunnel::append_frame(frame, type, data, len);
    srv_send(&tunnel_, frame.data(), static_cast<int>(frame.size()));
}

/**
 * @brief Send one IP packet to the phone.
 *
 * Records it (pcap file, live capture, optional packet log) exactly as the
 * phone will receive it, then sends it in a PACKET frame. A packet larger
 * than the phone's TUN MTU would be dropped by the phone's kernel, so it is
 * split into IP fragments first, as a router would do.
 *
 * @param packet Complete IPv4 or IPv6 packet addressed to the phone.
 */
void Session::send_packet(const std::string& packet) {
    if (closing_) {
        return;
    }
    ++packets_out_;
    bytes_out_ += packet.size();
    pcap_.write(reinterpret_cast<const uint8_t*>(packet.data()), packet.size());
    g_live_capture.publish(reinterpret_cast<const uint8_t*>(packet.data()), packet.size());
    if (g_inspector.log_packets()) {
        ParsedPacket p;
        if (parse_packet(reinterpret_cast<const uint8_t*>(packet.data()), packet.size(), p, nullptr)) {
            LOG_INFO("%s < %s", tag_.c_str(), describe_packet(p).c_str()); // "<" = to the phone
        }
    }
    if (packet.size() <= static_cast<size_t>(mtu_)) {
        send_frame(tunnel::kPacket, packet.data(), packet.size());
        return;
    }
    // Larger than the TUN MTU (e.g. a big UDP datagram): fragment it like a router would
    std::vector<std::string> fragments;
    fragment_packet(packet, mtu_, next_ip_id_++, fragments);
    for (const std::string& fragment : fragments) {
        send_frame(tunnel::kPacket, fragment.data(), fragment.size());
    }
}

/**
 * @brief Close the tunnel and drop all flows. Idempotent.
 *
 * srv_close() sends everything already queued (including the ERROR frame)
 * before closing, so the client learns why it was disconnected. The session
 * object itself is deleted later, in handle_client_close().
 *
 * @param reason Text for the ERROR frame and the log; nullptr = close without ERROR frame.
 */
void Session::close(const char* reason) {
    if (closing_) {
        return;
    }
    if (reason != nullptr) {
        LOG_INFO("%s closing tunnel: %s", tag_.c_str(), reason);
        send_frame(tunnel::kError, reason, std::strlen(reason));
    }
    closing_ = true;
    srv_close(&tunnel_);
    flows_.clear(); // abort all outbound sockets now
    dead_keys_.clear();
}

/**
 * @brief Handle one frame from the phone (called by handle_message_from_client()).
 *
 * Before authentication only HELLO is accepted. Afterwards PACKET carries
 * traffic, PING is answered with a PONG echoing the payload (the client uses
 * it to detect a dead connection), and ERROR from the client closes the tunnel.
 *
 * @param type    Frame type.
 * @param payload Frame payload (after the header).
 * @param len     Payload length.
 */
void Session::on_frame(uint8_t type, const uint8_t* payload, size_t len) {
    if (closing_) {
        return;
    }
    if (!authenticated_) {
        if (type != tunnel::kHello) {
            close("expected HELLO"); // nothing may pass before the token was checked
            return;
        }
        handle_hello(payload, len);
        return;
    }
    switch (type) {
    case tunnel::kPacket:
        handle_packet(payload, len);
        break;
    case tunnel::kPing:
        send_frame(tunnel::kPong, payload, len);
        break;
    case tunnel::kPong:  // we never send PINGs, nothing to do
    case tunnel::kHello: // duplicate HELLO: ignored
        break;
    case tunnel::kError:
        LOG_INFO("%s client error: %.*s", tag_.c_str(), static_cast<int>(len), reinterpret_cast<const char*>(payload));
        close(nullptr);
        break;
    default:
        // Unknown types are ignored, so newer clients can add frame types
        LOG_DEBUG("%s ignore frame type %u", tag_.c_str(), type);
        break;
    }
}

/**
 * @brief Process the HELLO frame: authenticate, read client parameters,
 *        start the pcap capture and answer with HELLO_ACK.
 *
 * @param payload "key=value\n" text (token, client, mtu, ipv4, ipv6, version).
 * @param len     Payload length.
 */
void Session::handle_hello(const uint8_t* payload, size_t len) {
    std::map<std::string, std::string> kv = tunnel::decode_kv(reinterpret_cast<const char*>(payload), len);
    // An empty vpn_token disables authentication (a warning was logged at start up)
    if (!g_vpn_config.token.empty() && kv["token"] != g_vpn_config.token) {
        char addr[64];
        LOG_WARN("%s authentication failed from %s", tag_.c_str(),
                 srv_addr_to_string(&tunnel_.remote_addr, addr, sizeof(addr)));
        close("authentication failed"); // the client looks for the word "authentication"
        return;
    }
    int mtu = std::atoi(kv["mtu"].c_str());
    // 576 is the minimum IPv4 datagram size every host must accept; fall back to 1500 on nonsense
    mtu_ = mtu >= 576 && mtu <= 65535 ? mtu : 1500;
    client_name_ = kv["client"];
    authenticated_ = true;
    LOG_INFO("%s authenticated: client=%s mtu=%d tun_ipv4=%s tun_ipv6=%s", tag_.c_str(),
             client_name_.empty() ? "-" : client_name_.c_str(), mtu_, kv["ipv4"].empty() ? "-" : kv["ipv4"].c_str(),
             kv["ipv6"].empty() ? "-" : kv["ipv6"].c_str());

    if (!g_vpn_config.pcap_dir.empty()) {
        // One file per session: <pcap_dir>/session-<id>-<YYYYmmdd-HHMMSS>.pcap
        char stamp[32];
        time_t t = time(nullptr);
        struct tm tm_buf;
        localtime_r(&t, &tm_buf); // thread safe variant of localtime()
        strftime(stamp, sizeof(stamp), "%Y%m%d-%H%M%S", &tm_buf);
        std::string path = g_vpn_config.pcap_dir + "/session-" + std::to_string(session_id_) + "-" + stamp + ".pcap";
        if (pcap_.open(path, g_vpn_config.pcap_max_bytes)) {
            LOG_INFO("%s capturing packets to %s", tag_.c_str(), path.c_str());
        }
    }

    // HELLO_ACK tells the client it may start sending packets
    std::map<std::string, std::string> ack;
    ack["server"] = "simplevpn-server/1.0";
    ack["session"] = std::to_string(session_id_);
    std::string text = tunnel::encode_kv(ack);
    send_frame(tunnel::kHelloAck, text.data(), text.size());
}

/**
 * @brief May the phone reach this destination? (vpn_block_private)
 *
 * Without this check a VPN user could reach services that are only meant to
 * be reachable from the server itself or its LAN (localhost admin ports,
 * cloud metadata at 169.254.169.254, ...).
 *
 * @param dst Destination address of a new flow.
 * @return true if allowed (always true unless vpn_block_private is set).
 */
bool Session::target_allowed(const IpAddr& dst) const {
    if (!g_vpn_config.block_private_targets) {
        return true;
    }
    const uint8_t* b = dst.bytes;
    if (dst.version == 4) {
        // 0/8, 10/8, 127/8 loopback, 169.254/16 link local, 172.16/12, 192.168/16, 100.64/10 carrier grade NAT
        return !(b[0] == 0 || b[0] == 10 || b[0] == 127 || (b[0] == 169 && b[1] == 254) ||
                 (b[0] == 172 && (b[1] & 0xf0) == 16) || (b[0] == 192 && b[1] == 168) ||
                 (b[0] == 100 && (b[1] & 0xc0) == 64));
    }
    static const uint8_t kLoopback[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    // IPv6: ::1, fc00::/7 unique local, fe80::/10 link local
    return !(std::memcmp(b, kLoopback, 16) == 0 || (b[0] & 0xfe) == 0xfc || (b[0] == 0xfe && (b[1] & 0xc0) == 0x80));
}

/**
 * @brief One raw IP packet from the phone (payload of a PACKET frame).
 *
 * The packet is captured before parsing, so even malformed packets show up
 * in Wireshark. IP fragments are collected until the datagram is complete,
 * because flows need the whole transport header and payload.
 *
 * @param data Packet bytes.
 * @param len  Packet length.
 */
void Session::handle_packet(const uint8_t* data, size_t len) {
    ++packets_in_;
    bytes_in_ += len;
    pcap_.write(data, len);
    g_live_capture.publish(data, len);

    ParsedPacket p;
    std::string error;
    if (!parse_packet(data, len, p, &error)) {
        ++dropped_;
        LOG_DEBUG("%s drop malformed packet (%zu bytes): %s", tag_.c_str(), len, error.c_str());
        return;
    }
    if (g_inspector.log_packets()) {
        LOG_INFO("%s > %s", tag_.c_str(), describe_packet(p).c_str()); // ">" = from the phone
    }
    if (p.fragment) {
        std::string whole;
        if (reassembler_.add(p, now_ms(), whole)) {
            LOG_DEBUG("%s reassembled %zu byte datagram from fragments", tag_.c_str(), whole.size());
            ParsedPacket full;
            // `full` points into `whole`, which lives until the end of this block
            if (parse_packet(reinterpret_cast<const uint8_t*>(whole.data()), whole.size(), full, &error) &&
                !full.fragment) {
                dispatch_packet(full);
            }
        }
        return; // incomplete: wait for the other fragments
    }
    dispatch_packet(p);
}

/**
 * @brief Route a complete, parsed packet to the handler of its transport protocol.
 *
 * Multicast / broadcast (mDNS, SSDP, ...) only makes sense on the phone's
 * local network, so it is not forwarded.
 *
 * @param p Parsed packet from the phone.
 */
void Session::dispatch_packet(const ParsedPacket& p) {
    if (p.dst.is_multicast_or_broadcast()) {
        ++dropped_;
        LOG_TRACE("%s drop multicast/broadcast: %s", tag_.c_str(), describe_packet(p).c_str());
        return;
    }

    switch (p.protocol) {
    case kProtoTcp:
        handle_tcp(p);
        break;
    case kProtoUdp:
        handle_udp(p);
        break;
    case kProtoIcmp:
    case kProtoIcmpV6:
        handle_icmp(p);
        break;
    default:
        // e.g. GRE, ESP, SCTP: there is no portable way to forward them with ordinary sockets
        ++dropped_;
        LOG_DEBUG("%s unsupported IP protocol %u dropped: %s", tag_.c_str(), p.protocol, describe_packet(p).c_str());
        break;
    }
}

/**
 * @brief Answer a TCP packet that belongs to no (live) connection with a RST,
 *        built as RFC 793 prescribes, so the phone's app fails fast instead
 *        of retransmitting for minutes.
 *
 * The RST pretends to come from the destination (addresses and ports swapped).
 *
 * @param p The offending packet from the phone (never answered if it is a RST itself).
 */
void Session::send_tcp_reset_for(const ParsedPacket& p) {
    if (p.tcp_flags & kTcpRst) {
        return; // never answer a RST with a RST
    }
    uint32_t seq;
    uint32_t ack = 0;
    uint8_t flags;
    if (p.tcp_flags & kTcpAck) {
        // The packet acknowledged something: our RST uses that number as its sequence number
        seq = p.ack;
        flags = kTcpRst;
    } else {
        // No ACK (e.g. a SYN): RST+ACK acknowledging everything the packet occupied
        seq = 0;
        ack = p.seq + static_cast<uint32_t>(p.payload_len) + ((p.tcp_flags & kTcpSyn) ? 1 : 0) +
              ((p.tcp_flags & kTcpFin) ? 1 : 0); // SYN and FIN each count as one sequence number
        flags = kTcpRst | kTcpAck;
    }
    std::string packet;
    build_tcp_packet(packet, p.dst, p.dst_port, p.src, p.src_port, seq, ack, flags, 0, nullptr, 0, nullptr, 0);
    send_packet(packet);
}

/**
 * @brief Handle a TCP segment from the phone: deliver it to its TcpFlow, or
 *        create a new flow for a SYN, or reset unknown connections.
 *
 * A new TcpFlow does not answer the SYN itself; start() first connects to the
 * real server, and only when that succeeds the phone gets its SYN-ACK
 * (see TcpFlow::on_upstream_open in flows.cpp).
 *
 * @param p Parsed TCP packet from the phone.
 */
void Session::handle_tcp(const ParsedPacket& p) {
    FlowKey key;
    key.protocol = kProtoTcp;
    key.src = p.src;
    key.dst = p.dst;
    key.src_port = p.src_port;
    key.dst_port = p.dst_port;
    // A pure SYN opens a connection (SYN+ACK or SYN+RST are not connection requests)
    bool syn = (p.tcp_flags & kTcpSyn) && !(p.tcp_flags & (kTcpAck | kTcpRst));

    auto it = flows_.find(key);
    if (it != flows_.end()) {
        TcpFlow* flow = static_cast<TcpFlow*>(it->second.get()); // the key's protocol is TCP
        // Normal case; a retransmitted SYN (same sequence number) also goes to the existing flow
        if (!flow->dead() && !(syn && flow->is_new_connection(p))) {
            flow->on_packet(p);
            return;
        }
        if (!syn) {
            send_tcp_reset_for(p); // late segment of a finished connection
            return;
        }
        flows_.erase(it); // the 4-tuple is reused by a new connection
    }

    if (!syn) {
        // Not part of any connection we know (e.g. after a server restart)
        LOG_DEBUG("%s no flow for %s, reset", tag_.c_str(), describe_packet(p).c_str());
        send_tcp_reset_for(p);
        return;
    }
    if (!target_allowed(p.dst)) {
        LOG_NOTICE("%s refuse connection to private address %s", tag_.c_str(), p.dst.to_string().c_str());
        send_tcp_reset_for(p); // "connection refused" for the app
        return;
    }
    if (flows_.size() >= static_cast<size_t>(g_vpn_config.max_flows_per_session)) {
        LOG_WARN("%s too many flows (%zu), reset new connection", tag_.c_str(), flows_.size());
        send_tcp_reset_for(p);
        return;
    }

    std::unique_ptr<TcpFlow> flow(new TcpFlow(this, key, allocate_flow_id(), p));
    TcpFlow* raw = flow.get();
    flows_[key] = std::move(flow); // store first: start() may finish() the flow right away
    ++flows_created_;
    raw->start(); // srv_connect() to the real destination
}

/**
 * @brief Handle a UDP datagram from the phone.
 *
 * UDP has no connections, so a "flow" is simply all datagrams with the same
 * 5-tuple; it ends after an idle timeout. Each flow gets its own outbound UDP
 * socket, which is what makes the replies find their way back (NAT).
 *
 * @param p Parsed UDP packet from the phone.
 */
void Session::handle_udp(const ParsedPacket& p) {
    FlowKey key;
    key.protocol = kProtoUdp;
    key.src = p.src;
    key.dst = p.dst;
    key.src_port = p.src_port;
    key.dst_port = p.dst_port;

    auto it = flows_.find(key);
    if (it != flows_.end() && !it->second->dead()) {
        it->second->on_packet(p);
        return;
    }
    if (it != flows_.end()) {
        flows_.erase(it); // a dead flow not reaped yet: replace it
    }
    if (!target_allowed(p.dst)) {
        ++dropped_;
        LOG_NOTICE("%s refuse UDP to private address %s", tag_.c_str(), p.dst.to_string().c_str());
        return;
    }
    if (g_vpn_config.block_quic && p.dst_port == 443) {
        // Answer like a firewall would; browsers then retry over TCP + TLS
        ++dropped_;
        LOG_DEBUG("%s QUIC to %s rejected (vpn_block_quic)", tag_.c_str(), p.dst.to_string().c_str());
        std::string icmp;
        bool v6 = p.ip_version == 6;
        // "Port unreachable": ICMPv4 type 3 code 3, ICMPv6 type 1 code 4. The error
        // quotes the original IP header + the first 8 bytes (the UDP header).
        build_icmp_packet(icmp, p.dst, p.src, v6 ? 1 : 3, v6 ? 4 : 3, 0, p.ip_header, p.ip_header_len + 8);
        send_packet(icmp);
        return;
    }
    if (flows_.size() >= static_cast<size_t>(g_vpn_config.max_flows_per_session)) {
        ++dropped_;
        LOG_WARN("%s too many flows (%zu), drop UDP packet", tag_.c_str(), flows_.size());
        return;
    }
    std::unique_ptr<UdpFlow> flow(new UdpFlow(this, key, allocate_flow_id()));
    UdpFlow* raw = flow.get();
    flows_[key] = std::move(flow);
    ++flows_created_;
    if (raw->start()) { // socket created: forward this first datagram
        raw->on_packet(p);
    }
}

/**
 * @brief Handle an ICMP / ICMPv6 packet from the phone.
 *
 * Only echo requests (ping) are forwarded: one flow per destination and echo
 * identifier, using an unprivileged ping socket or a raw socket on the
 * server. Other ICMP types from the phone (e.g. errors about packets we sent
 * it) have no meaning beyond the tunnel and are dropped.
 *
 * @param p Parsed ICMP packet from the phone.
 */
void Session::handle_icmp(const ParsedPacket& p) {
    // Echo request: ICMPv4 type 8, ICMPv6 type 128
    bool echo_request = (p.protocol == kProtoIcmp && p.icmp_type == 8) ||
                        (p.protocol == kProtoIcmpV6 && p.icmp_type == 128);
    if (!echo_request) {
        ++dropped_;
        LOG_DEBUG("%s ICMP%s type %u from client ignored", tag_.c_str(), p.protocol == kProtoIcmpV6 ? "v6" : "",
                  p.icmp_type);
        return;
    }
    FlowKey key;
    key.protocol = p.protocol;
    key.src = p.src;
    key.dst = p.dst;
    key.src_port = p.icmp_id; // the echo identifier plays the role of the source port

    auto it = flows_.find(key);
    if (it != flows_.end() && !it->second->dead()) {
        it->second->on_packet(p);
        return;
    }
    if (it != flows_.end()) {
        flows_.erase(it);
    }
    if (!target_allowed(p.dst) || flows_.size() >= static_cast<size_t>(g_vpn_config.max_flows_per_session)) {
        ++dropped_;
        return;
    }
    std::unique_ptr<IcmpFlow> flow(new IcmpFlow(this, key, allocate_flow_id()));
    IcmpFlow* raw = flow.get();
    flows_[key] = std::move(flow);
    ++flows_created_;
    if (raw->start()) {
        raw->on_packet(p);
    }
}

/**
 * @brief The engine reports that the tunnel's send queue is full / drained.
 *
 * While blocked, TCP flows do not send new data (it would only pile up in
 * the queue and add latency); once drained, every flow gets a chance to send.
 *
 * @param blocked true above the high watermark, false below the low watermark.
 */
void Session::on_tunnel_write_blocked(bool blocked) {
    tunnel_blocked_ = blocked;
    LOG_DEBUG("%s tunnel %s", tag_.c_str(), blocked ? "congested" : "writable again");
    if (!blocked) {
        for (auto& item : flows_) {
            item.second->on_tunnel_writable();
        }
    }
}

/**
 * @brief Periodic housekeeping (every timer tick of the worker, ~100 ms).
 *
 * Enforces the HELLO timeout, drives the flows' timers (retransmissions,
 * idle timeouts), deletes finished flows, expires incomplete fragment
 * sets, flushes the pcap file once a second and logs statistics.
 *
 * @param now Current time from now_ms().
 */
void Session::on_timer(int64_t now) {
    if (closing_) {
        return;
    }
    if (!authenticated_) {
        if (now - created_ms_ > g_vpn_config.hello_timeout_ms) {
            close("no HELLO received"); // e.g. a port scanner or a client that hangs
        }
        return;
    }
    for (auto& item : flows_) {
        item.second->on_timer(now); // flows only mark themselves dead here, no erase during iteration
    }
    reap();
    reassembler_.expire(now);
    if (now - last_flush_ms_ >= 1000) {
        // keep the pcap file current so it can be followed while capturing
        last_flush_ms_ = now;
        pcap_.flush();
    }
    if (g_vpn_config.stats_interval_s > 0 && now - last_stats_ms_ >= g_vpn_config.stats_interval_s * 1000LL) {
        last_stats_ms_ = now;
        log_stats("stats");
    }
}

/**
 * @brief Log one line of session statistics.
 * @param prefix "stats" for the periodic line, "closed" for the final one.
 */
void Session::log_stats(const char* prefix) const {
    LOG_INFO("%s %s: %lld s, from client %llu packets / %llu bytes, to client %llu packets / %llu bytes, "
             "dropped %llu, flows %zu active / %llu total",
             tag_.c_str(), prefix, static_cast<long long>((now_ms() - created_ms_) / 1000),
             static_cast<unsigned long long>(packets_in_), static_cast<unsigned long long>(bytes_in_),
             static_cast<unsigned long long>(packets_out_), static_cast<unsigned long long>(bytes_out_),
             static_cast<unsigned long long>(dropped_), flows_.size(),
             static_cast<unsigned long long>(flows_created_));
}

} // namespace vpn
