#include "vpn_session.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <ctime>
#include <sys/socket.h>

#include "flows.h"
#include "tunnel_protocol.h"

namespace vpn {

VpnConfig g_vpn_config;
thread_local WorkerState* t_worker = nullptr;

int64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

// ---------------------------------------------------------------------------
// Flow
// ---------------------------------------------------------------------------

Flow::Flow(Session* session, const FlowKey& key, uint64_t id)
    : session_(session), key_(key), id_(id), created_ms_(now_ms()), last_activity_ms_(created_ms_) {
    session_->register_flow(this);
}

Flow::~Flow() {
    if (has_upstream_) {
        srv_abort(&upstream_);
    }
    session_->unregister_flow(this);
}

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
        session_->mark_dead(key_);
    }
}

void Flow::touch() {
    last_activity_ms_ = now_ms();
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

Session::Session(const SocketInfo& tunnel, uint64_t session_id)
    : tunnel_(tunnel), session_id_(session_id), tag_("S" + std::to_string(session_id)), created_ms_(now_ms()),
      last_stats_ms_(created_ms_) {
    char addr[64];
    LOG_INFO("%s tunnel connection from %s", tag_.c_str(),
             srv_addr_to_string(&tunnel.remote_addr, addr, sizeof(addr)));
}

Session::~Session() {
    if (authenticated_) {
        log_stats("closed");
    }
    flows_.clear(); // aborts the outbound sockets
    pcap_.close();
}

uint64_t Session::allocate_flow_id() {
    return t_worker->next_flow_id++;
}

void Session::register_flow(Flow* flow) {
    t_worker->flows[flow->id()] = flow;
}

void Session::unregister_flow(Flow* flow) {
    t_worker->flows.erase(flow->id());
}

uint32_t Session::random32() {
    return static_cast<uint32_t>(t_worker->rng());
}

void Session::add_inflight(long delta) {
    if (delta < 0 && static_cast<size_t>(-delta) > inflight_) {
        inflight_ = 0;
    } else {
        inflight_ = static_cast<size_t>(static_cast<long>(inflight_) + delta);
    }
    if (delta < 0 && !starved_flows_.empty()) {
        budget_released_ = true;
    }
}

void Session::wait_for_budget(uint64_t flow_id) {
    if (std::find(starved_flows_.begin(), starved_flows_.end(), flow_id) == starved_flows_.end()) {
        starved_flows_.push_back(flow_id);
    }
}

void Session::reap() {
    // Let flows that waited for the in-flight budget continue (FIFO)
    if (budget_released_ && !tunnel_blocked_) {
        budget_released_ = false;
        std::vector<uint64_t> waiting;
        waiting.swap(starved_flows_);
        for (size_t i = 0; i < waiting.size(); ++i) {
            if (inflight_room() == 0) {
                // still no room: keep the rest waiting, in order
                starved_flows_.insert(starved_flows_.begin(), waiting.begin() + static_cast<long>(i), waiting.end());
                break;
            }
            auto it = t_worker->flows.find(waiting[i]);
            if (it != t_worker->flows.end() && it->second->session() == this && !it->second->dead()) {
                it->second->on_tunnel_writable();
            }
        }
    }

    for (const FlowKey& key : dead_keys_) {
        auto it = flows_.find(key);
        if (it != flows_.end() && it->second->dead()) {
            flows_.erase(it);
        }
    }
    dead_keys_.clear();
}

void Session::send_frame(uint8_t type, const void* data, size_t len) {
    std::string frame;
    frame.reserve(tunnel::kHeaderSize + len);
    tunnel::append_frame(frame, type, data, len);
    srv_send(&tunnel_, frame.data(), static_cast<int>(frame.size()));
}

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
            LOG_INFO("%s < %s", tag_.c_str(), describe_packet(p).c_str());
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
    flows_.clear();
    dead_keys_.clear();
}

void Session::on_frame(uint8_t type, const uint8_t* payload, size_t len) {
    if (closing_) {
        return;
    }
    if (!authenticated_) {
        if (type != tunnel::kHello) {
            close("expected HELLO");
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
    case tunnel::kPong:
    case tunnel::kHello:
        break;
    case tunnel::kError:
        LOG_INFO("%s client error: %.*s", tag_.c_str(), static_cast<int>(len), reinterpret_cast<const char*>(payload));
        close(nullptr);
        break;
    default:
        LOG_DEBUG("%s ignore frame type %u", tag_.c_str(), type);
        break;
    }
}

void Session::handle_hello(const uint8_t* payload, size_t len) {
    std::map<std::string, std::string> kv = tunnel::decode_kv(reinterpret_cast<const char*>(payload), len);
    if (!g_vpn_config.token.empty() && kv["token"] != g_vpn_config.token) {
        char addr[64];
        LOG_WARN("%s authentication failed from %s", tag_.c_str(),
                 srv_addr_to_string(&tunnel_.remote_addr, addr, sizeof(addr)));
        close("authentication failed");
        return;
    }
    int mtu = std::atoi(kv["mtu"].c_str());
    mtu_ = mtu >= 576 && mtu <= 65535 ? mtu : 1500;
    client_name_ = kv["client"];
    authenticated_ = true;
    LOG_INFO("%s authenticated: client=%s mtu=%d tun_ipv4=%s tun_ipv6=%s", tag_.c_str(),
             client_name_.empty() ? "-" : client_name_.c_str(), mtu_, kv["ipv4"].empty() ? "-" : kv["ipv4"].c_str(),
             kv["ipv6"].empty() ? "-" : kv["ipv6"].c_str());

    if (!g_vpn_config.pcap_dir.empty()) {
        char stamp[32];
        time_t t = time(nullptr);
        struct tm tm_buf;
        localtime_r(&t, &tm_buf);
        strftime(stamp, sizeof(stamp), "%Y%m%d-%H%M%S", &tm_buf);
        std::string path = g_vpn_config.pcap_dir + "/session-" + std::to_string(session_id_) + "-" + stamp + ".pcap";
        if (pcap_.open(path, g_vpn_config.pcap_max_bytes)) {
            LOG_INFO("%s capturing packets to %s", tag_.c_str(), path.c_str());
        }
    }

    std::map<std::string, std::string> ack;
    ack["server"] = "simplevpn-server/1.0";
    ack["session"] = std::to_string(session_id_);
    std::string text = tunnel::encode_kv(ack);
    send_frame(tunnel::kHelloAck, text.data(), text.size());
}

bool Session::target_allowed(const IpAddr& dst) const {
    if (!g_vpn_config.block_private_targets) {
        return true;
    }
    const uint8_t* b = dst.bytes;
    if (dst.version == 4) {
        return !(b[0] == 0 || b[0] == 10 || b[0] == 127 || (b[0] == 169 && b[1] == 254) ||
                 (b[0] == 172 && (b[1] & 0xf0) == 16) || (b[0] == 192 && b[1] == 168) ||
                 (b[0] == 100 && (b[1] & 0xc0) == 64));
    }
    static const uint8_t kLoopback[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    return !(std::memcmp(b, kLoopback, 16) == 0 || (b[0] & 0xfe) == 0xfc || (b[0] == 0xfe && (b[1] & 0xc0) == 0x80));
}

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
        LOG_INFO("%s > %s", tag_.c_str(), describe_packet(p).c_str());
    }
    if (p.fragment) {
        std::string whole;
        if (reassembler_.add(p, now_ms(), whole)) {
            LOG_DEBUG("%s reassembled %zu byte datagram from fragments", tag_.c_str(), whole.size());
            ParsedPacket full;
            if (parse_packet(reinterpret_cast<const uint8_t*>(whole.data()), whole.size(), full, &error) &&
                !full.fragment) {
                dispatch_packet(full);
            }
        }
        return;
    }
    dispatch_packet(p);
}

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
        ++dropped_;
        LOG_DEBUG("%s unsupported IP protocol %u dropped: %s", tag_.c_str(), p.protocol, describe_packet(p).c_str());
        break;
    }
}

void Session::send_tcp_reset_for(const ParsedPacket& p) {
    if (p.tcp_flags & kTcpRst) {
        return;
    }
    uint32_t seq;
    uint32_t ack = 0;
    uint8_t flags;
    if (p.tcp_flags & kTcpAck) {
        seq = p.ack;
        flags = kTcpRst;
    } else {
        seq = 0;
        ack = p.seq + static_cast<uint32_t>(p.payload_len) + ((p.tcp_flags & kTcpSyn) ? 1 : 0) +
              ((p.tcp_flags & kTcpFin) ? 1 : 0);
        flags = kTcpRst | kTcpAck;
    }
    std::string packet;
    build_tcp_packet(packet, p.dst, p.dst_port, p.src, p.src_port, seq, ack, flags, 0, nullptr, 0, nullptr, 0);
    send_packet(packet);
}

void Session::handle_tcp(const ParsedPacket& p) {
    FlowKey key;
    key.protocol = kProtoTcp;
    key.src = p.src;
    key.dst = p.dst;
    key.src_port = p.src_port;
    key.dst_port = p.dst_port;
    bool syn = (p.tcp_flags & kTcpSyn) && !(p.tcp_flags & (kTcpAck | kTcpRst));

    auto it = flows_.find(key);
    if (it != flows_.end()) {
        TcpFlow* flow = static_cast<TcpFlow*>(it->second.get());
        if (!flow->dead() && !(syn && flow->is_new_connection(p))) {
            flow->on_packet(p);
            return;
        }
        if (!syn) {
            send_tcp_reset_for(p);
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
        send_tcp_reset_for(p);
        return;
    }
    if (flows_.size() >= static_cast<size_t>(g_vpn_config.max_flows_per_session)) {
        LOG_WARN("%s too many flows (%zu), reset new connection", tag_.c_str(), flows_.size());
        send_tcp_reset_for(p);
        return;
    }

    std::unique_ptr<TcpFlow> flow(new TcpFlow(this, key, allocate_flow_id(), p));
    TcpFlow* raw = flow.get();
    flows_[key] = std::move(flow);
    ++flows_created_;
    raw->start();
}

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
        flows_.erase(it);
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
    if (raw->start()) {
        raw->on_packet(p);
    }
}

void Session::handle_icmp(const ParsedPacket& p) {
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
    key.src_port = p.icmp_id;

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

void Session::on_tunnel_write_blocked(bool blocked) {
    tunnel_blocked_ = blocked;
    LOG_DEBUG("%s tunnel %s", tag_.c_str(), blocked ? "congested" : "writable again");
    if (!blocked) {
        for (auto& item : flows_) {
            item.second->on_tunnel_writable();
        }
    }
}

void Session::on_timer(int64_t now) {
    if (closing_) {
        return;
    }
    if (!authenticated_) {
        if (now - created_ms_ > g_vpn_config.hello_timeout_ms) {
            close("no HELLO received");
        }
        return;
    }
    for (auto& item : flows_) {
        item.second->on_timer(now);
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
