#include "packet.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <sys/socket.h>

namespace vpn {

bool IpAddr::operator==(const IpAddr& o) const {
    return version == o.version && std::memcmp(bytes, o.bytes, version == 4 ? 4 : 16) == 0;
}

std::string IpAddr::to_string() const {
    char buf[INET6_ADDRSTRLEN] = "?";
    if (version == 4) {
        inet_ntop(AF_INET, bytes, buf, sizeof(buf));
    } else if (version == 6) {
        inet_ntop(AF_INET6, bytes, buf, sizeof(buf));
    }
    return buf;
}

NetAddr IpAddr::to_netaddr(uint16_t port) const {
    NetAddr addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.family = version == 4 ? AF_INET : AF_INET6;
    addr.port = port;
    std::memcpy(addr.ip, bytes, version == 4 ? 4 : 16);
    return addr;
}

IpAddr IpAddr::from_netaddr(const NetAddr& addr) {
    IpAddr ip;
    if (addr.family == AF_INET) {
        ip.version = 4;
        std::memcpy(ip.bytes, addr.ip, 4);
    } else if (addr.family == AF_INET6) {
        ip.version = 6;
        std::memcpy(ip.bytes, addr.ip, 16);
    }
    return ip;
}

bool IpAddr::is_multicast_or_broadcast() const {
    if (version == 4) {
        return (bytes[0] >= 224 && bytes[0] <= 239) ||
               (bytes[0] == 255 && bytes[1] == 255 && bytes[2] == 255 && bytes[3] == 255);
    }
    return bytes[0] == 0xff;
}

size_t IpAddr::hash() const {
    size_t h = version;
    for (int i = 0; i < (version == 4 ? 4 : 16); ++i) {
        h = h * 131 + bytes[i];
    }
    return h;
}

static void parse_tcp_options(const uint8_t* opt, size_t len, TcpOptions& out) {
    size_t i = 0;
    while (i < len) {
        uint8_t kind = opt[i];
        if (kind == 0) {
            break; // end of options
        }
        if (kind == 1) {
            ++i; // NOP
            continue;
        }
        if (i + 1 >= len) {
            break;
        }
        uint8_t olen = opt[i + 1];
        if (olen < 2 || i + olen > len) {
            break;
        }
        switch (kind) {
        case 2:
            if (olen == 4) {
                out.mss = read_be16(opt + i + 2);
            }
            break;
        case 3:
            if (olen == 3) {
                out.wscale = opt[i + 2] > 14 ? 14 : opt[i + 2];
            }
            break;
        case 4:
            out.sack_permitted = true;
            break;
        case 8:
            out.timestamps = true;
            break;
        default:
            break;
        }
        i += olen;
    }
}

static bool parse_transport(ParsedPacket& p, std::string* error) {
    const uint8_t* l4 = p.l4;
    size_t len = p.l4_len;
    if (p.fragment) {
        return true; // transport header may be missing
    }
    switch (p.protocol) {
    case kProtoTcp: {
        if (len < 20) {
            if (error) *error = "short TCP header";
            return false;
        }
        size_t hlen = static_cast<size_t>(l4[12] >> 4) * 4;
        if (hlen < 20 || hlen > len) {
            if (error) *error = "bad TCP header length";
            return false;
        }
        p.src_port = read_be16(l4);
        p.dst_port = read_be16(l4 + 2);
        p.seq = read_be32(l4 + 4);
        p.ack = read_be32(l4 + 8);
        p.tcp_flags = l4[13];
        p.window = read_be16(l4 + 14);
        parse_tcp_options(l4 + 20, hlen - 20, p.tcp_options);
        p.payload = l4 + hlen;
        p.payload_len = len - hlen;
        return true;
    }
    case kProtoUdp: {
        if (len < 8) {
            if (error) *error = "short UDP header";
            return false;
        }
        p.src_port = read_be16(l4);
        p.dst_port = read_be16(l4 + 2);
        size_t ulen = read_be16(l4 + 4);
        if (ulen < 8 || ulen > len) {
            ulen = len; // be tolerant
        }
        p.payload = l4 + 8;
        p.payload_len = ulen - 8;
        return true;
    }
    case kProtoIcmp:
    case kProtoIcmpV6: {
        if (len < 8) {
            if (error) *error = "short ICMP header";
            return false;
        }
        p.icmp_type = l4[0];
        p.icmp_code = l4[1];
        p.icmp_id = read_be16(l4 + 4);
        p.icmp_seq = read_be16(l4 + 6);
        p.payload = l4 + 8;
        p.payload_len = len - 8;
        return true;
    }
    default:
        p.payload = l4;
        p.payload_len = len;
        return true;
    }
}

bool parse_packet(const uint8_t* data, size_t len, ParsedPacket& p, std::string* error) {
    p = ParsedPacket();
    if (len < 1) {
        if (error) *error = "empty packet";
        return false;
    }
    uint8_t version = data[0] >> 4;
    if (version == 4) {
        if (len < 20) {
            if (error) *error = "short IPv4 header";
            return false;
        }
        size_t ihl = static_cast<size_t>(data[0] & 0x0f) * 4;
        size_t total = read_be16(data + 2);
        if (ihl < 20 || total < ihl || total > len) {
            if (error) *error = "bad IPv4 length";
            return false;
        }
        p.ip_version = 4;
        p.src.version = p.dst.version = 4;
        std::memcpy(p.src.bytes, data + 12, 4);
        std::memcpy(p.dst.bytes, data + 16, 4);
        p.protocol = data[9];
        p.ttl = data[8];
        uint16_t frag = read_be16(data + 6);
        p.fragment = (frag & 0x2000) != 0 || (frag & 0x1fff) != 0;
        p.frag_id = read_be16(data + 4);
        p.frag_offset = static_cast<uint32_t>(frag & 0x1fff) * 8;
        p.more_fragments = (frag & 0x2000) != 0;
        p.frag_data = data + ihl;
        p.frag_data_len = total - ihl;
        p.ip_header = data;
        p.ip_header_len = ihl;
        p.l4 = data + ihl;
        p.l4_len = total - ihl;
        p.total_len = total;
        return parse_transport(p, error);
    }
    if (version == 6) {
        if (len < 40) {
            if (error) *error = "short IPv6 header";
            return false;
        }
        size_t payload_len = read_be16(data + 4);
        if (40 + payload_len > len) {
            if (error) *error = "bad IPv6 length";
            return false;
        }
        p.ip_version = 6;
        p.src.version = p.dst.version = 6;
        std::memcpy(p.src.bytes, data + 8, 16);
        std::memcpy(p.dst.bytes, data + 24, 16);
        p.ttl = data[7];
        p.total_len = 40 + payload_len;
        p.ip_header = data;

        // Walk the extension headers
        uint8_t next = data[6];
        size_t offset = 40;
        for (int i = 0; i < 8; ++i) {
            if (next == 0 || next == 43 || next == 60) { // hop-by-hop, routing, destination options
                if (offset + 8 > p.total_len) {
                    if (error) *error = "truncated IPv6 extension header";
                    return false;
                }
                uint8_t nh = data[offset];
                offset += (static_cast<size_t>(data[offset + 1]) + 1) * 8;
                next = nh;
            } else if (next == 44) { // fragment
                if (offset + 8 > p.total_len) {
                    if (error) *error = "truncated IPv6 fragment header";
                    return false;
                }
                uint8_t nh = data[offset];
                uint16_t frag = read_be16(data + offset + 2);
                p.fragment = (frag & 0xfff8) != 0 || (frag & 1) != 0;
                p.frag_offset = frag & 0xfff8;
                p.more_fragments = (frag & 1) != 0;
                p.frag_id = read_be32(data + offset + 4);
                offset += 8;
                p.frag_data = data + offset;
                p.frag_data_len = p.total_len > offset ? p.total_len - offset : 0;
                next = nh;
            } else {
                break;
            }
        }
        if (offset > p.total_len) {
            if (error) *error = "bad IPv6 extension headers";
            return false;
        }
        p.protocol = next;
        p.ip_header_len = offset;
        p.l4 = data + offset;
        p.l4_len = p.total_len - offset;
        return parse_transport(p, error);
    }
    if (error) *error = "unknown IP version " + std::to_string(version);
    return false;
}

std::string tcp_flags_string(uint8_t flags) {
    std::string s;
    if (flags & kTcpSyn) s += 'S';
    if (flags & kTcpFin) s += 'F';
    if (flags & kTcpRst) s += 'R';
    if (flags & kTcpPsh) s += 'P';
    if (flags & kTcpAck) s += '.';
    if (flags & kTcpUrg) s += 'U';
    return s;
}

static std::string endpoint(const IpAddr& ip, uint16_t port) {
    if (ip.version == 6) {
        return "[" + ip.to_string() + "]:" + std::to_string(port);
    }
    return ip.to_string() + ":" + std::to_string(port);
}

std::string describe_packet(const ParsedPacket& p) {
    char buf[256];
    switch (p.protocol) {
    case kProtoTcp:
        snprintf(buf, sizeof(buf), "TCP %s -> %s [%s] seq=%u ack=%u win=%u len=%zu",
                 endpoint(p.src, p.src_port).c_str(), endpoint(p.dst, p.dst_port).c_str(),
                 tcp_flags_string(p.tcp_flags).c_str(), p.seq, p.ack, p.window, p.payload_len);
        break;
    case kProtoUdp:
        snprintf(buf, sizeof(buf), "UDP %s -> %s len=%zu", endpoint(p.src, p.src_port).c_str(),
                 endpoint(p.dst, p.dst_port).c_str(), p.payload_len);
        break;
    case kProtoIcmp:
    case kProtoIcmpV6:
        snprintf(buf, sizeof(buf), "ICMP%s %s -> %s type=%u code=%u id=%u seq=%u len=%zu",
                 p.protocol == kProtoIcmpV6 ? "v6" : "", p.src.to_string().c_str(), p.dst.to_string().c_str(),
                 p.icmp_type, p.icmp_code, p.icmp_id, p.icmp_seq, p.payload_len);
        break;
    default:
        snprintf(buf, sizeof(buf), "IP proto %u %s -> %s len=%zu", p.protocol, p.src.to_string().c_str(),
                 p.dst.to_string().c_str(), p.l4_len);
        break;
    }
    std::string s = buf;
    if (p.fragment) {
        s += " (fragment)";
    }
    return s;
}

uint32_t checksum_add(uint32_t sum, const uint8_t* data, size_t len) {
    size_t i = 0;
    for (; i + 1 < len; i += 2) {
        sum += static_cast<uint32_t>((data[i] << 8) | data[i + 1]);
    }
    if (i < len) {
        sum += static_cast<uint32_t>(data[i] << 8);
    }
    return sum;
}

uint16_t checksum_finish(uint32_t sum) {
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum & 0xffff);
}

// Write the IP header for `l4_len` bytes of transport data; returns header length
static size_t write_ip_header(uint8_t* out, const IpAddr& src, const IpAddr& dst, uint8_t protocol, size_t l4_len) {
    if (src.version == 4) {
        std::memset(out, 0, 20);
        out[0] = 0x45;
        write_be16(out + 2, static_cast<uint16_t>(20 + l4_len));
        write_be16(out + 6, 0x4000); // don't fragment
        out[8] = 64;
        out[9] = protocol;
        std::memcpy(out + 12, src.bytes, 4);
        std::memcpy(out + 16, dst.bytes, 4);
        write_be16(out + 10, checksum_finish(checksum_add(0, out, 20)));
        return 20;
    }
    std::memset(out, 0, 40);
    out[0] = 0x60;
    write_be16(out + 4, static_cast<uint16_t>(l4_len));
    out[6] = protocol;
    out[7] = 64;
    std::memcpy(out + 8, src.bytes, 16);
    std::memcpy(out + 24, dst.bytes, 16);
    return 40;
}

static uint32_t pseudo_header_sum(const IpAddr& src, const IpAddr& dst, uint8_t protocol, size_t l4_len) {
    uint32_t sum = 0;
    size_t alen = src.version == 4 ? 4 : 16;
    sum = checksum_add(sum, src.bytes, alen);
    sum = checksum_add(sum, dst.bytes, alen);
    sum += protocol;
    sum += static_cast<uint32_t>(l4_len & 0xffff);
    sum += static_cast<uint32_t>(l4_len >> 16);
    return sum;
}

void fragment_packet(const std::string& packet, int mtu, uint32_t id, std::vector<std::string>& out) {
    out.clear();
    const uint8_t* data = reinterpret_cast<const uint8_t*>(packet.data());
    if (packet.size() <= static_cast<size_t>(mtu) || packet.empty()) {
        out.push_back(packet);
        return;
    }
    if ((data[0] >> 4) == 4) {
        size_t ihl = static_cast<size_t>(data[0] & 0x0f) * 4;
        size_t chunk_max = ((static_cast<size_t>(mtu) - ihl) / 8) * 8;
        for (size_t off = ihl; off < packet.size(); off += chunk_max) {
            size_t chunk = std::min(chunk_max, packet.size() - off);
            bool more = off + chunk < packet.size();
            std::string frag(packet, 0, ihl);
            frag.append(packet, off, chunk);
            uint8_t* h = reinterpret_cast<uint8_t*>(&frag[0]);
            write_be16(h + 2, static_cast<uint16_t>(ihl + chunk));
            write_be16(h + 4, static_cast<uint16_t>(id));
            write_be16(h + 6, static_cast<uint16_t>(((off - ihl) / 8) | (more ? 0x2000 : 0)));
            write_be16(h + 10, 0);
            write_be16(h + 10, checksum_finish(checksum_add(0, h, ihl)));
            out.push_back(frag);
        }
        return;
    }
    // IPv6: insert a fragment header after the fixed 40 byte header (we only
    // build packets without extension headers)
    size_t chunk_max = ((static_cast<size_t>(mtu) - 48) / 8) * 8;
    uint8_t next_header = data[6];
    for (size_t off = 40; off < packet.size(); off += chunk_max) {
        size_t chunk = std::min(chunk_max, packet.size() - off);
        bool more = off + chunk < packet.size();
        std::string frag(packet, 0, 40);
        uint8_t fh[8];
        fh[0] = next_header;
        fh[1] = 0;
        write_be16(fh + 2, static_cast<uint16_t>((off - 40) | (more ? 1 : 0)));
        write_be32(fh + 4, id);
        frag.append(reinterpret_cast<const char*>(fh), 8);
        frag.append(packet, off, chunk);
        uint8_t* h = reinterpret_cast<uint8_t*>(&frag[0]);
        h[6] = 44;
        write_be16(h + 4, static_cast<uint16_t>(8 + chunk));
        out.push_back(frag);
    }
}

bool FragmentReassembler::add(const ParsedPacket& f, int64_t now_ms, std::string& packet) {
    if (f.frag_data == nullptr || f.frag_offset + f.frag_data_len > 65535) {
        return false;
    }
    if (f.more_fragments && f.frag_data_len % 8 != 0) {
        return false; // all but the last fragment carry a multiple of 8 bytes
    }
    Buffer* buf = nullptr;
    for (Buffer& b : buffers_) {
        if (b.version == f.ip_version && b.id == f.frag_id && b.protocol == f.protocol && b.src == f.src &&
            b.dst == f.dst) {
            buf = &b;
            break;
        }
    }
    if (buf == nullptr) {
        if (buffers_.size() >= 64) {
            buffers_.erase(buffers_.begin()); // drop the oldest
        }
        buffers_.emplace_back();
        buf = &buffers_.back();
        buf->version = f.ip_version;
        buf->src = f.src;
        buf->dst = f.dst;
        buf->id = f.frag_id;
        buf->protocol = f.protocol;
        buf->created_ms = now_ms;
    }

    size_t end = f.frag_offset + f.frag_data_len;
    if (buf->data.size() < end) {
        buf->data.resize(end);
        buf->have.resize((end + 7) / 8, false);
    }
    std::memcpy(&buf->data[f.frag_offset], f.frag_data, f.frag_data_len);
    for (size_t block = f.frag_offset / 8; block < (end + 7) / 8; ++block) {
        buf->have[block] = true;
    }
    if (!f.more_fragments) {
        buf->total = end;
    }
    if (f.frag_offset == 0) {
        if (f.ip_version == 4) {
            buf->header.assign(reinterpret_cast<const char*>(f.ip_header), f.ip_header_len);
        } else {
            buf->header.assign(reinterpret_cast<const char*>(f.ip_header), 40);
        }
    }

    if (buf->total == 0 || buf->header.empty()) {
        return false;
    }
    for (size_t block = 0; block < (buf->total + 7) / 8; ++block) {
        if (!buf->have[block]) {
            return false;
        }
    }

    // Complete: build an unfragmented packet
    packet = buf->header;
    packet.append(buf->data, 0, buf->total);
    uint8_t* h = reinterpret_cast<uint8_t*>(&packet[0]);
    if (buf->version == 4) {
        size_t ihl = buf->header.size();
        write_be16(h + 2, static_cast<uint16_t>(ihl + buf->total));
        write_be16(h + 6, 0);
        write_be16(h + 10, 0);
        write_be16(h + 10, checksum_finish(checksum_add(0, h, ihl)));
    } else {
        h[6] = buf->protocol; // extension headers before the fragment header are dropped
        write_be16(h + 4, static_cast<uint16_t>(buf->total));
    }
    buffers_.erase(buffers_.begin() + (buf - &buffers_[0]));
    return true;
}

void FragmentReassembler::expire(int64_t now_ms, int timeout_ms) {
    for (size_t i = 0; i < buffers_.size();) {
        if (now_ms - buffers_[i].created_ms > timeout_ms) {
            buffers_.erase(buffers_.begin() + static_cast<long>(i));
        } else {
            ++i;
        }
    }
}

void build_tcp_packet(std::string& out, const IpAddr& src, uint16_t src_port, const IpAddr& dst, uint16_t dst_port,
                      uint32_t seq, uint32_t ack, uint8_t flags, uint16_t window, const uint8_t* options,
                      size_t options_len, const uint8_t* payload, size_t payload_len) {
    size_t opt_padded = (options_len + 3) & ~static_cast<size_t>(3);
    size_t tcp_hlen = 20 + opt_padded;
    size_t l4_len = tcp_hlen + payload_len;
    size_t ip_hlen = src.version == 4 ? 20 : 40;
    out.assign(ip_hlen + l4_len, '\0');
    uint8_t* p = reinterpret_cast<uint8_t*>(&out[0]);
    write_ip_header(p, src, dst, kProtoTcp, l4_len);

    uint8_t* tcp = p + ip_hlen;
    write_be16(tcp, src_port);
    write_be16(tcp + 2, dst_port);
    write_be32(tcp + 4, seq);
    write_be32(tcp + 8, ack);
    tcp[12] = static_cast<uint8_t>((tcp_hlen / 4) << 4);
    tcp[13] = flags;
    write_be16(tcp + 14, window);
    if (options_len > 0) {
        std::memcpy(tcp + 20, options, options_len); // padding stays 0 (EOL)
    }
    if (payload_len > 0) {
        std::memcpy(tcp + tcp_hlen, payload, payload_len);
    }
    uint32_t sum = pseudo_header_sum(src, dst, kProtoTcp, l4_len);
    write_be16(tcp + 16, checksum_finish(checksum_add(sum, tcp, l4_len)));
}

void build_udp_packet(std::string& out, const IpAddr& src, uint16_t src_port, const IpAddr& dst, uint16_t dst_port,
                      const uint8_t* payload, size_t payload_len) {
    size_t l4_len = 8 + payload_len;
    size_t ip_hlen = src.version == 4 ? 20 : 40;
    out.assign(ip_hlen + l4_len, '\0');
    uint8_t* p = reinterpret_cast<uint8_t*>(&out[0]);
    write_ip_header(p, src, dst, kProtoUdp, l4_len);
    uint8_t* udp = p + ip_hlen;
    write_be16(udp, src_port);
    write_be16(udp + 2, dst_port);
    write_be16(udp + 4, static_cast<uint16_t>(l4_len));
    if (payload_len > 0) {
        std::memcpy(udp + 8, payload, payload_len);
    }
    uint32_t sum = pseudo_header_sum(src, dst, kProtoUdp, l4_len);
    uint16_t cs = checksum_finish(checksum_add(sum, udp, l4_len));
    write_be16(udp + 6, cs == 0 ? 0xffff : cs);
}

void build_icmp_packet(std::string& out, const IpAddr& src, const IpAddr& dst, uint8_t type, uint8_t code,
                       uint32_t header_rest, const uint8_t* payload, size_t payload_len) {
    bool v6 = src.version == 6;
    uint8_t protocol = v6 ? kProtoIcmpV6 : kProtoIcmp;
    size_t l4_len = 8 + payload_len;
    size_t ip_hlen = v6 ? 40 : 20;
    out.assign(ip_hlen + l4_len, '\0');
    uint8_t* p = reinterpret_cast<uint8_t*>(&out[0]);
    write_ip_header(p, src, dst, protocol, l4_len);
    uint8_t* icmp = p + ip_hlen;
    icmp[0] = type;
    icmp[1] = code;
    write_be32(icmp + 4, header_rest);
    if (payload_len > 0) {
        std::memcpy(icmp + 8, payload, payload_len);
    }
    uint32_t sum = v6 ? pseudo_header_sum(src, dst, protocol, l4_len) : 0;
    write_be16(icmp + 2, checksum_finish(checksum_add(sum, icmp, l4_len)));
}

} // namespace vpn
