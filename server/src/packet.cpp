/**
 * @file packet.cpp
 * @brief Implementation of IP / TCP / UDP / ICMP parsing, building,
 *        checksums, fragmentation and reassembly.
 *
 * Every packet the phone sends enters the server through parse_packet(), and
 * every packet the server sends back to the phone is produced by one of the
 * build_*_packet() functions (see packet.h for the role of each function in
 * the data path, and docs/en/architecture.md for the big picture).
 *
 * Reading guide: start with parse_packet() (IP layer), continue with
 * parse_transport() and parse_tcp_options() (transport layer), then the
 * checksum helpers, write_ip_header() / pseudo_header_sum() and the
 * builders, and finish with fragment_packet() and FragmentReassembler.
 *
 * Header layouts used below (byte offsets, all fields big endian):
 *
 *  IPv4 (RFC 791), 20 bytes + options:
 *    0 version (high 4 bits) + IHL (low 4 bits, header length in 32 bit words)
 *    1 DSCP / ECN (type of service)   2 total length (header + data)
 *    4 identification                 6 flags (3 bits) + fragment offset (13 bits)
 *    8 TTL      9 protocol            10 header checksum
 *   12 source address                16 destination address     20 options
 *
 *  IPv6 (RFC 8200), 40 bytes fixed:
 *    0 version (4 bits), traffic class (8), flow label (20)
 *    4 payload length (everything after these 40 bytes)
 *    6 next header      7 hop limit   8 source address   24 destination address
 *
 *  TCP (RFC 9293), 20 bytes + options:
 *    0 source port   2 destination port   4 sequence number   8 acknowledgment number
 *   12 data offset (high 4 bits, header length in 32 bit words)   13 flags
 *   14 window   16 checksum   18 urgent pointer   20 options
 *
 *  UDP (RFC 768), 8 bytes:
 *    0 source port   2 destination port   4 length (header + data)   6 checksum
 *
 *  ICMP / ICMPv6 (RFC 792 / RFC 4443), 8 bytes:
 *    0 type   1 code   2 checksum   4 rest of header (echo: identifier, sequence)
 */
#include "packet.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <sys/socket.h>

namespace vpn {

/**
 * @brief Compare family and address bytes.
 *
 * Only the first 4 bytes are compared for IPv4, so unused trailing bytes can
 * never make two equal IPv4 addresses differ.
 * @param o Other address.
 * @return true if equal.
 */
bool IpAddr::operator==(const IpAddr& o) const {
    return version == o.version && std::memcmp(bytes, o.bytes, version == 4 ? 4 : 16) == 0;
}

/**
 * @brief Text form of the address via inet_ntop().
 * @return Dotted quad for IPv4, RFC 5952 text for IPv6, "?" otherwise.
 */
std::string IpAddr::to_string() const {
    char buf[INET6_ADDRSTRLEN] = "?"; // big enough for the longest IPv6 text; "?" stays for unknown versions
    if (version == 4) {
        inet_ntop(AF_INET, bytes, buf, sizeof(buf));
    } else if (version == 6) {
        inet_ntop(AF_INET6, bytes, buf, sizeof(buf));
    }
    return buf;
}

/**
 * @brief Build the reactor's NetAddr (used by srv_connect) for this address.
 * @param port Port in host byte order (NetAddr stores the port in host order).
 * @return The socket address.
 */
NetAddr IpAddr::to_netaddr(uint16_t port) const {
    NetAddr addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.family = version == 4 ? AF_INET : AF_INET6;
    addr.port = port;
    std::memcpy(addr.ip, bytes, version == 4 ? 4 : 16); // both sides are network byte order
    return addr;
}

/**
 * @brief Take the IP part of a NetAddr.
 * @param addr Reactor socket address.
 * @return The address, or a version 0 IpAddr for an unknown family.
 */
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

/**
 * @brief Detect multicast and broadcast destinations.
 *
 * Note: subnet directed broadcasts (e.g. 192.168.1.255) cannot be recognized
 * without knowing the netmask and are therefore not detected.
 * @return true for IPv4 224.0.0.0/4 or 255.255.255.255, or IPv6 ff00::/8.
 */
bool IpAddr::is_multicast_or_broadcast() const {
    if (version == 4) {
        return (bytes[0] >= 224 && bytes[0] <= 239) ||                                // class D: 224.0.0.0 - 239.255.255.255
               (bytes[0] == 255 && bytes[1] == 255 && bytes[2] == 255 && bytes[3] == 255); // limited broadcast
    }
    return bytes[0] == 0xff; // IPv6 multicast prefix ff00::/8
}

/**
 * @brief Polynomial hash over version and the relevant address bytes.
 * @return Hash value (only needs to spread flows over hash buckets).
 */
size_t IpAddr::hash() const {
    size_t h = version;
    for (int i = 0; i < (version == 4 ? 4 : 16); ++i) {
        h = h * 131 + bytes[i]; // 131 is a prime, the multiplier of the classic BKDR string hash
    }
    return h;
}

/**
 * @brief Decode the TCP options that matter for the user-space TCP endpoint.
 *
 * The options area is a sequence of TLV entries (kind, length, value), plus
 * the single byte kinds 0 (End of Option List) and 1 (NOP, used as padding so
 * that following options are aligned). Parsing stops at the first malformed
 * entry; what was decoded so far is kept, which is what real stacks do too.
 *
 * @param opt Start of the options (TCP header + 20).
 * @param len Length of the options area (data offset * 4 - 20).
 * @param out Receives MSS, window scale, SACK permitted and timestamps flags.
 */
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
            break; // no room for the length byte
        }
        uint8_t olen = opt[i + 1]; // length of the whole option, kind and length bytes included
        if (olen < 2 || i + olen > len) {
            break; // a length < 2 would loop forever; a length past the end is truncated
        }
        switch (kind) {
        case 2: // Maximum Segment Size: 2 byte value, only valid in SYN segments
            if (olen == 4) {
                out.mss = read_be16(opt + i + 2);
            }
            break;
        case 3: // Window Scale: 1 byte shift count, window = field << shift (RFC 7323)
            if (olen == 3) {
                out.wscale = opt[i + 2] > 14 ? 14 : opt[i + 2]; // RFC 7323: values above 14 are treated as 14
            }
            break;
        case 4: // SACK Permitted (RFC 2018), no value
            out.sack_permitted = true;
            break;
        case 8: // Timestamps (RFC 7323): TSval + TSecr, 4 bytes each
            out.timestamps = true;
            break;
        default:
            break; // unknown options are skipped thanks to their length byte
        }
        i += olen;
    }
}

/**
 * @brief Decode the transport header of a parsed IP packet.
 *
 * Fills ports, sequence numbers, flags, window and options for TCP, ports
 * for UDP, type / code / id / sequence for ICMP and ICMPv6, and the payload
 * pointer for all of them. For other protocols the whole transport part is
 * the "payload".
 *
 * @param p     Packet whose IP layer fields (l4, l4_len, protocol, fragment) are set.
 * @param error Optional; receives the reason on failure.
 * @return false if the transport header is truncated or inconsistent.
 */
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
        size_t hlen = static_cast<size_t>(l4[12] >> 4) * 4; // data offset: header length in 32 bit words
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
        parse_tcp_options(l4 + 20, hlen - 20, p.tcp_options); // options sit between the fixed header and the data
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
        size_t ulen = read_be16(l4 + 4); // UDP length field: header (8) + data
        if (ulen < 8 || ulen > len) {
            ulen = len; // be tolerant
        }
        p.payload = l4 + 8;
        p.payload_len = ulen - 8; // a UDP length smaller than the IP payload trims trailing bytes
        return true;
    }
    case kProtoIcmp:
    case kProtoIcmpV6: {
        // Both ICMP versions share the first 8 bytes: type, code, checksum, 4 more bytes
        if (len < 8) {
            if (error) *error = "short ICMP header";
            return false;
        }
        p.icmp_type = l4[0];
        p.icmp_code = l4[1];
        p.icmp_id = read_be16(l4 + 4);  // meaningful for echo request / reply only
        p.icmp_seq = read_be16(l4 + 6); // meaningful for echo request / reply only
        p.payload = l4 + 8;
        p.payload_len = len - 8;
        return true;
    }
    default:
        // Unknown transport: no header to decode, expose everything after the IP header
        p.payload = l4;
        p.payload_len = len;
        return true;
    }
}

/**
 * @brief Parse a raw IPv4 / IPv6 packet (see packet.h for the contract).
 *
 * IPv4: checks IHL and total length, reads addresses, protocol, TTL and the
 * fragmentation fields. IPv6: checks the payload length, then walks up to 8
 * extension headers to find the transport protocol, decoding a Fragment
 * header on the way. Both then call parse_transport().
 *
 * @param data  Packet bytes.
 * @param len   Buffer length.
 * @param p     Output, reset to defaults first.
 * @param error Optional reason on failure.
 * @return true on success.
 */
bool parse_packet(const uint8_t* data, size_t len, ParsedPacket& p, std::string* error) {
    p = ParsedPacket();
    if (len < 1) {
        if (error) *error = "empty packet";
        return false;
    }
    uint8_t version = data[0] >> 4; // the version nibble is at the same place in IPv4 and IPv6
    if (version == 4) {
        if (len < 20) {
            if (error) *error = "short IPv4 header";
            return false;
        }
        size_t ihl = static_cast<size_t>(data[0] & 0x0f) * 4; // IHL counts 32 bit words: 5 = 20 bytes, max 15 = 60
        size_t total = read_be16(data + 2);                   // total length: header + data
        // total < ihl: impossible; total > len: truncated packet. total < len is fine
        // (bytes after `total` are link layer padding and are ignored).
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
        // Bytes 6..7: 0x8000 reserved, 0x4000 DF (don't fragment), 0x2000 MF (more
        // fragments), 0x1fff fragment offset in units of 8 bytes.
        uint16_t frag = read_be16(data + 6);
        // A fragment is any piece of a split datagram: MF set (all but the last
        // piece) or a non-zero offset (the last piece).
        p.fragment = (frag & 0x2000) != 0 || (frag & 0x1fff) != 0;
        p.frag_id = read_be16(data + 4);
        p.frag_offset = static_cast<uint32_t>(frag & 0x1fff) * 8; // convert 8 byte units to bytes
        p.more_fragments = (frag & 0x2000) != 0;
        p.frag_data = data + ihl; // in IPv4 everything after the header is fragmentable
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
        size_t payload_len = read_be16(data + 4); // excludes the fixed 40 byte header (jumbograms are not supported)
        if (40 + payload_len > len) {
            if (error) *error = "bad IPv6 length";
            return false;
        }
        p.ip_version = 6;
        p.src.version = p.dst.version = 6;
        std::memcpy(p.src.bytes, data + 8, 16);
        std::memcpy(p.dst.bytes, data + 24, 16);
        p.ttl = data[7]; // hop limit, the IPv6 name for TTL
        p.total_len = 40 + payload_len;
        p.ip_header = data;

        // Walk the extension headers
        // IPv6 has no protocol field: each header names the type of the next one
        // ("next header"), forming a chain that ends at the transport header.
        // The loop is bounded to 8 headers so a malicious chain cannot spin.
        uint8_t next = data[6];
        size_t offset = 40;
        for (int i = 0; i < 8; ++i) {
            if (next == 0 || next == 43 || next == 60) { // hop-by-hop, routing, destination options
                // Generic layout: next header (1), Hdr Ext Len (1) = length in 8 byte
                // units NOT counting the first 8 bytes, then the options.
                if (offset + 8 > p.total_len) {
                    if (error) *error = "truncated IPv6 extension header";
                    return false;
                }
                uint8_t nh = data[offset];
                offset += (static_cast<size_t>(data[offset + 1]) + 1) * 8;
                next = nh;
            } else if (next == 44) { // fragment
                // Fragment header, always 8 bytes: next header (1), reserved (1),
                // offset (13 bits, 8 byte units) + 2 reserved bits + M flag (1 bit),
                // identification (4).
                if (offset + 8 > p.total_len) {
                    if (error) *error = "truncated IPv6 fragment header";
                    return false;
                }
                uint8_t nh = data[offset];
                uint16_t frag = read_be16(data + offset + 2);
                // Offset 0 with M = 0 is an "atomic fragment" (RFC 6946): a whole
                // datagram that merely carries a fragment header, treated as unfragmented
                p.fragment = (frag & 0xfff8) != 0 || (frag & 1) != 0;
                // The offset occupies the top 13 bits, i.e. it is already shifted left
                // by 3: masking the low 3 bits gives "units * 8" = the byte offset.
                p.frag_offset = frag & 0xfff8;
                p.more_fragments = (frag & 1) != 0; // M flag
                p.frag_id = read_be32(data + offset + 4);
                offset += 8;
                p.frag_data = data + offset; // fragmentable part starts after the fragment header
                p.frag_data_len = p.total_len > offset ? p.total_len - offset : 0;
                next = nh;
            } else {
                break; // a transport protocol (or an unsupported header such as AH / ESP / 59 "no next header")
            }
        }
        // An extension header length may point past the end of the packet
        if (offset > p.total_len) {
            if (error) *error = "bad IPv6 extension headers";
            return false;
        }
        p.protocol = next;
        p.ip_header_len = offset; // fixed header + all extension headers
        p.l4 = data + offset;
        p.l4_len = p.total_len - offset;
        return parse_transport(p, error);
    }
    if (error) *error = "unknown IP version " + std::to_string(version);
    return false;
}

/**
 * @brief Flag letters in tcpdump notation ('.' means ACK).
 * @param flags kTcp* bits.
 * @return The letters of the set flags, e.g. "S." for SYN+ACK, "FP." for FIN+PSH+ACK.
 */
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

/**
 * @brief Format "address:port"; IPv6 addresses get brackets ("[::1]:53")
 *        because their text form already contains colons.
 * @param ip   Address.
 * @param port Port.
 * @return The endpoint text.
 */
static std::string endpoint(const IpAddr& ip, uint16_t port) {
    if (ip.version == 6) {
        return "[" + ip.to_string() + "]:" + std::to_string(port);
    }
    return ip.to_string() + ":" + std::to_string(port);
}

/**
 * @brief One line packet summary for the vpn_log_packets log.
 * @param p Parsed packet.
 * @return Summary text; output longer than 255 characters is truncated by snprintf.
 */
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
        s += " (fragment)"; // ports / flags are not decoded for fragments, so they print as 0
    }
    return s;
}

/**
 * @brief Add `data` to a running Internet checksum (see packet.h).
 *
 * A 32 bit accumulator cannot overflow for any IP packet: even 32768 words
 * of 0xffff (64 KiB of 0xff bytes) only add up to about 2^31. The carries
 * are folded later by checksum_finish().
 * @param sum  Running sum.
 * @param data Bytes.
 * @param len  Byte count.
 * @return New running sum.
 */
uint32_t checksum_add(uint32_t sum, const uint8_t* data, size_t len) {
    size_t i = 0;
    for (; i + 1 < len; i += 2) {
        sum += static_cast<uint32_t>((data[i] << 8) | data[i + 1]); // one big endian 16 bit word
    }
    if (i < len) {
        sum += static_cast<uint32_t>(data[i] << 8); // odd length: pad the last byte with a zero byte
    }
    return sum;
}

/**
 * @brief Fold carries into the low 16 bits and complement (see packet.h).
 * @param sum Running sum.
 * @return The checksum to store in the header.
 */
uint16_t checksum_finish(uint32_t sum) {
    // One's complement addition: a carry out of bit 15 is added back at bit 0
    // ("end around carry"). Repeat until no carry is left.
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum & 0xffff); // the checksum is the complement of the sum
}

/**
 * @brief Write a minimal IPv4 or IPv6 header (no options / extension headers).
 *
 * The family is chosen by `src.version`; `dst` must be of the same family.
 * IPv4 packets get DF set and identification 0 (RFC 6864 allows any ID for
 * atomic, i.e. unfragmented DF packets), TTL 64 and a computed header
 * checksum. IPv6 packets get traffic class / flow label 0 and hop limit 64.
 *
 * @param out      Destination buffer, at least 20 / 40 bytes.
 * @param src      Source address.
 * @param dst      Destination address.
 * @param protocol Transport protocol number.
 * @param l4_len   Length of the transport header + payload that follows.
 * @return The header length (20 or 40).
 */
static size_t write_ip_header(uint8_t* out, const IpAddr& src, const IpAddr& dst, uint8_t protocol, size_t l4_len) {
    if (src.version == 4) {
        std::memset(out, 0, 20); // also zeroes TOS, identification and the checksum field
        out[0] = 0x45;           // version 4, IHL 5 (20 bytes, no options)
        write_be16(out + 2, static_cast<uint16_t>(20 + l4_len)); // total length
        write_be16(out + 6, 0x4000); // don't fragment
        out[8] = 64;             // TTL: the common default initial value (Linux, Android)
        out[9] = protocol;
        std::memcpy(out + 12, src.bytes, 4);
        std::memcpy(out + 16, dst.bytes, 4);
        // The IPv4 header checksum covers only the header; it is computed while
        // the checksum field is still 0
        write_be16(out + 10, checksum_finish(checksum_add(0, out, 20)));
        return 20;
    }
    std::memset(out, 0, 40);
    out[0] = 0x60; // version 6, traffic class and flow label 0
    write_be16(out + 4, static_cast<uint16_t>(l4_len)); // payload length (header not included)
    out[6] = protocol; // next header: the transport protocol directly, no extension headers
    out[7] = 64;       // hop limit
    std::memcpy(out + 8, src.bytes, 16);
    std::memcpy(out + 24, dst.bytes, 16);
    return 40; // IPv6 has no header checksum: the transport checksums cover the addresses
}

/**
 * @brief Checksum contribution of the TCP / UDP / ICMPv6 "pseudo header".
 *
 * TCP, UDP and ICMPv6 checksums also cover a pseudo header made of IP layer
 * fields, so a packet delivered to the wrong address or protocol fails the
 * check. It is never sent, only summed:
 *  - IPv4: source (4), destination (4), zero (1), protocol (1), length (2)
 *  - IPv6: source (16), destination (16), length (4), zero (3), next header (1)
 * Because the one's complement sum only depends on where a byte falls inside
 * a 16 bit word, both layouts reduce to: addresses + protocol (as the low byte
 * of a word) + the length split into 16 bit halves.
 *
 * @param src      Source address.
 * @param dst      Destination address.
 * @param protocol Transport protocol number.
 * @param l4_len   Transport header + payload length.
 * @return Partial sum to pass to checksum_add() for the segment itself.
 */
static uint32_t pseudo_header_sum(const IpAddr& src, const IpAddr& dst, uint8_t protocol, size_t l4_len) {
    uint32_t sum = 0;
    size_t alen = src.version == 4 ? 4 : 16;
    sum = checksum_add(sum, src.bytes, alen);
    sum = checksum_add(sum, dst.bytes, alen);
    sum += protocol;                                // zero byte + protocol byte form one word
    sum += static_cast<uint32_t>(l4_len & 0xffff);  // low 16 bits of the length
    sum += static_cast<uint32_t>(l4_len >> 16);     // high 16 bits (IPv6 32 bit length; 0 in practice)
    return sum;
}

/**
 * @brief Split a packet into fragments of at most `mtu` bytes (see packet.h).
 *
 * The DF flag that write_ip_header() sets is ignored on purpose: these are
 * the server's own packets on their way into the tunnel, so it acts as the
 * sender, and the phone's stack will reassemble them.
 * @param packet Complete packet.
 * @param mtu    Maximum fragment size (>= 576, so chunk_max is never 0).
 * @param id     Fragment identification.
 * @param out    Receives the fragments, or the packet itself if it fits.
 */
void fragment_packet(const std::string& packet, int mtu, uint32_t id, std::vector<std::string>& out) {
    out.clear();
    const uint8_t* data = reinterpret_cast<const uint8_t*>(packet.data());
    if (packet.size() <= static_cast<size_t>(mtu) || packet.empty()) {
        out.push_back(packet);
        return;
    }
    if ((data[0] >> 4) == 4) {
        size_t ihl = static_cast<size_t>(data[0] & 0x0f) * 4;
        // Largest data size per fragment: what fits after the header, rounded
        // down to a multiple of 8 because the offset field counts 8 byte units
        size_t chunk_max = ((static_cast<size_t>(mtu) - ihl) / 8) * 8;
        for (size_t off = ihl; off < packet.size(); off += chunk_max) { // `off` indexes the original packet
            size_t chunk = std::min(chunk_max, packet.size() - off);
            bool more = off + chunk < packet.size(); // MF on every fragment but the last
            // Each fragment repeats the original header (built packets carry no
            // options, so the "copy only some options" rule does not matter)
            std::string frag(packet, 0, ihl);
            frag.append(packet, off, chunk);
            uint8_t* h = reinterpret_cast<uint8_t*>(&frag[0]);
            write_be16(h + 2, static_cast<uint16_t>(ihl + chunk)); // total length of this fragment
            write_be16(h + 4, static_cast<uint16_t>(id));          // same ID ties the fragments together
            // Offset of this piece's data in 8 byte units, plus MF; DF is cleared
            write_be16(h + 6, static_cast<uint16_t>(((off - ihl) / 8) | (more ? 0x2000 : 0)));
            write_be16(h + 10, 0); // zero the checksum field before recomputing it
            write_be16(h + 10, checksum_finish(checksum_add(0, h, ihl)));
            out.push_back(frag);
        }
        return;
    }
    // IPv6: insert a fragment header after the fixed 40 byte header (we only
    // build packets without extension headers)
    // 48 = 40 byte fixed header + 8 byte fragment header in every fragment
    size_t chunk_max = ((static_cast<size_t>(mtu) - 48) / 8) * 8;
    uint8_t next_header = data[6]; // the transport protocol; moves into the fragment header
    for (size_t off = 40; off < packet.size(); off += chunk_max) {
        size_t chunk = std::min(chunk_max, packet.size() - off);
        bool more = off + chunk < packet.size();
        std::string frag(packet, 0, 40);
        uint8_t fh[8]; // the fragment extension header
        fh[0] = next_header;
        fh[1] = 0; // reserved
        // (off - 40) is a multiple of 8, so the byte offset already equals
        // "offset in 8 byte units << 3"; bit 0 is the M (more fragments) flag
        write_be16(fh + 2, static_cast<uint16_t>((off - 40) | (more ? 1 : 0)));
        write_be32(fh + 4, id); // 32 bit identification
        frag.append(reinterpret_cast<const char*>(fh), 8);
        frag.append(packet, off, chunk);
        uint8_t* h = reinterpret_cast<uint8_t*>(&frag[0]);
        h[6] = 44; // next header of the fixed header: Fragment
        write_be16(h + 4, static_cast<uint16_t>(8 + chunk)); // payload length = fragment header + data
        out.push_back(frag);
    }
}

/**
 * @brief Add one fragment and return the full datagram once complete.
 *
 * Datagrams are identified by (version, id, protocol, src, dst). RFC 791 keys
 * IPv4 datagrams by source, destination, protocol and ID; RFC 8200 keys IPv6
 * ones by source, destination and ID (the extra protocol does no harm). Received data is tracked in 8 byte blocks; the
 * datagram is complete when the last fragment (MF = 0) told the total size,
 * the first fragment (offset 0) supplied the header, and every block is
 * present. Overlapping fragments simply overwrite earlier data (a learning
 * simplification; RFC 5722 says IPv6 should drop such datagrams).
 *
 * @param f      The fragment.
 * @param now_ms Current time, stored when a new datagram starts.
 * @param packet Receives the rebuilt packet.
 * @return true when `packet` holds the complete datagram.
 */
bool FragmentReassembler::add(const ParsedPacket& f, int64_t now_ms, std::string& packet) {
    // 65535 is the largest IP datagram; anything beyond it is an attack
    // ("ping of death") or garbage and would make the buffer grow arbitrarily
    if (f.frag_data == nullptr || f.frag_offset + f.frag_data_len > 65535) {
        return false;
    }
    if (f.more_fragments && f.frag_data_len % 8 != 0) {
        return false; // all but the last fragment carry a multiple of 8 bytes
    }
    // Find the datagram this fragment belongs to
    Buffer* buf = nullptr;
    for (Buffer& b : buffers_) {
        if (b.version == f.ip_version && b.id == f.frag_id && b.protocol == f.protocol && b.src == f.src &&
            b.dst == f.dst) {
            buf = &b;
            break;
        }
    }
    if (buf == nullptr) {
        // Bound the memory a misbehaving client can tie up
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

    // Copy the fragment's data to its place; fragments may arrive in any order
    size_t end = f.frag_offset + f.frag_data_len;
    if (buf->data.size() < end) {
        buf->data.resize(end);
        buf->have.resize((end + 7) / 8, false); // round up: the last fragment may end mid block
    }
    std::memcpy(&buf->data[f.frag_offset], f.frag_data, f.frag_data_len);
    for (size_t block = f.frag_offset / 8; block < (end + 7) / 8; ++block) {
        buf->have[block] = true;
    }
    if (!f.more_fragments) {
        buf->total = end; // the last fragment reveals the datagram size
    }
    if (f.frag_offset == 0) {
        // The first fragment's header becomes the header of the rebuilt packet
        if (f.ip_version == 4) {
            buf->header.assign(reinterpret_cast<const char*>(f.ip_header), f.ip_header_len);
        } else {
            buf->header.assign(reinterpret_cast<const char*>(f.ip_header), 40); // fixed header only
        }
    }

    if (buf->total == 0 || buf->header.empty()) {
        return false; // last or first fragment still missing
    }
    for (size_t block = 0; block < (buf->total + 7) / 8; ++block) {
        if (!buf->have[block]) {
            return false; // a hole: some middle fragment has not arrived yet
        }
    }

    // Complete: build an unfragmented packet
    packet = buf->header;
    packet.append(buf->data, 0, buf->total);
    uint8_t* h = reinterpret_cast<uint8_t*>(&packet[0]);
    if (buf->version == 4) {
        size_t ihl = buf->header.size();
        write_be16(h + 2, static_cast<uint16_t>(ihl + buf->total)); // new total length
        write_be16(h + 6, 0);  // clear MF and fragment offset (and DF)
        write_be16(h + 10, 0); // recompute the header checksum
        write_be16(h + 10, checksum_finish(checksum_add(0, h, ihl)));
    } else {
        h[6] = buf->protocol; // extension headers before the fragment header are dropped
        write_be16(h + 4, static_cast<uint16_t>(buf->total)); // payload length without the fragment header
    }
    buffers_.erase(buffers_.begin() + (buf - &buffers_[0])); // index of `buf` from pointer arithmetic
    return true;
}

/**
 * @brief Drop datagrams whose first received fragment arrived more than `timeout_ms` ago.
 * @param now_ms     Current time in milliseconds.
 * @param timeout_ms Maximum reassembly time.
 */
void FragmentReassembler::expire(int64_t now_ms, int timeout_ms) {
    for (size_t i = 0; i < buffers_.size();) {
        if (now_ms - buffers_[i].created_ms > timeout_ms) {
            buffers_.erase(buffers_.begin() + static_cast<long>(i)); // do not advance: the next entry moved to i
        } else {
            ++i;
        }
    }
}

/**
 * @brief Build an IP + TCP packet (see packet.h for the parameters).
 *
 * Layout: IP header, 20 byte TCP header, options padded to a multiple of 4,
 * payload. The TCP checksum covers pseudo header + TCP header + payload.
 */
void build_tcp_packet(std::string& out, const IpAddr& src, uint16_t src_port, const IpAddr& dst, uint16_t dst_port,
                      uint32_t seq, uint32_t ack, uint8_t flags, uint16_t window, const uint8_t* options,
                      size_t options_len, const uint8_t* payload, size_t payload_len) {
    size_t opt_padded = (options_len + 3) & ~static_cast<size_t>(3); // round up to a multiple of 4
    size_t tcp_hlen = 20 + opt_padded;
    size_t l4_len = tcp_hlen + payload_len;
    size_t ip_hlen = src.version == 4 ? 20 : 40;
    out.assign(ip_hlen + l4_len, '\0'); // zero filled: checksum, urgent pointer and padding start as 0
    uint8_t* p = reinterpret_cast<uint8_t*>(&out[0]);
    write_ip_header(p, src, dst, kProtoTcp, l4_len);

    uint8_t* tcp = p + ip_hlen;
    write_be16(tcp, src_port);
    write_be16(tcp + 2, dst_port);
    write_be32(tcp + 4, seq);
    write_be32(tcp + 8, ack);
    tcp[12] = static_cast<uint8_t>((tcp_hlen / 4) << 4); // data offset in 32 bit words, high nibble
    tcp[13] = flags;
    write_be16(tcp + 14, window);
    if (options_len > 0) {
        std::memcpy(tcp + 20, options, options_len); // padding stays 0 (EOL)
    }
    if (payload_len > 0) {
        std::memcpy(tcp + tcp_hlen, payload, payload_len);
    }
    uint32_t sum = pseudo_header_sum(src, dst, kProtoTcp, l4_len);
    write_be16(tcp + 16, checksum_finish(checksum_add(sum, tcp, l4_len))); // checksum field was 0 while summing
}

/**
 * @brief Build an IP + UDP packet (see packet.h for the parameters).
 *
 * UDP checksum detail (RFC 768): a transmitted value of 0 means "no
 * checksum" (allowed for IPv4 only), so a computed 0 is sent as 0xffff,
 * which is the same number in one's complement arithmetic (-0 vs +0).
 */
void build_udp_packet(std::string& out, const IpAddr& src, uint16_t src_port, const IpAddr& dst, uint16_t dst_port,
                      const uint8_t* payload, size_t payload_len) {
    size_t l4_len = 8 + payload_len; // 8 byte UDP header + data
    size_t ip_hlen = src.version == 4 ? 20 : 40;
    out.assign(ip_hlen + l4_len, '\0');
    uint8_t* p = reinterpret_cast<uint8_t*>(&out[0]);
    write_ip_header(p, src, dst, kProtoUdp, l4_len);
    uint8_t* udp = p + ip_hlen;
    write_be16(udp, src_port);
    write_be16(udp + 2, dst_port);
    write_be16(udp + 4, static_cast<uint16_t>(l4_len)); // UDP length includes the header
    if (payload_len > 0) {
        std::memcpy(udp + 8, payload, payload_len);
    }
    uint32_t sum = pseudo_header_sum(src, dst, kProtoUdp, l4_len);
    uint16_t cs = checksum_finish(checksum_add(sum, udp, l4_len));
    write_be16(udp + 6, cs == 0 ? 0xffff : cs); // 0 would mean "no checksum"
}

/**
 * @brief Build an IP + ICMP / ICMPv6 packet (see packet.h for the parameters).
 *
 * Difference between the versions: the ICMP (v4) checksum covers only the
 * ICMP message, while ICMPv6 (RFC 4443) includes the IPv6 pseudo header like
 * TCP and UDP do, because IPv6 has no header checksum of its own.
 */
void build_icmp_packet(std::string& out, const IpAddr& src, const IpAddr& dst, uint8_t type, uint8_t code,
                       uint32_t header_rest, const uint8_t* payload, size_t payload_len) {
    bool v6 = src.version == 6;
    uint8_t protocol = v6 ? kProtoIcmpV6 : kProtoIcmp;
    size_t l4_len = 8 + payload_len; // 8 byte ICMP header + data
    size_t ip_hlen = v6 ? 40 : 20;
    out.assign(ip_hlen + l4_len, '\0');
    uint8_t* p = reinterpret_cast<uint8_t*>(&out[0]);
    write_ip_header(p, src, dst, protocol, l4_len);
    uint8_t* icmp = p + ip_hlen;
    icmp[0] = type;
    icmp[1] = code;
    write_be32(icmp + 4, header_rest); // bytes 2..3 (checksum) stay 0 until computed below
    if (payload_len > 0) {
        std::memcpy(icmp + 8, payload, payload_len);
    }
    uint32_t sum = v6 ? pseudo_header_sum(src, dst, protocol, l4_len) : 0; // pseudo header only for ICMPv6
    write_be16(icmp + 2, checksum_finish(checksum_add(sum, icmp, l4_len)));
}

} // namespace vpn
