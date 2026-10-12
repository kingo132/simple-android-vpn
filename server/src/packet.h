// IPv4 / IPv6 / TCP / UDP / ICMP parsing and building
#ifndef SIMPLEVPN_PACKET_H
#define SIMPLEVPN_PACKET_H

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "server_api.h"

namespace vpn {

constexpr uint8_t kProtoIcmp = 1;
constexpr uint8_t kProtoTcp = 6;
constexpr uint8_t kProtoUdp = 17;
constexpr uint8_t kProtoIcmpV6 = 58;

// TCP flags
constexpr uint8_t kTcpFin = 0x01;
constexpr uint8_t kTcpSyn = 0x02;
constexpr uint8_t kTcpRst = 0x04;
constexpr uint8_t kTcpPsh = 0x08;
constexpr uint8_t kTcpAck = 0x10;
constexpr uint8_t kTcpUrg = 0x20;

struct IpAddr {
    uint8_t version = 0;   // 4 or 6
    uint8_t bytes[16] = {0};

    bool operator==(const IpAddr& o) const;
    bool operator!=(const IpAddr& o) const { return !(*this == o); }
    std::string to_string() const;
    NetAddr to_netaddr(uint16_t port) const;
    static IpAddr from_netaddr(const NetAddr& addr);
    bool is_multicast_or_broadcast() const;
    size_t hash() const;
};

struct TcpOptions {
    uint16_t mss = 0;          // 0 = not present
    int wscale = -1;           // -1 = not present
    bool sack_permitted = false;
    bool timestamps = false;
};

struct ParsedPacket {
    uint8_t ip_version = 0;
    IpAddr src;
    IpAddr dst;
    uint8_t protocol = 0;       // transport protocol (after IPv6 extension headers)
    uint8_t ttl = 0;
    bool fragment = false;      // IPv4 / IPv6 fragment (see FragmentReassembler)
    uint32_t frag_id = 0;       // identification (IPv4: 16 bit, IPv6: 32 bit)
    uint32_t frag_offset = 0;   // byte offset of this fragment
    bool more_fragments = false;
    const uint8_t* frag_data = nullptr; // fragmentable part (after the IPv4 header / IPv6 fragment header)
    size_t frag_data_len = 0;
    const uint8_t* ip_header = nullptr;
    size_t ip_header_len = 0;
    const uint8_t* l4 = nullptr; // transport header
    size_t l4_len = 0;           // transport header + payload
    size_t total_len = 0;

    // TCP / UDP
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    // TCP
    uint32_t seq = 0;
    uint32_t ack = 0;
    uint8_t tcp_flags = 0;
    uint16_t window = 0;
    TcpOptions tcp_options;
    // ICMP / ICMPv6
    uint8_t icmp_type = 0;
    uint8_t icmp_code = 0;
    uint16_t icmp_id = 0;
    uint16_t icmp_seq = 0;

    const uint8_t* payload = nullptr; // TCP / UDP / ICMP echo payload
    size_t payload_len = 0;
};

// Parse a raw IP packet. Returns false (with a reason) if it is malformed.
bool parse_packet(const uint8_t* data, size_t len, ParsedPacket& out, std::string* error);

// Human readable one line summary, e.g. "TCP 10.0.0.2:5000 -> 1.2.3.4:443 [S] seq=.. len=0"
std::string describe_packet(const ParsedPacket& p);
std::string tcp_flags_string(uint8_t flags);

// Split a packet larger than `mtu` into IP fragments (IPv4 or IPv6 fragment
// header). Packets that fit are returned unchanged.
void fragment_packet(const std::string& packet, int mtu, uint32_t id, std::vector<std::string>& out);

// Reassembles IPv4 / IPv6 fragments into complete packets
class FragmentReassembler {
public:
    // Add a fragment; returns true and fills `packet` once the datagram is complete
    bool add(const ParsedPacket& fragment, int64_t now_ms, std::string& packet);
    // Drop incomplete datagrams older than timeout_ms
    void expire(int64_t now_ms, int timeout_ms = 30000);
    size_t pending() const { return buffers_.size(); }

private:
    struct Buffer {
        uint8_t version = 0;
        IpAddr src, dst;
        uint32_t id = 0;
        uint8_t protocol = 0;
        std::string header;          // IP header of the first fragment (offset 0)
        std::string data;            // reassembled payload
        std::vector<bool> have;      // received 8 byte blocks
        size_t total = 0;            // payload length, known after the last fragment
        int64_t created_ms = 0;
    };
    std::vector<Buffer> buffers_;    // few at a time, a vector is fine
};

// Internet checksum helpers
uint32_t checksum_add(uint32_t sum, const uint8_t* data, size_t len);
uint16_t checksum_finish(uint32_t sum);

// Builders: the complete IP packet is written to `out` (replacing its content)
void build_tcp_packet(std::string& out, const IpAddr& src, uint16_t src_port, const IpAddr& dst, uint16_t dst_port,
                      uint32_t seq, uint32_t ack, uint8_t flags, uint16_t window, const uint8_t* options,
                      size_t options_len, const uint8_t* payload, size_t payload_len);

void build_udp_packet(std::string& out, const IpAddr& src, uint16_t src_port, const IpAddr& dst, uint16_t dst_port,
                      const uint8_t* payload, size_t payload_len);

// ICMP (v4) or ICMPv6 depending on the address family. `header_rest` are
// bytes 4..7 of the ICMP header (id/seq for echo, unused/MTU for errors).
void build_icmp_packet(std::string& out, const IpAddr& src, const IpAddr& dst, uint8_t type, uint8_t code,
                       uint32_t header_rest, const uint8_t* payload, size_t payload_len);

inline bool seq_lt(uint32_t a, uint32_t b) { return static_cast<int32_t>(a - b) < 0; }
inline bool seq_le(uint32_t a, uint32_t b) { return static_cast<int32_t>(a - b) <= 0; }
inline bool seq_gt(uint32_t a, uint32_t b) { return static_cast<int32_t>(a - b) > 0; }

inline uint16_t read_be16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
inline uint32_t read_be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}
inline void write_be16(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v);
}
inline void write_be32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

} // namespace vpn

#endif // SIMPLEVPN_PACKET_H
