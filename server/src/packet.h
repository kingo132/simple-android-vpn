/**
 * @file packet.h
 * @brief IPv4 / IPv6 / TCP / UDP / ICMP parsing and building.
 *
 * Overview
 * --------
 * The phone's TUN device hands the client app raw IP packets (no Ethernet
 * header). The client forwards each one through the tunnel and the server
 * (vpn_session.cpp) calls parse_packet() on it. The result, a ParsedPacket,
 * is a set of decoded header fields plus pointers into the original buffer;
 * nothing is copied. Flows (flows.cpp) use it to drive the user-space TCP
 * endpoint and the UDP / ICMP NAT.
 *
 * In the opposite direction the server has to invent packets that look as if
 * they came from the real internet host: SYN-ACKs, data segments and ACKs of
 * the terminated TCP connection, UDP replies, ICMP echo replies and errors.
 * build_tcp_packet(), build_udp_packet() and build_icmp_packet() produce
 * complete IP packets with correct lengths and checksums for that purpose.
 *
 * Fragmentation is handled at both edges: FragmentReassembler joins IP
 * fragments sent by the phone before they are dispatched, and
 * fragment_packet() splits a packet that is larger than the phone's TUN MTU
 * (for example a big UDP datagram) the way a router would.
 *
 * Reading guide
 * -------------
 *  1. IpAddr, TcpOptions, ParsedPacket: the data model.
 *  2. parse_packet() in packet.cpp: IPv4 header, IPv6 extension header walk,
 *     then parse_transport() for TCP / UDP / ICMP.
 *  3. checksum_add() / checksum_finish(): the Internet checksum (RFC 1071).
 *  4. The build_*_packet() functions and fragment_packet().
 *  5. FragmentReassembler.
 *
 * All multi-byte header fields on the wire are big endian ("network byte
 * order"); the read_be* / write_be* helpers at the end of this header convert
 * them byte by byte, which works on any host and at any alignment.
 * See docs/en/architecture.md for the overall data path.
 */
#ifndef SIMPLEVPN_PACKET_H
#define SIMPLEVPN_PACKET_H

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "server_api.h"

namespace vpn {

// IANA "Assigned Internet Protocol Numbers": the value of the IPv4 Protocol
// field or of the IPv6 Next Header field that names the transport protocol.
constexpr uint8_t kProtoIcmp = 1;    // ICMP for IPv4 (RFC 792)
constexpr uint8_t kProtoTcp = 6;     // TCP (RFC 9293)
constexpr uint8_t kProtoUdp = 17;    // UDP (RFC 768)
constexpr uint8_t kProtoIcmpV6 = 58; // ICMPv6 (RFC 4443); IPv6 uses it instead of ICMP

// TCP flags: bits of byte 13 of the TCP header. The two top bits (0x40 ECE,
// 0x80 CWR, used by ECN) are not needed by this project.
constexpr uint8_t kTcpFin = 0x01; // sender has finished sending (half close)
constexpr uint8_t kTcpSyn = 0x02; // synchronize sequence numbers (connection setup)
constexpr uint8_t kTcpRst = 0x04; // reset: abort the connection
constexpr uint8_t kTcpPsh = 0x08; // push: deliver buffered data to the application now
constexpr uint8_t kTcpAck = 0x10; // the acknowledgment number field is valid
constexpr uint8_t kTcpUrg = 0x20; // the urgent pointer field is valid (rarely used)

/**
 * @brief An IPv4 or IPv6 address stored as raw network-order bytes.
 *
 * One fixed size type for both families keeps flow keys (FlowKey in
 * vpn_session.h) simple. IPv4 uses bytes[0..3], the rest stays zero.
 * A default constructed IpAddr (version 0) means "no address".
 */
struct IpAddr {
    uint8_t version = 0;   // 4 or 6 (0 = unset)
    uint8_t bytes[16] = {0}; // address in network byte order; IPv4 only uses the first 4 bytes

    /**
     * @brief Equal if family and the address bytes of that family match.
     * @param o Address to compare with.
     * @return true for the same family and address.
     */
    bool operator==(const IpAddr& o) const;
    /** @brief Negation of operator==. */
    bool operator!=(const IpAddr& o) const { return !(*this == o); }
    /**
     * @brief Text form, e.g. "10.0.0.2" or "2001:db8::1" (via inet_ntop).
     * @return The address as text, "?" if the version is not 4 or 6.
     */
    std::string to_string() const;
    /**
     * @brief Convert to the reactor's family independent socket address.
     *
     * Used when a flow opens its outbound socket to the real target.
     * @param port Port in host byte order.
     * @return NetAddr with family AF_INET / AF_INET6, this address and port.
     */
    NetAddr to_netaddr(uint16_t port) const;
    /**
     * @brief Inverse of to_netaddr(): take the IP part of a NetAddr.
     * @param addr Socket address from the reactor (the port is ignored).
     * @return The address; version stays 0 if the family is neither AF_INET nor AF_INET6.
     */
    static IpAddr from_netaddr(const NetAddr& addr);
    /**
     * @brief True for addresses that do not name a single host.
     *
     * IPv4: 224.0.0.0/4 (multicast, first byte 224..239) or the limited
     * broadcast 255.255.255.255. IPv6: ff00::/8 (IPv6 has no broadcast,
     * multicast replaces it). Such packets (mDNS, SSDP, ...) cannot be
     * proxied to one target socket, so the session drops them.
     * @return true for multicast / broadcast destinations.
     */
    bool is_multicast_or_broadcast() const;
    /**
     * @brief Simple polynomial hash (base 131) of version and address bytes.
     *
     * Combined with ports and protocol into the FlowKey hash for the
     * session's unordered_map of flows.
     * @return Hash value.
     */
    size_t hash() const;
};

/**
 * @brief The TCP options of a SYN that matter to the user-space TCP endpoint.
 *
 * Options live between byte 20 of the TCP header and the data offset. Most
 * are type-length-value encoded: kind (1 byte), length (1 byte, counting
 * kind and length), value. Kind 0 (End of Option List) and kind 1 (NOP,
 * padding / alignment) are a single byte.
 */
struct TcpOptions {
    uint16_t mss = 0;          // kind 2, len 4: Maximum Segment Size the sender can receive; 0 = not present
    int wscale = -1;           // kind 3, len 3: window scale shift count (RFC 7323), clamped to 14; -1 = not present
    bool sack_permitted = false; // kind 4, len 2: sender understands selective ACKs (informational only)
    bool timestamps = false;     // kind 8, len 10: sender wants RFC 7323 timestamps (informational only)
};

/**
 * @brief Decoded view of one IP packet, filled by parse_packet().
 *
 * The pointer members point INTO the buffer passed to parse_packet(); they
 * are only valid while that buffer lives and is not modified. Fields that do
 * not apply to the packet's protocol keep their default value (0 / nullptr).
 */
struct ParsedPacket {
    uint8_t ip_version = 0;     // 4 or 6, from the high nibble of the first byte
    IpAddr src;                 // source address (the phone for packets from the TUN)
    IpAddr dst;                 // destination address (the internet target)
    uint8_t protocol = 0;       // transport protocol (after IPv6 extension headers)
    uint8_t ttl = 0;            // IPv4 TTL / IPv6 Hop Limit
    bool fragment = false;      // IPv4 / IPv6 fragment (see FragmentReassembler)
    uint32_t frag_id = 0;       // identification (IPv4: 16 bit, IPv6: 32 bit)
    uint32_t frag_offset = 0;   // byte offset of this fragment
    bool more_fragments = false; // MF flag: not the last fragment of the datagram
    const uint8_t* frag_data = nullptr; // fragmentable part (after the IPv4 header / IPv6 fragment header)
    size_t frag_data_len = 0;   // length of frag_data in bytes
    const uint8_t* ip_header = nullptr; // start of the IP header (= start of the packet)
    size_t ip_header_len = 0;   // IPv4: IHL * 4 (options included); IPv6: 40 + all extension headers
    const uint8_t* l4 = nullptr; // transport header
    size_t l4_len = 0;           // transport header + payload
    size_t total_len = 0;       // packet length according to the IP header (trailing padding excluded)

    // TCP / UDP
    uint16_t src_port = 0;      // source port (host byte order)
    uint16_t dst_port = 0;      // destination port (host byte order)
    // TCP
    uint32_t seq = 0;           // sequence number of the first payload byte (or of the SYN / FIN)
    uint32_t ack = 0;           // next sequence number the sender expects (valid if kTcpAck is set)
    uint8_t tcp_flags = 0;      // kTcp* bits
    uint16_t window = 0;        // raw window field, NOT multiplied by the window scale factor
    TcpOptions tcp_options;     // parsed options (meaningful on SYN segments)
    // ICMP / ICMPv6
    uint8_t icmp_type = 0;      // e.g. 8 / 0 echo request / reply (v4), 128 / 129 (v6)
    uint8_t icmp_code = 0;      // sub type, e.g. 3 = port unreachable for type 3 (v4)
    uint16_t icmp_id = 0;       // bytes 4..5 of the ICMP header: echo identifier
    uint16_t icmp_seq = 0;      // bytes 6..7 of the ICMP header: echo sequence number

    const uint8_t* payload = nullptr; // TCP / UDP / ICMP echo payload
    size_t payload_len = 0;     // payload length in bytes
};

/**
 * @brief Parse a raw IP packet (IPv4 or IPv6) as it comes out of a TUN device.
 *
 * Validates the lengths it relies on, then decodes the IP header, walks the
 * IPv6 extension headers, records fragmentation info and decodes the TCP,
 * UDP or ICMP header. Checksums are not verified: the packets come from the
 * phone's own IP stack through a reliable tunnel.
 * For a fragment only the IP layer is decoded (ports etc. stay 0) because the
 * transport header may be in another fragment.
 *
 * @param data  Packet bytes; must stay valid while `out` is used.
 * @param len   Number of bytes in `data`; may exceed the IP total length (padding).
 * @param out   Receives the decoded fields; reset first.
 * @param error Optional; receives a short reason if the packet is malformed.
 * @return true if the packet was parsed, false if it is malformed.
 */
bool parse_packet(const uint8_t* data, size_t len, ParsedPacket& out, std::string* error);

/**
 * @brief One line summary for logs (vpn_log_packets).
 * @param p A parsed packet.
 * @return Text such as "TCP 10.0.0.2:5000 -> 1.2.3.4:443 [S] seq=.. len=0";
 *         " (fragment)" is appended for fragments.
 */
std::string describe_packet(const ParsedPacket& p);
/**
 * @brief tcpdump style flag letters: S=SYN F=FIN R=RST P=PSH .=ACK U=URG.
 * @param flags kTcp* bit mask.
 * @return For example "S." for a SYN-ACK, "" if no flag is set.
 */
std::string tcp_flags_string(uint8_t flags);

/**
 * @brief Split a packet into IP fragments that each fit into `mtu` bytes.
 *
 * Used by Session::send_packet() when a packet for the phone is larger than
 * the MTU of its TUN device. IPv4 fragments repeat the IP header with new
 * length / offset / MF fields; IPv6 fragments get a Fragment extension
 * header (next header 44) inserted after the fixed header. Fragment data
 * sizes are multiples of 8 bytes because offsets are counted in 8 byte units.
 *
 * @param packet A complete IP packet built by this server (IPv6: without extension headers).
 * @param mtu    Maximum size of each output packet (the session keeps it >= 576).
 * @param id     Identification shared by all fragments (IPv4 uses the low 16 bits).
 * @param out    Cleared, then receives the fragments in order.
 */
void fragment_packet(const std::string& packet, int mtu, uint32_t id, std::vector<std::string>& out);

/**
 * @brief Reassembles IPv4 / IPv6 fragments into complete packets.
 *
 * A phone sends fragments when an app writes a datagram larger than the TUN
 * MTU (big UDP / ICMP payloads). The proxy needs the whole datagram (UDP
 * payload, ports), so Session::handle_packet() feeds every fragment to add()
 * and dispatches the rebuilt packet once it is complete. One instance per
 * session; not thread safe (each session lives on one worker thread).
 */
class FragmentReassembler {
public:
    /**
     * @brief Store one fragment; build the full packet when all parts are present.
     * @param fragment A ParsedPacket with `fragment == true`.
     * @param now_ms   Current time in milliseconds (start of the expiry timer).
     * @param packet   Receives the reassembled, unfragmented IP packet.
     * @return true if `packet` now holds a complete datagram, false if more
     *         fragments are needed or the fragment was rejected.
     */
    bool add(const ParsedPacket& fragment, int64_t now_ms, std::string& packet);
    /**
     * @brief Forget incomplete datagrams; called from the session timer.
     *
     * A lost fragment would otherwise keep its buffer forever. 30 s matches
     * the Linux default (net.ipv4.ipfrag_time).
     * @param now_ms     Current time in milliseconds.
     * @param timeout_ms Maximum age of an incomplete datagram.
     */
    void expire(int64_t now_ms, int timeout_ms = 30000);
    /** @return Number of datagrams currently being reassembled. */
    size_t pending() const { return buffers_.size(); }

private:
    /** @brief Reassembly state of one datagram. */
    struct Buffer {
        uint8_t version = 0;         // IP version of the fragments
        IpAddr src, dst;             // part of the datagram key
        uint32_t id = 0;             // identification field, part of the key
        uint8_t protocol = 0;        // transport protocol, part of the key
        std::string header;          // IP header of the first fragment (offset 0)
        std::string data;            // reassembled payload
        std::vector<bool> have;      // received 8 byte blocks
        size_t total = 0;            // payload length, known after the last fragment
        int64_t created_ms = 0;      // arrival time of the first fragment seen, for expire()
    };
    std::vector<Buffer> buffers_;    // few at a time, a vector is fine
};

// ---- Internet checksum helpers ----

/**
 * @brief Internet checksum, step 1: add `data` as big endian 16 bit words.
 *
 * The Internet checksum (RFC 1071), used by IPv4, TCP, UDP and ICMP, is the
 * one's complement of the one's complement sum of all 16 bit words. This
 * function only accumulates into a 32 bit integer; the carries above bit 15
 * are folded back later by checksum_finish(). Calls can be chained (pseudo
 * header first, then the segment), as long as every chunk except the last
 * has an even length. An odd last byte is padded with a zero low byte.
 *
 * @param sum  Running sum (0 to start).
 * @param data Bytes to add.
 * @param len  Number of bytes.
 * @return The new running sum.
 */
uint32_t checksum_add(uint32_t sum, const uint8_t* data, size_t len);
/**
 * @brief Internet checksum, step 2: fold the carries and complement.
 *
 * Write the result with write_be16() into the checksum field (which must
 * have been 0 while summing). Property used by receivers: summing data that
 * already contains a correct checksum yields 0xffff, i.e. a result of 0.
 * @param sum Running sum from checksum_add().
 * @return The 16 bit checksum value.
 */
uint16_t checksum_finish(uint32_t sum);

// ---- Builders: the complete IP packet is written to `out` (replacing its content) ----

/**
 * @brief Build a complete IPv4 / IPv6 + TCP packet.
 *
 * The family is taken from `src`. Used by TcpFlow to send SYN-ACK, data,
 * ACK, FIN and RST segments to the phone on behalf of the real server, and
 * by the session to reset unknown connections.
 *
 * @param out         Replaced by the packet.
 * @param src         Source address (the internet host being impersonated).
 * @param src_port    Source port.
 * @param dst         Destination address (the phone).
 * @param dst_port    Destination port.
 * @param seq         Sequence number.
 * @param ack         Acknowledgment number (pass 0 when kTcpAck is not set).
 * @param flags       kTcp* flags.
 * @param window      Raw window field (already scaled down by the caller).
 * @param options     Encoded TCP options (e.g. MSS, NOP, window scale) or nullptr.
 * @param options_len Length of `options`; padded with zeros (EOL) to a multiple of 4.
 * @param payload     Segment data or nullptr.
 * @param payload_len Length of `payload`.
 */
void build_tcp_packet(std::string& out, const IpAddr& src, uint16_t src_port, const IpAddr& dst, uint16_t dst_port,
                      uint32_t seq, uint32_t ack, uint8_t flags, uint16_t window, const uint8_t* options,
                      size_t options_len, const uint8_t* payload, size_t payload_len);

/**
 * @brief Build a complete IPv4 / IPv6 + UDP packet (UDP replies to the phone,
 *        synthesized DNS NXDOMAIN answers).
 * @param out         Replaced by the packet.
 * @param src         Source address (the remote host).
 * @param src_port    Source port.
 * @param dst         Destination address (the phone).
 * @param dst_port    Destination port.
 * @param payload     Datagram payload or nullptr.
 * @param payload_len Length of `payload`.
 */
void build_udp_packet(std::string& out, const IpAddr& src, uint16_t src_port, const IpAddr& dst, uint16_t dst_port,
                      const uint8_t* payload, size_t payload_len);

/**
 * @brief Build a complete ICMP (IPv4) or ICMPv6 packet.
 *
 * Used for echo replies (ping) and for error messages such as "port
 * unreachable" (refused UDP / blocked QUIC) or "packet too big".
 * Every ICMP message starts with type (1), code (1), checksum (2) and four
 * type dependent bytes, which the caller passes as `header_rest`.
 *
 * @param out         Replaced by the packet.
 * @param src         Source address; its version selects ICMP or ICMPv6.
 * @param dst         Destination address (the phone).
 * @param type        ICMP type, e.g. 0 echo reply / 3 destination unreachable (v4), 129 / 1 (v6).
 * @param code        ICMP code.
 * @param header_rest Bytes 4..7 of the header as one big endian 32 bit value:
 *                    (id << 16) | seq for echo, 0 for unreachable, the MTU for "packet too big".
 * @param payload     Echo data, or for errors the offending IP header + 8 bytes.
 * @param payload_len Length of `payload`.
 */
void build_icmp_packet(std::string& out, const IpAddr& src, const IpAddr& dst, uint8_t type, uint8_t code,
                       uint32_t header_rest, const uint8_t* payload, size_t payload_len);

// TCP sequence number comparison ("serial number arithmetic", RFC 1982).
// Sequence numbers are 32 bit and wrap around, so 0x00000010 comes AFTER
// 0xfffffff0. Interpreting the difference a - b as a signed 32 bit value
// gives the right answer as long as the two numbers are less than 2^31 apart,
// which TCP windows guarantee.
/** @brief a < b in sequence space. @return true if a comes before b. */
inline bool seq_lt(uint32_t a, uint32_t b) { return static_cast<int32_t>(a - b) < 0; }
/** @brief a <= b in sequence space. @return true if a comes before or equals b. */
inline bool seq_le(uint32_t a, uint32_t b) { return static_cast<int32_t>(a - b) <= 0; }
/** @brief a > b in sequence space. @return true if a comes after b. */
inline bool seq_gt(uint32_t a, uint32_t b) { return static_cast<int32_t>(a - b) > 0; }

// Big endian (network byte order) accessors. Byte by byte access works on
// little and big endian hosts and needs no alignment, unlike casting the
// pointer to uint16_t* / uint32_t* and calling ntohs() / ntohl().
/** @brief Read a big endian 16 bit value. @param p Two bytes. @return The value in host order. */
inline uint16_t read_be16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
/** @brief Read a big endian 32 bit value. @param p Four bytes. @return The value in host order. */
inline uint32_t read_be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}
/** @brief Write `v` as big endian 16 bit value. @param p Destination (2 bytes). @param v Value. */
inline void write_be16(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v);
}
/** @brief Write `v` as big endian 32 bit value. @param p Destination (4 bytes). @param v Value. */
inline void write_be32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

} // namespace vpn

#endif // SIMPLEVPN_PACKET_H
