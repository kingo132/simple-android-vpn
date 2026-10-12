// Tunnel protocol between the VPN client (Android / Linux test client) and
// the VPN server plugin. Shared by both sides, header only.
//
// The client opens one TCP connection to the server and exchanges frames:
//
//   +--------+--------+--------+--------+--------+--------+--------+--------+
//   |  magic 0x5356   | version|  type  |        payload length (BE)        |
//   +--------+--------+--------+--------+--------+--------+--------+--------+
//   |                         payload ...                                    |
//
//   HELLO      client -> server  text "key=value\n" lines: token, client, mtu, ipv4, ipv6
//   HELLO_ACK  server -> client  text "key=value\n" lines: server, session
//   PACKET     both directions   one raw IPv4 / IPv6 packet
//   PING/PONG  keepalive (payload echoed)
//   ERROR      text reason, the sender closes the connection afterwards
#ifndef SIMPLEVPN_TUNNEL_PROTOCOL_H
#define SIMPLEVPN_TUNNEL_PROTOCOL_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

namespace tunnel {

constexpr uint16_t kMagic = 0x5356; // "SV"
constexpr uint8_t kVersion = 1;
constexpr size_t kHeaderSize = 8;
constexpr uint32_t kMaxPayload = 65535 + 1024;
constexpr uint16_t kDefaultPort = 9443;

enum FrameType : uint8_t {
    kHello = 1,
    kHelloAck = 2,
    kPacket = 3,
    kPing = 4,
    kPong = 5,
    kError = 6
};

inline const char* frame_type_name(uint8_t type) {
    switch (type) {
    case kHello: return "HELLO";
    case kHelloAck: return "HELLO_ACK";
    case kPacket: return "PACKET";
    case kPing: return "PING";
    case kPong: return "PONG";
    case kError: return "ERROR";
    default: return "UNKNOWN";
    }
}

inline void write_header(uint8_t* out, uint8_t type, uint32_t payload_len) {
    out[0] = static_cast<uint8_t>(kMagic >> 8);
    out[1] = static_cast<uint8_t>(kMagic & 0xff);
    out[2] = kVersion;
    out[3] = type;
    out[4] = static_cast<uint8_t>(payload_len >> 24);
    out[5] = static_cast<uint8_t>(payload_len >> 16);
    out[6] = static_cast<uint8_t>(payload_len >> 8);
    out[7] = static_cast<uint8_t>(payload_len);
}

// Append one complete frame to `out`
inline void append_frame(std::string& out, uint8_t type, const void* payload, size_t len) {
    uint8_t header[kHeaderSize];
    write_header(header, type, static_cast<uint32_t>(len));
    out.append(reinterpret_cast<const char*>(header), kHeaderSize);
    if (len > 0) {
        out.append(static_cast<const char*>(payload), len);
    }
}

// Inspect the start of a byte stream.
// Returns the total frame length (header + payload) if a header is present
// (the frame may still be incomplete), 0 if fewer than 8 bytes are
// available, -1 if the data is not a valid frame.
inline long parse_header(const uint8_t* data, size_t len, uint8_t* type, uint32_t* payload_len) {
    if (len < kHeaderSize) {
        return 0;
    }
    uint16_t magic = static_cast<uint16_t>((data[0] << 8) | data[1]);
    if (magic != kMagic || data[2] != kVersion) {
        return -1;
    }
    uint32_t plen = (static_cast<uint32_t>(data[4]) << 24) | (static_cast<uint32_t>(data[5]) << 16) |
                    (static_cast<uint32_t>(data[6]) << 8) | static_cast<uint32_t>(data[7]);
    if (plen > kMaxPayload) {
        return -1;
    }
    if (type != nullptr) {
        *type = data[3];
    }
    if (payload_len != nullptr) {
        *payload_len = plen;
    }
    return static_cast<long>(kHeaderSize + plen);
}

// "key=value\n" encoding used by HELLO / HELLO_ACK
inline std::string encode_kv(const std::map<std::string, std::string>& kv) {
    std::string out;
    for (const auto& item : kv) {
        out += item.first + "=" + item.second + "\n";
    }
    return out;
}

inline std::map<std::string, std::string> decode_kv(const char* data, size_t len) {
    std::map<std::string, std::string> kv;
    std::string text(data, len);
    size_t start = 0;
    while (start < text.size()) {
        size_t end = text.find('\n', start);
        if (end == std::string::npos) {
            end = text.size();
        }
        std::string line = text.substr(start, end - start);
        size_t eq = line.find('=');
        if (eq != std::string::npos) {
            kv[line.substr(0, eq)] = line.substr(eq + 1);
        }
        start = end + 1;
    }
    return kv;
}

} // namespace tunnel

#endif // SIMPLEVPN_TUNNEL_PROTOCOL_H
