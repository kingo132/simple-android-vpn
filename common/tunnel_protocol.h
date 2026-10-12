/**
 * @file tunnel_protocol.h
 * @brief Wire format of the tunnel between the VPN client (Android app or
 *        Linux test client) and the VPN server plugin. Header only, shared by
 *        both sides so they can never disagree about the format.
 *
 * Overview
 * --------
 * The client opens exactly ONE TCP connection to the server and both sides
 * exchange "frames" over it. TCP is a byte stream: it has no message
 * boundaries, a single recv() may return half a frame or three and a half
 * frames. Therefore every frame starts with a fixed 8-byte header that says
 * how long the payload is; the receiver collects bytes until the whole frame
 * is there (see parse_header()). This is called "length-prefixed framing".
 *
 * Header layout (all multi-byte numbers in network byte order = big endian):
 *   - bytes 0..1  magic 0x5356 ("SV"), detects garbage / a wrong protocol early
 *   - byte  2     protocol version (kVersion)
 *   - byte  3     frame type (FrameType)
 *   - bytes 4..7  payload length in bytes (header not included)
 *   - then        the payload itself
 *
 * Frame types and their payloads:
 *   - HELLO      client to server, first frame after connecting. Text
 *                "key=value\n" lines: token, client, mtu, ipv4, ipv6, version.
 *                The server checks the token (authentication).
 *   - HELLO_ACK  server to client, handshake accepted. Text lines: server, session.
 *   - PACKET     both directions, exactly one raw IPv4 or IPv6 packet as it
 *                was read from / will be written to the TUN device.
 *   - PING/PONG  keepalive: the receiver of a PING answers with a PONG that
 *                echoes the payload. Detects dead connections (e.g. after
 *                the phone switched networks) faster than TCP itself would.
 *   - ERROR      text reason; the sender closes the connection afterwards
 *                (e.g. "authentication failed").
 *
 * Reading guide: start with FrameType, then append_frame() (sending side) and
 * parse_header() (receiving side). The client uses these in
 * client/app/src/main/cpp/tunnel_client.cpp, the server in
 * server/src/vpn_plugin.cpp (handle_input_from_client) and
 * server/src/vpn_session.cpp. See docs/en/tunnel-protocol.md for diagrams of
 * the handshake, keepalive and reconnect logic.
 */
#ifndef SIMPLEVPN_TUNNEL_PROTOCOL_H
#define SIMPLEVPN_TUNNEL_PROTOCOL_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

/// Everything that describes the tunnel wire protocol lives in this namespace.
namespace tunnel {

constexpr uint16_t kMagic = 0x5356; // "SV": first two bytes of every frame
constexpr uint8_t kVersion = 1;     // bumped on incompatible format changes; a mismatch is a protocol error
constexpr size_t kHeaderSize = 8;   // fixed header size, see the layout above
// Largest accepted payload: a maximum size IP packet (65535 bytes) plus some
// slack. Anything bigger is treated as a corrupt stream instead of making the
// receiver buffer gigabytes because of a bogus length field.
constexpr uint32_t kMaxPayload = 65535 + 1024;
constexpr uint16_t kDefaultPort = 9443; // default TCP port of the server's tunnel listener

/**
 * @brief Frame type, stored in byte 3 of the header.
 */
enum FrameType : uint8_t {
    kHello = 1,    ///< client -> server: authentication + client parameters
    kHelloAck = 2, ///< server -> client: handshake accepted, packets may flow
    kPacket = 3,   ///< both ways: one raw IP packet
    kPing = 4,     ///< keepalive request, payload is echoed in the PONG
    kPong = 5,     ///< keepalive answer
    kError = 6     ///< fatal error text, the connection is closed afterwards
};

/**
 * @brief Human readable name of a frame type, for log messages.
 * @param type Frame type byte (any value, unknown values are allowed).
 * @return A static string such as "PACKET", or "UNKNOWN".
 */
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

/**
 * @brief Serialize a frame header into 8 bytes.
 *
 * Numbers are written byte by byte with shifts, which produces big endian
 * output on every CPU (no htons/htonl and no alignment assumptions needed).
 *
 * @param out         Destination, must have room for kHeaderSize bytes.
 * @param type        Frame type (FrameType).
 * @param payload_len Number of payload bytes that will follow the header.
 */
inline void write_header(uint8_t* out, uint8_t type, uint32_t payload_len) {
    out[0] = static_cast<uint8_t>(kMagic >> 8);   // magic, high byte first
    out[1] = static_cast<uint8_t>(kMagic & 0xff);
    out[2] = kVersion;
    out[3] = type;
    out[4] = static_cast<uint8_t>(payload_len >> 24); // 32-bit length, big endian
    out[5] = static_cast<uint8_t>(payload_len >> 16);
    out[6] = static_cast<uint8_t>(payload_len >> 8);
    out[7] = static_cast<uint8_t>(payload_len);
}

/**
 * @brief Append one complete frame (header + payload) to a send buffer.
 *
 * Both sides build their outgoing byte stream with this function: the client
 * appends to its output buffer and flushes it with send(), the server builds
 * a frame and hands it to srv_send().
 *
 * @param out     Buffer the frame is appended to (existing content is kept).
 * @param type    Frame type (FrameType).
 * @param payload Payload bytes, may be nullptr when len is 0.
 * @param len     Payload length; the caller keeps it <= kMaxPayload.
 */
inline void append_frame(std::string& out, uint8_t type, const void* payload, size_t len) {
    uint8_t header[kHeaderSize];
    write_header(header, type, static_cast<uint32_t>(len));
    out.append(reinterpret_cast<const char*>(header), kHeaderSize);
    if (len > 0) {
        out.append(static_cast<const char*>(payload), len);
    }
}

/**
 * @brief Inspect the start of a received byte stream and find the frame boundary.
 *
 * This is the heart of the framing: the receiver calls it on whatever bytes
 * it has buffered so far. The reactor server calls it from
 * handle_input_from_client() so that the engine can cut the stream into
 * complete frames; the client calls it in a loop in process_frames().
 *
 * @param data        Start of the buffered, not yet processed bytes.
 * @param len         Number of bytes available at @p data.
 * @param type        Out (optional, may be nullptr): frame type byte.
 * @param payload_len Out (optional, may be nullptr): payload length.
 * @return The total frame length (header + payload) as soon as a complete
 *         header is present; the frame itself may still be incomplete, so the
 *         caller compares this value with @p len. 0 if fewer than 8 bytes are
 *         available (wait for more data). -1 if the data is not a valid frame
 *         (bad magic, unknown version, absurd length): the stream cannot be
 *         resynchronized and the connection must be closed.
 */
inline long parse_header(const uint8_t* data, size_t len, uint8_t* type, uint32_t* payload_len) {
    if (len < kHeaderSize) {
        return 0; // not even a full header yet
    }
    uint16_t magic = static_cast<uint16_t>((data[0] << 8) | data[1]);
    if (magic != kMagic || data[2] != kVersion) {
        return -1; // not our protocol (or a different version)
    }
    // Rebuild the big endian 32-bit length
    uint32_t plen = (static_cast<uint32_t>(data[4]) << 24) | (static_cast<uint32_t>(data[5]) << 16) |
                    (static_cast<uint32_t>(data[6]) << 8) | static_cast<uint32_t>(data[7]);
    if (plen > kMaxPayload) {
        return -1; // a length this big can only come from a corrupt stream
    }
    if (type != nullptr) {
        *type = data[3];
    }
    if (payload_len != nullptr) {
        *payload_len = plen;
    }
    return static_cast<long>(kHeaderSize + plen);
}

/**
 * @brief Encode a key/value map as "key=value\n" lines (HELLO / HELLO_ACK payload).
 *
 * A trivial text format was chosen on purpose: it is easy to read in a
 * packet capture and new keys can be added without breaking old peers
 * (unknown keys are simply ignored by decode_kv() users).
 *
 * @param kv Keys and values; they must not contain '\n', keys must not contain '='.
 * @return The encoded text (std::map iterates in sorted key order).
 */
inline std::string encode_kv(const std::map<std::string, std::string>& kv) {
    std::string out;
    for (const auto& item : kv) {
        out += item.first + "=" + item.second + "\n";
    }
    return out;
}

/**
 * @brief Decode "key=value\n" lines produced by encode_kv().
 *
 * Lines without '=' are skipped; the value is everything after the FIRST
 * '=' (so values may contain '='). A missing final newline is accepted.
 *
 * @param data Text to parse (not necessarily NUL terminated).
 * @param len  Length of @p data in bytes.
 * @return Map of all keys found; a later duplicate key overwrites an earlier one.
 */
inline std::map<std::string, std::string> decode_kv(const char* data, size_t len) {
    std::map<std::string, std::string> kv;
    std::string text(data, len);
    size_t start = 0; // start of the current line
    while (start < text.size()) {
        size_t end = text.find('\n', start);
        if (end == std::string::npos) {
            end = text.size(); // last line without '\n'
        }
        std::string line = text.substr(start, end - start);
        size_t eq = line.find('=');
        if (eq != std::string::npos) {
            kv[line.substr(0, eq)] = line.substr(eq + 1);
        }
        start = end + 1; // skip the '\n'
    }
    return kv;
}

} // namespace tunnel

#endif // SIMPLEVPN_TUNNEL_PROTOCOL_H
