/**
 * @file inspector.h
 * @brief Protocol inspection, logging and modification hooks.
 *
 * This is the place to experiment: every byte that flows between the phone
 * and the internet passes through inspect_tcp() / inspect_udp(), which can log,
 * rewrite or block it.
 *
 * Where it sits in the data path
 * ------------------------------
 * The server terminates every TCP connection of the phone in user space
 * (TcpFlow in flows.cpp) and opens a second, ordinary TCP connection to the
 * real server. Between the two, the application byte stream is plain data
 * in memory: TcpFlow hands each chunk to inspect_tcp() before forwarding it
 * in either direction. UdpFlow does the same with each datagram via
 * inspect_udp(). The inspector therefore never sees IP or TCP headers, only
 * application payload.
 *
 * What it does
 * ------------
 *  - Detects the application protocol from the first bytes of each
 *    direction: TLS (ClientHello: SNI, ALPN, offered version), HTTP/1.x
 *    (request line, Host, User-Agent; response status line), DNS over TCP,
 *    SSH banners, and logs a printable preview of anything else.
 *  - Logs DNS queries and answers over UDP (port 53 / 5353).
 *  - Blocks domains from vpn_block_domains (and their sub domains): a DNS
 *    query gets a synthesized NXDOMAIN reply, a TLS connection whose SNI or
 *    an HTTP request whose Host matches is reset.
 *  - Rewrites plaintext TCP streams with vpn_rewrite_N string replacement
 *    rules on the ports listed in vpn_rewrite_ports.
 *  - Optionally hex dumps payloads (vpn_log_payload_bytes).
 * QUIC (HTTP/3 over UDP 443) protects even its first handshake packets
 * (with keys derived from public header fields; decrypting them is beyond
 * this project), so the SNI is not read here; the inspector only notes QUIC
 * packets. The vpn_block_quic
 * option is enforced earlier, in Session::handle_udp() (vpn_session.cpp),
 * which answers UDP 443 with ICMP "port unreachable" so that apps fall back
 * to TCP + TLS, where the SNI is visible.
 *
 * Reading guide: inspect_tcp() -> detect_protocol() -> the static parsers
 * (parse_tls_client_hello(), parse_http_request(), parse_dns()), then
 * apply_rewrites(), then inspect_udp(). See docs/en/inspector-and-capture.md
 * for diagrams and docs/en/architecture.md for the overall data path.
 */
#ifndef SIMPLEVPN_INSPECTOR_H
#define SIMPLEVPN_INSPECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace vpn {

/**
 * @brief Per direction state of a TCP stream.
 *
 * Protocol detection may need more bytes than the first TCP segment carries
 * (a modern TLS ClientHello is often larger than one segment), so the first
 * bytes are collected in `buffer` until a decision is made.
 */
struct StreamInspectState {
    std::string buffer;      // first bytes, kept until the protocol is recognized
    bool done = false;       // detection finished for this direction
    uint64_t bytes = 0;      // bytes seen in this direction
};

/**
 * @brief Per flow inspection state, owned by the TcpFlow.
 */
struct FlowInspectState {
    std::string protocol;    // detected application protocol (HTTP, TLS, SSH, DNS ...)
    std::string host;        // HTTP Host / TLS SNI
    StreamInspectState up;   // client -> server
    StreamInspectState down; // server -> client
};

/**
 * @brief Application layer inspector: protocol detection, logging, domain
 *        blocking and stream rewriting.
 *
 * Configured once by load_config() in the MAIN thread at start up; all other
 * member functions are const, so the worker threads can share the single
 * global instance g_inspector without locking. Per flow state lives in the
 * flows (FlowInspectState) and is passed in.
 */
class Inspector {
public:
    /**
     * @brief Decision for a chunk / datagram.
     *
     * kPass: forward the (possibly rewritten) data. kBlock: do not forward;
     * the TcpFlow resets both connections, the UdpFlow drops the datagram
     * (and sends the synthesized DNS reply, if any).
     */
    enum Verdict { kPass, kBlock };

    /**
     * @brief Read the vpn_* options from the server configuration.
     *
     * Keys: vpn_log_packets, vpn_log_payload_bytes, vpn_block_domains
     * (comma separated), vpn_rewrite_1 .. vpn_rewrite_16 ("up|from|to" or
     * "down|from|to", with \r \n \t \| and \\ escapes) and vpn_rewrite_ports
     * (comma separated, default 80). Invalid rewrite rules are logged and skipped.
     */
    void load_config();

    /**
     * @brief Inspect one chunk of a TCP byte stream.
     *
     * Runs protocol detection until it is done for this direction, checks
     * the detected host against the block list (upstream only), optionally
     * hex dumps the chunk and applies the rewrite rules.
     * `data` can be modified in place (length changes are fine: both TCP
     * connections are terminated by the proxy, so sequence numbers are
     * independent).
     *
     * @param flow_name   Flow name used as log prefix.
     * @param server_port Port of the real server (destination port of the phone's connection).
     * @param upstream    true for phone -> internet, false for internet -> phone.
     * @param state       Inspection state of this flow.
     * @param data        The chunk; rewritten in place.
     * @return kBlock if the flow must be reset, otherwise kPass.
     */
    Verdict inspect_tcp(const std::string& flow_name, uint16_t server_port, bool upstream, FlowInspectState& state,
                        std::string& data) const;

    /**
     * @brief Inspect one UDP datagram.
     *
     * Logs DNS messages; a DNS query for a blocked domain gets a synthesized
     * NXDOMAIN reply in `reply`, which the UdpFlow sends back to the phone
     * instead of forwarding the query.
     *
     * @param flow_name   Flow name used as log prefix.
     * @param server_port Port of the remote side (53 = DNS, 443 = QUIC, ...).
     * @param upstream    true for phone -> internet.
     * @param data        Datagram payload.
     * @param len         Payload length.
     * @param reply       Optional; receives the DNS reply when blocking.
     * @return kBlock if the datagram must not be forwarded, otherwise kPass.
     */
    Verdict inspect_udp(const std::string& flow_name, uint16_t server_port, bool upstream, const uint8_t* data,
                        size_t len, std::string* reply) const;

    /** @return true if every IP packet should be logged (vpn_log_packets). */
    bool log_packets() const { return log_packets_; }
    /** @return Number of payload bytes to hex dump per chunk, 0 = off (vpn_log_payload_bytes). */
    size_t payload_dump_bytes() const { return payload_dump_bytes_; }
    /**
     * @brief Is `domain` or one of its parent domains in vpn_block_domains?
     *
     * Case insensitive, a trailing dot (fully qualified form) is ignored.
     * "example.org" blocks "example.org" and "www.example.org" but not
     * "badexample.org".
     * @param domain Host name from DNS, SNI or the HTTP Host header.
     * @return true if blocked.
     */
    bool is_blocked_domain(const std::string& domain) const;

    // Helpers, also useful on their own

    /**
     * @brief Classic hex dump: offset, 16 hex bytes, printable characters.
     * @param data      Bytes to dump.
     * @param len       Number of bytes available.
     * @param max_bytes Dump at most this many bytes.
     * @return Text where every line starts with "\n    " so it can be
     *         appended to a log message; notes how many bytes were omitted.
     */
    static std::string hexdump(const uint8_t* data, size_t len, size_t max_bytes);
    /**
     * @brief Printable one line preview: CR / LF shown as \r / \n, other
     *        non-printable bytes as '.'.
     * @param data      Bytes.
     * @param len       Number of bytes.
     * @param max_bytes Preview at most this many bytes ("..." is appended if cut).
     * @return The preview text.
     */
    static std::string printable_preview(const uint8_t* data, size_t len, size_t max_bytes);
    /**
     * @brief Decode a DNS message (RFC 1035 wire format) into a one line summary.
     *
     * Parses the 12 byte header, up to 4 questions and up to 16 answer
     * records (A, AAAA, CNAME, NS and PTR values are decoded).
     * @param data        DNS message (for DNS over TCP: without the 2 byte length prefix).
     * @param len         Message length.
     * @param summary     Optional; receives e.g.
     *                    "DNS query id=0x1a2b q=A www.example.com" or
     *                    "DNS response id=0x1a2b q=A example.com | example.com A 93.184.215.14 ttl=300".
     * @param first_qname Optional; receives the name of the first question.
     * @return false if the header or a question is malformed.
     */
    static bool parse_dns(const uint8_t* data, size_t len, std::string* summary, std::string* first_qname);
    /**
     * @brief Parse a TLS ClientHello at the start of a TCP stream.
     *
     * The ClientHello is the first, still unencrypted message of a TLS
     * handshake; its server_name extension (SNI) tells which host the client
     * wants, which is how middleboxes see the target of an HTTPS connection.
     * @param data    First bytes of the client -> server stream.
     * @param len     Number of bytes available.
     * @param sni     Optional; receives the SNI host name ("" if absent).
     * @param alpn    Optional; receives the offered ALPN protocols, e.g. "h2,http/1.1".
     * @param version Optional; receives "TLS1.0" .. "TLS1.3" (1.3 = offered via supported_versions).
     * @return 1 if a complete ClientHello was parsed, 0 if more data is
     *         needed, -1 if the data is not a (supported) ClientHello.
     */
    static int parse_tls_client_hello(const uint8_t* data, size_t len, std::string* sni, std::string* alpn,
                                      std::string* version);
    /**
     * @brief Recognize an HTTP/1.x request and extract a few fields.
     * @param data         First bytes of the client -> server stream.
     * @param request_line Optional; receives e.g. "GET /index.html HTTP/1.1".
     * @param host         Optional; receives the Host header value ("" if absent).
     * @param user_agent   Optional; receives the User-Agent header value ("" if absent).
     * @return true if `data` starts with a known HTTP method followed by a space.
     */
    static bool parse_http_request(const std::string& data, std::string* request_line, std::string* host,
                                   std::string* user_agent);

private:
    /** @brief One vpn_rewrite_N rule: replace every `from` by `to` in one direction. */
    struct RewriteRule {
        bool upstream;           // true: phone -> server ("up"), false: server -> phone ("down")
        std::string from;        // text to search (escapes already decoded)
        std::string to;          // replacement text (escapes already decoded)
    };

    /**
     * @brief Try to recognize the protocol from `dir.buffer` and log it.
     *
     * Sets `dir.done` once a decision is made (or the buffer limit is hit);
     * leaves it false to wait for more data. Fills `state.protocol` and
     * `state.host` when known.
     * @param flow_name   Log prefix.
     * @param server_port Port of the real server (53 hints DNS over TCP).
     * @param upstream    Direction of `dir`.
     * @param state       Flow state (protocol, host).
     * @param dir         Direction state with the collected first bytes.
     */
    void detect_protocol(const std::string& flow_name, uint16_t server_port, bool upstream,
                         FlowInspectState& state, StreamInspectState& dir) const;
    /**
     * @brief Apply the rewrite rules of this direction to one chunk.
     * @param flow_name   Log prefix.
     * @param server_port Only ports listed in vpn_rewrite_ports are rewritten.
     * @param upstream    Direction of the chunk.
     * @param data        Chunk, modified in place.
     */
    void apply_rewrites(const std::string& flow_name, uint16_t server_port, bool upstream, std::string& data) const;

    bool log_packets_ = false;              // vpn_log_packets: one log line per IP packet (used by Session)
    size_t payload_dump_bytes_ = 0;         // vpn_log_payload_bytes: hex dump length per chunk, 0 = off
    std::vector<std::string> blocked_domains_; // vpn_block_domains, lower case, without trailing dot
    std::vector<RewriteRule> rewrites_;     // vpn_rewrite_1 .. vpn_rewrite_16, in order
    std::vector<uint16_t> rewrite_ports_;   // vpn_rewrite_ports: server ports whose streams are rewritten
};

/**
 * @brief Process wide instance, configured once in the MAIN thread
 *        (handle_init), read-only afterwards.
 */
extern Inspector g_inspector;

} // namespace vpn

#endif // SIMPLEVPN_INSPECTOR_H
