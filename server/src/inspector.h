// Protocol inspection, logging and modification hooks.
//
// This is the place to experiment: every byte that flows between the phone
// and the internet passes through inspect_tcp() / inspect_udp(), which can log,
// rewrite or block it.
#ifndef SIMPLEVPN_INSPECTOR_H
#define SIMPLEVPN_INSPECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace vpn {

// Per direction state of a TCP stream
struct StreamInspectState {
    std::string buffer;      // first bytes, kept until the protocol is recognized
    bool done = false;       // detection finished for this direction
    uint64_t bytes = 0;      // bytes seen in this direction
};

// Per flow inspection state
struct FlowInspectState {
    std::string protocol;    // detected application protocol (HTTP, TLS, SSH, DNS ...)
    std::string host;        // HTTP Host / TLS SNI
    StreamInspectState up;   // client -> server
    StreamInspectState down; // server -> client
};

class Inspector {
public:
    enum Verdict { kPass, kBlock };

    // Read the vpn_* options from the server configuration
    void load_config();

    // TCP stream data. `upstream` is true for phone -> internet. `data` can
    // be modified in place (length changes are fine: both TCP connections
    // are terminated by the proxy, so sequence numbers are independent).
    Verdict inspect_tcp(const std::string& flow_name, uint16_t server_port, bool upstream, FlowInspectState& state,
                        std::string& data) const;

    // UDP datagram. A blocked DNS query gets a synthesized NXDOMAIN reply in `reply`.
    Verdict inspect_udp(const std::string& flow_name, uint16_t server_port, bool upstream, const uint8_t* data,
                        size_t len, std::string* reply) const;

    bool log_packets() const { return log_packets_; }
    size_t payload_dump_bytes() const { return payload_dump_bytes_; }
    bool is_blocked_domain(const std::string& domain) const;

    // Helpers, also useful on their own
    static std::string hexdump(const uint8_t* data, size_t len, size_t max_bytes);
    static std::string printable_preview(const uint8_t* data, size_t len, size_t max_bytes);
    // DNS message summary, e.g. "query A www.example.com" / "answer www.example.com A 1.2.3.4"
    static bool parse_dns(const uint8_t* data, size_t len, std::string* summary, std::string* first_qname);
    // TLS ClientHello: returns 1 complete, 0 need more data, -1 not a ClientHello
    static int parse_tls_client_hello(const uint8_t* data, size_t len, std::string* sni, std::string* alpn,
                                      std::string* version);
    static bool parse_http_request(const std::string& data, std::string* request_line, std::string* host,
                                   std::string* user_agent);

private:
    struct RewriteRule {
        bool upstream;
        std::string from;
        std::string to;
    };

    void detect_protocol(const std::string& flow_name, uint16_t server_port, bool upstream,
                         FlowInspectState& state, StreamInspectState& dir) const;
    void apply_rewrites(const std::string& flow_name, uint16_t server_port, bool upstream, std::string& data) const;

    bool log_packets_ = false;
    size_t payload_dump_bytes_ = 0;
    std::vector<std::string> blocked_domains_;
    std::vector<RewriteRule> rewrites_;
    std::vector<uint16_t> rewrite_ports_;
};

// Process wide instance, configured once in the MAIN thread, read-only afterwards
extern Inspector g_inspector;

} // namespace vpn

#endif // SIMPLEVPN_INSPECTOR_H
