/**
 * @file inspector.cpp
 * @brief Implementation of protocol detection (HTTP, TLS SNI, DNS, SSH),
 *        domain blocking, stream rewriting and payload dumps.
 *
 * See inspector.h for the role of the Inspector in the data path. This file
 * is mostly about wire formats:
 *  - DNS (RFC 1035): 12 byte header, questions and resource records, and
 *    the name compression scheme (read_dns_name(), parse_dns()).
 *  - TLS (RFC 8446 / RFC 5246): record header, handshake header and the
 *    ClientHello body with its extensions (parse_tls_client_hello()).
 *  - HTTP/1.x: request line and header lines (parse_http_request()).
 *
 * Reading guide: inspect_tcp() at the end of the file is the entry point for
 * TCP; it calls detect_protocol(), which uses the parsers above it, and then
 * apply_rewrites(). inspect_udp() is the entry point for UDP (DNS logging,
 * NXDOMAIN synthesis, QUIC note). The anonymous namespace at the top holds
 * small string and DNS helpers.
 */
#include "inspector.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <sys/socket.h>

#include "packet.h"
#include "server_api.h"

namespace vpn {

Inspector g_inspector; // the single process wide instance (see inspector.h)

namespace {

// Upper bound for the bytes collected per direction for protocol detection.
// 16 KiB is the size of a maximal TLS record payload (2^14 bytes), plenty for
// any real ClientHello or HTTP request header; it also bounds the memory per flow.
constexpr size_t kMaxDetectBuffer = 16384;

/**
 * @brief ASCII lower case copy of a string.
 * @param s Input (taken by value and modified).
 * @return Lower case string.
 */
std::string to_lower(std::string s) {
    // The unsigned char parameter avoids undefined behavior of tolower() for negative chars
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

/**
 * @brief Remove leading and trailing spaces, tabs, CR and LF.
 * @param s Input.
 * @return Trimmed copy ("" if only whitespace).
 */
std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) {
        return "";
    }
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

/**
 * @brief Split a config list such as "a.com, b.com" into trimmed, non-empty items.
 * @param s     Input.
 * @param delim Separator character.
 * @return The items in order; empty items are dropped.
 */
std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> parts;
    size_t start = 0;
    while (start <= s.size()) { // "<=" so the item after the last delimiter is processed too
        size_t pos = s.find(delim, start);
        if (pos == std::string::npos) {
            pos = s.size();
        }
        std::string item = trim(s.substr(start, pos - start));
        if (!item.empty()) {
            parts.push_back(item);
        }
        start = pos + 1;
    }
    return parts;
}

/**
 * @brief Decode the escapes of a rewrite rule part.
 *
 * Config values are single lines, so CR / LF / TAB have to be written as
 * escapes, e.g. to match "\r\nUser-Agent:". Any other escaped character
 * stands for itself, which covers backslash-backslash and backslash-pipe.
 * @param s Raw text from the config.
 * @return Text with escapes replaced.
 */
std::string unescape(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            char c = s[++i]; // skip the backslash, look at the escaped character
            switch (c) {
            case 'r': out += '\r'; break;
            case 'n': out += '\n'; break;
            case 't': out += '\t'; break;
            default: out += c; break;
            }
        } else {
            out += s[i];
        }
    }
    return out;
}

/**
 * @brief Split "dir|from|to" on '|' characters that are not escaped.
 *
 * Escape sequences are copied unchanged (backslash included) so that
 * unescape() can decode them afterwards; an escaped pipe therefore ends up
 * as a literal '|' in the pattern instead of separating fields.
 * @param s Rule text.
 * @return The fields (at least one, possibly empty).
 */
std::vector<std::string> split_rule(const std::string& s) {
    std::vector<std::string> parts(1);
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            parts.back() += s[i];   // keep the backslash ...
            parts.back() += s[++i]; // ... and the escaped character, for unescape()
        } else if (s[i] == '|') {
            parts.emplace_back();   // start the next field
        } else {
            parts.back() += s[i];
        }
    }
    return parts;
}

/**
 * @brief Read a (possibly compressed) DNS name.
 *
 * Wire format (RFC 1035 3.1): a sequence of labels, each a length byte
 * (0..63) followed by that many bytes, ended by a zero length byte (the
 * root). "www.example.com" is 3 'www' 7 'example' 3 'com' 0.
 *
 * Compression (RFC 1035 4.1.4): a length byte with the two top bits set
 * (0xc0) starts a 2 byte pointer; the low 14 bits are an offset from the
 * start of the message where the rest of the name continues. Names in
 * answers usually point back to the question, which saves space.
 *
 * @param msg    The whole DNS message (pointers are relative to its start).
 * @param len    Message length.
 * @param offset In: where the name starts. Out: the first byte after the
 *               name in its original position (after the first pointer if
 *               the name was compressed, not after the pointed-to data).
 * @param name   Receives the dotted name, "." for the root.
 * @return false if the name is truncated or has too many pointer hops.
 */
bool read_dns_name(const uint8_t* msg, size_t len, size_t& offset, std::string& name) {
    name.clear();
    size_t pos = offset;  // current read position, may jump around via pointers
    bool jumped = false;  // once a pointer was followed, `offset` is final
    int hops = 0;         // pointers followed, to break pointer loops
    while (pos < len) {
        uint8_t l = msg[pos];
        if (l == 0) {
            // End of the name (root label)
            if (!jumped) {
                offset = pos + 1;
            }
            if (name.empty()) {
                name = ".";
            }
            return true;
        }
        if ((l & 0xc0) == 0xc0) {
            // Compression pointer; a malicious message could make pointers form a
            // cycle, so give up after 16 hops
            if (pos + 1 >= len || ++hops > 16) {
                return false;
            }
            size_t ptr = static_cast<size_t>(((l & 0x3f) << 8) | msg[pos + 1]); // 14 bit offset
            if (!jumped) {
                offset = pos + 2; // the name ends, in place, right after the first pointer
            }
            jumped = true;
            pos = ptr;
            continue;
        }
        // Ordinary label: length byte + `l` bytes
        if (pos + 1 + l > len) {
            return false;
        }
        if (!name.empty()) {
            name += '.';
        }
        name.append(reinterpret_cast<const char*>(msg + pos + 1), l);
        pos += 1 + l;
    }
    return false; // ran off the end without the terminating zero
}

/**
 * @brief Mnemonic of a DNS record type (IANA "Resource Record (RR) TYPEs").
 * @param type Numeric type.
 * @return Static name, or nullptr for types not in this short list.
 */
const char* dns_type_name(uint16_t type) {
    switch (type) {
    case 1: return "A";       // IPv4 address
    case 2: return "NS";      // name server
    case 5: return "CNAME";   // alias: the canonical name
    case 6: return "SOA";     // start of authority (seen in negative answers)
    case 12: return "PTR";    // reverse lookup
    case 15: return "MX";     // mail exchanger
    case 16: return "TXT";    // text
    case 28: return "AAAA";   // IPv6 address
    case 33: return "SRV";    // service location
    case 64: return "SVCB";   // service binding (RFC 9460)
    case 65: return "HTTPS";  // HTTPS service binding (RFC 9460): ALPN, ECH keys, address hints
    default: return nullptr;
    }
}

/**
 * @brief Printable DNS record type, "TYPE<n>" for unknown types (RFC 3597 style).
 * @param type Numeric type.
 * @return Type name.
 */
std::string dns_type_string(uint16_t type) {
    const char* n = dns_type_name(type);
    return n ? std::string(n) : "TYPE" + std::to_string(type);
}

} // namespace

/**
 * @brief Read the inspector options (see inspector.h for the keys).
 *
 * Called once in the MAIN thread before the workers start, so the members
 * can be read without locks afterwards.
 */
void Inspector::load_config() {
    log_packets_ = srv_conf_int("vpn_log_packets", 0) != 0;
    payload_dump_bytes_ = static_cast<size_t>(std::max(0, srv_conf_int("vpn_log_payload_bytes", 0))); // negative = off

    // Normalize the block list once (lower case, no trailing dot) so that
    // is_blocked_domain() only has to normalize the name being tested
    blocked_domains_.clear();
    for (const std::string& d : split(srv_conf_string("vpn_block_domains", ""), ',')) {
        std::string domain = to_lower(d);
        while (!domain.empty() && domain.back() == '.') {
            domain.pop_back();
        }
        if (!domain.empty()) {
            blocked_domains_.push_back(domain);
        }
    }

    // Rewrite rules vpn_rewrite_1 .. vpn_rewrite_16; gaps in the numbering are allowed
    rewrites_.clear();
    for (int i = 1; i <= 16; ++i) {
        std::string key = "vpn_rewrite_" + std::to_string(i);
        std::string value = srv_conf_string(key.c_str(), "");
        if (value.empty()) {
            continue;
        }
        std::vector<std::string> parts = split_rule(value);
        // Expect exactly direction|from|to with a non-empty `from` (an empty
        // pattern would match everywhere); `to` may be empty (= delete)
        if (parts.size() != 3 || (parts[0] != "up" && parts[0] != "down") || parts[1].empty()) {
            LOG_WARN("Ignore invalid %s = %s (expected up|from|to or down|from|to)", key.c_str(), value.c_str());
            continue;
        }
        RewriteRule rule;
        rule.upstream = parts[0] == "up";
        rule.from = unescape(parts[1]);
        rule.to = unescape(parts[2]);
        rewrites_.push_back(rule);
        LOG_INFO("Rewrite rule %d (%s): \"%s\" -> \"%s\"", i, parts[0].c_str(), parts[1].c_str(), parts[2].c_str());
    }
    // Rewriting only makes sense for plaintext protocols; by default HTTP on port 80
    rewrite_ports_.clear();
    for (const std::string& p : split(srv_conf_string("vpn_rewrite_ports", "80"), ',')) {
        rewrite_ports_.push_back(static_cast<uint16_t>(std::atoi(p.c_str()))); // atoi: invalid text becomes port 0
    }
    if (!blocked_domains_.empty()) {
        LOG_INFO("Blocking %zu domain(s)", blocked_domains_.size());
    }
}

/**
 * @brief Exact or sub domain match against vpn_block_domains.
 * @param domain_in Host name to test (any case, trailing dot allowed).
 * @return true if it equals a blocked domain or ends with "." + a blocked domain.
 */
bool Inspector::is_blocked_domain(const std::string& domain_in) const {
    if (blocked_domains_.empty() || domain_in.empty()) {
        return false;
    }
    // DNS names are case insensitive and "example.org." (fully qualified, with
    // the root dot) is the same name as "example.org"
    std::string domain = to_lower(domain_in);
    while (!domain.empty() && domain.back() == '.') {
        domain.pop_back();
    }
    for (const std::string& b : blocked_domains_) {
        // Either the same name, or a longer name that ends with b and has a '.'
        // right before it (so "notexample.org" does not match "example.org")
        if (domain == b ||
            (domain.size() > b.size() && domain.compare(domain.size() - b.size(), b.size(), b) == 0 &&
             domain[domain.size() - b.size() - 1] == '.')) {
            return true;
        }
    }
    return false;
}

/**
 * @brief Hex dump in the familiar "offset  hex bytes  ascii" layout.
 *
 * Example line: "\n    0010  48 54 54 50 2f 31 2e 31 ...  HTTP/1.1 ..."
 * @param data      Bytes.
 * @param len       Available bytes.
 * @param max_bytes Limit for the dump.
 * @return The dump (see inspector.h).
 */
std::string Inspector::hexdump(const uint8_t* data, size_t len, size_t max_bytes) {
    size_t n = std::min(len, max_bytes);
    std::string out;
    char line[100]; // newline + 4 indent + 4 offset + 2 + 16 * 3 hex + 1 + 16 ASCII + NUL = 77 (offsets < 0x10000)
    for (size_t off = 0; off < n; off += 16) { // 16 bytes per line
        int pos = snprintf(line, sizeof(line), "\n    %04zx  ", off); // hex offset
        for (size_t i = 0; i < 16; ++i) {
            if (off + i < n) {
                pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), "%02x ", data[off + i]);
            } else {
                // Pad a short last line so the ASCII column stays aligned
                pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), "   ");
            }
        }
        pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), " ");
        for (size_t i = 0; i < 16 && off + i < n; ++i) {
            uint8_t c = data[off + i];
            line[pos++] = (c >= 32 && c < 127) ? static_cast<char>(c) : '.'; // printable ASCII or '.'
        }
        line[pos] = '\0';
        out += line;
    }
    if (len > n) {
        out += "\n    ... (" + std::to_string(len - n) + " more bytes)";
    }
    return out;
}

/**
 * @brief One line printable preview (see inspector.h).
 * @param data      Bytes.
 * @param len       Available bytes.
 * @param max_bytes Limit.
 * @return The preview.
 */
std::string Inspector::printable_preview(const uint8_t* data, size_t len, size_t max_bytes) {
    std::string out;
    size_t n = std::min(len, max_bytes);
    for (size_t i = 0; i < n; ++i) {
        uint8_t c = data[i];
        if (c == '\r') {
            out += "\\r"; // keep protocol line endings visible on one log line
        } else if (c == '\n') {
            out += "\\n";
        } else if (c >= 32 && c < 127) {
            out += static_cast<char>(c);
        } else {
            out += '.';
        }
    }
    if (len > n) {
        out += "...";
    }
    return out;
}

/**
 * @brief Summarize a DNS message (see inspector.h).
 *
 * Message layout (RFC 1035 4.1):
 *  - Header, 12 bytes: ID (2), flags (2), QDCOUNT (2), ANCOUNT (2),
 *    NSCOUNT (2), ARCOUNT (2).
 *    Flags: QR 0x8000 (1 = response), opcode 0x7800, AA 0x0400, TC 0x0200,
 *    RD 0x0100, RA 0x0080, Z / AD / CD 0x0070, RCODE 0x000f.
 *  - Question: name, QTYPE (2), QCLASS (2).
 *  - Answer / authority / additional records: name, TYPE (2), CLASS (2),
 *    TTL (4), RDLENGTH (2), RDATA (RDLENGTH bytes).
 * Only the question and answer sections are summarized.
 *
 * @param msg         DNS message.
 * @param len         Length.
 * @param summary     Optional summary output.
 * @param first_qname Optional first question name output.
 * @return false if the header or a question cannot be parsed.
 */
bool Inspector::parse_dns(const uint8_t* msg, size_t len, std::string* summary, std::string* first_qname) {
    if (len < 12) {
        return false; // shorter than the fixed header
    }
    uint16_t id = read_be16(msg);           // matches a response to its query
    uint16_t flags = read_be16(msg + 2);
    uint16_t qdcount = read_be16(msg + 4);  // number of questions (normally 1)
    uint16_t ancount = read_be16(msg + 6);  // number of answer records
    bool response = (flags & 0x8000) != 0;  // QR bit
    int rcode = flags & 0x000f;             // response code, 3 = NXDOMAIN (name does not exist)

    std::string text;
    char head[64];
    snprintf(head, sizeof(head), "DNS %s id=0x%04x", response ? "response" : "query", id);
    text = head;
    if (response && rcode != 0) {
        static const char* const kRcodes[] = {"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"};
        text += std::string(" rcode=") + (rcode < 6 ? kRcodes[rcode] : std::to_string(rcode).c_str());
    }

    size_t offset = 12; // the question section follows the header
    // Questions (at most 4 are shown; if there are more, the answer parsing below
    // starts at the wrong place and simply stops at the first inconsistency)
    for (int i = 0; i < qdcount && i < 4; ++i) {
        std::string name;
        if (!read_dns_name(msg, len, offset, name) || offset + 4 > len) {
            return false;
        }
        uint16_t qtype = read_be16(msg + offset);
        offset += 4; // QTYPE + QCLASS (class is practically always 1 = IN)
        text += " q=" + dns_type_string(qtype) + " " + name;
        if (i == 0 && first_qname != nullptr) {
            *first_qname = name;
        }
    }
    // Answer records (at most 16); a malformed record just ends the summary
    for (int i = 0; i < ancount && i < 16; ++i) {
        std::string name;
        if (!read_dns_name(msg, len, offset, name) || offset + 10 > len) {
            break;
        }
        uint16_t type = read_be16(msg + offset);
        uint32_t ttl = read_be32(msg + offset + 4);   // skips CLASS at offset + 2
        uint16_t rdlen = read_be16(msg + offset + 8);
        offset += 10; // TYPE, CLASS, TTL, RDLENGTH
        if (offset + rdlen > len) {
            break;
        }
        std::string value;
        char ip[INET6_ADDRSTRLEN];
        if (type == 1 && rdlen == 4) {
            inet_ntop(AF_INET, msg + offset, ip, sizeof(ip)); // A: 4 byte IPv4 address
            value = ip;
        } else if (type == 28 && rdlen == 16) {
            inet_ntop(AF_INET6, msg + offset, ip, sizeof(ip)); // AAAA: 16 byte IPv6 address
            value = ip;
        } else if (type == 5 || type == 2 || type == 12) {
            // CNAME / NS / PTR: RDATA is itself a (possibly compressed) name; use
            // a copy of the offset so the record walk is not disturbed
            size_t o = offset;
            read_dns_name(msg, len, o, value);
        } else {
            value = std::to_string(rdlen) + " bytes";
        }
        text += " | " + name + " " + dns_type_string(type) + " " + value + " ttl=" + std::to_string(ttl);
        offset += rdlen; // next record
    }
    if (summary != nullptr) {
        *summary = text;
    }
    return true;
}

/**
 * @brief Parse a TLS ClientHello (see inspector.h for the return values).
 *
 * Layout of the start of a TLS connection:
 *  - Record header, 5 bytes: content type (22 = 0x16 handshake), legacy
 *    record version (major 3: 0x0301 .. 0x0303), length (2).
 *  - Handshake header, 4 bytes: message type (1 = ClientHello), length (3).
 *  - ClientHello body: legacy_version (2), random (32), session id (1 byte
 *    length + data), cipher suites (2 byte length + 2 byte suites),
 *    compression methods (1 byte length + data), extensions (2 byte total
 *    length, then per extension: type (2), length (2), data).
 *
 * Only the first record is parsed. A ClientHello is usually one record (up
 * to 16 KiB) but often several TCP segments, so 0 ("need more data") is a
 * common result. Note that with Encrypted Client Hello (ECH) the visible
 * SNI is only a public cover name.
 *
 * @param data    Stream bytes.
 * @param len     Available length.
 * @param sni     Optional SNI output.
 * @param alpn    Optional ALPN output.
 * @param version Optional version output.
 * @return 1 complete, 0 need more data, -1 not a ClientHello.
 */
int Inspector::parse_tls_client_hello(const uint8_t* data, size_t len, std::string* sni, std::string* alpn,
                                      std::string* version) {
    if (len < 1) {
        return 0;
    }
    if (data[0] != 0x16) {
        return -1; // not a handshake record
    }
    if (len < 5) {
        return 0; // record header incomplete
    }
    if (data[1] != 0x03) {
        return -1; // record version major must be 3 (SSL 3.0 / TLS 1.x)
    }
    size_t record_len = read_be16(data + 3);
    if (len < 5 + 4) {
        return 0; // handshake header incomplete
    }
    const uint8_t* hs = data + 5; // handshake message
    if (hs[0] != 0x01) {
        return -1; // not a ClientHello
    }
    size_t hs_len = (static_cast<size_t>(hs[1]) << 16) | (static_cast<size_t>(hs[2]) << 8) | hs[3]; // 24 bit length
    // The ClientHello may span several records; only parse the first record
    // when it contains the full message (the normal case)
    size_t available = std::min(len - 5, record_len); // message bytes of the first record we have
    if (available < 4 + hs_len) {
        // Whole record received but the message is longer than the record:
        // it continues in a second record, which is not supported -> -1.
        // Otherwise the record itself is still incomplete -> wait (0).
        return len - 5 >= record_len && record_len < 4 + hs_len ? -1 : 0;
    }
    const uint8_t* p = hs + 4;      // start of the ClientHello body
    const uint8_t* end = p + hs_len;
    // Every length read below is checked against `end` before it is used
    if (end - p < 2 + 32 + 1) {
        return -1; // too short for version + random + session id length
    }
    uint16_t legacy_version = read_be16(p);
    p += 2 + 32; // version + random
    size_t sid_len = *p++; // session id (0..32 bytes; TLS 1.3 clients send a random one for compatibility)
    if (static_cast<size_t>(end - p) < sid_len + 2) {
        return -1;
    }
    p += sid_len;
    size_t cs_len = read_be16(p); // cipher suites list length in bytes
    p += 2;
    if (static_cast<size_t>(end - p) < cs_len + 1) {
        return -1;
    }
    p += cs_len;
    size_t comp_len = *p++; // compression methods (always just "null" today)
    if (static_cast<size_t>(end - p) < comp_len) {
        return -1;
    }
    p += comp_len;

    // TLS 1.3 freezes legacy_version at 0x0303 (TLS 1.2) and announces itself in
    // the supported_versions extension, checked below
    char vbuf[16];
    snprintf(vbuf, sizeof(vbuf), "0x%04x", legacy_version);
    std::string ver = legacy_version == 0x0303 ? "TLS1.2" : legacy_version == 0x0302 ? "TLS1.1" :
                      legacy_version == 0x0301 ? "TLS1.0" : vbuf;
    if (end - p >= 2) { // the extensions block is optional (absent in very old clients)
        size_t ext_total = read_be16(p);
        p += 2;
        const uint8_t* ext_end = p + std::min(ext_total, static_cast<size_t>(end - p)); // never past the message
        while (ext_end - p >= 4) { // room for an extension type + length
            uint16_t type = read_be16(p);
            size_t elen = read_be16(p + 2);
            p += 4;
            if (static_cast<size_t>(ext_end - p) < elen) {
                break; // truncated extension
            }
            const uint8_t* e = p; // extension data
            if (type == 0 && elen >= 5 && sni != nullptr) { // server_name
                // RFC 6066: server_name_list length (2), then entries of
                // name_type (1, 0 = host_name), name length (2), name.
                // Only the first entry is read (clients send exactly one).
                size_t name_len = read_be16(e + 3);
                if (e[2] == 0 && 5 + name_len <= elen) {
                    sni->assign(reinterpret_cast<const char*>(e + 5), name_len);
                }
            } else if (type == 16 && elen >= 2 && alpn != nullptr) { // ALPN
                // RFC 7301: protocol list length (2), then entries of length (1) +
                // name, e.g. "h2" (HTTP/2) and "http/1.1"; joined with ','
                size_t list_len = std::min(static_cast<size_t>(read_be16(e)), elen - 2);
                size_t i = 2;
                while (i < 2 + list_len) {
                    size_t l = e[i];
                    if (i + 1 + l > 2 + list_len) {
                        break;
                    }
                    if (!alpn->empty()) {
                        *alpn += ",";
                    }
                    alpn->append(reinterpret_cast<const char*>(e + i + 1), l);
                    i += 1 + l;
                }
            } else if (type == 43 && elen >= 3) { // supported_versions
                // RFC 8446 4.2.1 (ClientHello form): list length (1), then 2 byte
                // versions. 0x0304 = TLS 1.3. GREASE values (RFC 8701, 0x?a?a)
                // are ignored automatically.
                size_t list_len = e[0];
                for (size_t i = 1; i + 1 < 1 + list_len && i + 1 < elen; i += 2) {
                    if (read_be16(e + i) == 0x0304) {
                        ver = "TLS1.3"; // offered by the client; the server may still pick 1.2
                    }
                }
            }
            p += elen; // next extension
        }
    }
    if (version != nullptr) {
        *version = ver;
    }
    return 1;
}

/**
 * @brief Recognize an HTTP/1.x request (see inspector.h).
 *
 * An HTTP/1.x request starts with "METHOD SP request-target SP HTTP/1.1"
 * CRLF, followed by "Name: value" CRLF header lines and an empty line (CRLF
 * CRLF) that ends the header block. Header names are case insensitive.
 * @param data         Stream bytes collected so far.
 * @param request_line Optional output.
 * @param host         Optional output.
 * @param user_agent   Optional output.
 * @return true if the data starts like an HTTP request.
 */
bool Inspector::parse_http_request(const std::string& data, std::string* request_line, std::string* host,
                                   std::string* user_agent) {
    // The trailing space makes sure e.g. "GETX" does not count as GET
    static const char* const kMethods[] = {"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ",
                                           "CONNECT ", "TRACE "};
    bool is_http = false;
    for (const char* m : kMethods) {
        if (data.compare(0, std::strlen(m), m) == 0) {
            is_http = true;
            break;
        }
    }
    if (!is_http) {
        return false;
    }
    size_t line_end = data.find("\r\n");
    if (request_line != nullptr) {
        // Without a CRLF yet, show at most 200 bytes of the partial line
        *request_line = data.substr(0, line_end == std::string::npos ? std::min<size_t>(data.size(), 200) : line_end);
    }
    size_t header_end = data.find("\r\n\r\n"); // end of the header block
    std::string headers = data.substr(0, header_end == std::string::npos ? data.size() : header_end);
    // Search in a lower case copy (same length, same positions) and cut the
    // value from the original so its case is preserved
    std::string lower = to_lower(headers);
    // Find "\r\n<name>:" - the leading CRLF anchors the match at the start of a
    // header line (so "x-host:" does not match "host:") and skips the request line
    auto header_value = [&](const char* name) -> std::string {
        std::string key = std::string("\r\n") + name + ":";
        size_t pos = lower.find(key);
        if (pos == std::string::npos) {
            return "";
        }
        size_t start = pos + key.size();
        size_t end = headers.find("\r\n", start); // npos for the last header line: take the rest
        return trim(headers.substr(start, end == std::string::npos ? std::string::npos : end - start));
    };
    if (host != nullptr) {
        *host = header_value("host");
    }
    if (user_agent != nullptr) {
        *user_agent = header_value("user-agent");
    }
    return true;
}

/**
 * @brief Recognize the protocol of one direction (see inspector.h).
 *
 * Order of the checks:
 *  - client -> server: TLS ClientHello, HTTP request, DNS over TCP (port 53);
 *  - server -> client: HTTP response status line, TLS ServerHello;
 *  - both: SSH banner ("SSH-2.0-..." is sent by both sides);
 *  - otherwise: log a printable preview of the first bytes.
 * Returning without setting `dir.done` means "wait for more data"; that is
 * only done while the buffer is below kMaxDetectBuffer, so detection always
 * ends eventually.
 */
void Inspector::detect_protocol(const std::string& flow_name, uint16_t server_port, bool upstream,
                                FlowInspectState& state, StreamInspectState& dir) const {
    const std::string& buf = dir.buffer;
    const uint8_t* data = reinterpret_cast<const uint8_t*>(buf.data());
    const char* arrow = upstream ? "C->S" : "S->C"; // C = client (phone), S = server

    if (upstream) {
        std::string sni, alpn, version;
        int tls = parse_tls_client_hello(data, buf.size(), &sni, &alpn, &version);
        if (tls == 1) {
            state.protocol = "TLS";
            state.host = sni; // checked against the block list by inspect_tcp()
            LOG_INFO("%s %s TLS ClientHello %s SNI=%s ALPN=%s", flow_name.c_str(), arrow, version.c_str(),
                     sni.empty() ? "-" : sni.c_str(), alpn.empty() ? "-" : alpn.c_str());
            dir.done = true;
            return;
        }
        if (tls == 0 && buf.size() < kMaxDetectBuffer) {
            return; // wait for the rest of the ClientHello
        }

        std::string request_line, host, ua;
        if (parse_http_request(buf, &request_line, &host, &ua)) {
            // The Host header may come in a later segment: wait for the blank line
            if (buf.find("\r\n\r\n") == std::string::npos && buf.size() < kMaxDetectBuffer) {
                return; // wait for the complete header
            }
            state.protocol = "HTTP";
            state.host = host;
            LOG_INFO("%s %s HTTP %s Host=%s UA=%s", flow_name.c_str(), arrow,
                     printable_preview(reinterpret_cast<const uint8_t*>(request_line.data()), request_line.size(), 300).c_str(),
                     host.empty() ? "-" : host.c_str(), ua.empty() ? "-" : ua.c_str());
            dir.done = true;
            return;
        }
        if (server_port == 53 && buf.size() >= 2) {
            // DNS over TCP (RFC 1035 4.2.2, used for large answers / zone transfers):
            // every message is prefixed with a 2 byte length
            size_t msg_len = read_be16(data);
            if (buf.size() < 2 + msg_len && buf.size() < kMaxDetectBuffer) {
                return; // wait for the whole message
            }
            std::string summary;
            if (parse_dns(data + 2, std::min(msg_len, buf.size() - 2), &summary, nullptr)) {
                state.protocol = "DNS/TCP";
                LOG_INFO("%s %s %s", flow_name.c_str(), arrow, summary.c_str());
                dir.done = true;
                return;
            }
        }
    } else {
        // HTTP response: status line such as "HTTP/1.1 200 OK"
        if (buf.compare(0, 5, "HTTP/") == 0) {
            size_t line_end = buf.find("\r\n");
            if (line_end == std::string::npos && buf.size() < 512) {
                return; // wait for the end of the status line
            }
            LOG_INFO("%s %s %s", flow_name.c_str(), arrow,
                     printable_preview(data, line_end == std::string::npos ? buf.size() : line_end, 200).c_str());
            dir.done = true;
            return;
        }
        // TLS: handshake record (0x16), version major 3, handshake type at byte 5
        // (after the 5 byte record header) = 2 ServerHello
        if (buf.size() >= 6 && data[0] == 0x16 && data[1] == 0x03 && data[5] == 0x02) {
            LOG_INFO("%s %s TLS ServerHello", flow_name.c_str(), arrow);
            dir.done = true;
            return;
        }
    }

    // SSH (RFC 4253 4.2): each side starts with an identification line
    // "SSH-protoversion-softwareversion" CRLF
    if (buf.compare(0, 4, "SSH-") == 0) {
        size_t line_end = buf.find("\r\n");
        if (state.protocol.empty()) {
            state.protocol = "SSH";
        }
        LOG_INFO("%s %s SSH banner %s", flow_name.c_str(), arrow,
                 printable_preview(data, line_end == std::string::npos ? buf.size() : line_end, 100).c_str());
        dir.done = true;
        return;
    }

    // Unknown protocol: show a printable preview of the first bytes
    // (useful for server-speaks-first protocols such as SMTP / FTP banners)
    LOG_INFO("%s %s first %zu bytes: \"%s\"", flow_name.c_str(), arrow, buf.size(),
             printable_preview(data, buf.size(), 80).c_str());
    dir.done = true;
}

/**
 * @brief Replace every occurrence of each matching rule's `from` with `to`.
 *
 * Limitations worth knowing when experimenting:
 *  - Each chunk is processed on its own, so a pattern split across two TCP
 *    chunks is not found.
 *  - Only plaintext can be rewritten; HTTPS is encrypted and compressed
 *    (gzip) or chunked HTTP bodies do not contain the text literally.
 *  - Changing the length of an HTTP body breaks its Content-Length, so keep
 *    `from` and `to` the same length there (as in the sample config).
 */
void Inspector::apply_rewrites(const std::string& flow_name, uint16_t server_port, bool upstream,
                               std::string& data) const {
    if (rewrites_.empty() ||
        std::find(rewrite_ports_.begin(), rewrite_ports_.end(), server_port) == rewrite_ports_.end()) {
        return; // no rules, or this port is not configured for rewriting
    }
    for (const RewriteRule& rule : rewrites_) {
        if (rule.upstream != upstream) {
            continue;
        }
        size_t pos = 0;
        int count = 0;
        while ((pos = data.find(rule.from, pos)) != std::string::npos) {
            data.replace(pos, rule.from.size(), rule.to);
            pos += rule.to.size(); // continue after the replacement, so a `to` containing `from` cannot loop
            ++count;
        }
        if (count > 0) {
            LOG_INFO("%s rewrote %d occurrence(s) of \"%s\" (%s)", flow_name.c_str(), count,
                     printable_preview(reinterpret_cast<const uint8_t*>(rule.from.data()), rule.from.size(), 60).c_str(),
                     upstream ? "upstream" : "downstream");
        }
    }
}

/**
 * @brief TCP entry point (see inspector.h).
 *
 * Called by TcpFlow for each chunk: upstream right before the data is sent
 * to the real server, downstream right after it was received from it. On
 * kBlock the TcpFlow aborts the flow and sends a RST to the phone.
 */
Inspector::Verdict Inspector::inspect_tcp(const std::string& flow_name, uint16_t server_port, bool upstream,
                                          FlowInspectState& state, std::string& data) const {
    StreamInspectState& dir = upstream ? state.up : state.down;
    dir.bytes += data.size();

    if (!dir.done) {
        // Collect at most kMaxDetectBuffer bytes in total (inner min avoids an
        // unsigned underflow when the buffer is already full)
        dir.buffer.append(data, 0, std::min(data.size(), kMaxDetectBuffer - std::min(kMaxDetectBuffer, dir.buffer.size())));
        detect_protocol(flow_name, server_port, upstream, state, dir);
        if (dir.done) {
            // Detection finished: release the buffer memory
            dir.buffer.clear();
            dir.buffer.shrink_to_fit();
            // Blocking is decided once, from the client's first message (SNI / Host)
            if (upstream && !state.host.empty() && is_blocked_domain(state.host)) {
                LOG_NOTICE("%s BLOCKED (%s host %s)", flow_name.c_str(), state.protocol.c_str(), state.host.c_str());
                return kBlock;
            }
        }
    }

    if (payload_dump_bytes_ > 0) {
        LOG_INFO("%s %s %zu bytes:%s", flow_name.c_str(), upstream ? "C->S" : "S->C", data.size(),
                 hexdump(reinterpret_cast<const uint8_t*>(data.data()), data.size(), payload_dump_bytes_).c_str());
    }

    apply_rewrites(flow_name, server_port, upstream, data); // the dump above shows the data before rewriting
    return kPass;
}

/**
 * @brief UDP entry point (see inspector.h).
 *
 * Called by UdpFlow for each datagram. Upstream, kBlock means "do not
 * forward"; if `reply` was filled, the flow wraps it in a UDP packet from
 * the DNS server's address back to the phone. Downstream the verdict is
 * only informational (always kPass here).
 */
Inspector::Verdict Inspector::inspect_udp(const std::string& flow_name, uint16_t server_port, bool upstream,
                                          const uint8_t* data, size_t len, std::string* reply) const {
    if (server_port == 53 || server_port == 5353) { // DNS, and multicast DNS sent as unicast
        std::string summary, qname;
        if (parse_dns(data, len, &summary, &qname)) {
            LOG_INFO("%s %s %s", flow_name.c_str(), upstream ? "C->S" : "S->C", summary.c_str());
            if (upstream && is_blocked_domain(qname) && reply != nullptr && len >= 12) {
                // Answer NXDOMAIN ourselves: copy header + question, set QR/RA/RCODE=3
                // The reply keeps the query ID (so the client accepts it) and the
                // first question; all record counts except QDCOUNT become 0.
                size_t offset = 12;
                std::string name;
                if (read_dns_name(data, len, offset, name) && offset + 4 <= len) {
                    reply->assign(reinterpret_cast<const char*>(data), offset + 4); // header + QNAME + QTYPE + QCLASS
                    uint8_t* r = reinterpret_cast<uint8_t*>(&(*reply)[0]);
                    // Flags high byte: QR = 1 (0x80); keep opcode (0x78) and RD (0x01)
                    // from the query (mask 0x79); AA and TC are cleared
                    r[2] = static_cast<uint8_t>(0x80 | (data[2] & 0x79)); // QR, opcode, RD
                    // Flags low byte: RA = 1 (0x80), Z / AD / CD = 0, RCODE = 3 NXDOMAIN
                    r[3] = 0x83;                                         // RA, NXDOMAIN
                    write_be16(r + 4, 1);  // QDCOUNT: only the first question was copied
                    write_be16(r + 6, 0);  // ANCOUNT
                    write_be16(r + 8, 0);  // NSCOUNT
                    write_be16(r + 10, 0); // ARCOUNT (an EDNS OPT record of the query is dropped)
                    LOG_NOTICE("%s BLOCKED DNS query %s", flow_name.c_str(), qname.c_str());
                    return kBlock;
                }
            }
        }
    } else if (server_port == 443 && upstream && len > 0 && (data[0] & 0xc0) == 0xc0) {
        // QUIC (RFC 9000 17.2): first byte with Header Form bit 0x80 = long header
        // and Fixed Bit 0x40 = 1. Long header packets (Initial, Handshake, ...)
        // set up the connection. The Initial packet carries the TLS ClientHello,
        // protected with keys derived from its Destination Connection ID (RFC 9001
        // 5.2): anyone could decrypt it, but that is beyond this simple inspector,
        // so the SNI is not read here. To force TCP + TLS instead, see
        // vpn_block_quic (handled in Session::handle_udp()).
        LOG_DEBUG("%s C->S QUIC long header packet, %zu bytes", flow_name.c_str(), len);
    }
    if (payload_dump_bytes_ > 0) {
        LOG_INFO("%s %s %zu bytes:%s", flow_name.c_str(), upstream ? "C->S" : "S->C", len,
                 hexdump(data, len, payload_dump_bytes_).c_str());
    }
    return kPass;
}

} // namespace vpn
