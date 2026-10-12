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

Inspector g_inspector;

namespace {

constexpr size_t kMaxDetectBuffer = 16384;

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) {
        return "";
    }
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> parts;
    size_t start = 0;
    while (start <= s.size()) {
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

// Unescape \r \n \t \\ \| in rewrite rules
std::string unescape(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            char c = s[++i];
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

// Split on '|' not preceded by a backslash
std::vector<std::string> split_rule(const std::string& s) {
    std::vector<std::string> parts(1);
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            parts.back() += s[i];
            parts.back() += s[++i];
        } else if (s[i] == '|') {
            parts.emplace_back();
        } else {
            parts.back() += s[i];
        }
    }
    return parts;
}

// Read a (possibly compressed) DNS name starting at `offset`
bool read_dns_name(const uint8_t* msg, size_t len, size_t& offset, std::string& name) {
    name.clear();
    size_t pos = offset;
    bool jumped = false;
    int hops = 0;
    while (pos < len) {
        uint8_t l = msg[pos];
        if (l == 0) {
            if (!jumped) {
                offset = pos + 1;
            }
            if (name.empty()) {
                name = ".";
            }
            return true;
        }
        if ((l & 0xc0) == 0xc0) {
            if (pos + 1 >= len || ++hops > 16) {
                return false;
            }
            size_t ptr = static_cast<size_t>(((l & 0x3f) << 8) | msg[pos + 1]);
            if (!jumped) {
                offset = pos + 2;
            }
            jumped = true;
            pos = ptr;
            continue;
        }
        if (pos + 1 + l > len) {
            return false;
        }
        if (!name.empty()) {
            name += '.';
        }
        name.append(reinterpret_cast<const char*>(msg + pos + 1), l);
        pos += 1 + l;
    }
    return false;
}

const char* dns_type_name(uint16_t type) {
    switch (type) {
    case 1: return "A";
    case 2: return "NS";
    case 5: return "CNAME";
    case 6: return "SOA";
    case 12: return "PTR";
    case 15: return "MX";
    case 16: return "TXT";
    case 28: return "AAAA";
    case 33: return "SRV";
    case 64: return "SVCB";
    case 65: return "HTTPS";
    default: return nullptr;
    }
}

std::string dns_type_string(uint16_t type) {
    const char* n = dns_type_name(type);
    return n ? std::string(n) : "TYPE" + std::to_string(type);
}

} // namespace

void Inspector::load_config() {
    log_packets_ = srv_conf_int("vpn_log_packets", 0) != 0;
    payload_dump_bytes_ = static_cast<size_t>(std::max(0, srv_conf_int("vpn_log_payload_bytes", 0)));

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

    rewrites_.clear();
    for (int i = 1; i <= 16; ++i) {
        std::string key = "vpn_rewrite_" + std::to_string(i);
        std::string value = srv_conf_string(key.c_str(), "");
        if (value.empty()) {
            continue;
        }
        std::vector<std::string> parts = split_rule(value);
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
    rewrite_ports_.clear();
    for (const std::string& p : split(srv_conf_string("vpn_rewrite_ports", "80"), ',')) {
        rewrite_ports_.push_back(static_cast<uint16_t>(std::atoi(p.c_str())));
    }
    if (!blocked_domains_.empty()) {
        LOG_INFO("Blocking %zu domain(s)", blocked_domains_.size());
    }
}

bool Inspector::is_blocked_domain(const std::string& domain_in) const {
    if (blocked_domains_.empty() || domain_in.empty()) {
        return false;
    }
    std::string domain = to_lower(domain_in);
    while (!domain.empty() && domain.back() == '.') {
        domain.pop_back();
    }
    for (const std::string& b : blocked_domains_) {
        if (domain == b ||
            (domain.size() > b.size() && domain.compare(domain.size() - b.size(), b.size(), b) == 0 &&
             domain[domain.size() - b.size() - 1] == '.')) {
            return true;
        }
    }
    return false;
}

std::string Inspector::hexdump(const uint8_t* data, size_t len, size_t max_bytes) {
    size_t n = std::min(len, max_bytes);
    std::string out;
    char line[100];
    for (size_t off = 0; off < n; off += 16) {
        int pos = snprintf(line, sizeof(line), "\n    %04zx  ", off);
        for (size_t i = 0; i < 16; ++i) {
            if (off + i < n) {
                pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), "%02x ", data[off + i]);
            } else {
                pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), "   ");
            }
        }
        pos += snprintf(line + pos, sizeof(line) - static_cast<size_t>(pos), " ");
        for (size_t i = 0; i < 16 && off + i < n; ++i) {
            uint8_t c = data[off + i];
            line[pos++] = (c >= 32 && c < 127) ? static_cast<char>(c) : '.';
        }
        line[pos] = '\0';
        out += line;
    }
    if (len > n) {
        out += "\n    ... (" + std::to_string(len - n) + " more bytes)";
    }
    return out;
}

std::string Inspector::printable_preview(const uint8_t* data, size_t len, size_t max_bytes) {
    std::string out;
    size_t n = std::min(len, max_bytes);
    for (size_t i = 0; i < n; ++i) {
        uint8_t c = data[i];
        if (c == '\r') {
            out += "\\r";
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

bool Inspector::parse_dns(const uint8_t* msg, size_t len, std::string* summary, std::string* first_qname) {
    if (len < 12) {
        return false;
    }
    uint16_t id = read_be16(msg);
    uint16_t flags = read_be16(msg + 2);
    uint16_t qdcount = read_be16(msg + 4);
    uint16_t ancount = read_be16(msg + 6);
    bool response = (flags & 0x8000) != 0;
    int rcode = flags & 0x000f;

    std::string text;
    char head[64];
    snprintf(head, sizeof(head), "DNS %s id=0x%04x", response ? "response" : "query", id);
    text = head;
    if (response && rcode != 0) {
        static const char* const kRcodes[] = {"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"};
        text += std::string(" rcode=") + (rcode < 6 ? kRcodes[rcode] : std::to_string(rcode).c_str());
    }

    size_t offset = 12;
    for (int i = 0; i < qdcount && i < 4; ++i) {
        std::string name;
        if (!read_dns_name(msg, len, offset, name) || offset + 4 > len) {
            return false;
        }
        uint16_t qtype = read_be16(msg + offset);
        offset += 4;
        text += " q=" + dns_type_string(qtype) + " " + name;
        if (i == 0 && first_qname != nullptr) {
            *first_qname = name;
        }
    }
    for (int i = 0; i < ancount && i < 16; ++i) {
        std::string name;
        if (!read_dns_name(msg, len, offset, name) || offset + 10 > len) {
            break;
        }
        uint16_t type = read_be16(msg + offset);
        uint32_t ttl = read_be32(msg + offset + 4);
        uint16_t rdlen = read_be16(msg + offset + 8);
        offset += 10;
        if (offset + rdlen > len) {
            break;
        }
        std::string value;
        char ip[INET6_ADDRSTRLEN];
        if (type == 1 && rdlen == 4) {
            inet_ntop(AF_INET, msg + offset, ip, sizeof(ip));
            value = ip;
        } else if (type == 28 && rdlen == 16) {
            inet_ntop(AF_INET6, msg + offset, ip, sizeof(ip));
            value = ip;
        } else if (type == 5 || type == 2 || type == 12) {
            size_t o = offset;
            read_dns_name(msg, len, o, value);
        } else {
            value = std::to_string(rdlen) + " bytes";
        }
        text += " | " + name + " " + dns_type_string(type) + " " + value + " ttl=" + std::to_string(ttl);
        offset += rdlen;
    }
    if (summary != nullptr) {
        *summary = text;
    }
    return true;
}

int Inspector::parse_tls_client_hello(const uint8_t* data, size_t len, std::string* sni, std::string* alpn,
                                      std::string* version) {
    if (len < 1) {
        return 0;
    }
    if (data[0] != 0x16) {
        return -1; // not a handshake record
    }
    if (len < 5) {
        return 0;
    }
    if (data[1] != 0x03) {
        return -1;
    }
    size_t record_len = read_be16(data + 3);
    if (len < 5 + 4) {
        return 0;
    }
    const uint8_t* hs = data + 5;
    if (hs[0] != 0x01) {
        return -1; // not a ClientHello
    }
    size_t hs_len = (static_cast<size_t>(hs[1]) << 16) | (static_cast<size_t>(hs[2]) << 8) | hs[3];
    // The ClientHello may span several records; only parse the first record
    // when it contains the full message (the normal case)
    size_t available = std::min(len - 5, record_len);
    if (available < 4 + hs_len) {
        return len - 5 >= record_len && record_len < 4 + hs_len ? -1 : 0;
    }
    const uint8_t* p = hs + 4;
    const uint8_t* end = p + hs_len;
    if (end - p < 2 + 32 + 1) {
        return -1;
    }
    uint16_t legacy_version = read_be16(p);
    p += 2 + 32; // version + random
    size_t sid_len = *p++;
    if (static_cast<size_t>(end - p) < sid_len + 2) {
        return -1;
    }
    p += sid_len;
    size_t cs_len = read_be16(p);
    p += 2;
    if (static_cast<size_t>(end - p) < cs_len + 1) {
        return -1;
    }
    p += cs_len;
    size_t comp_len = *p++;
    if (static_cast<size_t>(end - p) < comp_len) {
        return -1;
    }
    p += comp_len;

    char vbuf[16];
    snprintf(vbuf, sizeof(vbuf), "0x%04x", legacy_version);
    std::string ver = legacy_version == 0x0303 ? "TLS1.2" : legacy_version == 0x0302 ? "TLS1.1" :
                      legacy_version == 0x0301 ? "TLS1.0" : vbuf;
    if (end - p >= 2) {
        size_t ext_total = read_be16(p);
        p += 2;
        const uint8_t* ext_end = p + std::min(ext_total, static_cast<size_t>(end - p));
        while (ext_end - p >= 4) {
            uint16_t type = read_be16(p);
            size_t elen = read_be16(p + 2);
            p += 4;
            if (static_cast<size_t>(ext_end - p) < elen) {
                break;
            }
            const uint8_t* e = p;
            if (type == 0 && elen >= 5 && sni != nullptr) { // server_name
                size_t name_len = read_be16(e + 3);
                if (e[2] == 0 && 5 + name_len <= elen) {
                    sni->assign(reinterpret_cast<const char*>(e + 5), name_len);
                }
            } else if (type == 16 && elen >= 2 && alpn != nullptr) { // ALPN
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
                size_t list_len = e[0];
                for (size_t i = 1; i + 1 < 1 + list_len && i + 1 < elen; i += 2) {
                    if (read_be16(e + i) == 0x0304) {
                        ver = "TLS1.3";
                    }
                }
            }
            p += elen;
        }
    }
    if (version != nullptr) {
        *version = ver;
    }
    return 1;
}

bool Inspector::parse_http_request(const std::string& data, std::string* request_line, std::string* host,
                                   std::string* user_agent) {
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
        *request_line = data.substr(0, line_end == std::string::npos ? std::min<size_t>(data.size(), 200) : line_end);
    }
    size_t header_end = data.find("\r\n\r\n");
    std::string headers = data.substr(0, header_end == std::string::npos ? data.size() : header_end);
    std::string lower = to_lower(headers);
    auto header_value = [&](const char* name) -> std::string {
        std::string key = std::string("\r\n") + name + ":";
        size_t pos = lower.find(key);
        if (pos == std::string::npos) {
            return "";
        }
        size_t start = pos + key.size();
        size_t end = headers.find("\r\n", start);
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

void Inspector::detect_protocol(const std::string& flow_name, uint16_t server_port, bool upstream,
                                FlowInspectState& state, StreamInspectState& dir) const {
    const std::string& buf = dir.buffer;
    const uint8_t* data = reinterpret_cast<const uint8_t*>(buf.data());
    const char* arrow = upstream ? "C->S" : "S->C";

    if (upstream) {
        std::string sni, alpn, version;
        int tls = parse_tls_client_hello(data, buf.size(), &sni, &alpn, &version);
        if (tls == 1) {
            state.protocol = "TLS";
            state.host = sni;
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
            size_t msg_len = read_be16(data);
            if (buf.size() < 2 + msg_len && buf.size() < kMaxDetectBuffer) {
                return;
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
        if (buf.compare(0, 5, "HTTP/") == 0) {
            size_t line_end = buf.find("\r\n");
            if (line_end == std::string::npos && buf.size() < 512) {
                return;
            }
            LOG_INFO("%s %s %s", flow_name.c_str(), arrow,
                     printable_preview(data, line_end == std::string::npos ? buf.size() : line_end, 200).c_str());
            dir.done = true;
            return;
        }
        if (buf.size() >= 6 && data[0] == 0x16 && data[1] == 0x03 && data[5] == 0x02) {
            LOG_INFO("%s %s TLS ServerHello", flow_name.c_str(), arrow);
            dir.done = true;
            return;
        }
    }

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
    LOG_INFO("%s %s first %zu bytes: \"%s\"", flow_name.c_str(), arrow, buf.size(),
             printable_preview(data, buf.size(), 80).c_str());
    dir.done = true;
}

void Inspector::apply_rewrites(const std::string& flow_name, uint16_t server_port, bool upstream,
                               std::string& data) const {
    if (rewrites_.empty() ||
        std::find(rewrite_ports_.begin(), rewrite_ports_.end(), server_port) == rewrite_ports_.end()) {
        return;
    }
    for (const RewriteRule& rule : rewrites_) {
        if (rule.upstream != upstream) {
            continue;
        }
        size_t pos = 0;
        int count = 0;
        while ((pos = data.find(rule.from, pos)) != std::string::npos) {
            data.replace(pos, rule.from.size(), rule.to);
            pos += rule.to.size();
            ++count;
        }
        if (count > 0) {
            LOG_INFO("%s rewrote %d occurrence(s) of \"%s\" (%s)", flow_name.c_str(), count,
                     printable_preview(reinterpret_cast<const uint8_t*>(rule.from.data()), rule.from.size(), 60).c_str(),
                     upstream ? "upstream" : "downstream");
        }
    }
}

Inspector::Verdict Inspector::inspect_tcp(const std::string& flow_name, uint16_t server_port, bool upstream,
                                          FlowInspectState& state, std::string& data) const {
    StreamInspectState& dir = upstream ? state.up : state.down;
    dir.bytes += data.size();

    if (!dir.done) {
        dir.buffer.append(data, 0, std::min(data.size(), kMaxDetectBuffer - std::min(kMaxDetectBuffer, dir.buffer.size())));
        detect_protocol(flow_name, server_port, upstream, state, dir);
        if (dir.done) {
            dir.buffer.clear();
            dir.buffer.shrink_to_fit();
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

    apply_rewrites(flow_name, server_port, upstream, data);
    return kPass;
}

Inspector::Verdict Inspector::inspect_udp(const std::string& flow_name, uint16_t server_port, bool upstream,
                                          const uint8_t* data, size_t len, std::string* reply) const {
    if (server_port == 53 || server_port == 5353) {
        std::string summary, qname;
        if (parse_dns(data, len, &summary, &qname)) {
            LOG_INFO("%s %s %s", flow_name.c_str(), upstream ? "C->S" : "S->C", summary.c_str());
            if (upstream && is_blocked_domain(qname) && reply != nullptr && len >= 12) {
                // Answer NXDOMAIN ourselves: copy header + question, set QR/RA/RCODE=3
                size_t offset = 12;
                std::string name;
                if (read_dns_name(data, len, offset, name) && offset + 4 <= len) {
                    reply->assign(reinterpret_cast<const char*>(data), offset + 4);
                    uint8_t* r = reinterpret_cast<uint8_t*>(&(*reply)[0]);
                    r[2] = static_cast<uint8_t>(0x80 | (data[2] & 0x79)); // QR, opcode, RD
                    r[3] = 0x83;                                         // RA, NXDOMAIN
                    write_be16(r + 4, 1);
                    write_be16(r + 6, 0);
                    write_be16(r + 8, 0);
                    write_be16(r + 10, 0);
                    LOG_NOTICE("%s BLOCKED DNS query %s", flow_name.c_str(), qname.c_str());
                    return kBlock;
                }
            }
        }
    } else if (server_port == 443 && upstream && len > 0 && (data[0] & 0xc0) == 0xc0) {
        LOG_DEBUG("%s C->S QUIC long header packet, %zu bytes", flow_name.c_str(), len);
    }
    if (payload_dump_bytes_ > 0) {
        LOG_INFO("%s %s %zu bytes:%s", flow_name.c_str(), upstream ? "C->S" : "S->C", len,
                 hexdump(data, len, payload_dump_bytes_).c_str());
    }
    return kPass;
}

} // namespace vpn
