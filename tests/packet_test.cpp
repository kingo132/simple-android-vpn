/**
 * @file packet_test.cpp
 * @brief Unit tests for the packet builder/parser, the protocol inspector and
 *        the tunnel framing (no network, no root needed).
 *
 * Each test_* function builds packets or payloads by hand, runs them through
 * the code under test (server/src/packet.cpp, server/src/inspector.cpp,
 * common/tunnel_protocol.h) and checks the result with CHECK(). Failures are
 * counted instead of aborting, so one run reports every broken check.
 *
 * Build and run: cmake --build build && build/tests/packet_test
 * (exit code 0 = all checks passed).
 *
 * Reading guide: the srv_* stubs and CHECK first, then any test_* function;
 * main() lists them all.
 */
#include <arpa/inet.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "inspector.h"
#include "packet.h"
#include "tunnel_protocol.h"

// Stubs for the srv_* functions normally exported by the server executable
// (the plugin code calls them for logging and configuration; here logging
// goes to stdout and every config key returns its default)
extern "C" {
void srv_log(int, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
}
int srv_log_enabled(int) { return 1; }
const char* srv_conf_string(const char*, const char* def) { return def; }
int srv_conf_int(const char*, int def) { return def; }
}

using namespace vpn;

static int g_failures = 0; // number of failed CHECKs, decides the exit code
/// Like assert(), but only records the failure (file, line, expression) and continues.
#define CHECK(cond)                                                                 \
    do {                                                                            \
        if (!(cond)) {                                                              \
            fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                           \
        }                                                                           \
    } while (0)

/**
 * @brief Build an IPv4 IpAddr from text.
 * @param s Dotted quad, e.g. "10.0.0.1".
 * @return The address (version 4).
 */
static IpAddr ip4(const char* s) {
    IpAddr a;
    a.version = 4;
    inet_pton(AF_INET, s, a.bytes);
    return a;
}

/**
 * @brief Build an IPv6 IpAddr from text.
 * @param s IPv6 text form, e.g. "fd00::1".
 * @return The address (version 6).
 */
static IpAddr ip6(const char* s) {
    IpAddr a;
    a.version = 6;
    inet_pton(AF_INET6, s, a.bytes);
    return a;
}

/**
 * @brief Recompute the TCP / UDP / ICMP checksum over a packet, including the
 *        stored checksum field: the Internet checksum of correct data is 0.
 *
 * TCP, UDP and ICMPv6 include a "pseudo header" (source and destination
 * address, protocol, length) in the sum; ICMPv4 does not.
 *
 * @param pkt Complete IP packet.
 * @return true if the checksum is correct.
 */
static bool transport_checksum_ok(const std::string& pkt) {
    ParsedPacket p;
    if (!parse_packet(reinterpret_cast<const uint8_t*>(pkt.data()), pkt.size(), p, nullptr)) {
        return false;
    }
    uint32_t sum = 0;
    if (p.protocol != kProtoIcmp) { // ICMPv4 has no pseudo header

        size_t alen = p.ip_version == 4 ? 4 : 16;
        sum = checksum_add(sum, p.src.bytes, alen);
        sum = checksum_add(sum, p.dst.bytes, alen);
        sum += p.protocol;
        sum += static_cast<uint32_t>(p.l4_len);
    }
    sum = checksum_add(sum, p.l4, p.l4_len);
    return checksum_finish(sum) == 0;
}

/**
 * @brief Build TCP packets (IPv4 with options, IPv6 without) and parse them
 *        back: every field, the options, payload and checksums must survive.
 */
static void test_tcp_roundtrip() {
    // TCP options: MSS 1460 (kind 2, len 4, 0x05b4), NOP (1), window scale 7 (kind 3, len 3)
    const uint8_t opts[8] = {2, 4, 0x05, 0xb4, 1, 3, 3, 7};
    const char payload[] = "hello world";
    std::string pkt;
    build_tcp_packet(pkt, ip4("10.0.0.1"), 1234, ip4("1.2.3.4"), 443, 1000, 2000, kTcpSyn | kTcpAck, 65535, opts, 8,
                     reinterpret_cast<const uint8_t*>(payload), 11);
    ParsedPacket p;
    std::string err;
    CHECK(parse_packet(reinterpret_cast<const uint8_t*>(pkt.data()), pkt.size(), p, &err));
    CHECK(p.ip_version == 4 && p.protocol == kProtoTcp);
    CHECK(p.src_port == 1234 && p.dst_port == 443 && p.seq == 1000 && p.ack == 2000);
    CHECK(p.tcp_flags == (kTcpSyn | kTcpAck) && p.window == 65535);
    CHECK(p.tcp_options.mss == 1460 && p.tcp_options.wscale == 7);
    CHECK(p.payload_len == 11 && std::memcmp(p.payload, payload, 11) == 0);
    CHECK(transport_checksum_ok(pkt));
    // IPv4 header checksum (the first 20 bytes; a correct header sums to 0)
    CHECK(checksum_finish(checksum_add(0, reinterpret_cast<const uint8_t*>(pkt.data()), 20)) == 0);

    build_tcp_packet(pkt, ip6("fd00::1"), 5555, ip6("2001:db8::2"), 80, 1, 2, kTcpAck, 100, nullptr, 0,
                     reinterpret_cast<const uint8_t*>(payload), 5);
    CHECK(parse_packet(reinterpret_cast<const uint8_t*>(pkt.data()), pkt.size(), p, &err));
    CHECK(p.ip_version == 6 && p.protocol == kProtoTcp && p.payload_len == 5);
    CHECK(p.src.to_string() == "fd00::1" && p.dst.to_string() == "2001:db8::2");
    CHECK(transport_checksum_ok(pkt));
    printf("%s\n", describe_packet(p).c_str());
}

/**
 * @brief Build UDP and ICMP (v4 and v6) packets and verify parsing and checksums.
 */
static void test_udp_icmp() {
    const uint8_t data[3] = {1, 2, 3};
    std::string pkt;
    build_udp_packet(pkt, ip4("8.8.8.8"), 53, ip4("10.0.0.2"), 40000, data, 3);
    ParsedPacket p;
    CHECK(parse_packet(reinterpret_cast<const uint8_t*>(pkt.data()), pkt.size(), p, nullptr));
    CHECK(p.protocol == kProtoUdp && p.src_port == 53 && p.payload_len == 3);
    CHECK(transport_checksum_ok(pkt));

    build_udp_packet(pkt, ip6("2001:4860:4860::8888"), 53, ip6("fd00::2"), 40000, data, 3);
    CHECK(transport_checksum_ok(pkt));

    // Echo reply (type 0); the "rest of header" word carries identifier 7 and sequence 9
    build_icmp_packet(pkt, ip4("1.1.1.1"), ip4("10.0.0.2"), 0, 0, (7u << 16) | 9u, data, 3);
    CHECK(parse_packet(reinterpret_cast<const uint8_t*>(pkt.data()), pkt.size(), p, nullptr));
    CHECK(p.protocol == kProtoIcmp && p.icmp_type == 0 && p.icmp_id == 7 && p.icmp_seq == 9);
    CHECK(transport_checksum_ok(pkt));

    // ICMPv6 echo reply is type 129
    build_icmp_packet(pkt, ip6("2001:db8::1"), ip6("fd00::2"), 129, 0, (7u << 16) | 9u, data, 3);
    CHECK(parse_packet(reinterpret_cast<const uint8_t*>(pkt.data()), pkt.size(), p, nullptr));
    CHECK(p.protocol == kProtoIcmpV6 && p.icmp_type == 129);
    CHECK(transport_checksum_ok(pkt));
}

/**
 * @brief The parser must reject garbage instead of reading out of bounds.
 */
static void test_malformed() {
    ParsedPacket p;
    std::string err;
    uint8_t junk[30] = {0x45, 0, 0, 200}; // IPv4 header claiming 200 bytes total, only 30 present
    CHECK(!parse_packet(junk, sizeof(junk), p, &err));
    uint8_t v7[20] = {0x70}; // IP version 7 does not exist
    CHECK(!parse_packet(v7, sizeof(v7), p, &err));
    CHECK(!parse_packet(junk, 0, p, &err)); // empty input
}

/**
 * @brief DNS message parsing used for the "DNS query / response" log lines and domain blocking.
 */
static void test_dns() {
    // query for www.example.com A, id 0x1234
    // (12-byte header: id, flags 0x0100 = recursion desired, 1 question; then
    // the name as length-prefixed labels, type A = 1, class IN = 1)
    const uint8_t query[] = {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'w', 'w', 'w', 7, 'e', 'x', 'a',
                             'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1};
    std::string summary, qname;
    CHECK(Inspector::parse_dns(query, sizeof(query), &summary, &qname));
    CHECK(qname == "www.example.com");
    printf("%s\n", summary.c_str());

    // response with a compressed A record
    std::vector<uint8_t> resp(query, query + sizeof(query));
    resp[2] = 0x81; // flags 0x8180: response, recursion desired + available, no error
    resp[3] = 0x80;
    resp[7] = 1;    // answer count = 1
    // 0xc00c = pointer to the name at offset 12 (compression), type A, class IN, TTL 60, 4 bytes address
    const uint8_t answer[] = {0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34};
    resp.insert(resp.end(), answer, answer + sizeof(answer));
    CHECK(Inspector::parse_dns(resp.data(), resp.size(), &summary, nullptr));
    CHECK(summary.find("93.184.216.34") != std::string::npos);
    printf("%s\n", summary.c_str());
}

/**
 * @brief Build a minimal TLS 1.3 ClientHello record by hand.
 *
 * Contains the extensions the inspector reads: server_name (SNI), ALPN "h2"
 * and supported_versions (TLS 1.3). Lengths are written big endian, layer by
 * layer from the inside out: extension -> handshake body -> handshake
 * header -> TLS record header.
 *
 * @param sni Host name to put into the server_name extension.
 * @return The complete TLS record bytes.
 */
static std::vector<uint8_t> make_client_hello(const std::string& sni) {
    std::vector<uint8_t> ext;
    // server_name (extension type 0): list length, name type 0 = host_name, name length, name
    std::vector<uint8_t> sn;
    uint16_t name_len = static_cast<uint16_t>(sni.size());
    uint16_t list_len = static_cast<uint16_t>(name_len + 3);
    sn.push_back(static_cast<uint8_t>(list_len >> 8));
    sn.push_back(static_cast<uint8_t>(list_len));
    sn.push_back(0);
    sn.push_back(static_cast<uint8_t>(name_len >> 8));
    sn.push_back(static_cast<uint8_t>(name_len));
    sn.insert(sn.end(), sni.begin(), sni.end());
    // extension header: type 0 (server_name), 16-bit length
    ext.push_back(0);
    ext.push_back(0);
    ext.push_back(static_cast<uint8_t>(sn.size() >> 8));
    ext.push_back(static_cast<uint8_t>(sn.size()));
    ext.insert(ext.end(), sn.begin(), sn.end());
    // ALPN h2: type 16, extension length 5, list length 3, string length 2, "h2"
    const uint8_t alpn[] = {0, 16, 0, 5, 0, 3, 2, 'h', '2'};
    ext.insert(ext.end(), alpn, alpn + sizeof(alpn));
    // supported_versions TLS1.3: type 43, extension length 3, list length 2, version 0x0304
    const uint8_t sv[] = {0, 43, 0, 3, 2, 3, 4};
    ext.insert(ext.end(), sv, sv + sizeof(sv));

    std::vector<uint8_t> body;
    // legacy_version 0x0303 (TLS 1.2, as TLS 1.3 clients send it)
    body.push_back(3);
    body.push_back(3);
    body.insert(body.end(), 32, 0xaa); // random
    body.push_back(0);                 // session id
    // cipher suites: 2 bytes long, TLS_AES_128_GCM_SHA256 (0x1301)
    body.push_back(0);
    body.push_back(2);
    body.push_back(0x13);
    body.push_back(0x01); // cipher suites
    body.push_back(1);
    body.push_back(0); // compression
    // extensions block: 16-bit length, then the extensions
    body.push_back(static_cast<uint8_t>(ext.size() >> 8));
    body.push_back(static_cast<uint8_t>(ext.size()));
    body.insert(body.end(), ext.begin(), ext.end());

    // Handshake header: type 1 = ClientHello, 24-bit length
    std::vector<uint8_t> hs;
    hs.push_back(1);
    hs.push_back(0);
    hs.push_back(static_cast<uint8_t>(body.size() >> 8));
    hs.push_back(static_cast<uint8_t>(body.size()));
    hs.insert(hs.end(), body.begin(), body.end());

    // TLS record header: content type 0x16 = handshake, version 0x0301, 16-bit length
    std::vector<uint8_t> rec = {0x16, 3, 1, static_cast<uint8_t>(hs.size() >> 8), static_cast<uint8_t>(hs.size())};
    rec.insert(rec.end(), hs.begin(), hs.end());
    return rec;
}

/**
 * @brief SNI / ALPN / version extraction from a ClientHello, plus the
 *        "need more data" (0) and "not TLS" (-1) results.
 */
static void test_tls() {
    std::vector<uint8_t> hello = make_client_hello("www.google.com");
    std::string sni, alpn, version;
    CHECK(Inspector::parse_tls_client_hello(hello.data(), hello.size(), &sni, &alpn, &version) == 1);
    CHECK(sni == "www.google.com");
    CHECK(alpn == "h2");
    CHECK(version == "TLS1.3");
    // partial data -> need more
    CHECK(Inspector::parse_tls_client_hello(hello.data(), 20, nullptr, nullptr, nullptr) == 0);
    const uint8_t http[] = "GET / HTTP/1.1\r\n";
    CHECK(Inspector::parse_tls_client_hello(http, sizeof(http) - 1, nullptr, nullptr, nullptr) == -1);
}

/**
 * @brief HTTP request line / Host / User-Agent extraction, and rejection of non-HTTP data.
 */
static void test_http() {
    std::string req = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8\r\n\r\n";
    std::string line, host, ua;
    CHECK(Inspector::parse_http_request(req, &line, &host, &ua));
    CHECK(line == "GET /index.html HTTP/1.1");
    CHECK(host == "example.com");
    CHECK(ua == "curl/8");
    CHECK(!Inspector::parse_http_request("SSH-2.0-OpenSSH\r\n", nullptr, nullptr, nullptr));
}

/**
 * @brief Tunnel framing (common/tunnel_protocol.h): length, incomplete header,
 *        bad magic, and the key=value HELLO encoding.
 */
static void test_tunnel_frames() {
    std::string out;
    tunnel::append_frame(out, tunnel::kPacket, "abc", 3);
    uint8_t type = 0;
    uint32_t len = 0;
    // 8-byte header + 3 bytes payload
    CHECK(tunnel::parse_header(reinterpret_cast<const uint8_t*>(out.data()), out.size(), &type, &len) == 11);
    CHECK(type == tunnel::kPacket && len == 3);
    CHECK(tunnel::parse_header(reinterpret_cast<const uint8_t*>(out.data()), 7, &type, &len) == 0); // header incomplete
    out[0] = 'X'; // corrupt the magic
    CHECK(tunnel::parse_header(reinterpret_cast<const uint8_t*>(out.data()), out.size(), &type, &len) == -1);
    auto kv = tunnel::decode_kv("a=1\nb=two\n", 10);
    CHECK(kv["a"] == "1" && kv["b"] == "two");
}

/**
 * @brief IP fragmentation (Session::send_packet for packets above the phone's
 *        MTU) and reassembly (fragments sent by the phone), for IPv4 and IPv6.
 */
static void test_fragmentation() {
    for (int version = 4; version <= 6; version += 2) { // 4, then 6
        std::vector<uint8_t> payload(5000);
        for (size_t i = 0; i < payload.size(); ++i) {
            payload[i] = static_cast<uint8_t>(i * 7);
        }
        std::string pkt;
        if (version == 4) {
            build_udp_packet(pkt, ip4("1.2.3.4"), 53, ip4("10.0.0.2"), 4000, payload.data(), payload.size());
        } else {
            build_udp_packet(pkt, ip6("2001:db8::1"), 53, ip6("fd00::2"), 4000, payload.data(), payload.size());
        }
        std::vector<std::string> frags;
        fragment_packet(pkt, 1500, 77, frags); // MTU 1500, IP identification 77
        CHECK(frags.size() == 4);              // 5000 bytes of payload need 4 fragments
        FragmentReassembler reassembler;
        std::string whole;
        bool done = false;
        // deliver out of order
        for (int i : {2, 0, 3, 1}) {
            CHECK(frags[i].size() <= 1500);
            ParsedPacket p;
            CHECK(parse_packet(reinterpret_cast<const uint8_t*>(frags[i].data()), frags[i].size(), p, nullptr));
            CHECK(p.fragment);
            done = reassembler.add(p, 0, whole);
        }
        CHECK(done);
        ParsedPacket full;
        CHECK(parse_packet(reinterpret_cast<const uint8_t*>(whole.data()), whole.size(), full, nullptr));
        CHECK(!full.fragment && full.protocol == kProtoUdp && full.payload_len == payload.size());
        CHECK(std::memcmp(full.payload, payload.data(), payload.size()) == 0);
        CHECK(transport_checksum_ok(whole));
        CHECK(reassembler.pending() == 0);
    }
    // small packets are not fragmented
    std::string small;
    build_udp_packet(small, ip4("1.2.3.4"), 1, ip4("5.6.7.8"), 2, nullptr, 0);
    std::vector<std::string> frags;
    fragment_packet(small, 1500, 1, frags);
    CHECK(frags.size() == 1 && frags[0] == small);
}

/**
 * @brief Run every test.
 * @return 0 if all checks passed, 1 otherwise.
 */
int main() {
    test_fragmentation();
    test_tcp_roundtrip();
    test_udp_icmp();
    test_malformed();
    test_dns();
    test_tls();
    test_http();
    test_tunnel_frames();
    if (g_failures == 0) {
        printf("packet_test: PASS\n");
        return 0;
    }
    printf("packet_test: %d FAILURES\n", g_failures);
    return 1;
}
