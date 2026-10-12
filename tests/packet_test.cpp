// Unit tests for the packet builder/parser and the protocol inspector
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

static int g_failures = 0;
#define CHECK(cond)                                                                 \
    do {                                                                            \
        if (!(cond)) {                                                              \
            fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                           \
        }                                                                           \
    } while (0)

static IpAddr ip4(const char* s) {
    IpAddr a;
    a.version = 4;
    inet_pton(AF_INET, s, a.bytes);
    return a;
}

static IpAddr ip6(const char* s) {
    IpAddr a;
    a.version = 6;
    inet_pton(AF_INET6, s, a.bytes);
    return a;
}

// Verify the transport checksum of a built packet by recomputing it
static bool transport_checksum_ok(const std::string& pkt) {
    ParsedPacket p;
    if (!parse_packet(reinterpret_cast<const uint8_t*>(pkt.data()), pkt.size(), p, nullptr)) {
        return false;
    }
    uint32_t sum = 0;
    if (p.protocol != kProtoIcmp) {
        size_t alen = p.ip_version == 4 ? 4 : 16;
        sum = checksum_add(sum, p.src.bytes, alen);
        sum = checksum_add(sum, p.dst.bytes, alen);
        sum += p.protocol;
        sum += static_cast<uint32_t>(p.l4_len);
    }
    sum = checksum_add(sum, p.l4, p.l4_len);
    return checksum_finish(sum) == 0;
}

static void test_tcp_roundtrip() {
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
    // IPv4 header checksum
    CHECK(checksum_finish(checksum_add(0, reinterpret_cast<const uint8_t*>(pkt.data()), 20)) == 0);

    build_tcp_packet(pkt, ip6("fd00::1"), 5555, ip6("2001:db8::2"), 80, 1, 2, kTcpAck, 100, nullptr, 0,
                     reinterpret_cast<const uint8_t*>(payload), 5);
    CHECK(parse_packet(reinterpret_cast<const uint8_t*>(pkt.data()), pkt.size(), p, &err));
    CHECK(p.ip_version == 6 && p.protocol == kProtoTcp && p.payload_len == 5);
    CHECK(p.src.to_string() == "fd00::1" && p.dst.to_string() == "2001:db8::2");
    CHECK(transport_checksum_ok(pkt));
    printf("%s\n", describe_packet(p).c_str());
}

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

    build_icmp_packet(pkt, ip4("1.1.1.1"), ip4("10.0.0.2"), 0, 0, (7u << 16) | 9u, data, 3);
    CHECK(parse_packet(reinterpret_cast<const uint8_t*>(pkt.data()), pkt.size(), p, nullptr));
    CHECK(p.protocol == kProtoIcmp && p.icmp_type == 0 && p.icmp_id == 7 && p.icmp_seq == 9);
    CHECK(transport_checksum_ok(pkt));

    build_icmp_packet(pkt, ip6("2001:db8::1"), ip6("fd00::2"), 129, 0, (7u << 16) | 9u, data, 3);
    CHECK(parse_packet(reinterpret_cast<const uint8_t*>(pkt.data()), pkt.size(), p, nullptr));
    CHECK(p.protocol == kProtoIcmpV6 && p.icmp_type == 129);
    CHECK(transport_checksum_ok(pkt));
}

static void test_malformed() {
    ParsedPacket p;
    std::string err;
    uint8_t junk[30] = {0x45, 0, 0, 200};
    CHECK(!parse_packet(junk, sizeof(junk), p, &err));
    uint8_t v7[20] = {0x70};
    CHECK(!parse_packet(v7, sizeof(v7), p, &err));
    CHECK(!parse_packet(junk, 0, p, &err));
}

static void test_dns() {
    // query for www.example.com A, id 0x1234
    const uint8_t query[] = {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'w', 'w', 'w', 7, 'e', 'x', 'a',
                             'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1};
    std::string summary, qname;
    CHECK(Inspector::parse_dns(query, sizeof(query), &summary, &qname));
    CHECK(qname == "www.example.com");
    printf("%s\n", summary.c_str());

    // response with a compressed A record
    std::vector<uint8_t> resp(query, query + sizeof(query));
    resp[2] = 0x81;
    resp[3] = 0x80;
    resp[7] = 1;
    const uint8_t answer[] = {0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34};
    resp.insert(resp.end(), answer, answer + sizeof(answer));
    CHECK(Inspector::parse_dns(resp.data(), resp.size(), &summary, nullptr));
    CHECK(summary.find("93.184.216.34") != std::string::npos);
    printf("%s\n", summary.c_str());
}

static std::vector<uint8_t> make_client_hello(const std::string& sni) {
    std::vector<uint8_t> ext;
    // server_name
    std::vector<uint8_t> sn;
    uint16_t name_len = static_cast<uint16_t>(sni.size());
    uint16_t list_len = static_cast<uint16_t>(name_len + 3);
    sn.push_back(static_cast<uint8_t>(list_len >> 8));
    sn.push_back(static_cast<uint8_t>(list_len));
    sn.push_back(0);
    sn.push_back(static_cast<uint8_t>(name_len >> 8));
    sn.push_back(static_cast<uint8_t>(name_len));
    sn.insert(sn.end(), sni.begin(), sni.end());
    ext.push_back(0);
    ext.push_back(0);
    ext.push_back(static_cast<uint8_t>(sn.size() >> 8));
    ext.push_back(static_cast<uint8_t>(sn.size()));
    ext.insert(ext.end(), sn.begin(), sn.end());
    // ALPN h2
    const uint8_t alpn[] = {0, 16, 0, 5, 0, 3, 2, 'h', '2'};
    ext.insert(ext.end(), alpn, alpn + sizeof(alpn));
    // supported_versions TLS1.3
    const uint8_t sv[] = {0, 43, 0, 3, 2, 3, 4};
    ext.insert(ext.end(), sv, sv + sizeof(sv));

    std::vector<uint8_t> body;
    body.push_back(3);
    body.push_back(3);
    body.insert(body.end(), 32, 0xaa); // random
    body.push_back(0);                 // session id
    body.push_back(0);
    body.push_back(2);
    body.push_back(0x13);
    body.push_back(0x01); // cipher suites
    body.push_back(1);
    body.push_back(0); // compression
    body.push_back(static_cast<uint8_t>(ext.size() >> 8));
    body.push_back(static_cast<uint8_t>(ext.size()));
    body.insert(body.end(), ext.begin(), ext.end());

    std::vector<uint8_t> hs;
    hs.push_back(1);
    hs.push_back(0);
    hs.push_back(static_cast<uint8_t>(body.size() >> 8));
    hs.push_back(static_cast<uint8_t>(body.size()));
    hs.insert(hs.end(), body.begin(), body.end());

    std::vector<uint8_t> rec = {0x16, 3, 1, static_cast<uint8_t>(hs.size() >> 8), static_cast<uint8_t>(hs.size())};
    rec.insert(rec.end(), hs.begin(), hs.end());
    return rec;
}

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

static void test_http() {
    std::string req = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8\r\n\r\n";
    std::string line, host, ua;
    CHECK(Inspector::parse_http_request(req, &line, &host, &ua));
    CHECK(line == "GET /index.html HTTP/1.1");
    CHECK(host == "example.com");
    CHECK(ua == "curl/8");
    CHECK(!Inspector::parse_http_request("SSH-2.0-OpenSSH\r\n", nullptr, nullptr, nullptr));
}

static void test_tunnel_frames() {
    std::string out;
    tunnel::append_frame(out, tunnel::kPacket, "abc", 3);
    uint8_t type = 0;
    uint32_t len = 0;
    CHECK(tunnel::parse_header(reinterpret_cast<const uint8_t*>(out.data()), out.size(), &type, &len) == 11);
    CHECK(type == tunnel::kPacket && len == 3);
    CHECK(tunnel::parse_header(reinterpret_cast<const uint8_t*>(out.data()), 7, &type, &len) == 0);
    out[0] = 'X';
    CHECK(tunnel::parse_header(reinterpret_cast<const uint8_t*>(out.data()), out.size(), &type, &len) == -1);
    auto kv = tunnel::decode_kv("a=1\nb=two\n", 10);
    CHECK(kv["a"] == "1" && kv["b"] == "two");
}

static void test_fragmentation() {
    for (int version = 4; version <= 6; version += 2) {
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
        fragment_packet(pkt, 1500, 77, frags);
        CHECK(frags.size() == 4);
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
