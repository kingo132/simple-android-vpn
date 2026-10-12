# Inspector and capture

**English** | [简体中文](../zh-CN/inspector-and-capture.md) · [README](../../README.md) · [Architecture](architecture.md) · [Tunnel protocol](tunnel-protocol.md) · [Android client](android-client.md) · [Learning guide](learning-guide.md) · [Configuration](configuration.md) · [Testing](testing.md) · [Source tour](source-tour.md)

Two places let you look at the traffic:

* the **Inspector** (`server/src/inspector.cpp`) sees the *application data* of every TCP connection
  and UDP datagram, and can log, rewrite or block it;
* the **capture** (`server/src/pcap_writer.cpp`) records the raw *IP packets* exactly as the phone sent
  and received them, for Wireshark.

```mermaid
flowchart LR
    PH["phone"] -->|"IP packets"| SES["Session"]
    SES -->|"every packet, both directions"| CAP["PcapWriter: session pcap file<br/>LiveCapture: port 9444"]
    SES --> TF["TcpFlow"]
    SES --> UF["UdpFlow"]
    TF -->|"byte chunks<br/>C->S and S->C"| INS["Inspector::inspect_tcp()"]
    UF -->|"datagrams"| INSU["Inspector::inspect_udp()"]
    INS -->|"pass (maybe rewritten)"| OUT["real server / phone"]
    INS -->|"block"| RST["RST both sides"]
    INSU -->|"blocked DNS"| NX["NXDOMAIN reply to the phone"]
```

## 1. Where the Inspector is called

| Call | Direction | Called from |
|---|---|---|
| `inspect_tcp(name, port, upstream=true, state, data)` | phone → server | `TcpFlow::deliver_upstream()` for every in-order data segment |
| `inspect_tcp(name, port, upstream=false, state, data)` | server → phone | `TcpFlow::on_upstream_data()` for every chunk read from the real server |
| `inspect_udp(name, port, upstream=true, data, len, &reply)` | phone → server | `UdpFlow::on_packet()` |
| `inspect_udp(name, port, upstream=false, data, len, nullptr)` | server → phone | `UdpFlow::on_upstream_data()` |

`data` in `inspect_tcp` is a `std::string&`: **you may change it in place, including its length**.
This works because the two TCP connections are independent (see
[Architecture § 1](architecture.md#1-the-idea-in-one-picture)): `TcpFlow` keeps its own sequence numbers
towards the phone, and the server kernel numbers the bytes towards the real server.

## 2. TCP inspection pipeline

```mermaid
flowchart TD
    IN(["inspect_tcp(chunk)"]) --> CNT["count bytes for this direction"]
    CNT --> DONE{"protocol detection<br/>done for this direction?"}
    DONE -->|"no"| BUF["append to the detection buffer<br/>(at most 16 KB)"]
    BUF --> DET["detect_protocol()"]
    DET --> D2{"detected now?"}
    D2 -->|"yes"| BL{"upstream and host (SNI / Host)<br/>in vpn_block_domains?"}
    BL -->|"yes"| BLOCK(["return kBlock: flow aborted,<br/>RST to the phone"])
    BL -->|"no"| DUMP
    D2 -->|"still waiting"| DUMP
    DONE -->|"yes"| DUMP{"vpn_log_payload_bytes > 0?"}
    DUMP -->|"yes"| HEX["log hex dump of the chunk"]
    DUMP -->|"no"| RW
    HEX --> RW["apply_rewrites():<br/>if port in vpn_rewrite_ports,<br/>replace every match of each rule<br/>of this direction"]
    RW --> PASS(["return kPass"])
```

### Protocol detection

```mermaid
flowchart TD
    UP{"direction"} -->|"phone to server"| TLS{"TLS ClientHello?<br/>parse_tls_client_hello()"}
    TLS -->|"complete"| TLSOK["protocol TLS, host = SNI<br/>log version, SNI, ALPN"]
    TLS -->|"incomplete, < 16 KB"| WAIT(["wait for more bytes"])
    TLS -->|"not TLS"| HTTP{"HTTP request line?<br/>GET / POST / ..."}
    HTTP -->|"yes, header complete"| HTTPOK["protocol HTTP, host = Host header<br/>log request line, Host, User-Agent"]
    HTTP -->|"yes, header incomplete"| WAIT
    HTTP -->|"no"| DNS{"port 53: DNS over TCP?<br/>2-byte length + message"}
    DNS -->|"yes"| DNSOK["protocol DNS/TCP, log query"]
    DNS -->|"no"| SSH
    UP -->|"server to phone"| RESP{"starts with HTTP/ ?"}
    RESP -->|"yes"| RESPOK["log status line"]
    RESP -->|"no"| SH{"TLS ServerHello?<br/>16 03 xx xx xx 02"}
    SH -->|"yes"| SHOK["log TLS ServerHello"]
    SH -->|"no"| SSH{"starts with SSH- ?"}
    SSH -->|"yes"| SSHOK["log SSH banner"]
    SSH -->|"no"| UNK["unknown: log a printable preview<br/>of the first bytes"]
```

### How the TLS SNI is found

The ClientHello is the first message of a TLS connection and is sent **in clear text** (except with
Encrypted ClientHello). The server name the client wants is in the `server_name` extension:

```mermaid
flowchart LR
    R["TLS record header<br/>type 0x16 (handshake)<br/>version, length"] --> H["handshake header<br/>type 0x01 (ClientHello)<br/>length (3 bytes)"]
    H --> B["client version<br/>32 bytes random"]
    B --> SID["session id<br/>(1-byte length)"]
    SID --> CS["cipher suites<br/>(2-byte length)"]
    CS --> CM["compression methods<br/>(1-byte length)"]
    CM --> EXT["extensions<br/>(2-byte total length)"]
    EXT --> E0["type 0x0000 server_name<br/>list, host_name = SNI"]
    EXT --> E16["type 0x0010 ALPN<br/>h2, http/1.1"]
    EXT --> E43["type 0x002b supported_versions<br/>TLS 1.3 = 0x0304"]
```

`parse_tls_client_hello()` walks these length-prefixed fields with bounds checks and returns 1
(complete), 0 (need more data) or -1 (not a ClientHello).

## 3. UDP and DNS inspection

```mermaid
sequenceDiagram
    participant Ph as Phone
    participant UF as UdpFlow
    participant I as Inspector
    participant DNS as DNS server
    Ph->>UF: DNS query A ads.example.com
    UF->>I: inspect_udp(upstream, query)
    I->>I: parse_dns(): header, question (name compression aware)
    alt name or a parent domain in vpn_block_domains
        I-->>UF: kBlock + reply = header and question,<br/>QR=1, RA=1, RCODE=3 (NXDOMAIN)
        UF->>Ph: forged NXDOMAIN response
    else allowed
        I-->>UF: kPass (query logged)
        UF->>DNS: query
        DNS-->>UF: response
        UF->>I: inspect_udp(downstream), answers logged
        UF->>Ph: response
    end
```

A domain matches when it equals a blocked entry or is a sub-domain of it (`ads.example.com` matches
`example.com`).

## 4. Blocking summary

| Traffic | Detected by | Result |
|---|---|---|
| DNS query for a blocked name | `inspect_udp`, port 53 / 5353 | NXDOMAIN answered by the server |
| TLS to a blocked SNI | ClientHello in `inspect_tcp` | flow aborted, RST to the phone |
| HTTP to a blocked Host | request header in `inspect_tcp` | flow aborted, RST to the phone |
| QUIC (UDP 443) with `vpn_block_quic = 1` | `Session::handle_udp` | ICMP port unreachable to the phone |
| private destinations with `vpn_block_private = 1` | `Session::target_allowed` | RST (TCP) / drop (UDP, ICMP) |

### Why block QUIC?

```mermaid
sequenceDiagram
    participant B as Browser
    participant S as SimpleVPN server
    B->>S: UDP 443 QUIC Initial (encrypted, SNI hidden from this inspector)
    S->>B: ICMP port unreachable (vpn_block_quic = 1)
    B->>S: TCP SYN to port 443
    S->>B: SYN-ACK
    B->>S: TLS ClientHello, the SNI is visible in clear text
    Note over S: Inspector logs SNI=www.google.com,<br/>blocking by domain works
```

QUIC (HTTP/3) runs over UDP and encrypts its Initial packet with keys derived from the connection id,
so this inspector does not parse it. Browsers fall back to TCP when QUIC fails, which makes the
traffic visible again.

## 5. Rewriting

Rules come from the config: `vpn_rewrite_N = up|from|to` or `down|from|to`, only applied on the ports
in `vpn_rewrite_ports` (default 80). Escapes `\r \n \t \| \\` are supported.

```mermaid
sequenceDiagram
    participant Ph as Phone (curl)
    participant TF as TcpFlow + Inspector
    participant W as Web server
    Ph->>TF: GET / HTTP/1.1, User-Agent: curl/8
    TF->>TF: up rule "User-Agent: curl" becomes "User-Agent: SimpleVPN"
    TF->>W: GET / HTTP/1.1, User-Agent: SimpleVPN/8
    W-->>TF: 200 OK ... Example Domain ...
    TF->>TF: down rule "Example Domain" becomes "Hacked! Domain"
    TF->>Ph: 200 OK ... Hacked! Domain ...
```

Limitations to keep in mind:

* Rules are applied **per chunk**. A string split across two TCP segments / reads is not found.
* If the length of an HTTP body changes, `Content-Length` must change too, or the client waits for
  missing bytes / ignores extra bytes. Equal-length replacements are the easy way.
* Compressed (`Content-Encoding: gzip`) or TLS-encrypted content cannot be rewritten as text. For
  experiments use plain HTTP, or a rewrite rule that removes `Accept-Encoding` upstream.

## 6. pcap capture

### File format

```mermaid
flowchart LR
    G["global header, 24 bytes<br/>magic a1b2c3d4, version 2.4<br/>snaplen 65535, linktype 101 (raw IP)"] --> R1["record header, 16 bytes<br/>ts_sec, ts_usec, incl_len, orig_len"] --> P1["packet bytes<br/>(IPv4 or IPv6 header first)"] --> R2["record header"] --> P2["packet bytes"] --> MORE["..."]
```

Link type 101 (`LINKTYPE_RAW`) means "the packet starts directly with an IP header", which is exactly
what the TUN device delivers — no fake Ethernet header is needed.

### Per-session files

With `vpn_pcap_dir = ./pcap` every authenticated session writes
`pcap/session-<id>-<YYYYmmdd-HHMMSS>.pcap`, both directions, up to `vpn_pcap_max_mb`. The file is
flushed once per second, so `tail -f` / Wireshark reloads show recent packets.

### Live capture

```mermaid
sequenceDiagram
    participant WS as Wireshark (reads stdin)
    participant NC as nc / ssh
    participant P as vpn_plugin (port 9444)
    participant LC as LiveCapture
    participant S as Sessions on all workers
    WS->>NC: tools/wireshark_live.sh
    NC->>P: TCP connect 127.0.0.1:9444
    P->>P: handle_client_open: loopback only<br/>(unless vpn_capture_allow_remote = 1)
    P->>LC: add_subscriber(si)
    LC->>NC: pcap global header
    loop every packet of every phone
        S->>LC: publish(packet)
        LC->>NC: one message = record header + packet (srv_send)
    end
    NC->>WS: pcap stream, packets appear live
```

* `LiveCapture` is shared by all workers and protected by a mutex — the only shared mutable plugin
  state.
* Each record is sent as **one** `srv_send()` message. If Wireshark reads too slowly, the engine drops
  whole messages (`send_overflow_policy = drop`), so the stream never contains half a record and
  stays parseable; the phone's traffic is never slowed down by a viewer.
* Port 9444 must also be listed in `conf/bind.txt`; keep it bound to `127.0.0.1` and use SSH from other
  machines (`tools/wireshark_live.sh user@server`).

## 7. Adding your own analysis

```cpp
// inspector.cpp, inside Inspector::inspect_tcp(), before apply_rewrites():
if (upstream && server_port == 6379 && data.compare(0, 1, "*") == 0) {
    LOG_INFO("%s Redis command: %s", flow_name.c_str(),
             printable_preview(reinterpret_cast<const uint8_t*>(data.data()), data.size(), 120).c_str());
}
```

Rebuild with `cmake --build build`, restart `mulserver`, and every Redis command the phone sends shows
up in the log. The [learning guide](learning-guide.md) has more ideas.
