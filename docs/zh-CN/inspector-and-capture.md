# Inspector 与抓包

[English](../en/inspector-and-capture.md) | **简体中文** · [README](../../README.zh-CN.md) · [架构](architecture.md) · [隧道协议](tunnel-protocol.md) · [Android 客户端](android-client.md) · [学习指南](learning-guide.md) · [配置](configuration.md) · [测试](testing.md) · [源码导读](source-tour.md)

有两个地方可以让你观察流量：

* **Inspector**（`server/src/inspector.cpp`）能看到每条 TCP 连接和每个 UDP 数据报中的*应用层数据*，
  并可以记录、改写或拦截它们；
* **抓包**（`server/src/pcap_writer.cpp`）把手机收发的原始 *IP 包*原样记录下来，供 Wireshark 使用。

```mermaid
flowchart LR
    PH["手机"] -->|"IP 包"| SES["Session"]
    SES -->|"每个包，两个方向"| CAP["PcapWriter：会话 pcap 文件<br/>LiveCapture：9444 端口"]
    SES --> TF["TcpFlow"]
    SES --> UF["UdpFlow"]
    TF -->|"字节块<br/>C->S 和 S->C"| INS["Inspector::inspect_tcp()"]
    UF -->|"数据报"| INSU["Inspector::inspect_udp()"]
    INS -->|"放行 (可能已改写)"| OUT["真实服务器 / 手机"]
    INS -->|"拦截"| RST["向两端发 RST"]
    INSU -->|"被拦截的 DNS"| NX["向手机回 NXDOMAIN"]
```

## 1. Inspector 在哪里被调用

| 调用 | 方向 | 调用位置 |
|---|---|---|
| `inspect_tcp(name, port, upstream=true, state, data)` | 手机 → 服务器 | `TcpFlow::deliver_upstream()`，每个按序到达的数据段 |
| `inspect_tcp(name, port, upstream=false, state, data)` | 服务器 → 手机 | `TcpFlow::on_upstream_data()`，每次从真实服务器读到的数据块 |
| `inspect_udp(name, port, upstream=true, data, len, &reply)` | 手机 → 服务器 | `UdpFlow::on_packet()` |
| `inspect_udp(name, port, upstream=false, data, len, nullptr)` | 服务器 → 手机 | `UdpFlow::on_upstream_data()` |

`inspect_tcp` 中的 `data` 是一个 `std::string&`：**你可以直接修改它，包括改变它的长度**。
之所以可行，是因为两条 TCP 连接是相互独立的（参见
[架构 § 1](architecture.md#1-一图看懂整体思路)）：`TcpFlow` 维护自己面向手机的序号，
而面向真实服务器的字节则由服务器内核编号。

## 2. TCP 检查流水线

```mermaid
flowchart TD
    IN(["inspect_tcp(chunk)"]) --> CNT["统计该方向的字节数"]
    CNT --> DONE{"该方向的协议识别<br/>已经完成？"}
    DONE -->|"否"| BUF["追加到识别缓冲区<br/>(最多 16 KB)"]
    BUF --> DET["detect_protocol()"]
    DET --> D2{"这次识别出来了？"}
    D2 -->|"是"| BL{"上行，且主机名 (SNI / Host)<br/>在 vpn_block_domains 中？"}
    BL -->|"是"| BLOCK(["返回 kBlock：中止流，<br/>向手机发 RST"])
    BL -->|"否"| DUMP
    D2 -->|"还在等待"| DUMP
    DONE -->|"是"| DUMP{"vpn_log_payload_bytes > 0？"}
    DUMP -->|"是"| HEX["记录该数据块的十六进制 dump"]
    DUMP -->|"否"| RW
    HEX --> RW["apply_rewrites()：<br/>如果端口在 vpn_rewrite_ports 中，<br/>就替换该方向每条规则<br/>的所有匹配"]
    RW --> PASS(["返回 kPass"])
```

### 协议识别

```mermaid
flowchart TD
    UP{"方向"} -->|"手机到服务器"| TLS{"TLS ClientHello？<br/>parse_tls_client_hello()"}
    TLS -->|"完整"| TLSOK["协议 TLS，host = SNI<br/>记录版本、SNI、ALPN"]
    TLS -->|"不完整，< 16 KB"| WAIT(["等待更多字节"])
    TLS -->|"不是 TLS"| HTTP{"HTTP 请求行？<br/>GET / POST / ..."}
    HTTP -->|"是，头部完整"| HTTPOK["协议 HTTP，host = Host 头<br/>记录请求行、Host、User-Agent"]
    HTTP -->|"是，头部不完整"| WAIT
    HTTP -->|"否"| DNS{"53 端口：DNS over TCP？<br/>2 字节长度 + 消息"}
    DNS -->|"是"| DNSOK["协议 DNS/TCP，记录查询"]
    DNS -->|"否"| SSH
    UP -->|"服务器到手机"| RESP{"以 HTTP/ 开头？"}
    RESP -->|"是"| RESPOK["记录状态行"]
    RESP -->|"否"| SH{"TLS ServerHello？<br/>16 03 xx xx xx 02"}
    SH -->|"是"| SHOK["记录 TLS ServerHello"]
    SH -->|"否"| SSH{"以 SSH- 开头？"}
    SSH -->|"是"| SSHOK["记录 SSH banner"]
    SSH -->|"否"| UNK["未知：记录前若干字节<br/>的可打印预览"]
```

### 如何找到 TLS SNI

ClientHello 是 TLS 连接的第一条消息，并且是以**明文**发送的（Encrypted ClientHello 除外）。
客户端想访问的服务器名称就在 `server_name` 扩展中：

```mermaid
flowchart LR
    R["TLS 记录头<br/>type 0x16 (handshake)<br/>版本、长度"] --> H["握手头<br/>type 0x01 (ClientHello)<br/>长度 (3 字节)"]
    H --> B["客户端版本<br/>32 字节随机数"]
    B --> SID["session id<br/>(1 字节长度)"]
    SID --> CS["密码套件<br/>(2 字节长度)"]
    CS --> CM["压缩方法<br/>(1 字节长度)"]
    CM --> EXT["扩展<br/>(2 字节总长度)"]
    EXT --> E0["type 0x0000 server_name<br/>列表，host_name = SNI"]
    EXT --> E16["type 0x0010 ALPN<br/>h2, http/1.1"]
    EXT --> E43["type 0x002b supported_versions<br/>TLS 1.3 = 0x0304"]
```

`parse_tls_client_hello()` 带边界检查地逐个遍历这些带长度前缀的字段，返回 1（完整）、
0（需要更多数据）或 -1（不是 ClientHello）。

## 3. UDP 和 DNS 检查

```mermaid
sequenceDiagram
    participant Ph as 手机
    participant UF as UdpFlow
    participant I as Inspector
    participant DNS as DNS 服务器
    Ph->>UF: DNS 查询 A ads.example.com
    UF->>I: inspect_udp(upstream, query)
    I->>I: parse_dns()，解析头部和问题 (支持名称压缩)
    alt 名称或其上级域名在 vpn_block_domains 中
        I-->>UF: kBlock + reply = 头部和问题，<br/>QR=1, RA=1, RCODE=3 (NXDOMAIN)
        UF->>Ph: 伪造的 NXDOMAIN 响应
    else 放行
        I-->>UF: kPass (记录查询)
        UF->>DNS: 查询
        DNS-->>UF: 响应
        UF->>I: inspect_udp(downstream)，记录应答
        UF->>Ph: 响应
    end
```

当一个域名与某个屏蔽条目相同，或者是它的子域名时，就算匹配（`ads.example.com` 匹配
`example.com`）。

## 4. 拦截一览

| 流量 | 识别位置 | 结果 |
|---|---|---|
| 查询被屏蔽名称的 DNS 请求 | `inspect_udp`，53 / 5353 端口 | 由服务器直接回 NXDOMAIN |
| 访问被屏蔽 SNI 的 TLS | `inspect_tcp` 中的 ClientHello | 中止流，向手机发 RST |
| 访问被屏蔽 Host 的 HTTP | `inspect_tcp` 中的请求头 | 中止流，向手机发 RST |
| `vpn_block_quic = 1` 时的 QUIC（UDP 443） | `Session::handle_udp` | 向手机回 ICMP port unreachable |
| `vpn_block_private = 1` 时的私有地址目标 | `Session::target_allowed` | RST（TCP）/ 丢弃（UDP、ICMP） |

### 为什么要拦截 QUIC？

```mermaid
sequenceDiagram
    participant B as 浏览器
    participant S as SimpleVPN 服务器
    B->>S: UDP 443 QUIC Initial (已加密，本 inspector 看不到 SNI)
    S->>B: ICMP port unreachable (vpn_block_quic = 1)
    B->>S: 向 443 端口发送 TCP SYN
    S->>B: SYN-ACK
    B->>S: TLS ClientHello，SNI 以明文可见
    Note over S: Inspector 记录 SNI=www.google.com，<br/>按域名拦截生效
```

QUIC（HTTP/3）运行在 UDP 之上，并用从连接 id 派生出的密钥加密它的 Initial 包，
所以这个 inspector 不解析它。QUIC 失败时浏览器会回退到 TCP，流量于是重新变得可见。

## 5. 改写

规则来自配置：`vpn_rewrite_N = up|from|to` 或 `down|from|to`，只作用于 `vpn_rewrite_ports`
中的端口（默认 80）。支持转义 `\r \n \t \| \\`。

```mermaid
sequenceDiagram
    participant Ph as 手机 (curl)
    participant TF as TcpFlow + Inspector
    participant W as Web 服务器
    Ph->>TF: GET / HTTP/1.1, User-Agent: curl/8
    TF->>TF: 上行规则把 "User-Agent: curl" 替换为 "User-Agent: SimpleVPN"
    TF->>W: GET / HTTP/1.1, User-Agent: SimpleVPN/8
    W-->>TF: 200 OK ... Example Domain ...
    TF->>TF: 下行规则把 "Example Domain" 替换为 "Hacked! Domain"
    TF->>Ph: 200 OK ... Hacked! Domain ...
```

需要记住的限制：

* 规则是**对每个数据块单独**应用的。跨越两个 TCP 数据段 / 两次读取的字符串匹配不到。
* 如果 HTTP body 的长度变了，`Content-Length` 也必须跟着改，否则客户端会一直等待缺失的字节 /
  忽略多出来的字节。等长替换是最省事的做法。
* 压缩过的（`Content-Encoding: gzip`）或 TLS 加密的内容无法按文本改写。做实验时请使用明文 HTTP，
  或者加一条在上行方向去掉 `Accept-Encoding` 的改写规则。

## 6. pcap 抓包

### 文件格式

```mermaid
flowchart LR
    G["全局头，24 字节<br/>magic a1b2c3d4，版本 2.4<br/>snaplen 65535，linktype 101 (raw IP)"] --> R1["记录头，16 字节<br/>ts_sec, ts_usec, incl_len, orig_len"] --> P1["数据包字节<br/>(以 IPv4 或 IPv6 头开始)"] --> R2["记录头"] --> P2["数据包字节"] --> MORE["..."]
```

链路类型 101（`LINKTYPE_RAW`）表示“数据包直接以 IP 头开始”，这正是 TUN 设备交付的格式——
不需要伪造以太网头。

### 每个会话的文件

设置 `vpn_pcap_dir = ./pcap` 后，每个通过认证的会话都会写入
`pcap/session-<id>-<YYYYmmdd-HHMMSS>.pcap`，包含两个方向，大小上限为 `vpn_pcap_max_mb`。
文件每秒刷盘一次，所以用 `tail -f` / 在 Wireshark 中重新加载都能看到最近的包。

### 实时抓包

```mermaid
sequenceDiagram
    participant WS as Wireshark (读取 stdin)
    participant NC as nc / ssh
    participant P as vpn_plugin (9444 端口)
    participant LC as LiveCapture
    participant S as 所有 worker 上的 Session
    WS->>NC: tools/wireshark_live.sh
    NC->>P: TCP 连接 127.0.0.1:9444
    P->>P: handle_client_open 只接受 loopback<br/>(除非 vpn_capture_allow_remote = 1)
    P->>LC: add_subscriber(si)
    LC->>NC: pcap 全局头
    loop 每部手机的每个包
        S->>LC: publish(packet)
        LC->>NC: 一条消息 = 记录头 + 数据包 (srv_send)
    end
    NC->>WS: pcap 流，数据包实时出现
```

* `LiveCapture` 由所有 worker 共享，并由一个互斥锁保护——这是插件中唯一共享的可变状态。
* 每条记录都作为**一条** `srv_send()` 消息发送。如果 Wireshark 读得太慢，引擎会整条丢弃消息
  （`send_overflow_policy = drop`），所以流中永远不会出现半条记录，始终可以被解析；
  手机的流量也永远不会因为查看者而变慢。
* 9444 端口也必须写在 `conf/bind.txt` 中；请让它只绑定在 `127.0.0.1` 上，从其它机器访问时使用 SSH
  （`tools/wireshark_live.sh user@server`）。

## 7. 添加你自己的分析

```cpp
// inspector.cpp，在 Inspector::inspect_tcp() 中、apply_rewrites() 之前：
if (upstream && server_port == 6379 && data.compare(0, 1, "*") == 0) {
    LOG_INFO("%s Redis command: %s", flow_name.c_str(),
             printable_preview(reinterpret_cast<const uint8_t*>(data.data()), data.size(), 120).c_str());
}
```

用 `cmake --build build` 重新编译，重启 `mulserver`，手机发出的每条 Redis 命令都会出现在日志里。
[学习指南](learning-guide.md)里还有更多想法。
