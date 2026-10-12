# 隧道协议

[English](../en/tunnel-protocol.md) | **简体中文** · [README](../../README.zh-CN.md) · [架构](architecture.md) · [Android 客户端](android-client.md) · [Inspector 与抓包](inspector-and-capture.md) · [学习指南](learning-guide.md) · [配置](configuration.md) · [测试](testing.md) · [源码导读](source-tour.md)

手机和服务器之间通过**一条 TCP 连接**通信（默认端口 9443）。格式定义在
[`common/tunnel_protocol.h`](../../common/tunnel_protocol.h) 中，这个头文件被 Android 客户端、
Linux 测试客户端和服务器插件原封不动地共用。

## 1. 为什么用 TCP，为什么要分帧

* TCP 提供有序、可靠的传输，几乎能穿过所有防火墙和 NAT；对学习来说它是最简单的传输方式。
  （代价是 “TCP over TCP”：隧道中丢失一个报文段，会拖慢隧道里的所有连接。UDP 隧道可以避免这个问题——
  参见 README 中的“以后可以做的”列表。）
* TCP 是**字节流**，而我们要传输的是一个个独立的 IP 包。所以每个 IP 包都被放进一个带长度头的**帧**里；
  接收方再把字节流切回成一个个包。

## 2. 帧格式

```mermaid
flowchart LR
    M["第 0-1 字节<br/>magic 0x5356<br/>(ASCII 'SV')"] --- V["第 2 字节<br/>version = 1"] --- T["第 3 字节<br/>type"] --- L["第 4-7 字节<br/>payload 长度<br/>uint32 大端序"] --- P["第 8 .. 8+length-1 字节<br/>payload"]
```

| 字段 | 大小 | 含义 |
|---|---|---|
| magic | 2 | `0x53 0x56`；用来识别不讲这个协议的对端（例如浏览器误连到这个端口） |
| version | 1 | `1`；将来不兼容的格式会使用别的数字 |
| type | 1 | 帧类型（见下表） |
| length | 4 | payload 长度，网络字节序，最大 65535 + 1024 |
| payload | length | 取决于帧类型 |

| 类型 | 值 | 方向 | Payload |
|---|---|---|---|
| HELLO | 1 | 客户端 → 服务器 | 文本行 `key=value\n`：`version`、`token`、`client`、`mtu`、`ipv4`、`ipv6` |
| HELLO_ACK | 2 | 服务器 → 客户端 | 文本行：`server`（软件名称）、`session`（id） |
| PACKET | 3 | 双向 | 恰好一个 IPv4 或 IPv6 包，以 IP 头开始 |
| PING | 4 | 双向 | 任意字节（客户端发送一个 8 字节的时间戳） |
| PONG | 5 | 双向 | 原样返回的 PING payload |
| ERROR | 6 | 双向 | UTF-8 编码的原因文本；发送方随后关闭连接 |

### 把字节流切分成帧

```mermaid
flowchart TD
    S(["收到的字节"]) --> H{"至少有 8 字节？"}
    H -->|"否"| WAIT(["等待更多数据"])
    H -->|"是"| MV{"magic == 0x5356 且 version == 1<br/>且 length <= 上限？"}
    MV -->|"否"| ERR(["协议错误：关闭连接"])
    MV -->|"是"| FULL{"已有 8 + length 字节？"}
    FULL -->|"否"| WAIT
    FULL -->|"是"| FR["一个完整的帧：<br/>处理它，移除 8 + length 字节"] --> H
```

`tunnel::parse_header()` 实现了这些检查。在服务器上，它由 `handle_input_from_client`
（reactor 引擎的分帧钩子）调用，所以插件看到的永远是完整的帧；在客户端，
`TunnelClient::run_session()` 自己执行同样的循环。

## 3. 握手

```mermaid
sequenceDiagram
    autonumber
    participant C as 客户端 (手机)
    participant S as 服务器 (Session)
    C->>S: TCP 连接到 9443 端口
    C->>S: HELLO token, client=android, mtu=1500, ipv4=172.19.0.2, ipv6=fd00:5356::2
    alt token 正确 (或者服务器没有设置 vpn_token)
        S->>S: 认证通过，保存 mtu，打开 pcap 文件
        S->>C: HELLO_ACK server=simplevpn-server/1.0, session=7
        C->>C: 进入 Connected 状态，开始读取 TUN
        C->>S: PACKET ...
        S->>C: PACKET ...
    else token 错误
        S->>C: ERROR "authentication failed"
        S->>S: 关闭连接
        C->>C: 进入 AuthFailed 状态，等待最大退避时间后才重试
    end
```

规则：

* 第一帧必须是 HELLO，否则服务器回 `ERROR "expected HELLO"` 并关闭连接。
* 服务器最多等待 `vpn_hello_timeout_ms`（10 s）来接收 HELLO；客户端最多等待
  `connect_timeout_ms`（10 s）来接收 HELLO_ACK。
* 客户端在收到 HELLO_ACK 之前不读取 TUN，所以不会有任何包在未认证的情况下发出。
* `mtu` 告诉服务器发往手机的包最大可以多大；更大的包会被分片
  （参见[架构 § 10](architecture.md#10-ip-分片)）。

## 4. 心跳

```mermaid
sequenceDiagram
    participant C as 客户端
    participant S as 服务器
    loop 每 15 s (keepalive_interval_ms)
        C->>S: PING (8 字节时间戳)
        S->>C: PONG (相同的字节)
    end
    Note over C: 收到任何数据都会重置 last_rx
    Note over C: 45 s 内什么都没收到 (keepalive_timeout_ms)：<br/>认为连接已断开，重新连接
```

为什么客户端需要自己的心跳：当手机悄无声息地断网时（NAT 超时、走出 Wi-Fi 覆盖范围），
TCP 连接要过很多分钟才会察觉。定期的 PING 能让 NAT 映射保持有效，而收不到应答则能在 45 s 内
发现路径已断。另外，服务器会关闭空闲时间超过 bind 文件中空闲超时（300 s）的隧道。

## 5. 客户端状态机

这些状态会报告给 App（`tunnel_client.h` 中的 `TunnelState`，数值与 `MyVpnService.kt` 中的
`STATE_*` 常量相同）：

```mermaid
stateDiagram-v2
    [*] --> Connecting: run()
    Connecting --> Connected: TCP 已连接且收到 HELLO_ACK
    Connecting --> Reconnecting: DNS、连接或握手失败
    Connected --> Reconnecting: 服务器关闭连接、出错、心跳超时
    Connected --> Reconnecting: 网络变化 (Java 调用 reconnect())
    Reconnecting --> Connected: 下一次尝试成功
    Connected --> AuthFailed: ERROR "authentication failed"
    AuthFailed --> Connected: 等待最大退避时间 (30 s) 后重试
    Connecting --> Stopped: stop()
    Connected --> Stopped: stop()
    Reconnecting --> Stopped: stop()
    AuthFailed --> Stopped: stop()
    Stopped --> [*]: 关闭 TUN fd
```

### 重连退避

```mermaid
flowchart TD
    F(["尝试失败或会话结束"]) --> NC{"网络变化了？"}
    NC -->|"是"| NOW["立即重连<br/>backoff = 1 s"]
    NC -->|"否"| AUTH{"认证失败？"}
    AUTH -->|"是"| MAX["等待 30 s (max_backoff_ms)"]
    AUTH -->|"否"| LONG{"会话持续了 10 s 以上？"}
    LONG -->|"是"| RESET["backoff = 1 s"]
    LONG -->|"否"| KEEP["保持当前的 backoff"]
    RESET --> WAIT
    KEEP --> WAIT["等待 backoff，<br/>期间持续排空 TUN"]
    MAX --> WAIT
    WAIT --> DOUBLE["backoff = min(2 x backoff, 30 s)"] --> TRY(["下一次尝试"])
    NOW --> TRY
```

断开期间，客户端会持续从 TUN 中**读取并丢弃**数据包。否则 TUN 队列会被填满，App 会卡在写满的
socket 缓冲区上，而不是快速失败然后重试。

## 6. 字节示例

一个带 8 字节 payload 的 PING：

```text
53 56 01 04 00 00 00 08   e8 03 00 00 00 00 00 00
\___/ \/ \/ \_________/   \_____________________/
magic v  t  length = 8     payload (时间戳，示例)
```

一个携带 60 字节 TCP SYN 的 PACKET：

```text
53 56 01 03 00 00 00 3c   45 00 00 3c ...   (IPv4 头以 0x45 开始)
```

你可以自己观察这些字节：在服务器上用
`tcpdump -i any -w tunnel.pcap port 9443` 抓取隧道端口，然后用 Wireshark 打开（*Follow TCP stream*）。

## 7. 安全方面的考虑

| 属性 | 现状 |
|---|---|
| 认证 | HELLO 中的共享 token（明文） |
| 机密性 | **无**：隧道没有加密 |
| 完整性 | 只有 TCP 校验和 |
| 防重放 | 无 |

在实验环境之外使用时，请把隧道放在 SSH 端口转发、WireGuard 或 TLS 代理（stunnel）之中。
自己实现一个 TLS 隧道会是个不错的练习。
