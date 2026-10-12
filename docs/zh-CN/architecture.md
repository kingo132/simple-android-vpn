# 架构

[English](../en/architecture.md) | **简体中文** · [README](../../README.zh-CN.md) · [隧道协议](tunnel-protocol.md) · [Android 客户端](android-client.md) · [Inspector 与抓包](inspector-and-capture.md) · [学习指南](learning-guide.md) · [配置](configuration.md) · [测试](testing.md) · [源码导读](source-tour.md)

本文跟随一个 IP 包，从手机上的 App 出发，到达互联网上的服务器再返回，
逐一讲解它经过的每个组件：这个组件做什么，以及为什么要这样设计。

## 目录

1. [一图看懂整体思路](#1-一图看懂整体思路)
2. [组件](#2-组件)
3. [一个 HTTP 请求的完整旅程](#3-一个-http-请求的完整旅程)
4. [基于 reactor 引擎的服务器插件](#4-基于-reactor-引擎的服务器插件)
5. [会话：一部手机，一条隧道](#5-会话一部手机一条隧道)
6. [从 IP 包到流](#6-从-ip-包到流)
7. [TCP：用户态 TCP 端点](#7-tcp用户态-tcp-端点)
8. [UDP：基于 connected socket 的 NAT](#8-udp基于-connected-socket-的-nat)
9. [ICMP echo（ping）](#9-icmp-echoping)
10. [IP 分片](#10-ip-分片)
11. [端到端的流控与背压](#11-端到端的流控与背压)
12. [定时器与超时](#12-定时器与超时)
13. [IPv6](#13-ipv6)

---

## 1. 一图看懂整体思路

普通的 VPN 会加密数据包，再由服务器通过 NAT 路由出去。SimpleVPN 的做法不同：它在服务器上**终结**
每一条连接，再向真正的目标新开一条连接。这种设计叫做 *split TCP*（分段 TCP）或*透明代理*：

```mermaid
flowchart LR
    subgraph P["手机"]
        APP["App<br/>connect(1.2.3.4:80)"]
        K1["手机内核 TCP"]
    end
    subgraph S["SimpleVPN 服务器"]
        U["用户态 TCP<br/>(TcpFlow)<br/>假扮成 1.2.3.4"]
        I["Inspector<br/>看到的是明文字节"]
        K2["服务器内核 TCP<br/>普通 socket"]
    end
    R["真实服务器<br/>1.2.3.4:80"]
    APP --> K1
    K1 -- "TCP 连接 1<br/>(隧道内的 IP 包)" --> U
    U --> I --> K2
    K2 -- "TCP 连接 2<br/>(普通互联网)" --> R
```

* 连接 1 位于手机内核和我们的**用户态 TCP 实现**（`TcpFlow`）之间。手机以为自己在和 1.2.3.4 通信。
* 连接 2 是服务器到 1.2.3.4 的一条普通 socket 连接。
* 在两者之间，服务器拿到的是**明文字节流**，可以记录、修改或丢弃。由于两条连接的序号相互独立，
  改变数据长度也没有问题。
* 服务器上不需要 root，也不需要 iptables（raw ICMP 除外）。

## 2. 组件

```mermaid
flowchart TB
    subgraph ANDROID["Android 手机"]
        direction TB
        UI["MainActivity.kt<br/>设置、启动 / 停止、统计"]
        SVC["MyVpnService.kt<br/>VpnService：创建 TUN 接口，<br/>监听网络变化"]
        JNI["native-lib.cpp<br/>JNI 胶水层、隧道线程、<br/>protect() 和状态回调"]
        TC["tunnel_client.cpp<br/>在 TUN fd 和 TCP socket 之间搬运数据，<br/>握手、心跳、重连"]
        TUNDEV[("TUN 设备<br/>172.19.0.2 / fd00:5356::2")]
        UI --> SVC --> JNI --> TC
        TC <--> TUNDEV
    end
    subgraph SERVER["服务器：mulserver 进程"]
        direction TB
        ENG["reactor 引擎<br/>(server/reactor)<br/>socket、线程、队列"]
        PLG["vpn_plugin.cpp<br/>引擎回调"]
        SES["vpn_session.cpp<br/>每条隧道一个 Session"]
        FLW["flows.cpp<br/>TcpFlow / UdpFlow / IcmpFlow"]
        PKT["packet.cpp<br/>解析和构造数据包"]
        INSP["inspector.cpp<br/>识别、日志、改写、拦截"]
        PCAP["pcap_writer.cpp<br/>pcap 文件、实时抓包"]
        ENG <--> PLG <--> SES <--> FLW
        SES --> PKT
        FLW --> PKT
        FLW --> INSP
        SES --> PCAP
    end
    TC <-->|"TCP :9443<br/>隧道帧"| ENG
    ENG <-->|"socket"| INTERNET(("互联网"))
    PCAP -->|"TCP :9444<br/>pcap 流"| WS["Wireshark"]
```

| 组件 | 语言 | 职责 |
|---|---|---|
| `MainActivity` | Kotlin | 界面，申请 VPN 权限，显示状态和计数器 |
| `MyVpnService` | Kotlin | 用 `VpnService.Builder` 创建 TUN 接口，启动/停止 native 隧道 |
| `native-lib.cpp` | C++ / JNI | 在独立线程上运行 `TunnelClient`，把 `protect()` 和状态回调桥接到 Java |
| `TunnelClient` | C++ | 在 TUN fd 和服务器连接之间搬运 IP 包；Linux 客户端也使用它 |
| reactor 引擎 | C++ | 服务器上所有的 socket I/O 和线程管理 |
| `vpn_plugin.cpp` | C++ | 把引擎回调映射到会话和流 |
| `Session` | C++ | 每条隧道一个：认证、帧、流表、统计、pcap |
| `TcpFlow` / `UdpFlow` / `IcmpFlow` | C++ | 每个连接 / 会话对话一个：协议逻辑和出站 socket |
| `packet.cpp` | C++ | IPv4/IPv6/TCP/UDP/ICMP 解析和构造、校验和、分片 |
| `Inspector` | C++ | 协议识别、日志、改写、拦截——**做实验的地方** |
| `PcapWriter` / `LiveCapture` | C++ | 抓包写入文件以及发给实时 Wireshark 客户端 |

## 3. 一个 HTTP 请求的完整旅程

手机上的浏览器加载 `http://example.com/` 时会发生什么：

```mermaid
sequenceDiagram
    autonumber
    participant App as 浏览器 (手机)
    participant PK as 手机内核
    participant TUN as TUN 设备
    participant TC as TunnelClient (手机)
    participant SES as Session (服务器)
    participant TF as TcpFlow (服务器)
    participant NET as example.com:80
    App->>PK: 查询 example.com 的 DNS (UDP 53)
    PK->>TUN: IP/UDP 包
    TUN->>TC: read(tun_fd)
    TC->>SES: PACKET 帧
    SES->>SES: UdpFlow，用 UDP socket 发送查询，应答以 PACKET 返回
    App->>PK: connect(93.184.215.14:80)
    PK->>TUN: IP/TCP SYN
    TC->>SES: PACKET(SYN)
    SES->>TF: 新建 TcpFlow，start()
    TF->>NET: srv_connect() = 真正的 TCP 握手
    NET-->>TF: 已连接 (handle_server_open)
    TF->>TC: 在用户态构造的 PACKET(SYN-ACK)
    TC->>TUN: write(tun_fd)
    PK->>TC: ACK，然后是 HTTP GET (经 TUN，以 PACKET 帧传输)
    TC->>TF: PACKET(ACK)，PACKET(数据 "GET / ...")
    TF->>TF: Inspector 记录 "HTTP GET / Host=example.com"
    TF->>NET: send(GET ...)
    TF->>TC: PACKET(对 GET 的 ACK)
    NET-->>TF: HTTP 响应字节
    TF->>TF: Inspector 记录 "HTTP/1.1 200 OK"，可能改写
    TF->>TC: PACKET(数据段，每段最多 MSS)
    TC->>TUN: write，手机内核把数据交给浏览器
    PK->>TC: 对数据的 ACK
    TC->>TF: PACKET(ACK)，TcpFlow 释放已确认的字节
```

有两点值得注意：

* SYN-ACK **只有在**真实服务器接受连接之后才会发送。如果服务器拒绝，手机会收到 RST——
  和不用 VPN 时看到的完全一样。
* 两个方向上的每个包都会同时写入会话的 pcap 文件并发给实时 Wireshark 客户端，
  这样你可以对比手机看到的内容和服务器日志记录的内容。

## 4. 基于 reactor 引擎的服务器插件

VPN 服务器是 reactor 引擎的一个插件（`libvpnproxy.so`）。引擎拥有 socket 和线程；
插件只负责响应回调。

```mermaid
flowchart LR
    subgraph ENGINE["reactor 引擎"]
        CONN["CONN 线程"]
        W["worker 线程 k"]
    end
    subgraph PLUGIN["vpn_plugin.cpp 回调"]
        HI["handle_input_from_client<br/>隧道帧边界"]
        HO["handle_client_open<br/>新建 Session"]
        HM["handle_message_from_client<br/>Session::on_frame()"]
        HC["handle_client_close<br/>删除 Session"]
        SO["handle_server_open<br/>Flow::on_upstream_open()"]
        SM["handle_message_from_server<br/>Flow::on_upstream_data()"]
        SC["handle_server_close<br/>Flow::on_upstream_close()"]
        WB["handle_write_blocked<br/>隧道或上游拥塞"]
        TM["handle_timer<br/>每 50 ms 调用 Session::on_timer()"]
    end
    CONN --> HI
    W --> HO & HM & HC & SO & SM & SC & WB & TM
```

| 引擎回调 | 调用线程 | 插件动作 |
|---|---|---|
| `handle_input_from_client` | CONN 线程 | `tunnel::parse_header()` → 一帧的长度（抓包客户端则是整块数据） |
| `handle_client_open` | worker | 抓包端口：添加一个实时抓包订阅者；隧道端口：`new Session` |
| `handle_message_from_client` | worker | `Session::on_frame(type, payload)`，然后 `reap()` |
| `handle_client_close` | worker | 删除 Session；它的析构函数会中止所有出站 socket |
| `handle_server_open/…_from_server/…_close` | worker | 通过 `si->user_tag`（= 流 id）找到 Flow 并转发事件 |
| `handle_write_blocked` | worker | 隧道 → `Session::on_tunnel_write_blocked`；上游 → `Flow::on_upstream_write_blocked` |
| `handle_timer` | worker | 对该 worker 的每个会话调用 `Session::on_timer()` |

### 为什么不需要锁

```mermaid
flowchart TB
    T["手机 A 的隧道连接<br/>accept 后按轮询分配 worker = 2"] --> W2["worker 2"]
    W2 --> S["Session A<br/>(t_worker->sessions)"]
    S --> F1["TcpFlow #1"]
    S --> F2["UdpFlow #2"]
    F1 -->|"在 worker 2 上 srv_connect()"| U1["出站 socket<br/>归 worker 2 所有"]
    F2 -->|"在 worker 2 上 srv_connect()"| U2["出站 socket<br/>归 worker 2 所有"]
    U1 -. "事件回到 worker 2" .-> F1
    U2 -. "事件回到 worker 2" .-> F2
```

引擎把每条连接固定在一个 worker 上，而 `srv_connect()` 创建的 socket 属于创建它的 worker。
因此隧道、它的会话、所有的流以及这些流的所有出站 socket 都在**同一个**线程上。
所有状态都保存在 `thread_local WorkerState` 中（`sessions` 以隧道 `conn_id` 为键，
`flows` 以流 id 为键），不需要任何互斥锁。不同的手机会分散到不同的 worker 上。

唯一的进程级对象要么在启动后只读（`g_vpn_config`、`g_inspector`），要么由自己的互斥锁保护
（`g_live_capture`）。

## 5. 会话：一部手机，一条隧道

```mermaid
classDiagram
    class Session {
        -SocketInfo tunnel_
        -bool authenticated_
        -int mtu_
        -unordered_map flows_
        -PcapWriter pcap_
        -FragmentReassembler reassembler_
        -size_t inflight_
        +on_frame(type, payload, len)
        +send_packet(packet)
        +on_tunnel_write_blocked(blocked)
        +on_timer(now)
        +reap()
        +add_inflight(delta)
        +inflight_room() size_t
        +close(reason)
        -handle_hello()
        -handle_packet()
        -dispatch_packet()
        -handle_tcp() / handle_udp() / handle_icmp()
    }
    class Flow {
        <<abstract>>
        #Session* session_
        #FlowKey key_
        #uint64 id_
        #SocketInfo upstream_
        #bool dead_
        +on_packet(packet)*
        +on_upstream_open(error)*
        +on_upstream_data(data, len)*
        +on_upstream_close(error)*
        +on_upstream_write_blocked(blocked)
        +on_tunnel_writable()
        +on_timer(now)*
        #finish(abort, reason)
    }
    class TcpFlow {
        -State state_
        -uint32 rcv_nxt_, snd_una_, snd_nxt_, snd_max_
        -uint32 snd_wnd_
        -string send_buf_
        -int rto_ms_
        +start() bool
    }
    class UdpFlow {
        -string last_header_
        +start() bool
    }
    class IcmpFlow {
        -bool raw_
        +start() bool
    }
    class FlowKey {
        +uint8 protocol
        +IpAddr src
        +IpAddr dst
        +uint16 src_port
        +uint16 dst_port
    }
    class WorkerState {
        +map sessions
        +map flows
        +uint64 next_flow_id
        +mt19937 rng
    }
    Session "1" *-- "many" Flow : flows_ 以 FlowKey 为键
    Flow <|-- TcpFlow
    Flow <|-- UdpFlow
    Flow <|-- IcmpFlow
    Flow --> FlowKey
    WorkerState o-- Session
    WorkerState o-- Flow : 以 id = user_tag 为键
```

### 会话的生命周期

```mermaid
stateDiagram-v2
    [*] --> WaitHello: 隧道已 accept (handle_client_open)
    WaitHello --> Authenticated: HELLO 中的 token 正确，发送 HELLO_ACK
    WaitHello --> Closing: token 错误，ERROR "authentication failed"
    WaitHello --> Closing: 第一帧不是 HELLO
    WaitHello --> Closing: vpn_hello_timeout_ms 内没有收到 HELLO
    Authenticated --> Authenticated: PACKET (IP 包)，PING 以 PONG 应答
    Authenticated --> Closing: 收到客户端的 ERROR
    Closing --> [*]: srv_close(tunnel)，销毁所有流
    Authenticated --> [*]: 隧道被手机或网络关闭 (handle_client_close)
```

### 删除流：finish() 和 reap()

一个流可能在它自己的回调执行到一半时决定结束（例如在处理 RST 时）。
如果在那里直接 delete `this`，就会造成 use-after-free。因此：

```mermaid
sequenceDiagram
    participant P as vpn_plugin 回调
    participant S as Session
    participant F as Flow
    P->>S: on_frame() / on_upstream_data() ...
    S->>F: on_packet()
    F->>F: finish()，关闭上游，dead_ = true
    F->>S: mark_dead(key)
    F-->>S: 返回 (对象仍然存活)
    S-->>P: 返回
    P->>S: reap()
    S->>S: 从 flows_ 中删除已死亡的流 (此时才执行析构)
    S->>S: 同时恢复正在等待在途预算的流
```

## 6. 从 IP 包到流

`Session::handle_packet()` 和 `dispatch_packet()`：

```mermaid
flowchart TD
    F(["来自手机的 PACKET 帧"]) --> CAP["写入 pcap 文件和实时抓包"]
    CAP --> PARSE{"parse_packet()<br/>是合法的 IPv4 或 IPv6 吗？"}
    PARSE -->|"否"| DROP1["丢弃，计入 dropped"]
    PARSE -->|"是"| LOG["vpn_log_packets：一行摘要"]
    LOG --> FRAG{"是分片吗？"}
    FRAG -->|"是"| RE["FragmentReassembler::add()"]
    RE -->|"不完整"| WAIT(["等待更多分片"])
    RE -->|"完整的数据报"| DISP
    FRAG -->|"否"| DISP{"目的地址是组播<br/>或广播吗？"}
    DISP -->|"是"| DROP2["丢弃"]
    DISP -->|"否"| PROTO{"协议"}
    PROTO -->|"TCP"| HT["handle_tcp()"]
    PROTO -->|"UDP"| HU["handle_udp()"]
    PROTO -->|"ICMP / ICMPv6"| HI["handle_icmp()<br/>只处理 echo request"]
    PROTO -->|"其它 (GRE、ESP ...)"| DROP3["记录日志并丢弃"]
```

流通过一个**五元组键**查找：协议、手机地址和端口、目的地址和端口
（对 ICMP 来说，端口就是 echo 的 identifier）。

```mermaid
flowchart TD
    HT(["handle_tcp(packet)"]) --> LOOK{"该五元组的流存在吗？"}
    LOOK -->|"存在、存活，且不是新的 SYN"| ON["flow->on_packet()"]
    LOOK -->|"存在，但收到带新 ISN 的 SYN"| REPL["端口被复用：删除旧流"] --> NEW
    LOOK -->|"存在但已死亡，或不存在"| SYN{"纯 SYN？"}
    SYN -->|"否"| RST["发送 RST<br/>(例如服务器重启之后)"]
    SYN -->|"是"| NEW{"允许吗？<br/>vpn_block_private、vpn_max_flows"}
    NEW -->|"否"| RST
    NEW -->|"是"| CREATE["新建 TcpFlow，start()<br/>srv_connect() 到目的地址"]
```

## 7. TCP：用户态 TCP 端点

`TcpFlow`（`flows.cpp`）面向手机实现了 TCP（RFC 9293）的服务器一侧，并在条件允许的地方做了简化。
它**没有**实现拥塞控制：手机和服务器之间是隧道，而隧道本身就是一条 TCP 连接，有自己的拥塞控制。

### 7.1 状态机

```mermaid
stateDiagram-v2
    [*] --> Connecting: 手机发来 SYN，srv_connect()
    Connecting --> Dead: 连接失败，向手机发 RST
    Connecting --> Connecting: 手机重传 SYN (忽略)
    Connecting --> SynAckSent: 真实服务器已接受，发送 SYN-ACK
    SynAckSent --> SynAckSent: RTO 超时，重发 SYN-ACK (最多 5 次)
    SynAckSent --> Established: 收到对 SYN-ACK 的 ACK
    SynAckSent --> Dead: 握手超时或收到 RST
    Established --> Established: 数据、ACK、窗口更新、重传
    Established --> Dead: 双方 FIN 都已交换并被确认
    Established --> Dead: 手机发来 RST、服务器出错、空闲超时、重传次数过多、被规则拦截
    Dead --> [*]: 稍后由 Session reap() 删除
```

这里没有显式的 FIN_WAIT/CLOSE_WAIT/TIME_WAIT 状态：关闭过程由四个标志描述
（`phone_fin_`、`upstream_eof_`、`fin_sent_`、`fin_acked_`）。TIME_WAIT 是不需要的，因为流的键会被移除，
带有不同 ISN 的新 SYN 会创建一个全新的流。

### 7.2 握手和选项

```mermaid
sequenceDiagram
    autonumber
    participant Ph as 手机内核
    participant TF as TcpFlow
    participant Srv as 真实服务器
    Ph->>TF: SYN seq=x, MSS=1460, WScale=7
    TF->>TF: irs = x, rcv_nxt = x+1, iss = 随机数, mss = min(我方, 对端)
    TF->>Srv: 通过引擎 connect() (SRV_CONNECT_HALF_CLOSE, RAW)
    Ph->>TF: 再次发来 SYN (重传)，连接中时忽略
    Srv-->>TF: SYN-ACK，connect 完成 (handle_server_open, error 0)
    TF->>Ph: SYN-ACK seq=iss ack=x+1, MSS, WScale, 窗口 (SYN 中不缩放)
    Ph->>TF: ACK ack=iss+1，进入 Established 状态
    Note over Ph,Srv: 如果 connect 失败：向手机发 RST+ACK，<br/>App 看到的就是「connection refused」
```

* **MSS**（最大报文段长度）：`min(我方 MTU - 40 (IPv4) / 60 (IPv6), 手机的 MSS)`；手机没有提供时
  默认为 536 / 1220。
* **窗口扩大**：只有手机提供了这个选项才使用。我们选取最小的移位数，使 `vpn_tcp_window`
  （512 KB）能放进 16 位。SYN 中的窗口字段永远不缩放。

### 7.3 序号空间的记账

```mermaid
flowchart LR
    subgraph SEND["我方发送序号空间 (服务器到手机)"]
        direction LR
        A["已确认<br/>(已经删除)"] --- B["已发送，尚未确认<br/>snd_una .. snd_nxt"] --- C["超时回退前已发送<br/>snd_nxt .. snd_max"] --- D["已缓冲，未发送<br/>.. send_buf_ 末尾"]
    end
```

| 变量 | 含义 |
|---|---|
| `snd_una_` | 手机尚未确认的最早字节；`send_buf_` 从这里开始 |
| `snd_nxt_` | 下一个要发送的字节；重传超时时回退到 `snd_una_`（go-back-N） |
| `snd_max_` | 曾经发送过的最高字节 + 1；即使回退之后，确认到这里的 ACK 仍然有效 |
| `snd_wnd_` | 手机的接收窗口（已缩放） |
| `rcv_nxt_` | 期望从手机收到的下一个字节（也就是我们确认的位置） |

### 7.4 下载：服务器 → 手机

```mermaid
sequenceDiagram
    participant Srv as 真实服务器
    participant TF as TcpFlow
    participant S as Session
    participant Ph as 手机
    Srv->>TF: on_upstream_data(bytes)
    TF->>TF: Inspector (日志、改写、拦截)，追加到 send_buf_
    alt send_buf_ > vpn_tcp_flow_buffer (1 MB)
        TF->>Srv: srv_pause_read(upstream, 1)
    end
    TF->>TF: transmit()
    loop 只要窗口、会话预算和数据都允许
        TF->>S: inflight_room()?
        TF->>Ph: 数据段 seq=snd_nxt, len <= MSS, 最后一段带 PSH
        TF->>TF: snd_nxt += len，开始 RTT 采样，启动 RTO
    end
    Ph->>TF: ACK ack=n, window=w
    TF->>TF: process_ack()，删除已确认字节，更新 RTT 和 RTO，snd_wnd = w
    alt send_buf_ < 流缓冲区 / 2 且处于暂停状态
        TF->>Srv: srv_pause_read(upstream, 0)
    end
    TF->>TF: 继续 transmit()
```

`transmit()` 发送的数据量取下面这些限制中最小的一个：

```mermaid
flowchart TD
    T(["transmit()"]) --> E{"处于 Established 状态<br/>且隧道没有拥塞？"}
    E -->|"否"| X(["返回"])
    E -->|"是"| U{"send_buf_ 中有未发送的字节？"}
    U -->|"否"| FIN{"服务器发来了 FIN<br/>而我方 FIN 还没发？"}
    FIN -->|"是"| SF["发送 FIN，snd_nxt += 1"] --> X
    FIN -->|"否"| X
    U -->|"是"| W["room = min(snd_wnd, 2 MB) - 在途字节数"]
    W --> NEWD{"是新数据 (不是重传)？"}
    NEWD -->|"是"| SB{"会话在途预算还有剩余？"}
    SB -->|"否"| WAITB["wait_for_budget()：稍后在 reap() 中恢复"] --> X
    SB -->|"是"| R2["room = min(room, max(budget, MSS))"]
    NEWD -->|"否"| ROOM
    R2 --> ROOM{"room > 0？"}
    ROOM -->|"否"| PERSIST["把 RTO 作为坚持定时器启动<br/>(稍后进行零窗口探测)"] --> X
    ROOM -->|"是"| SEG["发送 min(未发送, room, MSS) 字节"] --> U
```

### 7.5 上传：手机 → 服务器

```mermaid
flowchart TD
    P(["来自手机、携带数据的报文段"]) --> EST{"Established？"}
    EST -->|"否"| IGN(["忽略"])
    EST -->|"是"| PF{"手机已经发过 FIN？"}
    PF -->|"是"| ACK1["发送 ACK (这是重传)"]
    PF -->|"否"| OLD{"seq < rcv_nxt？"}
    OLD -->|"完全是旧数据"| ACK1
    OLD -->|"部分是旧数据"| TRIM["截掉旧的部分"] --> INORD
    OLD -->|"否"| INORD{"seq == rcv_nxt？"}
    INORD -->|"否，中间有空洞"| ACK2["发送重复 ACK<br/>(没有乱序队列，<br/>由手机重传)"]
    INORD -->|"是"| DATA["rcv_nxt += len<br/>Inspector (日志 / 改写 / 拦截)<br/>srv_send(upstream)"]
    DATA --> FINQ{"带 FIN 标志？"}
    FINQ -->|"是"| SHUT["rcv_nxt += 1<br/>srv_shutdown_write(upstream)"]
    FINQ -->|"否"| ACK3
    SHUT --> ACK3["发送带有我方窗口的 ACK"]
```

如果出站 socket 写不进更多数据，引擎会报告 `handle_write_blocked(1)`；流随即向手机通告**零窗口**，
手机就会停止发送。socket 中的数据排空后，会立即发送一个重新打开窗口的 ACK（`on_upstream_write_blocked`）。

### 7.6 重传

```mermaid
flowchart TD
    A(["来自手机的 ACK"]) --> NEWACK{"确认了新数据？<br/>snd_una < ack <= snd_max"}
    NEWACK -->|"是"| RTT["如果覆盖了被计时的报文段，就做一次 RTT 采样<br/>(Karn 算法：从不对重传计时)"]
    RTT --> UP["SRTT = 7/8 SRTT + 1/8 样本<br/>RTTVAR = 3/4 RTTVAR + 1/4 差值<br/>RTO = SRTT + max(10 ms, 4 RTTVAR)<br/>限制在 300 ms .. 30 s"]
    UP --> REARM["如果仍有在途数据，重启 RTO"]
    NEWACK -->|"相同的 ack、无数据、<br/>相同窗口、有在途数据"| DUP{"第 3 个重复 ACK？"}
    DUP -->|"是"| FR["快速重传<br/>第一个未确认的报文段"]
    DUP -->|"否"| NOTHING(["计数"])
    TO(["RTO 定时器触发 (on_timer)"]) --> ZW{"零窗口？"}
    ZW -->|"是"| PROBE["窗口探测：1 字节<br/>(不计入重试次数)"]
    ZW -->|"否"| RETRY{"重试超过 10 次？"}
    RETRY -->|"是"| ABORT["中止，向手机发 RST"]
    RETRY -->|"否"| GBN["RTO 翻倍 (最大 30 s)<br/>go back N：snd_nxt = snd_una<br/>从最早的字节开始重发"]
```

RTO 估计遵循 RFC 6298；快速重传使用 RFC 5681 中对重复 ACK 的定义。

### 7.7 关闭

```mermaid
sequenceDiagram
    participant Ph as 手机
    participant TF as TcpFlow
    participant Srv as 真实服务器
    Note over Ph,Srv: 情况 A：手机先关闭
    Ph->>TF: FIN
    TF->>Srv: srv_shutdown_write() = 我方向服务器发出的 FIN
    TF->>Ph: ACK
    Srv-->>TF: 剩余数据，然后是 FIN (ServerEof，半关闭)
    TF->>Ph: 数据，然后是 FIN
    Ph->>TF: 对我方 FIN 的 ACK，流结束
    Note over Ph,Srv: 情况 B：服务器先关闭
    Srv-->>TF: FIN (handle_message_from_server 传入 NULL)
    TF->>Ph: 发送 send_buf_ 中剩余的数据，然后发送 FIN
    Ph->>TF: ACK，可能仍会发送数据 (半关闭)
    Ph->>TF: FIN
    TF->>Ph: ACK，流结束
```

这一切靠的是 `SRV_CONNECT_HALF_CLOSE`：没有它，引擎会在收到服务器的 FIN 时关闭出站 socket，
依赖半关闭的协议（例如用 shutdown 的 `nc`）就会出错。

以下情况会生成 RST：手机为一个未知连接发来非 SYN 报文段（例如服务器重启之后）、
目标拒绝连接或不可达、命中拦截规则、重传次数过多，或者流的空闲时间超过 `vpn_tcp_idle_timeout`。

## 8. UDP：基于 connected socket 的 NAT

```mermaid
sequenceDiagram
    participant Ph as 手机 App
    participant UF as UdpFlow
    participant Srv as 8.8.8.8:53
    Ph->>UF: UDP 172.19.0.2:47385 到 8.8.8.8:53 (新的五元组)
    UF->>UF: srv_connect(SOCK_DGRAM) = connected UDP socket
    UF->>UF: Inspector 记录 DNS 查询，被屏蔽的域名直接回 NXDOMAIN
    UF->>Srv: send(payload)
    Srv-->>UF: 应答数据报 (在 connected socket 上 recv)
    UF->>UF: Inspector 记录 DNS 应答
    UF->>Ph: 构造 IP/UDP 包 8.8.8.8:53 到 172.19.0.2:47385
    Note over UF: 空闲 20 s (DNS) 或 120 s (其它)，流结束
```

* 每个 (手机地址:端口, 目的地址:端口) 一个 socket，也就是使用服务器地址的一种类似 full-cone 的 NAT。
* socket 是 **connected** 的，所以内核只会交付来自该目的地址的数据报——和有状态防火墙做的过滤一样。
* 如果目的端口没有开放，内核会报告 `ECONNREFUSED`；流会像路由器一样，向手机发回一个
  **ICMP destination unreachable**。
* `vpn_block_quic = 1` 时，对发往 443 端口的新 UDP 流回 ICMP port unreachable，让浏览器回退到
  TCP + TLS（参见 [Inspector 与抓包](inspector-and-capture.md)）。
* 隧道拥塞时，下行的数据报会被丢弃：UDP 协议本身能应对丢包，缓存它们只会增加延迟。
* 空数据报（负载为 0 字节）也是真正的 UDP 消息，两个方向都会被转发；引擎不会把它误认为流结束信号。

## 9. ICMP echo（ping）

```mermaid
flowchart TD
    REQ(["来自手机的 echo request<br/>id = 0x1234, seq = 1"]) --> FLOW{"存在对应<br/>(src, dst, id) 的 IcmpFlow？"}
    FLOW -->|"否"| OPEN["尝试 srv_connect(SOCK_DGRAM, IPPROTO_ICMP)<br/>= 免 root 的 ping socket"]
    OPEN -->|"EACCES / EPERM"| RAW["srv_connect(SOCK_RAW, IPPROTO_ICMP)<br/>需要 root"]
    OPEN -->|"成功"| SEND
    RAW --> SEND["发送 ICMP 头 + payload<br/>(IP 头由内核添加)"]
    FLOW -->|"是"| SEND
    SEND --> REPLY(["echo reply 到达 socket"])
    REPLY --> STRIP["raw IPv4 socket：去掉 IP 头"]
    STRIP --> MATCH{"raw socket：id 匹配吗？<br/>(raw socket 能看到所有 reply)"}
    MATCH -->|"否"| IGN(["忽略"])
    MATCH -->|"是"| BUILD["恢复手机的 id<br/>(ping socket 会改写它)<br/>构造发给手机的 IP + ICMP reply"]
```

Linux 的 ping socket 通过 `sysctl net.ipv4.ping_group_range` 开启。在 macOS 上，ICMP 数据报 socket
的行为和 raw socket 一样（包含 IP 头，identifier 不会被改写），代码对此做了处理。

## 10. IP 分片

```mermaid
flowchart LR
    subgraph UP["手机到服务器"]
        F1["分片 1<br/>offset 0, MF=1"] --> RA["FragmentReassembler<br/>键：src, dst, protocol, id<br/>30 s 后过期"]
        F2["分片 2<br/>offset 1480, MF=1"] --> RA
        F3["分片 3<br/>offset 2960, MF=0"] --> RA
        RA --> WHOLE["完整的数据报<br/>重新解析并分发"]
    end
    subgraph DOWN["服务器到手机"]
        BIG["大于手机 MTU 的包<br/>(例如 6000 字节的 ping reply、<br/>大的 UDP 数据报)"] --> FP["fragment_packet(packet, mtu)"]
        FP --> P1["分片，每片 <= MTU，<br/>offset 以 8 字节为单位"]
    end
```

TCP 在这里永远不需要分片，因为报文段是按协商好的 MSS 构造的。UDP 和 ICMP 可能比 MTU 大，
所以会话会像路由器（IPv4）或发送主机（IPv6 分片头）那样对它们进行分片。

## 11. 端到端的流控与背压

真实服务器和手机 App 之间的每一个缓冲区都有上限，而每一个满了的缓冲区都会让它前面的生产者慢下来：

```mermaid
flowchart RL
    subgraph PH["手机"]
        APPR["App 读得慢"] --> RWIN["手机通告<br/>一个很小的窗口"]
    end
    subgraph SV["服务器"]
        RWIN --> SNDWND["TcpFlow：snd_wnd 限制<br/>在途字节数"]
        SNDWND --> SBUF["send_buf_ 增长"]
        SBUF -->|"> vpn_tcp_flow_buffer"| PAUSE["srv_pause_read(upstream)"]
        TUNQ["隧道发送缓冲区<br/>> send_high_watermark"] -->|"handle_write_blocked(1)"| TB["Session：tunnel_blocked<br/>各个流停止 transmit()，<br/>丢弃下行 UDP"]
        BUDGET["会话在途预算<br/>vpn_session_inflight (4 MB)"] --> SNDWND
    end
    subgraph RS["真实服务器"]
        PAUSE --> KWIN["服务器内核接收缓冲区被填满，<br/>其 TCP 窗口关闭，<br/>真实服务器放慢速度"]
    end
```

| 限制 | 位置 | 原因 |
|---|---|---|
| 手机的 TCP 窗口 | `TcpFlow::snd_wnd_` | 标准的 TCP 流控 |
| 每个流 2 MB（`kMaxInFlight`） | `transmit()` | 即使窗口很大，也限制单个流 |
| `vpn_session_inflight`（4 MB） | `Session::inflight_room()` | 一条隧道的所有流共享它，这样一个下载不会占满隧道而拖慢其它所有流量（延迟） |
| `vpn_tcp_flow_buffer`（1 MB） | `on_upstream_data()` | 暂停读取真实服务器；降到一半以下时恢复（迟滞） |
| 隧道水位线 | 引擎的 `send_high_watermark` | 手机链路慢时，停止该会话的所有流 |
| 上游水位线 | `on_upstream_write_blocked()` | 真实服务器读得慢时，向手机通告零窗口 |
| 手机 TUN 队列 | `TunnelClient` | 最多读入 4 MB 未发送的帧，分批处理 |

被会话预算卡住的流会保存在一个 FIFO（`starved_flows_`）中，一旦 ACK 释放了预算，
`Session::reap()` 就会按顺序恢复它们，保证每个流都能轮到。

## 12. 定时器与超时

`handle_timer` 每隔 `timer_interval_ms`（`server.ini` 中为 50 ms）在每个 worker 上运行一次，
并调用 `Session::on_timer()`：

```mermaid
flowchart TD
    T(["Session::on_timer(now)"]) --> AUTH{"已认证？"}
    AUTH -->|"否"| HT{"超过 vpn_hello_timeout_ms？"}
    HT -->|"是"| CLOSE["关闭：没有收到 HELLO"]
    AUTH -->|"是"| FLOWS["每个流：on_timer(now)<br/>TCP：空闲和半关闭超时、RTO、SYN-ACK 重试<br/>UDP：空闲 120 s / DNS 20 s<br/>ICMP：空闲 30 s"]
    FLOWS --> REAP["reap()：删除已结束的流"]
    REAP --> FRAG["reassembler.expire()：丢弃过期的分片"]
    FRAG --> PCAP["每秒一次：把 pcap 文件刷到磁盘"]
    PCAP --> STATS["每隔 vpn_stats_interval：记录统计信息"]
```

## 13. IPv6

上面的所有内容同样适用于 IPv6：TUN 接口获得 `fd00:5356::2/64` 地址和默认路由 `::/0`（可在 App 中开关），
`packet.cpp` 解析 IPv6 头并遍历扩展头（包括分片头），校验和使用 IPv6 伪首部，ICMPv6 echo 使用
类型 128/129，服务器用 IPv6 socket 连接 IPv6 目的地址。如果服务器本身没有 IPv6 连通性，
连接就会失败，手机收到 RST / unreachable，App 会回退到 IPv4（Happy Eyeballs）。
