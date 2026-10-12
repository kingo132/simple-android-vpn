# Architecture

**English** | [简体中文](../zh-CN/architecture.md) · [README](../../README.md) · [Tunnel protocol](tunnel-protocol.md) · [Android client](android-client.md) · [Inspector and capture](inspector-and-capture.md) · [Learning guide](learning-guide.md) · [Configuration](configuration.md) · [Testing](testing.md) · [Source tour](source-tour.md)

This document follows an IP packet from an app on the phone to a server on the internet and back, and
explains every component it passes, what that component does and why it is built that way.

## Contents

1. [The idea in one picture](#1-the-idea-in-one-picture)
2. [Components](#2-components)
3. [The journey of one HTTP request](#3-the-journey-of-one-http-request)
4. [The server plugin on the reactor engine](#4-the-server-plugin-on-the-reactor-engine)
5. [Sessions: one phone, one tunnel](#5-sessions-one-phone-one-tunnel)
6. [From IP packet to flow](#6-from-ip-packet-to-flow)
7. [TCP: a user-space TCP endpoint](#7-tcp-a-user-space-tcp-endpoint)
8. [UDP: NAT with connected sockets](#8-udp-nat-with-connected-sockets)
9. [ICMP echo (ping)](#9-icmp-echo-ping)
10. [IP fragmentation](#10-ip-fragmentation)
11. [Flow control and back pressure end to end](#11-flow-control-and-back-pressure-end-to-end)
12. [Timers and timeouts](#12-timers-and-timeouts)
13. [IPv6](#13-ipv6)

---

## 1. The idea in one picture

A normal VPN encrypts packets and a server routes them with NAT. SimpleVPN instead **terminates**
every connection on the server and opens a new one to the real destination. This is called a
*split TCP* or *transparent proxy* design:

```mermaid
flowchart LR
    subgraph P["Phone"]
        APP["App<br/>connect(1.2.3.4:80)"]
        K1["Phone kernel TCP"]
    end
    subgraph S["SimpleVPN server"]
        U["user-space TCP<br/>(TcpFlow)<br/>pretends to be 1.2.3.4"]
        I["Inspector<br/>sees plain bytes"]
        K2["Server kernel TCP<br/>ordinary socket"]
    end
    R["Real server<br/>1.2.3.4:80"]
    APP --> K1
    K1 -- "TCP connection 1<br/>(IP packets inside the tunnel)" --> U
    U --> I --> K2
    K2 -- "TCP connection 2<br/>(normal internet)" --> R
```

* Connection 1 runs between the phone's kernel and our **user-space TCP implementation** (`TcpFlow`).
  The phone believes it talks to 1.2.3.4.
* Connection 2 is an ordinary socket from the server to 1.2.3.4.
* Between them the server has the **plain byte stream**. It can log, modify or drop it. Because the two
  connections have independent sequence numbers, changing the length of the data is no problem.
* No root and no iptables are needed on the server (except for raw ICMP).

## 2. Components

```mermaid
flowchart TB
    subgraph ANDROID["Android phone"]
        direction TB
        UI["MainActivity.kt<br/>settings, start / stop, statistics"]
        SVC["MyVpnService.kt<br/>VpnService: builds the TUN interface,<br/>watches network changes"]
        JNI["native-lib.cpp<br/>JNI glue, tunnel thread,<br/>protect() and state callbacks"]
        TC["tunnel_client.cpp<br/>TUN fd and TCP socket pump,<br/>handshake, keepalive, reconnect"]
        TUNDEV[("TUN device<br/>172.19.0.2 / fd00:5356::2")]
        UI --> SVC --> JNI --> TC
        TC <--> TUNDEV
    end
    subgraph SERVER["Server: mulserver process"]
        direction TB
        ENG["reactor engine<br/>(server/reactor)<br/>sockets, threads, queues"]
        PLG["vpn_plugin.cpp<br/>engine callbacks"]
        SES["vpn_session.cpp<br/>Session per tunnel"]
        FLW["flows.cpp<br/>TcpFlow / UdpFlow / IcmpFlow"]
        PKT["packet.cpp<br/>parse and build packets"]
        INSP["inspector.cpp<br/>detect, log, rewrite, block"]
        PCAP["pcap_writer.cpp<br/>pcap files, live capture"]
        ENG <--> PLG <--> SES <--> FLW
        SES --> PKT
        FLW --> PKT
        FLW --> INSP
        SES --> PCAP
    end
    TC <-->|"TCP :9443<br/>tunnel frames"| ENG
    ENG <-->|"sockets"| INTERNET(("Internet"))
    PCAP -->|"TCP :9444<br/>pcap stream"| WS["Wireshark"]
```

| Component | Language | Responsibility |
|---|---|---|
| `MainActivity` | Kotlin | UI, asks for VPN permission, shows state and counters |
| `MyVpnService` | Kotlin | creates the TUN interface with `VpnService.Builder`, starts/stops the native tunnel |
| `native-lib.cpp` | C++ / JNI | runs `TunnelClient` on its own thread, bridges `protect()` and state callbacks to Java |
| `TunnelClient` | C++ | moves IP packets between the TUN fd and the server connection; also used by the Linux client |
| reactor engine | C++ | all socket I/O and threading on the server |
| `vpn_plugin.cpp` | C++ | maps engine callbacks to sessions and flows |
| `Session` | C++ | one per tunnel: authentication, frames, flow table, statistics, pcap |
| `TcpFlow` / `UdpFlow` / `IcmpFlow` | C++ | one per connection / conversation: protocol logic and the outbound socket |
| `packet.cpp` | C++ | IPv4/IPv6/TCP/UDP/ICMP parsing and building, checksums, fragmentation |
| `Inspector` | C++ | protocol detection, logging, rewriting, blocking — **the place for experiments** |
| `PcapWriter` / `LiveCapture` | C++ | capture to files and to live Wireshark clients |

## 3. The journey of one HTTP request

What happens when the browser on the phone loads `http://example.com/`:

```mermaid
sequenceDiagram
    autonumber
    participant App as Browser (phone)
    participant PK as Phone kernel
    participant TUN as TUN device
    participant TC as TunnelClient (phone)
    participant SES as Session (server)
    participant TF as TcpFlow (server)
    participant NET as example.com:80
    App->>PK: DNS query for example.com (UDP 53)
    PK->>TUN: IP/UDP packet
    TUN->>TC: read(tun_fd)
    TC->>SES: PACKET frame
    SES->>SES: UdpFlow, send query with a UDP socket, reply back as PACKET
    App->>PK: connect(93.184.215.14:80)
    PK->>TUN: IP/TCP SYN
    TC->>SES: PACKET(SYN)
    SES->>TF: new TcpFlow, start()
    TF->>NET: srv_connect() = real TCP handshake
    NET-->>TF: connected (handle_server_open)
    TF->>TC: PACKET(SYN-ACK) built in user space
    TC->>TUN: write(tun_fd)
    PK->>TC: ACK, then HTTP GET (via TUN, PACKET frames)
    TC->>TF: PACKET(ACK), PACKET(data "GET / ...")
    TF->>TF: Inspector logs "HTTP GET / Host=example.com"
    TF->>NET: send(GET ...)
    TF->>TC: PACKET(ACK of the GET)
    NET-->>TF: HTTP response bytes
    TF->>TF: Inspector logs "HTTP/1.1 200 OK", may rewrite
    TF->>TC: PACKET(data segments, at most MSS each)
    TC->>TUN: write, the phone kernel delivers to the browser
    PK->>TC: ACKs for the data
    TC->>TF: PACKET(ACK), TcpFlow frees acknowledged bytes
```

Two things are worth noticing:

* The SYN-ACK is sent **only after** the real server accepted the connection. If the server refuses,
  the phone gets a RST — exactly what it would see without a VPN.
* Every packet in both directions is also written to the session's pcap file and to live Wireshark
  clients, so you can compare what the phone sees with what the server logs.

## 4. The server plugin on the reactor engine

The VPN server is a plugin (`libvpnproxy.so`) of the reactor engine. The engine owns the sockets and
threads; the plugin only reacts to callbacks.

```mermaid
flowchart LR
    subgraph ENGINE["reactor engine"]
        CONN["CONN thread"]
        W["worker thread k"]
    end
    subgraph PLUGIN["vpn_plugin.cpp callbacks"]
        HI["handle_input_from_client<br/>tunnel frame boundaries"]
        HO["handle_client_open<br/>new Session"]
        HM["handle_message_from_client<br/>Session::on_frame()"]
        HC["handle_client_close<br/>delete Session"]
        SO["handle_server_open<br/>Flow::on_upstream_open()"]
        SM["handle_message_from_server<br/>Flow::on_upstream_data()"]
        SC["handle_server_close<br/>Flow::on_upstream_close()"]
        WB["handle_write_blocked<br/>tunnel or upstream congested"]
        TM["handle_timer<br/>Session::on_timer() every 50 ms"]
    end
    CONN --> HI
    W --> HO & HM & HC & SO & SM & SC & WB & TM
```

| Engine callback | Who | Plugin action |
|---|---|---|
| `handle_input_from_client` | CONN thread | `tunnel::parse_header()` → length of one frame (or the whole chunk for capture clients) |
| `handle_client_open` | worker | capture port: add a live capture subscriber; tunnel port: `new Session` |
| `handle_message_from_client` | worker | `Session::on_frame(type, payload)` then `reap()` |
| `handle_client_close` | worker | delete the Session; its destructor aborts every outbound socket |
| `handle_server_open/…_from_server/…_close` | worker | find the Flow by `si->user_tag` (= flow id) and forward the event |
| `handle_write_blocked` | worker | tunnel → `Session::on_tunnel_write_blocked`; upstream → `Flow::on_upstream_write_blocked` |
| `handle_timer` | worker | `Session::on_timer()` for every session of this worker |

### Why no locks are needed

```mermaid
flowchart TB
    T["tunnel connection of phone A<br/>accepted, worker = round robin = 2"] --> W2["worker 2"]
    W2 --> S["Session A<br/>(t_worker->sessions)"]
    S --> F1["TcpFlow #1"]
    S --> F2["UdpFlow #2"]
    F1 -->|"srv_connect() on worker 2"| U1["outbound socket<br/>owned by worker 2"]
    F2 -->|"srv_connect() on worker 2"| U2["outbound socket<br/>owned by worker 2"]
    U1 -. "events come back to worker 2" .-> F1
    U2 -. "events come back to worker 2" .-> F2
```

The engine pins every connection to one worker, and `srv_connect()` sockets belong to the worker
that created them. So the tunnel, its session, all its flows and all their outbound sockets live on
**one** thread. All state is kept in the `thread_local WorkerState` (`sessions` by tunnel `conn_id`,
`flows` by flow id) and no mutex is needed. Different phones are spread over the workers.

The only process-wide objects are read-only after start (`g_vpn_config`, `g_inspector`) or protected
by their own mutex (`g_live_capture`).

## 5. Sessions: one phone, one tunnel

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
    Session "1" *-- "many" Flow : flows_ by FlowKey
    Flow <|-- TcpFlow
    Flow <|-- UdpFlow
    Flow <|-- IcmpFlow
    Flow --> FlowKey
    WorkerState o-- Session
    WorkerState o-- Flow : by id = user_tag
```

### Session life cycle

```mermaid
stateDiagram-v2
    [*] --> WaitHello: tunnel accepted (handle_client_open)
    WaitHello --> Authenticated: HELLO with the right token, send HELLO_ACK
    WaitHello --> Closing: wrong token, ERROR "authentication failed"
    WaitHello --> Closing: first frame is not HELLO
    WaitHello --> Closing: no HELLO within vpn_hello_timeout_ms
    Authenticated --> Authenticated: PACKET (IP packet), PING answered with PONG
    Authenticated --> Closing: ERROR from client
    Closing --> [*]: srv_close(tunnel), flows destroyed
    Authenticated --> [*]: tunnel closed by the phone or the network (handle_client_close)
```

### Flow deletion: finish() and reap()

A flow can decide to die in the middle of its own callback (for example while processing a RST).
Deleting `this` there would be a use-after-free. Therefore:

```mermaid
sequenceDiagram
    participant P as vpn_plugin callback
    participant S as Session
    participant F as Flow
    P->>S: on_frame() / on_upstream_data() ...
    S->>F: on_packet()
    F->>F: finish(): close upstream, dead_ = true
    F->>S: mark_dead(key)
    F-->>S: return (object still alive)
    S-->>P: return
    P->>S: reap()
    S->>S: erase dead flows from flows_ (destructor runs now)
    S->>S: also resume flows waiting for in-flight budget
```

## 6. From IP packet to flow

`Session::handle_packet()` and `dispatch_packet()`:

```mermaid
flowchart TD
    F(["PACKET frame from the phone"]) --> CAP["write to pcap file and live capture"]
    CAP --> PARSE{"parse_packet()<br/>IPv4 or IPv6 valid?"}
    PARSE -->|"no"| DROP1["drop, count as dropped"]
    PARSE -->|"yes"| LOG["vpn_log_packets: one line summary"]
    LOG --> FRAG{"fragment?"}
    FRAG -->|"yes"| RE["FragmentReassembler::add()"]
    RE -->|"incomplete"| WAIT(["wait for more fragments"])
    RE -->|"complete datagram"| DISP
    FRAG -->|"no"| DISP{"destination multicast<br/>or broadcast?"}
    DISP -->|"yes"| DROP2["drop"]
    DISP -->|"no"| PROTO{"protocol"}
    PROTO -->|"TCP"| HT["handle_tcp()"]
    PROTO -->|"UDP"| HU["handle_udp()"]
    PROTO -->|"ICMP / ICMPv6"| HI["handle_icmp()<br/>echo request only"]
    PROTO -->|"other (GRE, ESP ...)"| DROP3["log and drop"]
```

Flows are looked up by a **5-tuple key**: protocol, phone address and port, destination address and
port (for ICMP the port is the echo identifier).

```mermaid
flowchart TD
    HT(["handle_tcp(packet)"]) --> LOOK{"flow for the 5-tuple exists?"}
    LOOK -->|"yes, alive, not a new SYN"| ON["flow->on_packet()"]
    LOOK -->|"yes, but a SYN with a new ISN"| REPL["port reused: erase the old flow"] --> NEW
    LOOK -->|"yes but dead, or no flow"| SYN{"pure SYN?"}
    SYN -->|"no"| RST["send RST<br/>(e.g. after a server restart)"]
    SYN -->|"yes"| NEW{"allowed?<br/>vpn_block_private, vpn_max_flows"}
    NEW -->|"no"| RST
    NEW -->|"yes"| CREATE["new TcpFlow, start()<br/>srv_connect() to the destination"]
```

## 7. TCP: a user-space TCP endpoint

`TcpFlow` (`flows.cpp`) implements the server side of TCP (RFC 9293) towards the phone, simplified
where the situation allows it. It does **not** implement congestion control: the phone and the server
are connected by the tunnel, which is itself a TCP connection with its own congestion control.

### 7.1 State machine

```mermaid
stateDiagram-v2
    [*] --> Connecting: SYN from phone, srv_connect()
    Connecting --> Dead: connect failed, RST to phone
    Connecting --> Connecting: phone retransmits SYN (ignored)
    Connecting --> SynAckSent: real server accepted, send SYN-ACK
    SynAckSent --> SynAckSent: RTO, resend SYN-ACK (max 5 times)
    SynAckSent --> Established: ACK of our SYN-ACK
    SynAckSent --> Dead: handshake timeout or RST
    Established --> Established: data, ACKs, window updates, retransmissions
    Established --> Dead: both FINs exchanged and acknowledged
    Established --> Dead: RST from phone, server error, idle timeout, too many retransmissions, blocked by rule
    Dead --> [*]: deleted later by Session reap()
```

There is no explicit FIN_WAIT/CLOSE_WAIT/TIME_WAIT: the closing state is described by four flags
(`phone_fin_`, `upstream_eof_`, `fin_sent_`, `fin_acked_`). TIME_WAIT is unnecessary because the flow
key is removed and a new SYN with a different ISN creates a fresh flow.

### 7.2 Handshake and options

```mermaid
sequenceDiagram
    autonumber
    participant Ph as Phone kernel
    participant TF as TcpFlow
    participant Srv as Real server
    Ph->>TF: SYN seq=x, MSS=1460, WScale=7
    TF->>TF: irs = x, rcv_nxt = x+1, iss = random, mss = min(ours, peer)
    TF->>Srv: connect() through the engine (SRV_CONNECT_HALF_CLOSE, RAW)
    Ph->>TF: SYN again (retransmission), ignored while connecting
    Srv-->>TF: SYN-ACK, connect done (handle_server_open, error 0)
    TF->>Ph: SYN-ACK seq=iss ack=x+1, MSS, WScale, window (unscaled in SYN)
    Ph->>TF: ACK ack=iss+1, state Established
    Note over Ph,Srv: if connect fails instead: RST+ACK to the phone,<br/>so the app sees "connection refused"
```

* **MSS** (maximum segment size): `min(our MTU - 40 (IPv4) / 60 (IPv6), phone's MSS)`; defaults 536 /
  1220 when the phone sends none.
* **Window scale**: only if the phone offered it. We pick the smallest shift so that `vpn_tcp_window`
  (512 KB) fits into 16 bits. The window field of a SYN is never scaled.

### 7.3 Sequence space bookkeeping

```mermaid
flowchart LR
    subgraph SEND["Our send sequence space (server to phone)"]
        direction LR
        A["acknowledged<br/>(already erased)"] --- B["sent, not yet acked<br/>snd_una .. snd_nxt"] --- C["sent before a timeout rewind<br/>snd_nxt .. snd_max"] --- D["buffered, not sent<br/>.. end of send_buf_"]
    end
```

| Variable | Meaning |
|---|---|
| `snd_una_` | oldest byte not acknowledged by the phone; `send_buf_` starts here |
| `snd_nxt_` | next byte to send; rewound to `snd_una_` on a retransmission timeout (go-back-N) |
| `snd_max_` | highest byte ever sent + 1; ACKs up to here are valid even after a rewind |
| `snd_wnd_` | phone's receive window (scaled) |
| `rcv_nxt_` | next byte expected from the phone (what we acknowledge) |

### 7.4 Download: server → phone

```mermaid
sequenceDiagram
    participant Srv as Real server
    participant TF as TcpFlow
    participant S as Session
    participant Ph as Phone
    Srv->>TF: on_upstream_data(bytes)
    TF->>TF: Inspector (log, rewrite, block), append to send_buf_
    alt send_buf_ > vpn_tcp_flow_buffer (1 MB)
        TF->>Srv: srv_pause_read(upstream, 1)
    end
    TF->>TF: transmit()
    loop while window, session budget and data allow
        TF->>S: inflight_room()?
        TF->>Ph: segment seq=snd_nxt, len <= MSS, PSH on the last
        TF->>TF: snd_nxt += len, start RTT sample, arm RTO
    end
    Ph->>TF: ACK ack=n, window=w
    TF->>TF: process_ack(): erase acked bytes, update RTT and RTO, snd_wnd = w
    alt send_buf_ < flow buffer / 2 and paused
        TF->>Srv: srv_pause_read(upstream, 0)
    end
    TF->>TF: transmit() more
```

`transmit()` sends as much as the smallest of these limits allows:

```mermaid
flowchart TD
    T(["transmit()"]) --> E{"Established and<br/>tunnel not congested?"}
    E -->|"no"| X(["return"])
    E -->|"yes"| U{"unsent bytes in send_buf_?"}
    U -->|"no"| FIN{"server sent FIN<br/>and our FIN not sent?"}
    FIN -->|"yes"| SF["send FIN, snd_nxt += 1"] --> X
    FIN -->|"no"| X
    U -->|"yes"| W["room = min(snd_wnd, 2 MB) - bytes in flight"]
    W --> NEWD{"new data (not a retransmission)?"}
    NEWD -->|"yes"| SB{"session in-flight budget left?"}
    SB -->|"no"| WAITB["wait_for_budget(): resume later in reap()"] --> X
    SB -->|"yes"| R2["room = min(room, max(budget, MSS))"]
    NEWD -->|"no"| ROOM
    R2 --> ROOM{"room > 0?"}
    ROOM -->|"no"| PERSIST["arm RTO as persist timer<br/>(zero window probe later)"] --> X
    ROOM -->|"yes"| SEG["send min(unsent, room, MSS) bytes"] --> U
```

### 7.5 Upload: phone → server

```mermaid
flowchart TD
    P(["segment from the phone with data"]) --> EST{"Established?"}
    EST -->|"no"| IGN(["ignore"])
    EST -->|"yes"| PF{"phone already sent FIN?"}
    PF -->|"yes"| ACK1["send ACK (retransmission)"]
    PF -->|"no"| OLD{"seq < rcv_nxt?"}
    OLD -->|"completely old"| ACK1
    OLD -->|"partly old"| TRIM["cut off the old part"] --> INORD
    OLD -->|"no"| INORD{"seq == rcv_nxt?"}
    INORD -->|"no, a hole"| ACK2["send duplicate ACK<br/>(no out-of-order queue,<br/>the phone retransmits)"]
    INORD -->|"yes"| DATA["rcv_nxt += len<br/>Inspector (log / rewrite / block)<br/>srv_send(upstream)"]
    DATA --> FINQ{"FIN flag?"}
    FINQ -->|"yes"| SHUT["rcv_nxt += 1<br/>srv_shutdown_write(upstream)"]
    FINQ -->|"no"| ACK3
    SHUT --> ACK3["send ACK with our window"]
```

If the outbound socket cannot take more data, the engine reports `handle_write_blocked(1)`; the flow
then advertises a **zero window** to the phone, which stops sending. When the socket drains, an ACK
with the reopened window is sent right away (`on_upstream_write_blocked`).

### 7.6 Retransmission

```mermaid
flowchart TD
    A(["ACK from the phone"]) --> NEWACK{"acknowledges new data?<br/>snd_una < ack <= snd_max"}
    NEWACK -->|"yes"| RTT["RTT sample if it covers the timed segment<br/>(Karn: never time retransmissions)"]
    RTT --> UP["SRTT = 7/8 SRTT + 1/8 sample<br/>RTTVAR = 3/4 RTTVAR + 1/4 diff<br/>RTO = SRTT + max(10 ms, 4 RTTVAR)<br/>clamped to 300 ms .. 30 s"]
    UP --> REARM["restart RTO if data is still in flight"]
    NEWACK -->|"same ack, no data,<br/>same window, data in flight"| DUP{"3rd duplicate ACK?"}
    DUP -->|"yes"| FR["fast retransmit<br/>the first unacked segment"]
    DUP -->|"no"| NOTHING(["count it"])
    TO(["RTO timer fires (on_timer)"]) --> ZW{"zero window?"}
    ZW -->|"yes"| PROBE["window probe: 1 byte<br/>(does not count as a retry)"]
    ZW -->|"no"| RETRY{"more than 10 retries?"}
    RETRY -->|"yes"| ABORT["abort, RST to the phone"]
    RETRY -->|"no"| GBN["RTO doubles (max 30 s)<br/>go back N: snd_nxt = snd_una<br/>resend from the oldest byte"]
```

The RTO estimator follows RFC 6298; fast retransmit uses the RFC 5681 definition of a duplicate ACK.

### 7.7 Closing

```mermaid
sequenceDiagram
    participant Ph as Phone
    participant TF as TcpFlow
    participant Srv as Real server
    Note over Ph,Srv: Case A: the phone closes first
    Ph->>TF: FIN
    TF->>Srv: srv_shutdown_write() = our FIN to the server
    TF->>Ph: ACK
    Srv-->>TF: remaining data, then FIN (ServerEof, half close)
    TF->>Ph: data, then FIN
    Ph->>TF: ACK of our FIN, flow finished
    Note over Ph,Srv: Case B: the server closes first
    Srv-->>TF: FIN (handle_message_from_server with NULL)
    TF->>Ph: send the rest of send_buf_, then FIN
    Ph->>TF: ACK, may still send data (half close)
    Ph->>TF: FIN
    TF->>Ph: ACK, flow finished
```

`SRV_CONNECT_HALF_CLOSE` is what makes this possible: without it the engine would close the outbound
socket on the server's FIN, and half-closed protocols (for example `nc` with shutdown) would break.

RSTs are generated when: the phone sends a non-SYN segment for an unknown connection (e.g. after a
server restart), the destination refuses or cannot be reached, a block rule matches, too many
retransmissions happen, or a flow idles longer than `vpn_tcp_idle_timeout`.

## 8. UDP: NAT with connected sockets

```mermaid
sequenceDiagram
    participant Ph as Phone app
    participant UF as UdpFlow
    participant Srv as 8.8.8.8:53
    Ph->>UF: UDP 172.19.0.2:47385 to 8.8.8.8:53 (new 5-tuple)
    UF->>UF: srv_connect(SOCK_DGRAM) = connected UDP socket
    UF->>UF: Inspector: log DNS query, blocked domain gives NXDOMAIN reply
    UF->>Srv: send(payload)
    Srv-->>UF: reply datagram (recv on the connected socket)
    UF->>UF: Inspector: log DNS answer
    UF->>Ph: build IP/UDP packet 8.8.8.8:53 to 172.19.0.2:47385
    Note over UF: idle 20 s (DNS) or 120 s (other): flow finished
```

* One socket per (phone address:port, destination address:port), i.e. a full-cone-like NAT with the
  server's address.
* The socket is **connected**, so the kernel only delivers datagrams from that destination — the same
  filtering a stateful firewall does.
* If the destination port is closed the kernel reports `ECONNREFUSED`; the flow sends an **ICMP
  destination unreachable** back to the phone, as a router would.
* `vpn_block_quic = 1` answers new UDP flows to port 443 with ICMP port unreachable, so browsers fall
  back to TCP + TLS (see [Inspector and capture](inspector-and-capture.md)).
* When the tunnel is congested, downstream datagrams are dropped: UDP protocols cope with loss, and
  buffering them would only add latency.
* Empty datagrams (zero bytes of payload) are real UDP messages and are forwarded in both
  directions; the engine never confuses them with an end-of-stream signal.

## 9. ICMP echo (ping)

```mermaid
flowchart TD
    REQ(["echo request from the phone<br/>id = 0x1234, seq = 1"]) --> FLOW{"IcmpFlow for<br/>(src, dst, id)?"}
    FLOW -->|"no"| OPEN["try srv_connect(SOCK_DGRAM, IPPROTO_ICMP)<br/>= unprivileged ping socket"]
    OPEN -->|"EACCES / EPERM"| RAW["srv_connect(SOCK_RAW, IPPROTO_ICMP)<br/>needs root"]
    OPEN -->|"ok"| SEND
    RAW --> SEND["send ICMP header + payload<br/>(the kernel adds the IP header)"]
    FLOW -->|"yes"| SEND
    SEND --> REPLY(["echo reply arrives on the socket"])
    REPLY --> STRIP["raw IPv4 socket: strip the IP header"]
    STRIP --> MATCH{"raw socket: id matches?<br/>(raw sockets see every reply)"}
    MATCH -->|"no"| IGN(["ignore"])
    MATCH -->|"yes"| BUILD["restore the phone's id<br/>(ping sockets rewrite it)<br/>build IP + ICMP reply to the phone"]
```

Linux ping sockets are enabled with `sysctl net.ipv4.ping_group_range`. On macOS ICMP datagram sockets
behave like raw sockets (IP header included, identifier not rewritten), which the code handles.

## 10. IP fragmentation

```mermaid
flowchart LR
    subgraph UP["Phone to server"]
        F1["fragment 1<br/>offset 0, MF=1"] --> RA["FragmentReassembler<br/>key: src, dst, protocol, id<br/>expires after 30 s"]
        F2["fragment 2<br/>offset 1480, MF=1"] --> RA
        F3["fragment 3<br/>offset 2960, MF=0"] --> RA
        RA --> WHOLE["complete datagram<br/>parsed again, dispatched"]
    end
    subgraph DOWN["Server to phone"]
        BIG["packet larger than the phone MTU<br/>(e.g. 6000 byte ping reply,<br/>big UDP datagram)"] --> FP["fragment_packet(packet, mtu)"]
        FP --> P1["fragments, each <= MTU,<br/>offsets in units of 8 bytes"]
    end
```

TCP never needs fragmentation here because segments are built with the negotiated MSS. UDP and ICMP
can be larger than the MTU, so the session fragments them like a router (IPv4) or a sending host
(IPv6 fragment header) would.

## 11. Flow control and back pressure end to end

Every buffer between the real server and the phone app is bounded, and every full buffer slows down
the producer before it:

```mermaid
flowchart RL
    subgraph PH["Phone"]
        APPR["app reads slowly"] --> RWIN["phone advertises<br/>a small window"]
    end
    subgraph SV["Server"]
        RWIN --> SNDWND["TcpFlow: snd_wnd limits<br/>bytes in flight"]
        SNDWND --> SBUF["send_buf_ grows"]
        SBUF -->|"> vpn_tcp_flow_buffer"| PAUSE["srv_pause_read(upstream)"]
        TUNQ["tunnel send buffer<br/>> send_high_watermark"] -->|"handle_write_blocked(1)"| TB["Session: tunnel_blocked<br/>flows stop transmit(),<br/>UDP downstream dropped"]
        BUDGET["session in-flight budget<br/>vpn_session_inflight (4 MB)"] --> SNDWND
    end
    subgraph RS["Real server"]
        PAUSE --> KWIN["server kernel receive buffer fills,<br/>its TCP window closes,<br/>real server slows down"]
    end
```

| Limit | Where | Why |
|---|---|---|
| phone's TCP window | `TcpFlow::snd_wnd_` | standard TCP flow control |
| 2 MB per flow (`kMaxInFlight`) | `transmit()` | caps a single flow even with huge windows |
| `vpn_session_inflight` (4 MB) | `Session::inflight_room()` | all flows of one tunnel share it, so one download cannot fill the tunnel and delay everything else (latency) |
| `vpn_tcp_flow_buffer` (1 MB) | `on_upstream_data()` | pause reading the real server; resume below half (hysteresis) |
| tunnel watermark | engine `send_high_watermark` | stop all flows of the session while the phone's link is slow |
| upstream watermark | `on_upstream_write_blocked()` | zero window to the phone while the real server reads slowly |
| phone TUN queue | `TunnelClient` | reads at most 4 MB of unsent frames, works in batches |

Flows that were stopped by the session budget are kept in a FIFO (`starved_flows_`) and resumed in
order by `Session::reap()` as soon as ACKs free budget, so every flow gets its turn.

## 12. Timers and timeouts

`handle_timer` runs every `timer_interval_ms` (50 ms in `server.ini`) on each worker and calls
`Session::on_timer()`:

```mermaid
flowchart TD
    T(["Session::on_timer(now)"]) --> AUTH{"authenticated?"}
    AUTH -->|"no"| HT{"older than vpn_hello_timeout_ms?"}
    HT -->|"yes"| CLOSE["close: no HELLO received"]
    AUTH -->|"yes"| FLOWS["every flow: on_timer(now)<br/>TCP: idle and half-close timeouts, RTO, SYN-ACK retries<br/>UDP: idle 120 s / DNS 20 s<br/>ICMP: idle 30 s"]
    FLOWS --> REAP["reap(): delete finished flows"]
    REAP --> FRAG["reassembler.expire(): drop stale fragments"]
    FRAG --> PCAP["once per second: flush the pcap file"]
    PCAP --> STATS["every vpn_stats_interval: log statistics"]
```

## 13. IPv6

Everything above works for IPv6 as well: the TUN interface gets `fd00:5356::2/64` and a default route
`::/0` (switch in the app), `packet.cpp` parses IPv6 headers and walks extension headers (including
the fragment header), checksums use the IPv6 pseudo header, ICMPv6 echo uses type 128/129 and the
server connects to IPv6 destinations with IPv6 sockets. If the server itself has no IPv6
connectivity, the connect fails, the phone gets a RST / unreachable, and apps fall back to IPv4
(Happy Eyeballs).
