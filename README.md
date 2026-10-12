# SimpleVPN

一个用来学习各种网络协议**拦截、修改和监测**的 Android VPN。

手机上的 App 只做一件事：把系统交给 VPN 的**每一个 IP 包**原样通过一条 TCP 隧道发给你自己的服务器，
再把服务器发回来的 IP 包写回系统。所有“聪明”的事情都在服务器上做：服务器把这些 IP 包里的
TCP / UDP / ICMP 连接在用户态终结掉，打印到日志（HTTP 请求、TLS SNI、DNS 查询……），
按规则改写或拦截，然后用普通 socket 透明地转发给真正的目标服务器，回包再原路返回给手机。

```
  Android 手机                                  VPN 服务器: mulserver + libvpnproxy.so             互联网
 ┌──────────────────────┐                     ┌───────────────────────────────────────────┐
 │ App ──► TUN 设备      │   TCP 隧道          │ 解析 IP 包                                  │
 │   (VpnService)       │  一帧 = 一个 IP 包   │  ├─ TCP : 用户态 TCP 终结 ──┐                │  TCP socket
 │        │             │ ──────────────────► │  ├─ UDP : NAT 映射 ─────────┼─ Inspector ───┼──────────────► 目标服务器
 │ NDK 隧道客户端         │ ◄────────────────── │  ├─ ICMP: ping socket ─────┘  日志/改写/拦截 │  UDP / ICMP
 │ (tunnel_client.cpp)  │                     │  └─ 分片重组 / pcap 抓包                     │ ◄──────────────
 └──────────────────────┘                     └───────────────────────────────────────────┘
```

为什么服务器要在用户态终结 TCP，而不是直接把 IP 包丢进服务器的 TUN 再做 NAT？
因为终结之后服务器看到的是**应用层字节流**：可以直接打印 HTTP 请求、解析 TLS ClientHello、
改写响应内容（长度变化也没关系，两边是两条独立的 TCP 连接，序号互不相关），而且不需要 root 和 iptables。

服务器基于 [simple-cplusplus-multithread-reactor-server](https://github.com/kingo132/simple-cplusplus-multithread-reactor-server)
（以 git submodule 的形式放在 `server/reactor`），VPN 逻辑是它的一个插件。

## 功能

* **TCP**：完整的用户态 TCP 端点——握手（先连上真实服务器再回 SYN-ACK，连不上就回 RST）、MSS / 窗口扩大选项、
  确认、重传（RTT 估计 + 超时退避 + 快速重传）、零窗口探测、流控（服务器写不动时向手机通告零窗口；
  手机收不动时暂停读服务器）、半关闭、RST；IPv4 和 IPv6
* **UDP**：每个 (源, 目的) 一个 socket；端口不可达时给手机回 ICMP unreachable；DNS 流单独的空闲超时
* **ICMP echo**（ping）：优先使用免 root 的 ping socket，失败时用 raw socket（root）
* IP 分片：手机发来的分片会重组，发给手机的超过 MTU 的包会分片
* **Inspector**（`server/src/inspector.cpp`）：
  * 日志：HTTP 请求行 / Host / User-Agent、HTTP 响应行、TLS ClientHello（版本、SNI、ALPN）、DNS 查询和应答、
    SSH banner、未知协议的前若干字节；可选每个包一行摘要、可选十六进制 dump
  * 拦截：`vpn_block_domains` 里的域名，DNS 回 NXDOMAIN，TLS SNI / HTTP Host 命中则 RST
  * 改写：`vpn_rewrite_N` 规则对明文 TCP 流做字符串替换（上行 / 下行）
  * `vpn_block_quic`：拒绝 UDP 443，让浏览器回退到 TCP + TLS（这样能看到 SNI）
* **pcap 抓包**：每个会话写一个 pcap 文件，直接用 Wireshark 打开
* 隧道：token 认证、心跳、断线自动重连（指数退避）
* Android App：服务器/端口/token/DNS/MTU 设置、只代理指定 App、IPv6 开关、实时状态和流量统计、always-on VPN

## 目录结构

```
common/tunnel_protocol.h        客户端和服务器共用的隧道帧格式
client/                         Android Studio 工程
  app/src/main/cpp/
    tunnel_client.{h,cpp}       隧道客户端核心（Android 和 Linux 测试客户端共用）
    native-lib.cpp              JNI
  app/src/main/java/.../
    MyVpnService.kt             VpnService：创建 TUN、启动 native 隧道
    MainActivity.kt, VpnSettings.kt
server/
  reactor/                      git submodule: 多线程 reactor 服务器框架
  src/
    vpn_plugin.cpp              框架回调入口 (handle_*)
    vpn_session.{h,cpp}         一个手机 = 一个会话：隧道帧、流表、统计、pcap
    flows.{h,cpp}               TcpFlow (用户态 TCP) / UdpFlow / IcmpFlow
    packet.{h,cpp}              IPv4/IPv6/TCP/UDP/ICMP 解析和构造、校验和、分片
    inspector.{h,cpp}           协议识别、日志、改写、拦截 ← 做实验主要改这里
    pcap_writer.{h,cpp}
  conf/server.ini, conf/bind.txt
tools/linux_client/             Linux 命令行客户端（同一个隧道核心 + Linux TUN），不用手机也能调试
tests/                          单元测试、端到端测试、JNI 测试
```

## 快速开始

### 1. 编译和运行服务器（Linux，macOS 也可以编译）

```bash
git clone --recursive https://github.com/kingo132/simple-android-vpn.git
cd simple-android-vpn            # 已经 clone 过的: git submodule update --init
cmake -B build && cmake --build build -j

cd server
vi conf/server.ini               # 至少把 vpn_token 改掉
../build/server/reactor/mulserver conf/server.ini ../build/server/libvpnproxy.so
```

* 监听地址在 `conf/bind.txt`（默认 `0.0.0.0:9443`），云服务器记得在安全组 / 防火墙放行这个 TCP 端口。
* 日志在 `server/log/server.log`，pcap 在 `server/pcap/`。
* 要支持 ping：用 root 运行，或者允许免 root 的 ping socket：
  `sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"`。
* 服务器要能访问 IPv6 才能代理手机的 IPv6 流量；没有 IPv6 也没关系，App 连接 IPv6 失败后会自动回退到 IPv4。

### 2. 编译和安装 Android App

用 Android Studio 打开 `client/` 目录（需要 NDK 和 CMake 3.22.1，Android Studio 会提示安装），
运行到手机上即可；命令行：`cd client && ./gradlew assembleDebug`。

在 App 里填写服务器地址、端口、token（和服务器 `vpn_token` 一致），点 **Start VPN**，
第一次会弹出系统的 VPN 授权对话框。“Only these apps” 填包名（逗号分隔）就只代理这些 App，
留空则代理除本 App 以外的所有 App。

### 3. 不用手机：Linux 客户端

```bash
sudo ./build/tools/simplevpn-client -s <服务器IP> -p 9443 -t <token> -d tun0 --ipv4 172.19.0.2/24
# 另一个终端：把要测试的流量路由进 tun0（不要把到服务器本身的路由也指进去）
sudo ip route add 93.184.0.0/16 dev tun0
curl http://93.184.215.14/
```

## 做实验

服务器日志（`log_level = 6`）大概是这样的：

```
S2 tunnel connection from 172.30.0.2:59956
S2 authenticated: client=android mtu=1500 tun_ipv4=172.19.0.2 tun_ipv6=fd00:5356::2
S2 TCP#1 172.19.0.2:56154 -> 198.51.100.10:8080 connected (server side local address 198.51.100.1:47288)
S2 TCP#1 172.19.0.2:56154 -> 198.51.100.10:8080 C->S HTTP GET /index.html HTTP/1.1 Host=198.51.100.10:8080 UA=curl/8.5.0
S2 TCP#1 172.19.0.2:56154 -> 198.51.100.10:8080 S->C HTTP/1.0 200 OK
S2 TCP#1 172.19.0.2:56154 -> 198.51.100.10:8080 rewrote 1 occurrence(s) of "Hello SimpleVPN" (downstream)
S2 TCP#1 172.19.0.2:56154 -> 198.51.100.10:8080 closed (up 91 bytes, down 202 bytes, 9 ms, 0 retransmits, HTTP 198.51.100.10:8080)
S2 UDP#24 172.19.0.2:47385 -> 198.51.100.10:53 C->S DNS query id=0xeffd q=A www.example.test
S2 UDP#24 172.19.0.2:47385 -> 198.51.100.10:53 S->C DNS response id=0xeffd q=A www.example.test | www.example.test A 1.2.3.4 ttl=60
S2 UDP#26 172.19.0.2:54401 -> 198.51.100.10:53 BLOCKED DNS query ads.blocked.test
S2 TCP#36 172.19.0.2:39336 -> 198.51.100.10:25 S->C first 29 bytes: "220 banner.test ESMTP ready\r\n"
S2 TCP#68 172.19.0.2:45030 -> 198.51.100.10:443 C->S TLS ClientHello TLS1.3 SNI=www.google.com ALPN=h2,http/1.1
```

`server.ini` 里和实验相关的配置：

| 配置 | 作用 |
|---|---|
| `vpn_log_packets = 1` | 每个 IP 包一行摘要（`S2 > TCP ... [S] seq=...`，`>` 手机发出，`<` 发给手机） |
| `vpn_log_payload_bytes = 256` | 每个 TCP 数据块 / UDP 包十六进制 dump 前 256 字节 |
| `vpn_pcap_dir = ./pcap` | 每个会话一个 pcap 文件（手机看到的原始 IP 包，两个方向都有） |
| `vpn_block_domains = a.com,b.com` | 屏蔽域名及其子域名（DNS → NXDOMAIN，TLS SNI / HTTP Host → RST） |
| `vpn_rewrite_1 = down\|Example Domain\|Hacked! Domain` | 改写明文流，`up` 手机→服务器，`down` 服务器→手机；端口由 `vpn_rewrite_ports` 指定 |
| `vpn_block_quic = 1` | 拒绝 QUIC，逼 App 走 TCP + TLS |
| `log_level = 7` | debug：连接建立、FIN、重传等 TCP 细节 |

想写自己的分析/修改逻辑，改 `server/src/inspector.cpp` 的 `Inspector::inspect_tcp()` / `inspect_udp()` 即可：
每一块经过代理的数据都会经过这里，可以记录、修改（`std::string& data`，长度随意）或返回 `kBlock` 断开连接。

注意：

* 改写 HTTP body 时如果长度变了，记得同时改 `Content-Length`，否则客户端会认为响应不完整。
  替换规则是对每个数据块单独做的，跨越两个 TCP 数据块的字符串匹配不到。
* HTTPS 的内容是加密的，这里只能看到 SNI、证书之前的握手信息和流量特征。要看明文需要做 TLS 中间人
  （给手机装自己的 CA 证书，服务器用这个 CA 动态签发证书，很多 App 会做证书锁定而拒绝），这个还没有实现。
* 隧道本身**没有加密**，只有 token 认证。请在可信网络里使用，或者把 9443 端口放到 SSH 隧道 / WireGuard / TLS 后面。
  服务器暴露在公网时一定要设置 `vpn_token`，并考虑 `vpn_block_private = 1`（禁止通过代理访问服务器所在内网）。

## 隧道协议

`common/tunnel_protocol.h`：一条 TCP 连接上传输帧，帧头 8 字节：

```
magic 0x5356 (2) | version 1 (1) | type (1) | payload length, big endian (4) | payload
```

| type | 方向 | payload |
|---|---|---|
| HELLO (1) | 客户端→服务器 | `key=value\n`：token, client, mtu, ipv4, ipv6 |
| HELLO_ACK (2) | 服务器→客户端 | `key=value\n`：server, session |
| PACKET (3) | 双向 | 一个完整的 IPv4 / IPv6 包 |
| PING (4) / PONG (5) | 双向 | 心跳，原样返回 |
| ERROR (6) | 双向 | 错误原因（如 `authentication failed`），发送方随后关闭连接 |

## 测试

```bash
cmake -B build && cmake --build build -j
./build/tests/packet_test                 # 包解析/构造、校验和、分片重组、DNS/TLS/HTTP 解析
sudo tests/e2e_test.sh                    # 端到端（需要 root）
sudo tests/jni_test.sh                    # 在 Linux JVM 上运行 App 的 JNI 代码
```

`tests/e2e_test.sh` 用 network namespace 在一台机器上搭出完整链路：
“手机” namespace（TUN + Linux 客户端）→ VPN 服务器 → “互联网” namespace（HTTP / echo / DNS / SMTP 风格服务、ping）。
它会测试 HTTP 改写、50 MB 下载和 20 MB 上传的校验和、20 个并发下载、DNS 和 DNS 拦截、TLS SNI 拦截、
ping（raw socket 和 ping socket、6000 字节分片）、TCP 半关闭、UDP 大包分片、服务器先说话的协议、
连接被拒绝、QUIC 拦截、服务器重启后自动重连、错误 token、pcap 文件。
在开发机上本地链路的吞吐大约 100 MB/s（单连接）/ 170 MB/s（20 个并发连接）。

`tests/jni_test.sh` 用一个 Java 版的 `MyVpnService` 替身加载 `native-lib.cpp`（主机编译），
在同样的环境里验证 JNI 层：线程 attach、`protect()` 回调、状态回调、统计、停止。

## 限制 / 以后可以做的

* 只代理 TCP、UDP 和 ICMP echo；其它 IP 协议（GRE、ESP、SCTP……）会被记录日志后丢弃
* 没有 SACK、没有拥塞控制算法（发送量受手机窗口、单流 2 MB 和每个会话 `vpn_session_inflight` 限制）
* TLS 中间人解密、隧道加密、UDP 隧道（避免 TCP over TCP）都还没有做
