# Android client

**English** | [简体中文](../zh-CN/android-client.md) · [README](../../README.md) · [Architecture](architecture.md) · [Tunnel protocol](tunnel-protocol.md) · [Inspector and capture](inspector-and-capture.md) · [Learning guide](learning-guide.md) · [Configuration](configuration.md) · [Testing](testing.md) · [Source tour](source-tour.md)

The app is deliberately thin: Kotlin sets up the VPN with Android's `VpnService` API, and a small C++
core (shared with the Linux test client) pumps IP packets between the TUN device and the server.

## 1. How Android VPNs work

```mermaid
flowchart LR
    subgraph APPS["Other apps"]
        A1["Chrome"]
        A2["any app"]
    end
    subgraph KERNEL["Android kernel"]
        RT["routing:<br/>default route via tun0"]
        TUN[("tun0<br/>172.19.0.2/24<br/>fd00:5356::2/64")]
        NIC["wlan0 / rmnet<br/>physical network"]
    end
    subgraph OURAPP["SimpleVPN app process"]
        FD["TUN file descriptor<br/>read() = packets apps sent<br/>write() = packets for apps"]
        SOCK["tunnel socket<br/>protect()ed"]
    end
    A1 & A2 --> RT --> TUN
    TUN <--> FD
    FD <--> SOCK
    SOCK --> NIC --> SERVER(("SimpleVPN server"))
```

* `VpnService.Builder.establish()` creates a TUN interface and returns its file descriptor. The routes
  we add (`0.0.0.0/0`, `::/0`) make the system send apps' traffic into it.
* Reading the fd returns one complete IP packet per `read()`; writing a packet injects it into the
  kernel as if it arrived from a network.
* Our own tunnel socket must **not** be routed into the TUN — that would be an endless loop. Two
  mechanisms prevent it: the app excludes itself (`addDisallowedApplication(packageName)`) and every
  tunnel socket is passed to `VpnService.protect(fd)` before `connect()`, which binds it to the
  physical network.

## 2. Classes and threads

```mermaid
flowchart TB
    subgraph MAIN["Android main (UI) thread"]
        MA["MainActivity<br/>settings, permission dialog,<br/>status refresh every second"]
        NCB["ConnectivityManager<br/>NetworkCallback"]
    end
    subgraph EXEC["MyVpnService single-thread executor"]
        CON["connect(): resolve server, build TUN,<br/>nativeStart()"]
        DIS["disconnect(): nativeStop()<br/>(joins the tunnel thread)"]
    end
    subgraph NATIVE["native tunnel thread (std::thread)"]
        RUN["TunnelClient::run()<br/>poll(): socket, TUN, wake pipe"]
    end
    MA -->|"startService(ACTION_CONNECT)"| CON
    MA -->|"startService(ACTION_DISCONNECT)"| DIS
    CON -->|"JNI nativeStart"| RUN
    NCB -->|"nativeReconnect()"| RUN
    RUN -->|"JNI: protect(fd)"| SVC["MyVpnService.protect()"]
    RUN -->|"JNI: onNativeState(state, msg)"| ST["lastState / lastMessage"]
    MA -->|"nativeGetStats() every 1 s"| RUN
```

| Thread | Why it exists |
|---|---|
| UI thread | Android requires UI work there; it must never block |
| service executor | connect/disconnect can block (DNS lookup, joining the native thread); one thread also serializes them so two connects never overlap |
| native tunnel thread | runs the blocking `poll()` loop of `TunnelClient` for the whole VPN lifetime |

## 3. Starting the VPN

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant MA as MainActivity
    participant SYS as Android system
    participant SVC as MyVpnService
    participant JNI as native-lib.cpp
    participant TC as TunnelClient thread
    participant S as Server
    U->>MA: tap Start VPN
    MA->>MA: save VpnSettings (SharedPreferences)
    MA->>SYS: VpnService.prepare()
    alt first time
        SYS->>U: VPN consent dialog
        U->>SYS: OK
    end
    MA->>SVC: startService(ACTION_CONNECT)
    SVC->>SVC: executor: connect()
    SVC->>SVC: resolve server name (before the VPN exists)
    SVC->>SYS: Builder: address, routes, DNS, MTU, apps, establish()
    SYS-->>SVC: ParcelFileDescriptor (TUN)
    SVC->>JNI: nativeStart(detachFd(), server, port, token, mtu, ipv4, ipv6)
    JNI->>JNI: NewGlobalRef(service), look up protect and onNativeState
    JNI->>TC: std::thread, AttachCurrentThread
    TC->>SVC: protect(socket) via JNI
    TC->>S: connect, HELLO
    S-->>TC: HELLO_ACK
    TC->>SVC: onNativeState(CONNECTED, "connected to ...")
    loop every second
        MA->>SVC: stats(), nativeGetStats(handle)
    end
```

Details worth knowing:

* **The server name is resolved before `establish()`**. Once the VPN is up, DNS goes into the tunnel,
  which is not connected yet.
* **`detachFd()`** transfers ownership of the TUN fd to native code; `TunnelClient::run()` closes it
  when it ends, which tears the VPN interface down.
* **JNI threads**: a native thread must `AttachCurrentThread()` before calling Java and
  `DetachCurrentThread()` before it ends. The service object is kept as a **global reference** because
  local references are only valid during one JNI call.
* `onNativeState` is called on the tunnel thread, so it only stores two volatile fields; the UI reads
  them once per second.

## 4. Inside TunnelClient::run_session()

```mermaid
flowchart TD
    S(["connected socket"]) --> HELLO["queue HELLO frame"]
    HELLO --> POLL["poll(): socket (IN, OUT if data queued),<br/>wake pipe, TUN (IN only if authenticated<br/>and out buffer < 4 MB), timeout 1 s"]
    POLL --> WAKE{"wake pipe?"}
    WAKE -->|"stop()"| STOP(["SessionEnd::Stopped"])
    WAKE -->|"reconnect()"| NETCH(["SessionEnd::NetworkChanged"])
    WAKE -->|"no"| RX{"socket readable?"}
    RX -->|"yes"| READ["up to 16 x recv(64 KB),<br/>process complete frames:<br/>PACKET: write(tun)<br/>PING: queue PONG<br/>HELLO_ACK: Connected<br/>ERROR: end session"]
    READ --> PUMP1["between reads: pump_tun(64)<br/>(the kernel generates ACKs<br/>for the packets we wrote)"]
    PUMP1 --> TX
    RX -->|"no"| TX{"TUN readable?"}
    TX -->|"yes"| PUMP2["pump_tun(256): read packets,<br/>append PACKET frames"]
    TX -->|"no"| TIMERS
    PUMP2 --> TIMERS["timers: HELLO timeout,<br/>PING every 15 s,<br/>keepalive timeout 45 s"]
    TIMERS --> FLUSH["flush(): send() queued frames<br/>until EAGAIN"]
    FLUSH --> POLL
```

Why work in small batches and alternate between directions? Writing many packets into the TUN makes
the phone's kernel produce ACKs right away. If we did not read them out of the TUN in between, its
transmit queue (500 packets on Linux/Android) would overflow and packets would be lost, which TCP
would interpret as congestion.

## 5. Network changes

```mermaid
sequenceDiagram
    participant NET as ConnectivityManager
    participant SVC as MyVpnService
    participant TC as TunnelClient
    participant S as Server
    Note over TC,S: tunnel over Wi-Fi
    NET->>SVC: onAvailable(mobile network), a different default network
    SVC->>TC: nativeReconnect() writes to the wake pipe
    TC->>TC: run_session() returns NetworkChanged
    TC->>S: new socket, protect(), connect over mobile data
    TC->>S: HELLO
    S-->>TC: HELLO_ACK, a new session
    Note over TC: apps keep their TUN, but their old TCP<br/>connections were bound to the old session<br/>and get RST, apps reconnect
```

Without this callback the client would only notice the dead Wi-Fi connection after the 45 s keepalive
timeout.

## 6. VpnService.Builder settings

| Builder call | Value | Why |
|---|---|---|
| `addAddress` | `172.19.0.2/24`, `fd00:5356::2/64` | the phone's addresses inside the VPN (private ranges) |
| `addRoute` | `0.0.0.0/0`, `::/0` | send all traffic into the VPN |
| `addDnsServer` | setting (default `8.8.8.8`) | DNS queries go through the tunnel to this server |
| `setMtu` | setting (default 1500) | largest packet the TUN delivers; also sent in HELLO |
| `setBlocking(false)` | | the native loop uses `poll()` and non-blocking reads |
| `addDisallowedApplication` / `addAllowedApplication` | own package / "Only these apps" | avoid the routing loop; per-app VPN |
| `setMetered(false)` | Android 10+ | do not make apps think they are on a metered network |
| `setConfigureIntent` | MainActivity | opens the app from the system VPN notification |

Always-on VPN works too: the system starts the service with the `android.net.VpnService` action, which
`onStartCommand` treats like `ACTION_CONNECT`. `onRevoke()` is called when another VPN takes over or
the user disconnects in the system settings.

## 7. Debug automation hook

Debug builds accept commands through an activity intent, which `tests/device_test.sh` uses:

```bash
adb shell am start -n com.kingo132.simplevpn/.MainActivity --es vpn_action connect \
    --es server 192.168.1.10 --ei port 9443 --es token secret [--es dns 8.8.8.8] [--ez ipv6 false]
adb shell am start -n com.kingo132.simplevpn/.MainActivity --es vpn_action disconnect
```

Release builds ignore it (`FLAG_DEBUGGABLE` check), so another app cannot redirect the VPN to its own
server.

## 8. Native build notes

* `client/app/src/main/cpp/CMakeLists.txt` builds `libsimplevpn.so` from `native-lib.cpp`,
  `tunnel_client.cpp` and the shared `common/tunnel_protocol.h`.
* `-Wl,-z,max-page-size=16384` aligns the ELF segments to 16 KB, required for devices with 16 KB memory
  pages (Android 15+); such a library still works on 4 KB devices.
* The same `tunnel_client.cpp` is compiled into `tools/linux_client` (with a Linux TUN device) and into
  the host JNI test (`tests/jni_test.sh`), so most client logic can be tested without a phone.
