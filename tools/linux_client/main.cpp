/**
 * @file main.cpp
 * @brief Linux command line VPN client: the same tunnel core as the Android
 *        app (TunnelClient), attached to a Linux TUN device.
 *
 * Used for end-to-end tests (tests/e2e_test.sh) and for debugging the server
 * without a phone.
 *
 *   simplevpn-client -s SERVER [-p PORT] [-t TOKEN] [-d tun0] [-m 1500]
 *                    [--ipv4 172.19.0.2/24] [--ipv6 fd00:5356::2/64]
 *
 * The device is created and given the addresses; routing is left to you,
 * e.g. "ip route add 1.2.3.0/24 dev tun0" (keep the route to the server
 * itself on the physical interface).
 *
 * What it replaces from the Android app: VpnService.Builder becomes
 * open_tun() plus a few "ip" commands, and VpnService.protect() is not
 * needed because the routes are under your control (no protect_socket
 * callback is set). Needs root (or CAP_NET_ADMIN) for /dev/net/tun and "ip".
 *
 * Reading guide: main() parses options, opens and configures the TUN device,
 * builds a TunnelClientConfig and calls TunnelClient::run() on the main
 * thread until SIGINT / SIGTERM.
 */
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <getopt.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <string>
#include <sys/ioctl.h>
#include <thread>
#include <unistd.h>

#include "tunnel_client.h"

namespace {

simplevpn::TunnelClient* g_client = nullptr; // for the signal handler; set while run() executes
int g_verbose = 0;                           // -v count: print commands and debug log lines

/**
 * @brief SIGINT / SIGTERM handler: ask the tunnel to stop.
 *
 * TunnelClient::stop() only sets an atomic flag and writes to a pipe, both
 * async-signal-safe, so it may be called from a signal handler.
 */
void on_signal(int) {
    if (g_client != nullptr) {
        g_client->stop();
    }
}

/**
 * @brief Create (or attach to) a TUN device.
 *
 * IFF_TUN = layer 3 device (IP packets, not Ethernet frames); IFF_NO_PI =
 * no 4-byte packet information prefix, so each read()/write() is exactly
 * one raw IP packet, the same format Android's TUN fd uses.
 *
 * @param name In: requested device name (e.g. "tun0"; "tun%d" lets the
 *             kernel pick). Out: the name the kernel actually used.
 * @return The TUN file descriptor, or -1 (error printed).
 */
int open_tun(std::string& name) {
    int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        perror("open /dev/net/tun");
        return -1;
    }
    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name.c_str());
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) { // binds this fd to the (new) interface
        perror("ioctl TUNSETIFF");
        close(fd);
        return -1;
    }
    name = ifr.ifr_name;
    return fd;
}

/**
 * @brief Run a shell command (used for the "ip" configuration commands).
 * @param cmd Command line, passed to /bin/sh.
 * @return true if it exited with status 0.
 */
bool run_cmd(const std::string& cmd) {
    if (g_verbose) {
        std::fprintf(stderr, "+ %s\n", cmd.c_str());
    }
    return std::system(cmd.c_str()) == 0;
}

/**
 * @brief Print the command line syntax.
 * @param prog argv[0].
 */
void usage(const char* prog) {
    std::fprintf(stderr,
                 "Usage: %s -s SERVER [-p PORT] [-t TOKEN] [-d DEVICE] [-m MTU] [--ipv4 ADDR/PREFIX] "
                 "[--ipv6 ADDR/PREFIX] [-v]\n",
                 prog);
}

} // namespace

/**
 * @brief Parse options, set up the TUN device, run the tunnel until a signal.
 * @return 0 after a normal stop, 1 on bad usage or if the TUN device cannot be opened.
 */
int main(int argc, char** argv) {
    // Defaults; an empty ipv4 / ipv6 means "do not configure that address"
    std::string server;
    int port = 9443;
    std::string token;
    std::string device = "tun0";
    int mtu = 1500;
    std::string ipv4 = "172.19.0.2/24";
    std::string ipv6;

    // Long options without a short form get the pseudo letters '4' and '6'
    static option long_options[] = {{"ipv4", required_argument, nullptr, '4'},
                                    {"ipv6", required_argument, nullptr, '6'},
                                    {nullptr, 0, nullptr, 0}};
    int opt;
    while ((opt = getopt_long(argc, argv, "s:p:t:d:m:vh", long_options, nullptr)) != -1) {
        switch (opt) {
        case 's': server = optarg; break;
        case 'p': port = std::atoi(optarg); break;
        case 't': token = optarg; break;
        case 'd': device = optarg; break;
        case 'm': mtu = std::atoi(optarg); break;
        case '4': ipv4 = optarg; break;
        case '6': ipv6 = optarg; break;
        case 'v': ++g_verbose; break;
        default: usage(argv[0]); return 1; // includes -h
        }
    }
    if (server.empty()) {
        usage(argv[0]);
        return 1;
    }

    // The equivalent of VpnService.Builder.setMtu / addAddress / establish()
    int tun_fd = open_tun(device);
    if (tun_fd < 0) {
        return 1;
    }
    run_cmd("ip link set dev " + device + " mtu " + std::to_string(mtu) + " up");
    if (!ipv4.empty()) {
        run_cmd("ip addr add " + ipv4 + " dev " + device);
    }
    if (!ipv6.empty()) {
        // nodad: skip duplicate address detection, the address is usable at once
        run_cmd("ip -6 addr add " + ipv6 + " dev " + device + " nodad");
    }
    std::fprintf(stderr, "TUN device %s ready\n", device.c_str());

    simplevpn::TunnelClientConfig config;
    config.server_host = server;
    config.server_port = static_cast<uint16_t>(port);
    config.token = token;
    config.tun_fd = tun_fd; // owned by the client from now on
    config.mtu = mtu;
    config.client_name = "linux-client";
    config.tun_ipv4 = ipv4;
    config.tun_ipv6 = ipv6;
    // No protect_socket: on Linux the user keeps the route to the server outside the TUN
    config.log = [](int level, const std::string& message) {
        if (level <= simplevpn::kLogInfo || g_verbose) {
            std::fprintf(stderr, "[simplevpn] %s\n", message.c_str());
        }
    };

    simplevpn::TunnelClient client(config);
    g_client = &client;
    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, nullptr);  // Ctrl+C
    sigaction(SIGTERM, &sa, nullptr); // kill (used by the test scripts)
    signal(SIGPIPE, SIG_IGN);         // extra safety; send() already uses MSG_NOSIGNAL

    client.run(); // blocks; reconnects by itself until stop()
    g_client = nullptr;

    // Final counters
    const simplevpn::TunnelStats& s = client.stats();
    std::fprintf(stderr, "tx %llu packets / %llu bytes, rx %llu packets / %llu bytes, dropped %llu, reconnects %llu\n",
                 static_cast<unsigned long long>(s.tx_packets.load()),
                 static_cast<unsigned long long>(s.tx_bytes.load()),
                 static_cast<unsigned long long>(s.rx_packets.load()),
                 static_cast<unsigned long long>(s.rx_bytes.load()), static_cast<unsigned long long>(s.dropped.load()),
                 static_cast<unsigned long long>(s.reconnects.load()));
    return 0;
}
