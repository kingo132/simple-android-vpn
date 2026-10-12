// Linux command line VPN client: the same tunnel core as the Android app,
// attached to a Linux TUN device. Used for end-to-end tests (tests/e2e_test.sh)
// and for debugging the server without a phone.
//
//   simplevpn-client -s SERVER [-p PORT] [-t TOKEN] [-d tun0] [-m 1500]
//                    [--ipv4 172.19.0.2/24] [--ipv6 fd00:5356::2/64]
//
// The device is created and given the addresses; routing is left to you,
// e.g. "ip route add 1.2.3.0/24 dev tun0" (keep the route to the server
// itself on the physical interface).
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

simplevpn::TunnelClient* g_client = nullptr;
int g_verbose = 0;

void on_signal(int) {
    if (g_client != nullptr) {
        g_client->stop();
    }
}

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
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        perror("ioctl TUNSETIFF");
        close(fd);
        return -1;
    }
    name = ifr.ifr_name;
    return fd;
}

bool run_cmd(const std::string& cmd) {
    if (g_verbose) {
        std::fprintf(stderr, "+ %s\n", cmd.c_str());
    }
    return std::system(cmd.c_str()) == 0;
}

void usage(const char* prog) {
    std::fprintf(stderr,
                 "Usage: %s -s SERVER [-p PORT] [-t TOKEN] [-d DEVICE] [-m MTU] [--ipv4 ADDR/PREFIX] "
                 "[--ipv6 ADDR/PREFIX] [-v]\n",
                 prog);
}

} // namespace

int main(int argc, char** argv) {
    std::string server;
    int port = 9443;
    std::string token;
    std::string device = "tun0";
    int mtu = 1500;
    std::string ipv4 = "172.19.0.2/24";
    std::string ipv6;

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
        default: usage(argv[0]); return 1;
        }
    }
    if (server.empty()) {
        usage(argv[0]);
        return 1;
    }

    int tun_fd = open_tun(device);
    if (tun_fd < 0) {
        return 1;
    }
    run_cmd("ip link set dev " + device + " mtu " + std::to_string(mtu) + " up");
    if (!ipv4.empty()) {
        run_cmd("ip addr add " + ipv4 + " dev " + device);
    }
    if (!ipv6.empty()) {
        run_cmd("ip -6 addr add " + ipv6 + " dev " + device + " nodad");
    }
    std::fprintf(stderr, "TUN device %s ready\n", device.c_str());

    simplevpn::TunnelClientConfig config;
    config.server_host = server;
    config.server_port = static_cast<uint16_t>(port);
    config.token = token;
    config.tun_fd = tun_fd;
    config.mtu = mtu;
    config.client_name = "linux-client";
    config.tun_ipv4 = ipv4;
    config.tun_ipv6 = ipv6;
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
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    signal(SIGPIPE, SIG_IGN);

    client.run();
    g_client = nullptr;

    const simplevpn::TunnelStats& s = client.stats();
    std::fprintf(stderr, "tx %llu packets / %llu bytes, rx %llu packets / %llu bytes, dropped %llu, reconnects %llu\n",
                 static_cast<unsigned long long>(s.tx_packets.load()),
                 static_cast<unsigned long long>(s.tx_bytes.load()),
                 static_cast<unsigned long long>(s.rx_packets.load()),
                 static_cast<unsigned long long>(s.rx_bytes.load()), static_cast<unsigned long long>(s.dropped.load()),
                 static_cast<unsigned long long>(s.reconnects.load()));
    return 0;
}
