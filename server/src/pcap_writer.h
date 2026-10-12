// Minimal pcap file writer (LINKTYPE_RAW: every record is an IPv4/IPv6 packet).
// Open the files with Wireshark / tcpdump -r to study the captured traffic.
#ifndef SIMPLEVPN_PCAP_WRITER_H
#define SIMPLEVPN_PCAP_WRITER_H

#include <cstddef>
#include <cstdint>
#include <atomic>
#include <cstdio>
#include <mutex>
#include <string>
#include <vector>

#include "server_api.h"

namespace vpn {

class PcapWriter {
public:
    PcapWriter() = default;
    ~PcapWriter() { close(); }
    PcapWriter(const PcapWriter&) = delete;
    PcapWriter& operator=(const PcapWriter&) = delete;

    bool open(const std::string& path, size_t max_bytes);
    void write(const uint8_t* packet, size_t len);
    void flush();
    void close();
    bool is_open() const { return file_ != nullptr; }
    const std::string& path() const { return path_; }

private:
    FILE* file_ = nullptr;
    std::string path_;
    size_t written_ = 0;
    size_t max_bytes_ = 0;
};

// Live capture: every connected client of the capture port (vpn_capture_port)
// receives a pcap stream of all packets of all sessions, e.g.
//   nc 127.0.0.1 9444 | wireshark -k -i -
// Thread safe: packets are published from every worker thread.
class LiveCapture {
public:
    // A capture client connected: send it the pcap file header
    void add_subscriber(const SocketInfo& si);
    void remove_subscriber(uint64_t conn_id);
    void publish(const uint8_t* packet, size_t len);
    bool active() const { return count_.load(std::memory_order_relaxed) > 0; }

private:
    std::mutex mutex_;
    std::vector<SocketInfo> subscribers_;
    std::atomic<int> count_{0};
};

extern LiveCapture g_live_capture;

} // namespace vpn

#endif // SIMPLEVPN_PCAP_WRITER_H
