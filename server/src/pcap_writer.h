// Minimal pcap file writer (LINKTYPE_RAW: every record is an IPv4/IPv6 packet).
// Open the files with Wireshark / tcpdump -r to study the captured traffic.
#ifndef SIMPLEVPN_PCAP_WRITER_H
#define SIMPLEVPN_PCAP_WRITER_H

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>

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

} // namespace vpn

#endif // SIMPLEVPN_PCAP_WRITER_H
