#include "pcap_writer.h"

#include <sys/time.h>

#include "server_api.h"

namespace vpn {

namespace {
struct PcapGlobalHeader {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct PcapRecordHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

constexpr uint32_t kLinkTypeRaw = 101;
} // namespace

bool PcapWriter::open(const std::string& path, size_t max_bytes) {
    close();
    file_ = fopen(path.c_str(), "wb");
    if (file_ == nullptr) {
        LOG_ERR("Failed to create pcap file %s", path.c_str());
        return false;
    }
    PcapGlobalHeader header = {0xa1b2c3d4, 2, 4, 0, 0, 65535, kLinkTypeRaw};
    fwrite(&header, sizeof(header), 1, file_);
    path_ = path;
    written_ = sizeof(header);
    max_bytes_ = max_bytes;
    return true;
}

void PcapWriter::write(const uint8_t* packet, size_t len) {
    if (file_ == nullptr) {
        return;
    }
    if (max_bytes_ > 0 && written_ + len + sizeof(PcapRecordHeader) > max_bytes_) {
        LOG_NOTICE("pcap file %s reached its size limit, capture stopped", path_.c_str());
        close();
        return;
    }
    timeval tv;
    gettimeofday(&tv, nullptr);
    PcapRecordHeader rec;
    rec.ts_sec = static_cast<uint32_t>(tv.tv_sec);
    rec.ts_usec = static_cast<uint32_t>(tv.tv_usec);
    rec.incl_len = static_cast<uint32_t>(len > 65535 ? 65535 : len);
    rec.orig_len = static_cast<uint32_t>(len);
    fwrite(&rec, sizeof(rec), 1, file_);
    fwrite(packet, 1, rec.incl_len, file_);
    written_ += sizeof(rec) + rec.incl_len;
}

void PcapWriter::flush() {
    if (file_ != nullptr) {
        fflush(file_);
    }
}

void PcapWriter::close() {
    if (file_ != nullptr) {
        fclose(file_);
        file_ = nullptr;
    }
}

} // namespace vpn
