/**
 * @file pcap_writer.cpp
 * @brief pcap file format, per session pcap files and the live capture stream.
 *
 * The format is the classic libpcap one (not pcapng); see
 * https://wiki.wireshark.org/Development/LibpcapFileFormat and pcap_writer.h
 * for the overview. The headers are written with the host's byte order:
 * readers recognize the order from how the magic number appears in the file
 * (a1 b2 c3 d4 or d4 c3 b2 a1) and swap the fields if necessary.
 *
 * Reading guide: PcapGlobalHeader / PcapRecordHeader and make_record_header()
 * first, then PcapWriter (files), then LiveCapture (TCP stream).
 */
#include "pcap_writer.h"

#include <sys/time.h>

#include "server_api.h"

namespace vpn {

namespace {
/**
 * @brief pcap global (file) header, 24 bytes, written once at the start.
 *
 * All members are naturally aligned (4 + 2 + 2 + 4 * 4), so the struct has
 * no padding and can be written to the file as is.
 */
struct PcapGlobalHeader {
    uint32_t magic;          // 0xa1b2c3d4: pcap with microsecond timestamps; also reveals the byte order
    uint16_t version_major;  // 2 (format version 2.4)
    uint16_t version_minor;  // 4
    int32_t thiszone;        // GMT offset of the timestamps in seconds; 0 = timestamps are UTC
    uint32_t sigfigs;        // timestamp accuracy; always 0 in practice
    uint32_t snaplen;        // maximum bytes stored per packet
    uint32_t network;        // link type of every record (LINKTYPE_*)
};

/**
 * @brief pcap record header, 16 bytes, precedes every packet.
 */
struct PcapRecordHeader {
    uint32_t ts_sec;   // capture time, seconds since the Unix epoch (UTC)
    uint32_t ts_usec;  // microseconds part of the capture time
    uint32_t incl_len; // bytes of the packet stored in the file (<= snaplen)
    uint32_t orig_len; // real length of the packet (larger than incl_len if it was cut)
};

// LINKTYPE_RAW: the record starts directly with an IPv4 or IPv6 header (the
// version nibble tells which). This is the "file" value; the DLT_RAW value of
// the libpcap API differs between operating systems (12 or 14), 101 does not.
constexpr uint32_t kLinkTypeRaw = 101;

// The global header is the same for every file and stream: microsecond
// magic, version 2.4, UTC, snaplen 65535 (the IPv4 maximum packet size), raw IP.
const PcapGlobalHeader kGlobalHeader = {0xa1b2c3d4, 2, 4, 0, 0, 65535, kLinkTypeRaw};

/**
 * @brief Make the record header for a packet captured now.
 *
 * Timestamps come from gettimeofday() (wall clock, microsecond resolution),
 * which is what the 0xa1b2c3d4 magic promises.
 * @param len Packet length.
 * @return Record header; incl_len is limited to the snaplen (65535).
 */
PcapRecordHeader make_record_header(size_t len) {
    timeval tv;
    gettimeofday(&tv, nullptr);
    PcapRecordHeader rec;
    rec.ts_sec = static_cast<uint32_t>(tv.tv_sec);   // 32 bit seconds: fine until the year 2106
    rec.ts_usec = static_cast<uint32_t>(tv.tv_usec);
    rec.incl_len = static_cast<uint32_t>(len > 65535 ? 65535 : len); // never store more than snaplen
    rec.orig_len = static_cast<uint32_t>(len);
    return rec;
}
} // namespace

LiveCapture g_live_capture; // process wide instance (see pcap_writer.h)

/**
 * @brief Create the file and write the global header (see pcap_writer.h).
 * @param path      File to create.
 * @param max_bytes Size limit, 0 = none.
 * @return true if the file is open.
 */
bool PcapWriter::open(const std::string& path, size_t max_bytes) {
    close();
    file_ = fopen(path.c_str(), "wb"); // binary mode, truncate an existing file
    if (file_ == nullptr) {
        LOG_ERR("Failed to create pcap file %s", path.c_str());
        return false;
    }
    fwrite(&kGlobalHeader, sizeof(kGlobalHeader), 1, file_);
    path_ = path;
    written_ = sizeof(kGlobalHeader);
    max_bytes_ = max_bytes;
    return true;
}

/**
 * @brief Append one record (see pcap_writer.h).
 *
 * Writes go through stdio's buffer; flush() / close() push them to disk.
 * @param packet Raw IP packet.
 * @param len    Packet length.
 */
void PcapWriter::write(const uint8_t* packet, size_t len) {
    if (file_ == nullptr) {
        return; // no pcap_dir configured, open failed, or the limit was reached
    }
    // Stop before the limit instead of cutting a record in half: the file stays valid
    if (max_bytes_ > 0 && written_ + len + sizeof(PcapRecordHeader) > max_bytes_) {
        LOG_NOTICE("pcap file %s reached its size limit, capture stopped", path_.c_str());
        close();
        return;
    }
    PcapRecordHeader rec = make_record_header(len);
    fwrite(&rec, sizeof(rec), 1, file_);
    fwrite(packet, 1, rec.incl_len, file_); // incl_len, not len: at most snaplen bytes
    written_ += sizeof(rec) + rec.incl_len;
}

/** @brief Flush stdio's buffer so readers of the file see all records so far. */
void PcapWriter::flush() {
    if (file_ != nullptr) {
        fflush(file_);
    }
}

/** @brief Close the file if open; safe to call repeatedly. */
void PcapWriter::close() {
    if (file_ != nullptr) {
        fclose(file_);
        file_ = nullptr;
    }
}

/**
 * @brief Send the global header to a new capture client and register it.
 *
 * The header is sent while holding the mutex, before the client is added to
 * the list, and publish() also sends under the mutex: so no packet record can
 * reach the client before the header.
 * @param si The capture client's connection.
 */
void LiveCapture::add_subscriber(const SocketInfo& si) {
    std::lock_guard<std::mutex> lock(mutex_);
    srv_send(&si, &kGlobalHeader, sizeof(kGlobalHeader));
    subscribers_.push_back(si);
    count_.store(static_cast<int>(subscribers_.size())); // lets active() skip the lock
}

/**
 * @brief Remove a capture client by connection id.
 * @param conn_id Unique id of the closed connection (fds can be reused, ids cannot).
 */
void LiveCapture::remove_subscriber(uint64_t conn_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (size_t i = 0; i < subscribers_.size(); ++i) {
        if (subscribers_[i].conn_id == conn_id) {
            subscribers_.erase(subscribers_.begin() + static_cast<long>(i));
            break;
        }
    }
    count_.store(static_cast<int>(subscribers_.size()));
}

/**
 * @brief Send one packet record to all capture clients.
 *
 * The relaxed active() check is only a fast path: a client that connects
 * at the same moment may miss a packet, which is harmless.
 * srv_send() only queues the data in the reactor; it never blocks the
 * worker thread on a slow viewer.
 * @param packet Raw IP packet.
 * @param len    Packet length.
 */
void LiveCapture::publish(const uint8_t* packet, size_t len) {
    if (!active()) {
        return;
    }
    // One record per message: if a slow viewer's buffer overflows, the server
    // drops whole messages (send_overflow_policy = drop) and the stream stays valid
    PcapRecordHeader rec = make_record_header(len);
    // Build header + data in one buffer outside the lock, so it is one srv_send() message
    std::string record(reinterpret_cast<const char*>(&rec), sizeof(rec));
    record.append(reinterpret_cast<const char*>(packet), rec.incl_len);
    std::lock_guard<std::mutex> lock(mutex_);
    for (const SocketInfo& si : subscribers_) {
        srv_send(&si, record.data(), static_cast<int>(record.size()));
    }
}

} // namespace vpn
