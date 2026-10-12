/**
 * @file pcap_writer.h
 * @brief Minimal pcap file writer and live pcap stream for Wireshark.
 *
 * Minimal pcap file writer (LINKTYPE_RAW: every record is an IPv4/IPv6 packet).
 * Open the files with Wireshark / tcpdump -r to study the captured traffic.
 *
 * The classic libpcap file format is tiny: one 24 byte global header
 * (magic number, version, snapshot length, link type) followed by one record
 * per packet, each a 16 byte record header (timestamp, captured length,
 * original length) plus the packet bytes. The link type tells the reader
 * what the bytes start with; LINKTYPE_RAW (101) means "a raw IP packet, no
 * Ethernet header", which is exactly what a TUN device carries. Wireshark
 * then dissects IP, TCP, TLS, DNS ... as usual.
 *
 * Two outputs use the same format:
 *  - PcapWriter: one file per session (vpn_pcap_dir, size limit
 *    vpn_pcap_max_mb), owned by the Session.
 *  - LiveCapture: a pcap byte stream sent to every client of the capture
 *    port (vpn_capture_port, 9444 on 127.0.0.1 by default), e.g. for
 *    tools/wireshark_live.sh.
 * Both see the packets exactly as the phone sends / receives them: the
 * session records incoming packets before parsing them and outgoing packets
 * before they are fragmented for the TUN MTU.
 *
 * Reading guide: the header structs and make_record_header() in
 * pcap_writer.cpp first, then PcapWriter, then LiveCapture.
 * See docs/en/inspector-and-capture.md for diagrams of both capture paths.
 */
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

/**
 * @brief Writes packets to a pcap file, with an optional size limit.
 *
 * Owned by one Session and therefore used by one worker thread only (no
 * locking). Non-copyable because it owns a FILE handle.
 */
class PcapWriter {
public:
    PcapWriter() = default;
    ~PcapWriter() { close(); } // closing flushes stdio's buffer to disk
    PcapWriter(const PcapWriter&) = delete;
    PcapWriter& operator=(const PcapWriter&) = delete;

    /**
     * @brief Create (truncate) `path` and write the pcap global header.
     *
     * A previously open file is closed first.
     * @param path      File to create, e.g. "./pcap/session-3-20240101-120000.pcap".
     * @param max_bytes Stop capturing once the file would exceed this size; 0 = no limit.
     * @return false if the file cannot be created (an error is logged).
     */
    bool open(const std::string& path, size_t max_bytes);
    /**
     * @brief Append one packet as a pcap record, timestamped now.
     *
     * Does nothing when no file is open. When the size limit would be
     * exceeded the file is closed and capturing stops for this session.
     * @param packet Raw IP packet.
     * @param len    Packet length.
     */
    void write(const uint8_t* packet, size_t len);
    /**
     * @brief Push buffered records to the file.
     *
     * The session calls it once per second so the file can be opened or
     * followed while the session is still running.
     */
    void flush();
    /** @brief Close the file (idempotent). */
    void close();
    /** @return true while a file is open (false after the size limit was hit). */
    bool is_open() const { return file_ != nullptr; }
    /** @return Path given to the last successful open(). */
    const std::string& path() const { return path_; }

private:
    FILE* file_ = nullptr;   // open file, nullptr when closed
    std::string path_;       // file name, for log messages
    size_t written_ = 0;     // bytes written so far (headers included)
    size_t max_bytes_ = 0;   // size limit, 0 = unlimited
};

/**
 * @brief Live capture: streams all packets of all sessions to the clients
 *        of the capture port.
 *
 * Every connected client of the capture port (vpn_capture_port) receives a
 * pcap stream of all packets of all sessions, e.g.
 *   nc 127.0.0.1 9444 | wireshark -k -i -
 * ("-i -" reads a capture from stdin, "-k" starts capturing immediately.)
 * The stream is the same byte sequence as a pcap file: the global header once,
 * then one record per packet.
 *
 * Thread safe: packets are published from every worker thread, while
 * subscribers come and go on the worker that owns their connection.
 */
class LiveCapture {
public:
    /**
     * @brief Register a newly connected capture client.
     *
     * A capture client connected: send it the pcap file header first, so
     * the stream it receives is a valid pcap file from the first byte.
     * @param si Connection of the client (a copy is kept for srv_send()).
     */
    void add_subscriber(const SocketInfo& si);
    /**
     * @brief Forget a capture client whose connection closed.
     * @param conn_id SocketInfo::conn_id of the closed connection.
     */
    void remove_subscriber(uint64_t conn_id);
    /**
     * @brief Send one packet as a pcap record to every subscriber.
     *
     * Cheap when nobody is listening (one atomic load), which is the normal case.
     * @param packet Raw IP packet.
     * @param len    Packet length.
     */
    void publish(const uint8_t* packet, size_t len);
    /** @return true if at least one capture client is connected (lock free check). */
    bool active() const { return count_.load(std::memory_order_relaxed) > 0; }

private:
    std::mutex mutex_;                   // guards subscribers_ and the order of sends
    std::vector<SocketInfo> subscribers_; // connected capture clients
    std::atomic<int> count_{0};          // subscribers_.size(), readable without the mutex
};

/** @brief Process wide live capture, shared by all worker threads. */
extern LiveCapture g_live_capture;

} // namespace vpn

#endif // SIMPLEVPN_PCAP_WRITER_H
