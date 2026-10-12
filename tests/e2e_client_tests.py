#!/usr/bin/env python3
"""Socket level checks run inside the "phone" namespace (traffic goes through the VPN)."""
import hashlib
import os
import socket
import sys
import threading

TARGET4 = "198.51.100.10"
TARGET6 = "2001:db8:100::10"
failures = 0


def check(name, ok, detail=""):
    global failures
    print(("PASS " if ok else "FAIL ") + name + (" " + detail if detail else ""), flush=True)
    if not ok:
        failures += 1


def tcp_echo(host, size):
    """Send `size` random bytes while reading the echo, half close, compare."""
    data = os.urandom(size)
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(30)
    s.connect((host, 7))
    received = bytearray()

    def reader():
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            received.extend(chunk)

    t = threading.Thread(target=reader)
    t.start()
    s.sendall(data)
    s.shutdown(socket.SHUT_WR)  # half close: the echo server answers with FIN after the data
    t.join(60)
    s.close()
    return bytes(received) == data, len(received)


def udp_echo(host, count, size):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(2)
    ok = 0
    for i in range(count):
        payload = os.urandom(size)
        s.sendto(payload, (host, 7))
        try:
            data, _ = s.recvfrom(65535)
            ok += data == payload
        except socket.timeout:
            pass
    return ok


def udp_empty_reply(host):
    """An empty datagram from the internet must reach the phone, not be taken for EOF"""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(2)
    try:
        for _ in range(3):
            s.sendto(b"x", (host, 9))
            try:
                if s.recvfrom(65535)[0] == b"":
                    return True
            except socket.timeout:
                pass
        return False
    finally:
        s.close()


def banner(host):
    s = socket.create_connection((host, 25), timeout=10)
    f = s.makefile("rwb")
    first = f.readline()
    f.write(b"HELO phone\r\n")
    f.flush()
    second = f.readline()
    f.write(b"QUIT\r\n")
    f.flush()
    third = f.readline()
    s.close()
    return first.startswith(b"220") and second == b"250 HELO phone\r\n" and third.startswith(b"221")


def quic_rejected(host):
    """vpn_block_quic answers UDP 443 with ICMP port unreachable -> ECONNREFUSED"""
    s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.connect((host, 443))
    s.send(b"\xc0" + os.urandom(1199))
    try:
        s.recv(100)
        return False
    except ConnectionRefusedError:
        return True
    except socket.timeout:
        return False
    finally:
        s.close()


def main():
    hosts = (TARGET4, TARGET6) if os.environ.get("HAVE_V6") == "1" else (TARGET4,)
    for host in hosts:
        for size in (1, 1000, 100000, 5 * 1024 * 1024):
            ok, n = tcp_echo(host, size)
            check("tcp echo %s %d bytes" % (host, size), ok, "(got %d)" % n)
        check("udp echo %s" % host, udp_echo(host, 50, 1200) >= 48)
        check("udp echo large datagram %s" % host, udp_echo(host, 5, 8000) >= 4)
        check("udp empty datagram reply %s" % host, udp_empty_reply(host))
        check("server speaks first %s" % host, banner(host))

    check("QUIC (UDP 443) rejected with ICMP unreachable", quic_rejected(TARGET4))

    # many parallel connections
    results = []

    def worker():
        results.append(tcp_echo(TARGET4, 200000)[0])

    threads = [threading.Thread(target=worker) for _ in range(30)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    check("30 parallel echo connections", all(results) and len(results) == 30)

    # connection refused must fail fast (RST from the proxy)
    try:
        socket.create_connection((TARGET4, 9), timeout=5)
        check("connection refused", False)
    except ConnectionRefusedError:
        check("connection refused", True)
    except Exception as e:  # noqa
        check("connection refused", False, repr(e))

    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
