#!/usr/bin/env python3
"""Target services for the end-to-end test, run inside the "internet" namespace.

  TCP 8080  HTTP (static files from the given directory)
  TCP 7     echo (echoes until the client half-closes, then closes)
  UDP 7     echo
  UDP 9     answers every datagram with an empty datagram
  UDP 53    DNS: answers A 1.2.3.4 / AAAA 2001:db8::1234 for every name
  TCP 25    "server speaks first": sends a banner, then echoes lines
"""
import http.server
import os
import socket
import socketserver
import struct
import sys
import threading


HAVE_V6 = socket.has_ipv6 and os.path.isdir("/proc/sys/net/ipv6")
ANY = "::" if HAVE_V6 else "0.0.0.0"


def dual_stack(sock_type):
    """IPv6 socket that also accepts IPv4, or plain IPv4 without kernel IPv6 support"""
    if HAVE_V6:
        s = socket.socket(socket.AF_INET6, sock_type)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    else:
        s = socket.socket(socket.AF_INET, sock_type)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return s


class DualStackHTTPServer(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6 if HAVE_V6 else socket.AF_INET

    def server_bind(self):
        if HAVE_V6:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        remaining = length
        h = __import__("hashlib").sha256()
        while remaining > 0:
            chunk = self.rfile.read(min(65536, remaining))
            if not chunk:
                break
            h.update(chunk)
            remaining -= len(chunk)
        body = (h.hexdigest() + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve_http(directory):
    handler = lambda *a, **kw: QuietHandler(*a, directory=directory, **kw)
    DualStackHTTPServer((ANY, 8080), handler).serve_forever()


def tcp_echo_conn(conn):
    with conn:
        while True:
            data = conn.recv(65536)
            if not data:
                break
            conn.sendall(data)
        conn.shutdown(socket.SHUT_WR)


def serve_tcp_echo():
    s = dual_stack(socket.SOCK_STREAM)
    s.bind((ANY, 7))
    s.listen(128)
    while True:
        conn, _ = s.accept()
        threading.Thread(target=tcp_echo_conn, args=(conn,), daemon=True).start()


def banner_conn(conn):
    with conn:
        conn.sendall(b"220 banner.test ESMTP ready\r\n")
        f = conn.makefile("rb")
        for line in f:
            if line.strip().upper() == b"QUIT":
                conn.sendall(b"221 bye\r\n")
                break
            conn.sendall(b"250 " + line)


def serve_banner():
    s = dual_stack(socket.SOCK_STREAM)
    s.bind((ANY, 25))
    s.listen(16)
    while True:
        conn, _ = s.accept()
        threading.Thread(target=banner_conn, args=(conn,), daemon=True).start()


def serve_udp_echo():
    s = dual_stack(socket.SOCK_DGRAM)
    s.bind((ANY, 7))
    while True:
        data, addr = s.recvfrom(65535)
        s.sendto(data, addr)


def serve_udp_empty():
    s = dual_stack(socket.SOCK_DGRAM)
    s.bind((ANY, 9))
    while True:
        _, addr = s.recvfrom(65535)
        s.sendto(b"", addr)


def dns_answer(query):
    if len(query) < 12:
        return None
    qid, flags, qd = struct.unpack("!HHH", query[:6])
    pos = 12
    while pos < len(query) and query[pos] != 0:
        pos += query[pos] + 1
    qtype = struct.unpack("!H", query[pos + 1:pos + 3])[0]
    question = query[12:pos + 5]
    header = struct.pack("!HHHHHH", qid, 0x8180, 1, 1 if qtype in (1, 28) else 0, 0, 0)
    answer = b""
    if qtype == 1:
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("1.2.3.4")
    elif qtype == 28:
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 60, 16) + socket.inet_pton(socket.AF_INET6, "2001:db8::1234")
    return header + question + answer


def serve_dns():
    s = dual_stack(socket.SOCK_DGRAM)
    s.bind((ANY, 53))
    while True:
        data, addr = s.recvfrom(4096)
        reply = dns_answer(data)
        if reply:
            s.sendto(reply, addr)


def main():
    directory = sys.argv[1]
    for target, args in ((serve_http, (directory,)), (serve_tcp_echo, ()), (serve_udp_echo, ()),
                         (serve_udp_empty, ()), (serve_dns, ()), (serve_banner, ())):
        threading.Thread(target=target, args=args, daemon=True).start()
    print("services ready", flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
