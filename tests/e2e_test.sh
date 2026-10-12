#!/usr/bin/env bash
# End-to-end test of the whole chain on one Linux machine (needs root):
#
# Three network "machines" are simulated with network namespaces:
#   - namespace svpn_phone plays the phone: curl / dig / ping send their
#     traffic into tun0, where simplevpn-client (the app's tunnel core) picks
#     it up and tunnels it over TCP to 172.30.0.1:9443 (veth pair p0 <-> s0).
#   - the root namespace plays the VPN server: mulserver + libvpnproxy.so.
#   - namespace svpn_inet plays the internet (veth pair r0 <-> i0): target
#     services from tests/e2e_services.py on 198.51.100.10 and
#     2001:db8:100::10 (HTTP :8080, echo :7, DNS :53, banner :25).
# The phone namespace has no route to the "internet" except through the VPN,
# so every passing check proves the packets went through the tunnel.
# A diagram of the same setup is in docs/en/testing.md.
#
#   BUILD_DIR=build tests/e2e_test.sh
#
# Environment: BUILD_DIR, WORK_DIR (logs, pcap), LOG_LEVEL (server log level),
# E2E_SETUP_ONLY=1 (set everything up and leave it running),
# E2E_NO_CLIENT=1 (set up without the Linux client; used by tests/jni_test.sh),
# PARALLEL_TIMEOUT (seconds for each of the 20 parallel downloads).
# No "set -e": a failed check is reported with fail() and the run continues
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build}"
WORK="${WORK_DIR:-$(mktemp -d /tmp/svpn-e2e.XXXXXX)}"
mkdir -p "$WORK"
PHONE=svpn_phone
INET=svpn_inet
TOKEN=e2e-secret
FAILED=0

# Output helpers; fail() also marks the whole run as failed
log() { echo -e "\033[1;34m==> $*\033[0m"; }
pass() { echo -e "\033[1;32mPASS\033[0m $*"; }
fail() { echo -e "\033[1;31mFAIL\033[0m $*"; FAILED=1; }
# Run a command inside the phone / internet namespace
in_phone() { ip netns exec $PHONE "$@"; }
in_inet() { ip netns exec $INET "$@"; }

# Stop everything and remove the namespaces and veth pairs (also run at exit)
cleanup() {
    [ -n "${CLIENT_PID:-}" ] && kill "$CLIENT_PID" 2>/dev/null
    [ -n "${SERVER_PID:-}" ] && kill -INT "$SERVER_PID" 2>/dev/null
    [ -n "${SERVICES_PID:-}" ] && kill "$SERVICES_PID" 2>/dev/null
    sleep 1
    ip netns del $PHONE 2>/dev/null
    ip netns del $INET 2>/dev/null
    ip link del s0 2>/dev/null
    ip link del r0 2>/dev/null
}
trap cleanup EXIT

if [ "$(id -u)" != 0 ]; then
    echo "must run as root (network namespaces + TUN)"; exit 1
fi
for bin in "$BUILD/server/reactor/mulserver" "$BUILD/server/libvpnproxy.so" "$BUILD/tools/simplevpn-client"; do
    [ -e "$bin" ] || { echo "missing $bin, build first: cmake -B build && cmake --build build"; exit 1; }
done

# IPv6 checks only when the kernel supports IPv6; v6 <cmd> runs <cmd> only then
HAVE_V6=0
[ -d /proc/sys/net/ipv6 ] && HAVE_V6=1
[ $HAVE_V6 = 1 ] || echo "IPv6 is not available in this kernel, IPv6 checks are skipped"
v6() { [ $HAVE_V6 = 1 ] && "$@"; }

log "Network namespaces (work dir $WORK)"
cleanup 2>/dev/null
# Two veth pairs: s0 (root) <-> p0 (phone), r0 (root) <-> i0 (internet).
# The root namespace (the server) gets 172.30.0.1 towards the phone and
# 198.51.100.1 / 2001:db8:100::1 towards the internet, and acts as the
# internet's default gateway, so answers to the server's sockets come back.
ip netns add $PHONE
ip netns add $INET
ip link add s0 type veth peer name p0
ip link set p0 netns $PHONE
ip link add r0 type veth peer name i0
ip link set i0 netns $INET
ip addr add 172.30.0.1/24 dev s0 && ip link set s0 up
ip addr add 198.51.100.1/24 dev r0 && ip link set r0 up
v6 ip -6 addr add 2001:db8:100::1/64 dev r0 nodad
in_phone ip link set lo up
in_phone ip addr add 172.30.0.2/24 dev p0 && in_phone ip link set p0 up
in_inet ip link set lo up
in_inet ip addr add 198.51.100.10/24 dev i0
v6 in_inet ip -6 addr add 2001:db8:100::10/64 dev i0 nodad
in_inet ip link set i0 up
in_inet ip route add default via 198.51.100.1
v6 in_inet ip -6 route add default via 2001:db8:100::1

log "Target services"
# Files served by the HTTP target; big.bin is random, its checksum proves byte exact transfers
mkdir -p "$WORK/www"
echo "Hello SimpleVPN" > "$WORK/www/index.html"
head -c 50000000 /dev/urandom > "$WORK/www/big.bin"
BIG_SHA=$(sha256sum "$WORK/www/big.bin" | cut -d' ' -f1)
in_inet python3 -u "$ROOT/tests/e2e_services.py" "$WORK/www" > "$WORK/services.log" 2>&1 &
SERVICES_PID=$!

log "VPN server"
mkdir -p "$WORK/server/conf"
# Bind file: the tunnel port towards the phone (idle timeout 300 s) and the
# live capture port on loopback (no idle timeout)
printf "172.30.0.1 9443 tcp 300\n127.0.0.1 9444 tcp 0\n" > "$WORK/server/conf/bind.txt"
# Test config derived from server/conf/server.ini: token, log to file, pcap on,
# a blocked domain, a response rewrite rule for port 8080 and QUIC blocking
sed -e "s|^vpn_token = .*|vpn_token = $TOKEN|" \
    -e "s|^log_level = .*|log_level = ${LOG_LEVEL:-6}|" \
    -e "s|^log_dest = .*|log_dest = 2|" \
    -e "s|^bind_file = .*|bind_file = $WORK/server/conf/bind.txt|" \
    -e "s|^log_dir = .*|log_dir = $WORK/server/log|" \
    -e "s|^vpn_pcap_dir = .*|vpn_pcap_dir = $WORK/server/pcap|" \
    -e "s|^#vpn_block_domains = .*|vpn_block_domains = blocked.test|" \
    -e "s/^#vpn_rewrite_2 = .*/vpn_rewrite_2 = down|Hello SimpleVPN|Hello Rewritten/" \
    -e "s|^vpn_rewrite_ports = .*|vpn_rewrite_ports = 8080|" \
    -e "s|^vpn_block_quic = .*|vpn_block_quic = 1|" \
    "$ROOT/server/conf/server.ini" > "$WORK/server/conf/server.ini"
# Start the server in the background from its work dir (the config uses relative paths)
(cd "$WORK/server" && exec "$BUILD/server/reactor/mulserver" conf/server.ini "$BUILD/server/libvpnproxy.so" \
    > "$WORK/server/stdout.txt" 2>&1) &
SERVER_PID=$!
sleep 1
grep -q "Server started" "$WORK/server/log/server.log" || { fail "server did not start"; cat "$WORK/server/stdout.txt"; exit 1; }

# jni_test.sh mode: leave services + server running and record their pids for its cleanup
if [ -n "${E2E_NO_CLIENT:-}" ]; then
    echo "$SERVICES_PID $SERVER_PID" > "$WORK/pids"
    trap - EXIT
    echo "Setup done without client (server pid $SERVER_PID)"
    exit 0
fi

log "VPN client in the phone namespace"
V6_ARG=""
[ $HAVE_V6 = 1 ] && V6_ARG="--ipv6 fd00:5356::2/64"
in_phone "$BUILD/tools/simplevpn-client" -s 172.30.0.1 -p 9443 -t $TOKEN -d tun0 \
    --ipv4 172.19.0.2/24 $V6_ARG > "$WORK/client.log" 2>&1 &
CLIENT_PID=$!
# Wait up to 5 s for the HELLO / HELLO_ACK handshake ("connected to ..." in the client log)
for _ in $(seq 50); do grep -q "connected to" "$WORK/client.log" && break; sleep 0.1; done
grep -q "connected to" "$WORK/client.log" || { fail "client did not connect"; cat "$WORK/client.log"; exit 1; }
# Like Android: everything goes into the VPN, except the tunnel itself (172.30.0.0/24 stays on p0)
in_phone ip route add default dev tun0
v6 in_phone ip -6 route add default dev tun0
pass "tunnel established"

if [ -n "${E2E_SETUP_ONLY:-}" ]; then
    trap - EXIT
    echo "Setup done, environment left running. Try: ip netns exec $PHONE curl http://198.51.100.10:8080/"
    echo "Clean up with: ip netns del $PHONE; ip netns del $INET; kill $SERVER_PID $CLIENT_PID $SERVICES_PID"
    echo "$SERVICES_PID $SERVER_PID $CLIENT_PID" > "$WORK/pids"
    exit 0
fi

log "HTTP"
# Record the live capture stream (vpn_capture_port 9444) while the HTTP requests run
nc 127.0.0.1 9444 > "$WORK/live.pcap" &
LIVE_PID=$!
sleep 0.5
out=$(in_phone curl --noproxy '*' -s -m 10 http://198.51.100.10:8080/index.html)
[ "$out" = "Hello Rewritten" ] && pass "HTTP GET over IPv4 (response rewritten by rule)" || fail "HTTP GET got '$out'"
if [ $HAVE_V6 = 1 ]; then
    out=$(in_phone curl --noproxy '*' -s -m 10 "http://[2001:db8:100::10]:8080/index.html")
    [ "$out" = "Hello Rewritten" ] && pass "HTTP GET over IPv6" || fail "HTTP GET IPv6 got '$out'"
fi

sleep 1
kill $LIVE_PID 2>/dev/null; wait $LIVE_PID 2>/dev/null
n=$(tcpdump -nr "$WORK/live.pcap" 'tcp port 8080' 2>/dev/null | wc -l)
[ "$n" -gt 5 ] && pass "live capture stream readable by tcpdump ($n HTTP packets)" || fail "live capture got $n packets"

# Throughput and integrity: download 50 MB through the user-space TCP of the server
start=$(date +%s.%N)
sha=$(in_phone curl --noproxy '*' -s -m 120 http://198.51.100.10:8080/big.bin | sha256sum | cut -d' ' -f1)
secs=$(echo "$(date +%s.%N) - $start" | bc)
[ "$sha" = "$BIG_SHA" ] && pass "50 MB download, checksum ok ($(echo "scale=1; 50 / $secs" | bc) MB/s)" || fail "50 MB download checksum"

# Upload direction: the target answers with the sha256 of what it received
head -c 20000000 /dev/urandom > "$WORK/upload.bin"
UP_SHA=$(sha256sum "$WORK/upload.bin" | cut -d' ' -f1)
out=$(in_phone curl --noproxy '*' -s -m 120 --data-binary @"$WORK/upload.bin" http://198.51.100.10:8080/upload)
[ "$out" = "$UP_SHA" ] && pass "20 MB upload, checksum ok" || fail "20 MB upload checksum ($out)"

# 20 parallel downloads: fairness and back pressure between flows of one session
ok=0
for i in $(seq 20); do
    (in_phone curl --noproxy '*' -s -m ${PARALLEL_TIMEOUT:-120} http://198.51.100.10:8080/big.bin | sha256sum | cut -d' ' -f1 > "$WORK/par.$i") &
done
# Wait only for the downloads, not for the long running background services
wait $(jobs -p | grep -v -e "^$SERVICES_PID$" -e "^$SERVER_PID$" -e "^$CLIENT_PID$") 2>/dev/null
for i in $(seq 20); do [ "$(cat "$WORK/par.$i")" = "$BIG_SHA" ] && ok=$((ok + 1)); done
[ $ok -eq 20 ] && pass "20 parallel 50 MB downloads" || fail "parallel downloads: $ok/20 ok"

log "DNS"
out=$(in_phone dig +short +time=2 +tries=2 @198.51.100.10 www.example.test A)
[ "$out" = "1.2.3.4" ] && pass "DNS A query over UDP" || fail "DNS A got '$out'"
out=$(in_phone dig +short +time=2 +tries=2 @198.51.100.10 www.example.test AAAA)
[ "$out" = "2001:db8::1234" ] && pass "DNS AAAA query" || fail "DNS AAAA got '$out'"
if [ $HAVE_V6 = 1 ]; then
    out=$(in_phone dig +short +time=2 +tries=2 @2001:db8:100::10 www.example.test A)
    [ "$out" = "1.2.3.4" ] && pass "DNS query over IPv6" || fail "DNS over IPv6 got '$out'"
fi
# vpn_block_domains: the server answers the query itself with NXDOMAIN
out=$(in_phone dig +time=2 +tries=1 @198.51.100.10 ads.blocked.test A | grep -o "status: [A-Z]*")
[ "$out" = "status: NXDOMAIN" ] && pass "blocked domain answered with NXDOMAIN" || fail "DNS block got '$out'"

log "ICMP"
in_phone ping -c 3 -i 0.2 -W 2 198.51.100.10 > "$WORK/ping4.txt" 2>&1 && pass "ping IPv4 (raw socket)" || { fail "ping IPv4"; cat "$WORK/ping4.txt"; }
if [ $HAVE_V6 = 1 ]; then
    in_phone ping -6 -c 3 -i 0.2 -W 2 2001:db8:100::10 > "$WORK/ping6.txt" 2>&1 && pass "ping IPv6" || { fail "ping IPv6"; cat "$WORK/ping6.txt"; }
fi
# Allow unprivileged ICMP "ping sockets" (SOCK_DGRAM + IPPROTO_ICMP) for every group, so the
# server's other ICMP code path is exercised too; the old setting is restored afterwards
old_range=$(cat /proc/sys/net/ipv4/ping_group_range)
echo "0 2147483647" > /proc/sys/net/ipv4/ping_group_range
in_phone ping -c 3 -i 0.2 -W 2 -p 5356 198.51.100.10 > "$WORK/ping4b.txt" 2>&1 && pass "ping IPv4 (unprivileged ping socket)" || { fail "ping via ping socket"; cat "$WORK/ping4b.txt"; }
in_phone ping -c 3 -i 0.2 -W 2 -s 6000 198.51.100.10 > "$WORK/ping4c.txt" 2>&1 && pass "ping with 6000 byte payload (fragmented both ways)" || { fail "large ping"; cat "$WORK/ping4c.txt"; }
echo "$old_range" > /proc/sys/net/ipv4/ping_group_range

log "Socket level tests (echo, half close, UDP, parallel, refused)"
in_phone env HAVE_V6=$HAVE_V6 python3 -u "$ROOT/tests/e2e_client_tests.py" || fail "socket level tests"

log "Blocked TLS SNI"
# The inspector sees the host name in the TLS ClientHello (SNI) and resets the connection
out=$(in_phone curl --noproxy '*' -s -m 5 -k --resolve blocked.test:8080:198.51.100.10 https://blocked.test:8080/ 2>&1; echo "rc=$?")
grep -q "BLOCKED (TLS host blocked.test)" "$WORK/server/log/server.log" && pass "TLS ClientHello with blocked SNI reset ($out)" || fail "SNI block"

log "Server restart -> client reconnects"
# The client must notice the lost connection, back off and reconnect by itself
kill -INT $SERVER_PID; wait $SERVER_PID 2>/dev/null
(cd "$WORK/server" && exec "$BUILD/server/reactor/mulserver" conf/server.ini "$BUILD/server/libvpnproxy.so" \
    >> "$WORK/server/stdout.txt" 2>&1) &
SERVER_PID=$!
for _ in $(seq 100); do
    [ "$(grep -c "connected to" "$WORK/client.log")" -ge 2 ] && break
    sleep 0.1
done
out=$(in_phone curl --noproxy '*' -s -m 10 http://198.51.100.10:8080/index.html)
[ "$out" = "Hello Rewritten" ] && pass "traffic flows again after reconnect" || fail "after reconnect got '$out'"

log "Wrong token is rejected"
# A second client on a separate TUN device with a wrong token: the server must send ERROR "authentication failed"
in_phone ip tuntap add dev tun9 mode tun
in_phone timeout 3 "$BUILD/tools/simplevpn-client" -s 172.30.0.1 -t wrong -d tun9 --ipv4 "" > "$WORK/client-bad.log" 2>&1
grep -q "authentication failed" "$WORK/client-bad.log" && pass "authentication failure reported" || { fail "bad token"; cat "$WORK/client-bad.log"; }

log "Logs and capture"
grep -E "TCP#[0-9]+ .* HTTP GET /index.html" "$WORK/server/log/server.log" | head -1
grep -E "DNS query" "$WORK/server/log/server.log" | head -1
PCAP=$(ls "$WORK"/server/pcap/*.pcap 2>/dev/null | head -1)
# Stop the server first so the pcap file is complete, then let tcpdump parse it
if [ -n "$PCAP" ] && command -v tcpdump >/dev/null; then
    kill -INT $SERVER_PID; wait $SERVER_PID 2>/dev/null; SERVER_PID=
    n=$(tcpdump -nr "$PCAP" 2>/dev/null | wc -l)
    [ "$n" -gt 1000 ] && pass "pcap capture readable by tcpdump ($n packets in $(basename "$PCAP"))" || fail "pcap has $n packets"
fi
# With a -DSIMPLEVPN_SANITIZE build, any sanitizer report fails the run
if grep -E "ERROR: (AddressSanitizer|LeakSanitizer)|WARNING: ThreadSanitizer|runtime error" "$WORK/server/stdout.txt" "$WORK/client.log" >/dev/null; then
    fail "sanitizer reported problems"; grep -A30 -E "ERROR: |WARNING: ThreadSanitizer|runtime error" "$WORK/server/stdout.txt" | head -80
fi
grep -c "" "$WORK/server/log/server.log" | xargs echo "server log lines:"

echo
if [ $FAILED -eq 0 ]; then
    echo -e "\033[1;32mALL END-TO-END TESTS PASSED\033[0m (logs: $WORK)"
else
    echo -e "\033[1;31mSOME END-TO-END TESTS FAILED\033[0m (logs: $WORK)"
fi
exit $FAILED
