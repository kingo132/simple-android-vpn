#!/usr/bin/env bash
# End-to-end test of the whole chain on one Linux machine (needs root):
#
#   [ns svpn_phone]                      [root ns]                        [ns svpn_inet]
#   curl/dig/ping -> tun0                                                  HTTP :8080, echo :7,
#   simplevpn-client --TCP 172.30.0.1:9443--> mulserver + libvpnproxy --->  DNS :53, banner :25
#        (the "phone")                      (the VPN server)               198.51.100.10
#                                                                          2001:db8:100::10
#
#   BUILD_DIR=build tests/e2e_test.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build}"
WORK="${WORK_DIR:-$(mktemp -d /tmp/svpn-e2e.XXXXXX)}"
mkdir -p "$WORK"
PHONE=svpn_phone
INET=svpn_inet
TOKEN=e2e-secret
FAILED=0

log() { echo -e "\033[1;34m==> $*\033[0m"; }
pass() { echo -e "\033[1;32mPASS\033[0m $*"; }
fail() { echo -e "\033[1;31mFAIL\033[0m $*"; FAILED=1; }
in_phone() { ip netns exec $PHONE "$@"; }
in_inet() { ip netns exec $INET "$@"; }

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

HAVE_V6=0
[ -d /proc/sys/net/ipv6 ] && HAVE_V6=1
[ $HAVE_V6 = 1 ] || echo "IPv6 is not available in this kernel, IPv6 checks are skipped"
v6() { [ $HAVE_V6 = 1 ] && "$@"; }

log "Network namespaces (work dir $WORK)"
cleanup 2>/dev/null
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
mkdir -p "$WORK/www"
echo "Hello SimpleVPN" > "$WORK/www/index.html"
head -c 50000000 /dev/urandom > "$WORK/www/big.bin"
BIG_SHA=$(sha256sum "$WORK/www/big.bin" | cut -d' ' -f1)
in_inet python3 -u "$ROOT/tests/e2e_services.py" "$WORK/www" > "$WORK/services.log" 2>&1 &
SERVICES_PID=$!

log "VPN server"
mkdir -p "$WORK/server/conf"
printf "172.30.0.1 9443 tcp 300\n127.0.0.1 9444 tcp 0\n" > "$WORK/server/conf/bind.txt"
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
(cd "$WORK/server" && exec "$BUILD/server/reactor/mulserver" conf/server.ini "$BUILD/server/libvpnproxy.so" \
    > "$WORK/server/stdout.txt" 2>&1) &
SERVER_PID=$!
sleep 1
grep -q "Server started" "$WORK/server/log/server.log" || { fail "server did not start"; cat "$WORK/server/stdout.txt"; exit 1; }

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

start=$(date +%s.%N)
sha=$(in_phone curl --noproxy '*' -s -m 120 http://198.51.100.10:8080/big.bin | sha256sum | cut -d' ' -f1)
secs=$(echo "$(date +%s.%N) - $start" | bc)
[ "$sha" = "$BIG_SHA" ] && pass "50 MB download, checksum ok ($(echo "scale=1; 50 / $secs" | bc) MB/s)" || fail "50 MB download checksum"

head -c 20000000 /dev/urandom > "$WORK/upload.bin"
UP_SHA=$(sha256sum "$WORK/upload.bin" | cut -d' ' -f1)
out=$(in_phone curl --noproxy '*' -s -m 120 --data-binary @"$WORK/upload.bin" http://198.51.100.10:8080/upload)
[ "$out" = "$UP_SHA" ] && pass "20 MB upload, checksum ok" || fail "20 MB upload checksum ($out)"

ok=0
for i in $(seq 20); do
    (in_phone curl --noproxy '*' -s -m ${PARALLEL_TIMEOUT:-120} http://198.51.100.10:8080/big.bin | sha256sum | cut -d' ' -f1 > "$WORK/par.$i") &
done
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
out=$(in_phone dig +time=2 +tries=1 @198.51.100.10 ads.blocked.test A | grep -o "status: [A-Z]*")
[ "$out" = "status: NXDOMAIN" ] && pass "blocked domain answered with NXDOMAIN" || fail "DNS block got '$out'"

log "ICMP"
in_phone ping -c 3 -i 0.2 -W 2 198.51.100.10 > "$WORK/ping4.txt" 2>&1 && pass "ping IPv4 (raw socket)" || { fail "ping IPv4"; cat "$WORK/ping4.txt"; }
if [ $HAVE_V6 = 1 ]; then
    in_phone ping -6 -c 3 -i 0.2 -W 2 2001:db8:100::10 > "$WORK/ping6.txt" 2>&1 && pass "ping IPv6" || { fail "ping IPv6"; cat "$WORK/ping6.txt"; }
fi
old_range=$(cat /proc/sys/net/ipv4/ping_group_range)
echo "0 2147483647" > /proc/sys/net/ipv4/ping_group_range
in_phone ping -c 3 -i 0.2 -W 2 -p 5356 198.51.100.10 > "$WORK/ping4b.txt" 2>&1 && pass "ping IPv4 (unprivileged ping socket)" || { fail "ping via ping socket"; cat "$WORK/ping4b.txt"; }
in_phone ping -c 3 -i 0.2 -W 2 -s 6000 198.51.100.10 > "$WORK/ping4c.txt" 2>&1 && pass "ping with 6000 byte payload (fragmented both ways)" || { fail "large ping"; cat "$WORK/ping4c.txt"; }
echo "$old_range" > /proc/sys/net/ipv4/ping_group_range

log "Socket level tests (echo, half close, UDP, parallel, refused)"
in_phone env HAVE_V6=$HAVE_V6 python3 -u "$ROOT/tests/e2e_client_tests.py" || fail "socket level tests"

log "Blocked TLS SNI"
out=$(in_phone curl --noproxy '*' -s -m 5 -k --resolve blocked.test:8080:198.51.100.10 https://blocked.test:8080/ 2>&1; echo "rc=$?")
grep -q "BLOCKED (TLS host blocked.test)" "$WORK/server/log/server.log" && pass "TLS ClientHello with blocked SNI reset ($out)" || fail "SNI block"

log "Server restart -> client reconnects"
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
in_phone ip tuntap add dev tun9 mode tun
in_phone timeout 3 "$BUILD/tools/simplevpn-client" -s 172.30.0.1 -t wrong -d tun9 --ipv4 "" > "$WORK/client-bad.log" 2>&1
grep -q "authentication failed" "$WORK/client-bad.log" && pass "authentication failure reported" || { fail "bad token"; cat "$WORK/client-bad.log"; }

log "Logs and capture"
grep -E "TCP#[0-9]+ .* HTTP GET /index.html" "$WORK/server/log/server.log" | head -1
grep -E "DNS query" "$WORK/server/log/server.log" | head -1
PCAP=$(ls "$WORK"/server/pcap/*.pcap 2>/dev/null | head -1)
if [ -n "$PCAP" ] && command -v tcpdump >/dev/null; then
    kill -INT $SERVER_PID; wait $SERVER_PID 2>/dev/null; SERVER_PID=
    n=$(tcpdump -nr "$PCAP" 2>/dev/null | wc -l)
    [ "$n" -gt 1000 ] && pass "pcap capture readable by tcpdump ($n packets in $(basename "$PCAP"))" || fail "pcap has $n packets"
fi
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
