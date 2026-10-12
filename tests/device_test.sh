#!/usr/bin/env bash
# End-to-end test with a real Android phone, run on the computer (macOS or
# Linux) the phone is plugged into with USB debugging enabled:
#
#   tests/device_test.sh
#
# It builds the server and the app, starts the server on this computer,
# installs the app, connects the VPN without any tap on the phone (debug
# builds accept the connect command through adb), generates DNS / ICMP /
# HTTP / HTTPS traffic on the phone and checks the server log and logcat.
#
# Environment:
#   ADB_SERIAL   phone serial if several devices are attached
#   HOST_IP      IP of this computer as seen from the phone (auto detected)
#   PORT         tunnel port (default 9443)
#   SKIP_BUILD=1 reuse the existing build
#   TOKEN        vpn_token for this run (default: a fresh one per run)
#   WORK_DIR     server config, logs and pcap (default build/device-test)
#
# The phone must reach HOST_IP:PORT: same Wi-Fi, and on macOS allow incoming
# connections for "mulserver" if the firewall asks.
#
# How the phone is driven without taps: debug builds of MainActivity accept
# "am start ... --es vpn_action connect --es server ... --es token ..." (see
# MainActivity.handleTestIntent; release builds ignore it). The VPN consent
# dialog is pre-approved with "appops set ACTIVATE_VPN allow", and if it
# still shows up, accept_vpn_dialog() taps its OK button via uiautomator.
# Success is judged from the server log (authentication, DNS / HTTP / TLS log
# lines) and from logcat (state messages of MyVpnService).

# No "set -e": checks report with pass / fail / warn and the run continues
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PKG=com.kingo132.simplevpn
PORT="${PORT:-9443}"
TOKEN="${TOKEN:-device-test-$$}"
WORK="${WORK_DIR:-$ROOT/build/device-test}"
# adb as an array, so "-s SERIAL" can be added safely
ADB=(adb)
[ -n "${ADB_SERIAL:-}" ] && ADB=(adb -s "$ADB_SERIAL")
SERVER_PID=""
FAILED=0
WARNINGS=0

# Output helpers: fail marks the run failed, warn only counts, die aborts
log() { printf '\033[1;34m==> %s\033[0m\n' "$*"; }
pass() { printf '\033[1;32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31mFAIL\033[0m %s\n' "$*"; FAILED=1; }
warn() { printf '\033[1;33mWARN\033[0m %s\n' "$*"; WARNINGS=$((WARNINGS + 1)); }
die() { fail "$*"; exit 1; }
# Run a shell command on the phone
adbs() { "${ADB[@]}" shell "$@"; }

SERVER_LOG="$WORK/log/server.log"

# wait_log <regex> <seconds>: wait until the server log matches
wait_log() {
    local pattern=$1 seconds=$2 i
    for ((i = 0; i < seconds * 5; i++)); do
        grep -Eq -- "$pattern" "$SERVER_LOG" 2>/dev/null && return 0
        sleep 0.2
    done
    return 1
}

# count_log <regex>: number of matching lines in the server log
count_log() {
    local n
    n=$(grep -Ec -- "$1" "$SERVER_LOG" 2>/dev/null)
    echo "${n:-0}"
}

# start_server <n>: start mulserver in the background and wait until the log
# contains its n-th "Server started" line (n = 2 after a restart, the log is appended)
start_server() {
    (cd "$WORK" && exec "$ROOT/build/server/reactor/mulserver" conf/server.ini "$ROOT/build/server/libvpnproxy.so" \
        >> "$WORK/stdout.txt" 2>&1) &
    SERVER_PID=$!
    for _ in $(seq 50); do
        [ "$(count_log "Server started")" -ge "${1:-1}" ] && return 0
        kill -0 "$SERVER_PID" 2>/dev/null || break
        sleep 0.2
    done
    cat "$WORK/stdout.txt"
    return 1
}

# stop_server: SIGINT = graceful shutdown (closes the tunnels, finishes the pcap files)
stop_server() {
    if [ -n "$SERVER_PID" ]; then
        kill -INT "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null
        SERVER_PID=""
    fi
}

# At exit: disconnect the VPN on the phone, stop the server, save logcat
cleanup() {
    adbs am start -n "$PKG/.MainActivity" --es vpn_action disconnect >/dev/null 2>&1
    sleep 1
    stop_server
    "${ADB[@]}" logcat -d -s SimpleVPN AndroidRuntime > "$WORK/logcat.txt" 2>/dev/null
}

# Tap the "OK" button of the system VPN consent dialog if it is showing
# (dump the UI hierarchy, find the button with id android:id/button1 and tap the centre of its bounds)
accept_vpn_dialog() {
    adbs uiautomator dump /sdcard/svpn_ui.xml >/dev/null 2>&1 || return 1
    local xml
    xml=$(adbs cat /sdcard/svpn_ui.xml 2>/dev/null)
    local bounds
    bounds=$(printf '%s' "$xml" | tr '>' '\n' | grep 'resource-id="android:id/button1"' |
        sed -E 's/.*bounds="\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]".*/\1 \2 \3 \4/' | head -1)
    [ -z "$bounds" ] && return 1
    set -- $bounds
    adbs input tap $((($1 + $3) / 2)) $((($2 + $4) / 2))
    log "Accepted the VPN permission dialog"
}

# ---------------------------------------------------------------------------
log "Checking prerequisites"
command -v adb >/dev/null || die "adb not found (add <Android SDK>/platform-tools to PATH)"
command -v cmake >/dev/null || die "cmake not found"
[ "$("${ADB[@]}" get-state 2>/dev/null)" = "device" ] ||
    die "no authorized phone (adb devices; accept the USB debugging prompt on the phone, set ADB_SERIAL if several)"
pass "phone $("${ADB[@]}" get-serialno): $(adbs getprop ro.product.model | tr -d '\r'), Android $(adbs getprop ro.build.version.release | tr -d '\r')"

# The phone connects to this computer's LAN address: find it from the default route
if [ -z "${HOST_IP:-}" ]; then
    if [ "$(uname -s)" = "Darwin" ]; then
        iface=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
        HOST_IP=$(ipconfig getifaddr "${iface:-en0}" 2>/dev/null)
    else
        HOST_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}')
    fi
fi
[ -n "${HOST_IP:-}" ] || die "cannot detect the LAN IP of this computer, set HOST_IP"
pass "server address for the phone: $HOST_IP:$PORT"

# ---------------------------------------------------------------------------
if [ -z "${SKIP_BUILD:-}" ]; then
    log "Building the server"
    cmake -S "$ROOT" -B "$ROOT/build" -DCMAKE_BUILD_TYPE=RelWithDebInfo > "$ROOT/build-cmake.log" 2>&1 &&
        cmake --build "$ROOT/build" -j 4 >> "$ROOT/build-cmake.log" 2>&1 ||
        { tail -40 "$ROOT/build-cmake.log"; die "server build failed (log: build-cmake.log)"; }
    "$ROOT/build/tests/packet_test" > /dev/null || die "packet_test failed"
    pass "server built, unit tests ok"

    log "Building the app"
    if [ ! -f "$ROOT/client/local.properties" ]; then
        sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
        echo "sdk.dir=$sdk" > "$ROOT/client/local.properties"
    fi
    # Gradle 8.7 runs on Java 17..21; newer JDKs (Android Studio now bundles
    # Java 25) fail with just the version number as the error.
    jver=$("${JAVA_HOME:+$JAVA_HOME/bin/}java" -version 2>&1 | awk -F'"' '/version/{split($2, v, "."); print v[1]; exit}')
    if [ "${jver:-0}" -gt 21 ] 2>/dev/null || [ "${jver:-0}" -lt 17 ] 2>/dev/null; then
        for v in 21 17; do
            jh=$( { [ -x /usr/libexec/java_home ] && /usr/libexec/java_home -v "$v" 2>/dev/null; } ||
                ls -d /usr/lib/jvm/*-"$v"-* 2>/dev/null | head -1)
            if [ -n "$jh" ] && "$jh/bin/java" -version 2>&1 | grep -q "version \"$v\."; then
                export JAVA_HOME="$jh"
                log "Java $jver is not supported by Gradle 8.7, using $JAVA_HOME"
                break
            fi
        done
    fi
    (cd "$ROOT/client" && ./gradlew assembleDebug > "$ROOT/build-gradle.log" 2>&1) ||
        { tail -40 "$ROOT/build-gradle.log"; die "app build failed (log: build-gradle.log)"; }
    pass "app built"
fi
APK="$ROOT/client/app/build/outputs/apk/debug/app-debug.apk"
[ -f "$APK" ] || die "missing $APK"

# A VPN left up by an earlier run would capture the shell traffic below
# (and keep retrying with its old token): stop the app first.
adbs am force-stop "$PKG" >/dev/null 2>&1

# ---------------------------------------------------------------------------
log "Starting the VPN server (work dir $WORK)"
# Fresh work dir; the server listens on all addresses so the phone can reach it over Wi-Fi
rm -rf "$WORK"
mkdir -p "$WORK/conf"
echo "0.0.0.0 $PORT tcp 300" > "$WORK/conf/bind.txt"
# Test config derived from server/conf/server.ini (token, log file, pcap, QUIC blocked so browsers use TCP + TLS)
sed -e "s|^vpn_token = .*|vpn_token = $TOKEN|" \
    -e "s|^log_dest = .*|log_dest = 2|" \
    -e "s|^log_dir = .*|log_dir = $WORK/log|" \
    -e "s|^bind_file = .*|bind_file = $WORK/conf/bind.txt|" \
    -e "s|^vpn_pcap_dir = .*|vpn_pcap_dir = $WORK/pcap|" \
    -e "s|^vpn_block_quic = .*|vpn_block_quic = 1|" \
    "$ROOT/server/conf/server.ini" > "$WORK/conf/server.ini"
start_server 1 || die "server did not start"
trap cleanup EXIT
pass "server running (pid $SERVER_PID)"

# Can the phone reach us at all? (before the VPN is up; toybox nc may be missing)
if adbs 'command -v nc' >/dev/null 2>&1; then
    adbs "echo | nc -w 3 $HOST_IP $PORT" >/dev/null 2>&1
    if wait_log "tunnel connection from" 3; then
        pass "phone reaches $HOST_IP:$PORT"
    else
        die "the phone cannot reach $HOST_IP:$PORT: same Wi-Fi? On macOS allow incoming connections for mulserver
     (System Settings > Network > Firewall, or: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add $ROOT/build/server/reactor/mulserver --unblockapp $ROOT/build/server/reactor/mulserver)"
    fi
fi

# ---------------------------------------------------------------------------
log "Installing the app"
if ! "${ADB[@]}" install -r -t "$APK" > "$WORK/install.txt" 2>&1; then
    cat "$WORK/install.txt"
    warn "install failed, uninstalling the old version (different signature?) and retrying"
    "${ADB[@]}" uninstall "$PKG" >/dev/null 2>&1
    "${ADB[@]}" install -t "$APK" > "$WORK/install.txt" 2>&1 || { cat "$WORK/install.txt"; die "install failed"; }
fi
pass "app installed"
# Pre-approve the VPN (what the system consent dialog does)
adbs appops set "$PKG" ACTIVATE_VPN allow >/dev/null 2>&1 || true

log "Connecting the VPN"
# Clear logcat so the checks below only see this run; force-stop for a clean start
"${ADB[@]}" logcat -c
adbs am force-stop "$PKG"
adbs am start -n "$PKG/.MainActivity" --es vpn_action connect --es server "$HOST_IP" --ei port "$PORT" \
    --es token "$TOKEN" --es dns 8.8.8.8 --ez ipv6 false >/dev/null
# Wait up to 30 s for the server to log the HELLO; try the consent dialog after 3 s and 8 s
connected=0
for i in $(seq 30); do
    if grep -q "authenticated: client=android" "$SERVER_LOG"; then
        connected=1
        break
    fi
    [ "$i" -eq 3 ] || [ "$i" -eq 8 ] && accept_vpn_dialog
    sleep 1
done
if [ $connected -eq 1 ]; then
    pass "tunnel established: $(grep "authenticated: client=android" "$SERVER_LOG" | tail -1 | sed 's/.*\] //')"
else
    "${ADB[@]}" logcat -d -s SimpleVPN AndroidRuntime | tail -30
    die "the app did not connect (see logcat above, server log $SERVER_LOG)"
fi
sleep 2
if "${ADB[@]}" logcat -d -s SimpleVPN | grep -q "state 2: connected"; then
    pass "app reports connected"
else
    fail "app did not report the connected state"
fi

# ---------------------------------------------------------------------------
log "DNS + ICMP (ping from the phone's shell goes through the VPN)"
if adbs ping -c 3 -W 5 www.google.com > "$WORK/ping.txt" 2>&1; then
    pass "ping www.google.com: $(grep -E "packets transmitted" "$WORK/ping.txt" | tr -d '\r')"
else
    cat "$WORK/ping.txt"
    if grep -q "unknown host" "$WORK/ping.txt"; then
        fail "DNS resolution through the VPN failed"
    else
        warn "ping failed (the server may not be allowed to send ICMP; DNS worked)"
    fi
fi
if wait_log "DNS (query|response).*google|:853 " 5; then
    pass "server logged the DNS lookup: $(grep -E "DNS (query|response).*google|:853 " "$SERVER_LOG" | head -1 | sed 's/.*\] //' | cut -c1-150)"
else
    fail "no DNS traffic in the server log"
fi
if wait_log "ICMP#[0-9]+ .* new" 3; then
    pass "server logged: $(grep -E "ICMP#[0-9]+ .* new" "$SERVER_LOG" | head -1 | sed 's/.*\] //' | cut -c1-150)"
else
    warn "no ICMP flow in the server log"
fi

if adbs 'command -v nc' >/dev/null 2>&1; then
    log "Plain HTTP with netcat on the phone"
    # Several sites: from some networks one of them only answers every other SYN.
    # nc half-closes the connection on stdin EOF, and some servers (Cloudflare,
    # speedtest.tele2.net) then stop answering: keep stdin open until nc exits.
    http_host=""
    for h in example.com info.cern.ch neverssl.com; do
        adbs "{ printf 'GET / HTTP/1.1\r\nHost: $h\r\nUser-Agent: simplevpn-device-test\r\nConnection: close\r\n\r\n'; sleep 61; } |
            nc -w 10 -W 20 $h 80 | { cat; pkill -f 'sleep 61'; }" > "$WORK/http.txt" 2>&1
        if head -1 "$WORK/http.txt" | grep -q "^HTTP/1.1 200"; then
            http_host=$h
            break
        fi
        warn "no HTTP response from $h: $(head -1 "$WORK/http.txt" | tr -d '\r')"
    done
    if [ -n "$http_host" ]; then
        pass "HTTP response from $http_host received on the phone ($(wc -c < "$WORK/http.txt" | tr -d ' ') bytes)"
        if wait_log "HTTP GET / HTTP/1.1 Host=$http_host" 5; then
            pass "server logged: $(grep "Host=$http_host" "$SERVER_LOG" | head -1 | sed 's/.*\] //' | cut -c1-150)"
        else
            fail "HTTP request not in the server log"
        fi
    else
        fail "no HTTP response through the VPN"
    fi

    log "Download speed (10 MB, best effort)"
    # stdin kept open as above (tele2 stops after ~270 KB on a half-close)
    start=$(date +%s)
    bytes=$(adbs "{ printf 'GET /10MB.zip HTTP/1.1\r\nHost: speedtest.tele2.net\r\nConnection: close\r\n\r\n'; sleep 61; } |
        nc -w 10 -W 20 speedtest.tele2.net 80 | { wc -c; pkill -f 'sleep 61'; }" 2>/dev/null | tr -d '\r ')
    secs=$(( $(date +%s) - start ))
    if [ "${bytes:-0}" -gt 10000000 ] 2>/dev/null; then
        pass "downloaded $bytes bytes in ${secs}s"
    else
        warn "speed test download got ${bytes:-0} bytes (test server unreachable?)"
    fi
else
    warn "no nc on the phone, plain HTTP checks skipped"
fi

log "HTTPS in the browser"
# Open a web page in the default browser: the server should log the TLS ClientHello with its SNI
adbs am start -a android.intent.action.VIEW -d "https://www.wikipedia.org/" >/dev/null 2>&1
if wait_log "TLS ClientHello.*SNI=[a-z0-9.-]*wikipedia" 20; then
    pass "server logged: $(grep -E "TLS ClientHello.*wikipedia" "$SERVER_LOG" | head -1 | sed 's/.*\] //' | cut -c1-160)"
elif wait_log "TLS ClientHello" 1; then
    pass "TLS traffic seen: $(grep "TLS ClientHello" "$SERVER_LOG" | head -1 | sed 's/.*\] //' | cut -c1-160)"
    warn "the browser did not open wikipedia (first-run screen?), other TLS traffic was proxied"
else
    warn "no TLS ClientHello seen (browser first-run screen? open a web page by hand to check)"
fi
adbs input keyevent KEYCODE_HOME >/dev/null 2>&1

# ---------------------------------------------------------------------------
log "Server restart: the app must reconnect by itself"
# Tests the native client's reconnect with back off (TunnelClient::run)
stop_server
start_server 2 || die "server did not restart"
for _ in $(seq 40); do
    [ "$(count_log "authenticated: client=android")" -ge 2 ] && break
    sleep 1
done
if [ "$(count_log "authenticated: client=android")" -ge 2 ]; then
    pass "app reconnected"
else
    fail "app did not reconnect within 40 s"
fi
# Generate some traffic and check that new log lines appear
before=$(count_log "DNS (query|response)|ICMP#|:853 ")
adbs ping -c 2 -W 5 www.wikipedia.org >/dev/null 2>&1
sleep 1
if [ "$(count_log "DNS (query|response)|ICMP#|:853 ")" -gt "$before" ]; then
    pass "traffic flows after the reconnect"
else
    fail "no traffic after the reconnect"
fi

log "Disconnect"
adbs am start -n "$PKG/.MainActivity" --es vpn_action disconnect >/dev/null
if wait_log "Tunnel from .* closed" 10; then
    pass "tunnel closed by the app"
else
    fail "tunnel not closed after disconnect"
fi

"${ADB[@]}" logcat -d -s SimpleVPN AndroidRuntime > "$WORK/logcat.txt" 2>/dev/null
if grep -q "FATAL EXCEPTION" "$WORK/logcat.txt"; then
    grep -A20 "FATAL EXCEPTION" "$WORK/logcat.txt" | head -40
    fail "the app crashed"
else
    pass "no crash in logcat"
fi
# Errors in the server log (except the expected authentication ones) are only a warning
if grep -E "ERROR|CRIT" "$SERVER_LOG" | grep -v "authentication" | head -5 | grep -q .; then
    grep -E "ERROR|CRIT" "$SERVER_LOG" | head -5
    warn "errors in the server log (above)"
fi

echo
echo "Server log: $SERVER_LOG"
echo "pcap:       $(ls "$WORK"/pcap/*.pcap 2>/dev/null | head -1)"
echo "logcat:     $WORK/logcat.txt"
if [ $FAILED -eq 0 ]; then
    printf '\033[1;32mDEVICE TEST PASSED\033[0m (%d warning(s))\n' "$WARNINGS"
else
    printf '\033[1;31mDEVICE TEST FAILED\033[0m\n'
fi
exit $FAILED
