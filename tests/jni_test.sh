#!/usr/bin/env bash
# Runs the Android JNI glue (client/app/src/main/cpp/native-lib.cpp) on a Linux
# JVM: a Java test double of MyVpnService drives the real native code through
# the VPN server, inside the network namespaces of tests/e2e_test.sh.
#   BUILD_DIR=build tests/jni_test.sh      (root, JDK and the server build needed)
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${BUILD_DIR:-$ROOT/build}"
WORK="${WORK_DIR:-$(mktemp -d /tmp/svpn-jni.XXXXXX)}"
mkdir -p "$WORK/lib" "$WORK/classes"
JAVA_HOME="${JAVA_HOME:-$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")}"
CPP="$ROOT/client/app/src/main/cpp"

g++ -std=c++11 -O2 -Wall -shared -fPIC -pthread -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" \
    -I"$CPP" -I"$ROOT/common" "$CPP/native-lib.cpp" "$CPP/tunnel_client.cpp" -o "$WORK/lib/libsimplevpn.so" || exit 1
g++ -std=c++11 -O2 -shared -fPIC -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" \
    "$ROOT/tests/jni/tun_helper.cpp" -o "$WORK/lib/libtunhelper.so" || exit 1
javac -d "$WORK/classes" "$ROOT/tests/jni/com/kingo132/simplevpn/MyVpnService.java" || exit 1

# Network namespaces + server, without the Linux client
E2E_SETUP_ONLY=1 E2E_NO_CLIENT=1 BUILD_DIR="$BUILD" WORK_DIR="$WORK/e2e" "$ROOT/tests/e2e_test.sh" > "$WORK/setup.log" 2>&1 || {
    cat "$WORK/setup.log"; exit 1; }

ip netns exec svpn_phone java -Djava.library.path="$WORK/lib" -cp "$WORK/classes" \
    com.kingo132.simplevpn.MyVpnService 172.30.0.1 9443 e2e-secret 8 > "$WORK/java.log" 2>&1 &
JAVA_PID=$!
for _ in $(seq 100); do grep -q READY "$WORK/java.log" && break; sleep 0.1; done
out=$(ip netns exec svpn_phone curl --noproxy '*' -s -m 10 http://198.51.100.10:8080/index.html)
sha=$(ip netns exec svpn_phone curl --noproxy '*' -s -m 30 http://198.51.100.10:8080/big.bin | sha256sum | cut -d' ' -f1)
wait $JAVA_PID
cat "$WORK/java.log"

RC=0
[ "$out" = "Hello Rewritten" ] && echo "PASS HTTP through the JNI tunnel" || { echo "FAIL HTTP got '$out'"; RC=1; }
[ "$sha" = "$(sha256sum "$WORK/e2e/www/big.bin" | cut -d' ' -f1)" ] && echo "PASS 50 MB download through the JNI tunnel" || { echo "FAIL download"; RC=1; }
grep -q "JNI OK" "$WORK/java.log" && echo "PASS JNI callbacks (protect, state) and stats" || RC=1

# cleanup what e2e_test.sh left running
for p in $(cat "$WORK/e2e/pids" 2>/dev/null); do kill "$p" 2>/dev/null; done
ip netns del svpn_phone 2>/dev/null; ip netns del svpn_inet 2>/dev/null
ip link del s0 2>/dev/null; ip link del r0 2>/dev/null
exit $RC
