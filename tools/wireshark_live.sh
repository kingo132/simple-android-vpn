#!/usr/bin/env bash
# Show the VPN traffic live in Wireshark.
#   tools/wireshark_live.sh                 server on this machine
#   tools/wireshark_live.sh user@server     server elsewhere, through SSH
# The server streams pcap on vpn_capture_port (default 9444, loopback only).
set -euo pipefail
PORT="${PORT:-9444}"

WIRESHARK="${WIRESHARK:-}"
if [ -z "$WIRESHARK" ]; then
    if [ -x /Applications/Wireshark.app/Contents/MacOS/Wireshark ]; then
        WIRESHARK=/Applications/Wireshark.app/Contents/MacOS/Wireshark
    else
        WIRESHARK=$(command -v wireshark || true)
    fi
fi
[ -n "$WIRESHARK" ] || { echo "Wireshark not found (set WIRESHARK=/path/to/wireshark)"; exit 1; }

if [ $# -ge 1 ]; then
    # Run nc on the server and bring the stream back over SSH
    ssh "$1" "nc 127.0.0.1 $PORT" | "$WIRESHARK" -k -i -
else
    nc 127.0.0.1 "$PORT" | "$WIRESHARK" -k -i -
fi
