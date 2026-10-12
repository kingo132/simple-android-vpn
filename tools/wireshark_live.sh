#!/usr/bin/env bash
# Show the VPN traffic live in Wireshark.
#   tools/wireshark_live.sh                 server on this machine
#   tools/wireshark_live.sh user@server     server elsewhere, through SSH
# The server streams pcap on vpn_capture_port (default 9444, loopback only).
#
# How it works: the plugin (server/src/pcap_writer.cpp, LiveCapture) sends a
# pcap file header to every client of the capture port, followed by one pcap
# record per tunnelled packet. "wireshark -k -i -" reads such a stream from
# stdin and starts capturing immediately, so piping nc into it is enough.
# The port only accepts loopback clients (the stream contains every user's
# traffic), hence the SSH variant for a remote server.
#
# Environment: PORT (capture port, default 9444), WIRESHARK (path to the binary).
# Strict mode: stop on errors, unset variables and failures inside pipes
set -euo pipefail
PORT="${PORT:-9444}"

# Find Wireshark: $WIRESHARK if set, else the macOS app bundle, else the PATH
WIRESHARK="${WIRESHARK:-}"
if [ -z "$WIRESHARK" ]; then
    if [ -x /Applications/Wireshark.app/Contents/MacOS/Wireshark ]; then
        WIRESHARK=/Applications/Wireshark.app/Contents/MacOS/Wireshark
    else
        WIRESHARK=$(command -v wireshark || true)
    fi
fi
[ -n "$WIRESHARK" ] || { echo "Wireshark not found (set WIRESHARK=/path/to/wireshark)"; exit 1; }

# With an argument: remote server via SSH; without: server on this machine
if [ $# -ge 1 ]; then
    # Run nc on the server and bring the stream back over SSH
    ssh "$1" "nc 127.0.0.1 $PORT" | "$WIRESHARK" -k -i -
else
    # -k: start capturing at once, -i -: read the pcap stream from stdin
    nc 127.0.0.1 "$PORT" | "$WIRESHARK" -k -i -
fi
