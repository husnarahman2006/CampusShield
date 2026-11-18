#!/usr/bin/env bash
# =============================================================================
# CampusShield - Demo and verification commands
#
# WHAT: Short names for the long commands used to PROVE that each module works.
#       Every check compares CampusShield's own output with an independent
#       tool (Wireshark/tshark), so the result does not rely on our code alone.
#
# USAGE (on the Ubuntu gateway, from the CampusShield folder):
#   sudo ./tests/demo.sh status    # health of every part of the system
#   sudo ./tests/demo.sh record    # start recording traffic on both network cards
#   sudo ./tests/demo.sh stop      # stop recording
#   sudo ./tests/demo.sh sni       # websites seen INSIDE vs websites that LEFT the gateway
#   sudo ./tests/demo.sh blocked   # every connection Suricata blocked
#   sudo ./tests/demo.sh flows     # Wireshark vs CampusShield packet counts, same connections
#
# Typical demo:  record -> (open websites on Kali) -> stop -> sni -> blocked -> flows
# =============================================================================

set -uo pipefail   # no "-e": a check that finds nothing should not stop the script

# --- Settings ----------------------------------------------------------------
LAN_IF="${LAN_IF:-ens160}"            # card facing the clients (inside)
WAN_IF="${WAN_IF:-ens33}"             # card facing the internet (outside)
CLIENT_IP="${CLIENT_IP:-192.168.74.20}"
EVE=/var/log/suricata/eve.json

# Repository folder = the folder above this script (tests/..).
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Data folder sits NEXT TO the repository (e.g. /home/ubuntu/campusshield-data),
# so captured traffic is never committed to GitHub. We do not use "~" because
# under sudo "~" means /root, not the user's home folder.
DATA_DIR="${DATA_DIR:-$(dirname "$REPO_DIR")/campusshield-data}"
LAN_PCAP="$DATA_DIR/lan.pcap"
WAN_PCAP="$DATA_DIR/wan.pcap"
PID_FILE="$DATA_DIR/.tcpdump.pids"

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root: sudo $0 ${1:-help}"
  exit 1
fi
mkdir -p "$DATA_DIR"

# Print a section title so the output is easy to read in front of the committee.
title() { echo; echo "=== $* ==="; }

# List the SNI of every TLS Client Hello in a capture file (one name per line).
# tls.handshake.type==1 means "Client Hello", the first message of every HTTPS
# connection, which carries the website name.
sni_list() {
  tshark -r "$1" -Y "tls.handshake.type==1" -T fields \
         -e tls.handshake.extensions_server_name 2>/dev/null | sed '/^$/d' | sort -u
}

case "${1:-help}" in

  status)
    title "Gateway"
    echo "IP forwarding: $(cat /proc/sys/net/ipv4/ip_forward)  (1 = gateway is routing)"
    echo "Boot service:  $(systemctl is-active campusshield)"
    title "Suricata and blocking"
    "$REPO_DIR/stage3-dpi-sni/blocking.sh" status | head -4
    title "Database"
    docker ps --filter name=campusshield-db --format "{{.Names}}: {{.Status}}"
    ;;

  record)
    if [[ -f "$PID_FILE" ]]; then
      echo "Already recording. Run: sudo $0 stop"; exit 1
    fi
    # One recording per card. Only HTTPS (TCP port 443) is kept, to keep the
    # files small and focused. -U writes each packet immediately, so the files
    # are complete even if recording is stopped suddenly.
    tcpdump -i "$LAN_IF" -U -w "$LAN_PCAP" tcp port 443 >/dev/null 2>&1 &
    echo $! >  "$PID_FILE"
    tcpdump -i "$WAN_IF" -U -w "$WAN_PCAP" tcp port 443 >/dev/null 2>&1 &
    echo $! >> "$PID_FILE"
    echo "[+] Recording on $LAN_IF (inside) and $WAN_IF (outside)."
    echo "    Now open websites on the client, then run: sudo $0 stop"
    ;;

  stop)
    if [[ ! -f "$PID_FILE" ]]; then
      echo "Not recording."; exit 0
    fi
    kill $(cat "$PID_FILE") 2>/dev/null
    rm -f "$PID_FILE"
    sleep 1
    echo "[-] Recording stopped."
    echo "    Inside  ($LAN_IF): $(tcpdump -r "$LAN_PCAP" 2>/dev/null | wc -l) packets -> $LAN_PCAP"
    echo "    Outside ($WAN_IF): $(tcpdump -r "$WAN_PCAP" 2>/dev/null | wc -l) packets -> $WAN_PCAP"
    echo "    Open in Wireshark with: wireshark $LAN_PCAP"
    ;;

  sni)
    # The key proof of blocking: a website that reached the INSIDE card but
    # never appeared on the OUTSIDE card was stopped by the gateway.
    [[ -f "$LAN_PCAP" && -f "$WAN_PCAP" ]] || { echo "No recording yet. Run: record, then stop."; exit 1; }
    sni_list "$LAN_PCAP" > "$DATA_DIR/.sni_in"
    sni_list "$WAN_PCAP" > "$DATA_DIR/.sni_out"
    title "Websites that ENTERED the gateway (Wireshark, $LAN_IF)"
    cat "$DATA_DIR/.sni_in"
    title "Websites that LEFT the gateway to the internet (Wireshark, $WAN_IF)"
    cat "$DATA_DIR/.sni_out"
    title "Stopped by CampusShield (entered but never left)"
    # comm -23 prints lines that are only in the first list.
    comm -23 "$DATA_DIR/.sni_in" "$DATA_DIR/.sni_out"
    ;;

  blocked)
    # Suricata's own record of every connection it blocked.
    title "Blocked connections (Suricata eve.json)"
    grep '"CampusShield BLOCK' "$EVE" 2>/dev/null | \
      jq -r '[.timestamp[11:19], .src_ip, .tls.sni, .alert.signature, .alert.action] | @tsv'
    title "Total blocked"
    grep -c '"CampusShield BLOCK' "$EVE" 2>/dev/null
    title "Blocked per website"
    grep '"CampusShield BLOCK' "$EVE" 2>/dev/null | jq -r '.tls.sni' | sort | uniq -c | sort -rn
    ;;

  flows)
    # Two different tools count the packets of the SAME connections:
    # Wireshark (from the recording) and CampusShield's flow records
    # (Suricata eve.json, read the same way as the Flow Aggregator).
    # Connections are matched by client port + server IP.
    # Suricata writes a flow record only after the connection ends, so wait
    # 1-2 minutes after opening the websites before running this.
    [[ -f "$LAN_PCAP" ]] || { echo "No recording yet. Run: record, then stop."; exit 1; }
    title "Packet counts: Wireshark vs CampusShield (same connections)"
    python3 "$REPO_DIR/tests/compare_flows.py" "$LAN_PCAP" "$CLIENT_IP" 10
    ;;

  *)
    sed -n '2,20p' "$0"   # print the explanation at the top of this file
    ;;
esac
