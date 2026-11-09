#!/usr/bin/env bash
# CampusShield - Stage 1: Gateway (traffic interception point)
# Turns this Ubuntu VM into the router between campus clients (LAN) and the internet (WAN).
# Usage: sudo ./setup-gateway.sh start | stop | status

set -euo pipefail

WAN_IF="${WAN_IF:-ens33}"            # internet side (VMware NAT)
LAN_IF="${LAN_IF:-ens160}"            # campus client side (Host-only)
LAN_NET="${LAN_NET:-192.168.74.0/24}" # campus client network

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root: sudo $0 ${1:-start}"
  exit 1
fi

# Add a rule only if it does not already exist (safe to run many times)
add_rule() { local t=$1; shift; iptables -t "$t" -C "$@" 2>/dev/null || iptables -t "$t" -A "$@"; }
# Delete a rule only if it exists
del_rule() { local t=$1; shift; iptables -t "$t" -C "$@" 2>/dev/null && iptables -t "$t" -D "$@" || true; }

RULES=(
  "nat POSTROUTING -s $LAN_NET -o $WAN_IF -j MASQUERADE"
  "filter FORWARD -i $LAN_IF -o $WAN_IF -s $LAN_NET -j ACCEPT"
  "filter FORWARD -i $WAN_IF -o $LAN_IF -d $LAN_NET -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
)

case "${1:-start}" in
  start)
    sysctl -qw net.ipv4.ip_forward=1
    for r in "${RULES[@]}"; do add_rule $r; done
    echo "[+] Gateway started: $LAN_NET ($LAN_IF) -> internet ($WAN_IF)"
    ;;
  stop)
    for r in "${RULES[@]}"; do del_rule $r; done
    sysctl -qw net.ipv4.ip_forward=0
    echo "[-] Gateway stopped"
    ;;
  status)
    echo "ip_forward = $(cat /proc/sys/net/ipv4/ip_forward)"
    echo "--- NAT (POSTROUTING) ---"; iptables -t nat -L POSTROUTING -n -v | grep -E "pkts|$LAN_NET" || true
    echo "--- FORWARD ---";           iptables -L FORWARD -n -v | grep -E "pkts|$LAN_NET" || true
    ;;
  *)
    echo "Usage: sudo $0 start | stop | status"; exit 1
    ;;
esac
