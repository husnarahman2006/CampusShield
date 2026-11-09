#!/usr/bin/env bash
# =============================================================================
# CampusShield - Stage 1: Gateway (traffic interception point)
#
# WHAT:  Turns this Ubuntu VM into a router between campus clients (LAN)
#        and the internet (WAN), like the router in a home or campus.
# WHY:   CampusShield can only inspect traffic that passes THROUGH it.
#        Once every client uses this machine as its gateway, Suricata can
#        read the TLS SNI of every connection on the LAN interface.
#
#   Kali client (192.168.74.20) --> [ens160  Ubuntu gateway  ens33] --> Internet
#                                    LAN side                 WAN side
#
# USAGE: sudo ./setup-gateway.sh start    # turn the gateway on
#        sudo ./setup-gateway.sh stop     # turn it off and remove the rules
#        sudo ./setup-gateway.sh status   # show rules and packet counters
# =============================================================================

# Stop the script immediately if any command fails (-e), if an unset variable
# is used (-u), or if any command inside a pipe fails (pipefail).
# This avoids leaving the firewall half-configured.
set -euo pipefail

# --- Network settings --------------------------------------------------------
# The ${VAR:-default} form means: use the value from the environment if given,
# otherwise use the default. So the same script works on another machine with:
#   sudo WAN_IF=eth0 LAN_IF=eth1 ./setup-gateway.sh start
WAN_IF="${WAN_IF:-ens33}"             # internet side (VMware NAT adapter)
LAN_IF="${LAN_IF:-ens160}"            # campus client side (Host-only adapter, vmxnet3)
LAN_NET="${LAN_NET:-192.168.74.0/24}" # campus client network (all client IPs)

# --- Root check --------------------------------------------------------------
# Changing kernel settings and firewall rules needs administrator rights.
# $EUID is the user id of whoever runs the script; root is always 0.
if [[ $EUID -ne 0 ]]; then
  echo "Please run as root: sudo $0 ${1:-start}"
  exit 1
fi

# --- Helper functions --------------------------------------------------------
# iptables -C checks whether a rule already exists.
# add_rule adds a rule only if it is missing, so running "start" twice does
# not create duplicate rules (this property is called "idempotent").
add_rule() { local t=$1; shift; iptables -t "$t" -C "$@" 2>/dev/null || iptables -t "$t" -A "$@"; }

# del_rule removes a rule only if it exists, so "stop" never shows errors.
del_rule() { local t=$1; shift; iptables -t "$t" -C "$@" 2>/dev/null && iptables -t "$t" -D "$@" || true; }

# --- The three gateway rules -------------------------------------------------
# Each entry is: <table> <chain> <match conditions> -j <action>
RULES=(
  # 1) NAT: replace the client's private IP (192.168.74.x) with the gateway's
  #    own WAN IP before the packet goes to the internet. The internet cannot
  #    reply to private IPs, so without this, clients get no answers.
  "nat POSTROUTING -s $LAN_NET -o $WAN_IF -j MASQUERADE"

  # 2) Allow NEW traffic going OUT: from the campus LAN to the internet.
  "filter FORWARD -i $LAN_IF -o $WAN_IF -s $LAN_NET -j ACCEPT"

  # 3) Allow only REPLIES coming back IN. conntrack remembers every connection
  #    a client opened; ESTABLISHED/RELATED lets only answers to those through.
  #    The internet cannot start a new connection to a campus client.
  "filter FORWARD -i $WAN_IF -o $LAN_IF -d $LAN_NET -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
)

# --- Main: decide what to do from the first argument (default: start) ------
case "${1:-start}" in
  start)
    # ip_forward=1 lets the Linux kernel pass packets from one network card
    # to another. By default Linux drops them (it is not a router by default).
    sysctl -qw net.ipv4.ip_forward=1
    # $r is left unquoted on purpose so it splits into separate words
    # (table, chain, options) for add_rule.
    for r in "${RULES[@]}"; do add_rule $r; done
    echo "[+] Gateway started: $LAN_NET ($LAN_IF) -> internet ($WAN_IF)"
    ;;
  stop)
    for r in "${RULES[@]}"; do del_rule $r; done
    sysctl -qw net.ipv4.ip_forward=0
    echo "[-] Gateway stopped"
    ;;
  status)
    # Packet counters (pkts) that increase prove client traffic is passing
    # through this gateway.
    echo "ip_forward = $(cat /proc/sys/net/ipv4/ip_forward)"
    echo "--- NAT (POSTROUTING) ---"; iptables -t nat -L POSTROUTING -n -v | grep -E "pkts|$LAN_NET" || true
    echo "--- FORWARD ---";           iptables -L FORWARD -n -v | grep -E "pkts|$LAN_NET" || true
    ;;
  *)
    echo "Usage: sudo $0 start | stop | status"; exit 1
    ;;
esac
