#!/usr/bin/env bash
# =============================================================================
# CampusShield - SNI Blocking (Stage 3 enforcement, proof of concept)
#
# WHAT: Switches Suricata from "watch only" (IDS) to "watch and block" (IPS)
#       and blocks every connection whose TLS SNI is in a blocked category.
#
# HOW:
#   1. generate_block_rules.py reads the blocked domains from the database
#      and writes Suricata "drop" rules that match the SNI.
#   2. Suricata is restarted in NFQUEUE mode (-q 0). In this mode the Linux
#      kernel hands every forwarded packet to Suricata and waits for its
#      verdict: accept (packet continues) or drop (packet is thrown away).
#   3. iptables sends client traffic to that queue.
#   4. QUIC (HTTP/3 over UDP port 443) is dropped, so browsers and apps fall
#      back to normal HTTPS over TCP, where the SNI can be read and blocked.
#
#   Kali -> gateway -> NFQUEUE -> Suricata: SNI blocked? -> drop / accept -> internet
#
# USAGE: sudo ./blocking.sh enable    # start blocking
#        sudo ./blocking.sh disable   # back to watch-only mode
#        sudo ./blocking.sh status    # show mode, rules and recent blocks
#        sudo ./blocking.sh resume    # after a reboot: re-add the queue rules only
#        sudo ./blocking.sh pause     # remove the queue rules only (Suricata unchanged)
# resume and pause are used by the campusshield.service boot service.
#
# Run the gateway first:  sudo ./gateway/setup-gateway.sh start
# =============================================================================

set -euo pipefail

# --- Settings (same names and values as the gateway script) ------------------
WAN_IF="${WAN_IF:-ens33}"
LAN_IF="${LAN_IF:-ens160}"
LAN_NET="${LAN_NET:-192.168.74.0/24}"
QUEUE=0                                        # NFQUEUE number Suricata listens on

SURICATA_YAML=/etc/suricata/suricata.yaml
RULE_FILE=/etc/suricata/rules/campusshield.rules
# A systemd "drop-in" file changes how the Suricata service starts, without
# editing the package's own service file (so updates do not overwrite it).
OVERRIDE_DIR=/etc/systemd/system/suricata.service.d
OVERRIDE_FILE=$OVERRIDE_DIR/campusshield-ips.conf
EVE=/var/log/suricata/eve.json

# Folder of this script, so it can find generate_block_rules.py next to it.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root: sudo $0 ${1:-status}"
  exit 1
fi

# --- iptables rules for IPS mode --------------------------------------------
# --queue-bypass: if Suricata is not running, packets are ACCEPTED instead of
# being dropped. This keeps the lab network usable if Suricata crashes
# ("fail-open"). A production deployment could remove it to "fail-closed".
IPS_RULES=(
  # 1) Drop QUIC from clients so traffic falls back to TCP + TLS (SNI visible).
  "FORWARD -i $LAN_IF -o $WAN_IF -s $LAN_NET -p udp --dport 443 -j DROP"
  # 2) Client -> internet traffic goes to Suricata for a verdict.
  "FORWARD -i $LAN_IF -o $WAN_IF -s $LAN_NET -j NFQUEUE --queue-num $QUEUE --queue-bypass"
  # 3) Replies from the internet also go to Suricata (it needs both directions
  #    to follow the TLS handshake). Only replies: new inbound connections are
  #    not matched here and are still dropped by the FORWARD policy.
  "FORWARD -i $WAN_IF -o $LAN_IF -d $LAN_NET -m conntrack --ctstate RELATED,ESTABLISHED -j NFQUEUE --queue-num $QUEUE --queue-bypass"
)

add_ips_rules() {
  # Insert in reverse order at position 1, so the final order is 1, 2, 3
  # and all three sit ABOVE the gateway's normal ACCEPT rules.
  for (( i=${#IPS_RULES[@]}-1; i>=0; i-- )); do
    # shellcheck disable=SC2086
    iptables -C ${IPS_RULES[$i]} 2>/dev/null || iptables -I ${IPS_RULES[$i]/FORWARD/FORWARD 1}
  done
}

del_ips_rules() {
  for r in "${IPS_RULES[@]}"; do
    # shellcheck disable=SC2086
    while iptables -C $r 2>/dev/null; do iptables -D $r; done
  done
}

wait_for_suricata() {
  # Loading 69,000+ rules takes time; wait up to 120 s for the service.
  for _ in $(seq 1 60); do
    systemctl is-active --quiet suricata && return 0
    sleep 2
  done
  echo "[!] Suricata did not start. Check: sudo journalctl -u suricata -n 30"
  return 1
}

case "${1:-status}" in
  enable)
    # The gateway must already be forwarding traffic.
    if [[ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]]; then
      echo "[!] Gateway is not running. First run: sudo ./gateway/setup-gateway.sh start"
      exit 1
    fi

    # Step 1: build the block rules from the database.
    mkdir -p "$(dirname "$RULE_FILE")"
    python3 "$SCRIPT_DIR/generate_block_rules.py" --out "$RULE_FILE"

    # Step 2: make sure Suricata loads our rule file (added once, under rule-files:).
    if ! grep -q "$RULE_FILE" "$SURICATA_YAML"; then
      sed -i "/^rule-files:/a\\  - $RULE_FILE" "$SURICATA_YAML"
      echo "[+] Added $RULE_FILE to $SURICATA_YAML"
    fi

    # Step 3: test the configuration BEFORE restarting, so a mistake never
    # leaves the gateway without a running Suricata.
    suricata -T -c "$SURICATA_YAML" >/dev/null \
      || { echo "[!] Suricata configuration test failed. Nothing was changed."; exit 1; }

    # Step 4: start Suricata in NFQUEUE (IPS) mode instead of AF_PACKET (IDS).
    # The empty "ExecStart=" clears the original command; the next line replaces it.
    mkdir -p "$OVERRIDE_DIR"
    cat > "$OVERRIDE_FILE" <<CONF
[Service]
ExecStart=
ExecStart=/usr/bin/suricata -D -q $QUEUE -c $SURICATA_YAML --pidfile /run/suricata.pid
CONF
    systemctl daemon-reload
    systemctl restart suricata
    wait_for_suricata

    # Step 5: send client traffic to Suricata and block QUIC.
    add_ips_rules
    echo "[+] Blocking ENABLED: Suricata is in IPS mode on NFQUEUE $QUEUE"
    ;;

  disable)
    # Remove the queue rules first, so traffic flows normally straight away.
    del_ips_rules
    # Return Suricata to its original AF_PACKET (watch-only) start command.
    rm -f "$OVERRIDE_FILE"
    systemctl daemon-reload
    systemctl restart suricata
    wait_for_suricata
    # The drop rules stay in the rule file; in watch-only mode they only raise
    # alerts ("would have blocked"), which is useful for reporting.
    echo "[-] Blocking DISABLED: Suricata is back in watch-only (IDS) mode"
    ;;

  resume)
    # iptables rules are lost on reboot, but the Suricata IPS setting is not
    # (it is a file). So after a reboot only the queue rules need adding back,
    # and only if blocking was enabled before.
    if [[ -f "$OVERRIDE_FILE" ]]; then
      wait_for_suricata
      add_ips_rules
      echo "[+] Blocking resumed"
    else
      echo "[i] Blocking is not enabled; nothing to resume"
    fi
    ;;

  pause)
    del_ips_rules
    echo "[-] Queue rules removed (blocking paused)"
    ;;

  status)
    if [[ -f "$OVERRIDE_FILE" ]]; then
      echo "Mode: IPS (blocking)"
    else
      echo "Mode: IDS (watch only)"
    fi
    echo "Suricata service: $(systemctl is-active suricata)"
    if [[ -f "$RULE_FILE" ]]; then
      echo "Block rules: $(grep -c '^drop' "$RULE_FILE")"
    fi
    echo "--- Queue rules (pkts = packets checked by Suricata) ---"
    iptables -L FORWARD -n -v | grep -E "pkts|NFQUEUE|udp dpt:443" || true
    echo "--- Last 5 blocked connections ---"
    grep '"CampusShield BLOCK' "$EVE" 2>/dev/null | tail -5 | \
      python3 -c 'import sys, json
for line in sys.stdin:
    e = json.loads(line)
    print(e["timestamp"][11:19], e.get("src_ip"), "->", e.get("tls", {}).get("sni", "?"),
          "|", e["alert"]["signature"], "|", e["alert"].get("action"))' || true
    ;;

  *)
    echo "Usage: sudo $0 enable | disable | status | resume | pause"
    exit 1
    ;;
esac
