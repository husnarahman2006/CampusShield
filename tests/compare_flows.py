#!/usr/bin/env python3
"""
CampusShield - Flow comparison (Wireshark vs Flow Aggregator)

WHAT: For the same connections, puts two independent packet counts side by side:
        1. Wireshark (tshark) counting packets in the recording lan.pcap
        2. Suricata's flow records, which the Flow Aggregator reads from eve.json
      A connection is matched by its client port + server IP, which is unique
      for each connection.

WHY:  If two different tools count the same packets for the same connection,
      the Flow Aggregator's numbers can be trusted. This is the proof for
      Stage 1 (packet capture and flow aggregation).

USAGE: sudo python3 tests/compare_flows.py <lan.pcap> [client_ip] [max_rows]
"""

import json        # eve.json is one JSON object per line
import subprocess  # runs tshark
import sys

EVE = "/var/log/suricata/eve.json"


def wireshark_conversations(pcap):
    """Return {(client_port, server_ip): (packets_out, packets_in)} from tshark.

    tshark's "conv,tcp" table prints one line per TCP connection, e.g.
      192.168.74.20:51402  <->  57.144.149.32:443   5705 8,363 kB   1503 97 kB ...
    Column "<-" = packets from server to client (in),
    column "->" = packets from client to server (out).
    Each byte count is two words (number + unit), so the "->" frames are word 6.
    """
    out = subprocess.run(["tshark", "-r", pcap, "-q", "-z", "conv,tcp"],
                         capture_output=True, text=True).stdout
    convs = {}
    for line in out.splitlines():
        words = line.split()
        if len(words) < 7 or words[1] != "<->":
            continue                       # skip headers and separator lines
        client, server = words[0], words[2]
        try:
            pkts_in = int(words[3].replace(",", ""))
            pkts_out = int(words[6].replace(",", ""))
        except ValueError:
            continue
        client_port = client.rsplit(":", 1)[1]
        server_ip = server.rsplit(":", 1)[0]
        convs[(client_port, server_ip)] = (pkts_out, pkts_in)
    return convs


def suricata_flows(client_ip):
    """Return {(client_port, server_ip): (packets_out, packets_in)} from eve.json flow events."""
    flows = {}
    with open(EVE, encoding="utf-8", errors="replace") as f:
        for line in f:
            if '"event_type":"flow"' not in line:
                continue                   # quick filter before parsing JSON
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if e.get("src_ip") != client_ip or e.get("proto") != "TCP":
                continue
            fl = e.get("flow", {})
            key = (str(e.get("src_port")), e.get("dest_ip"))
            out_, in_ = fl.get("pkts_toserver", 0), fl.get("pkts_toclient", 0)
            # A connection that stays idle for a long time (e.g. a browser's
            # background push connection) is closed by Suricata's flow timeout,
            # and a NEW flow record starts when traffic resumes. Both records
            # belong to the same TCP connection, so their counts are added.
            old = flows.get(key, (0, 0))
            flows[key] = (old[0] + out_, old[1] + in_)
    return flows


def classify(w, c):
    """Explain the result for one connection.

    w = Wireshark (out, in), c = CampusShield (out, in).
      MATCH    - both tools counted exactly the same packets.
      BLOCKED  - same packets from the client, but CampusShield counted MORE
                 packets from the server: those server replies reached the
                 gateway, Suricata counted them and then DROPPED them, so they
                 never reached the LAN card where Wireshark was recording.
      PARTIAL  - CampusShield counted more in both directions: the connection
                 started before or ended after the Wireshark recording, so
                 Wireshark saw only part of it while Suricata saw all of it.
      OTHER    - any other difference (should be rare; check by hand).
    """
    if w == c:
        return "MATCH"
    if w[0] == c[0] and c[1] > w[1]:
        return "BLOCKED"
    if c[0] >= w[0] and c[1] >= w[1]:
        return "PARTIAL"
    return "OTHER"


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    pcap = sys.argv[1]
    client_ip = sys.argv[2] if len(sys.argv) > 2 else "192.168.74.20"
    max_rows = int(sys.argv[3]) if len(sys.argv) > 3 else 10

    ws = wireshark_conversations(pcap)
    fa = suricata_flows(client_ip)
    common = [k for k in ws if k in fa]
    # Show the biggest connections first: they are the most convincing.
    common.sort(key=lambda k: sum(ws[k]), reverse=True)

    print(f"{'Server':<17}{'Port':>7} | {'Wireshark out/in':>17} | {'CampusShield out/in':>20} | Result")
    print("-" * 80)
    for key in common[:max_rows]:
        port, server = key
        w, c = ws[key], fa[key]
        print(f"{server:<17}{port:>7} | {w[0]:>8}/{w[1]:<8} | {c[0]:>9}/{c[1]:<10} | {classify(w, c)}")
    print("-" * 80)

    # Summary over ALL matched connections (not only the rows shown).
    counts = {"MATCH": 0, "BLOCKED": 0, "PARTIAL": 0, "OTHER": 0}
    for key in common:
        counts[classify(ws[key], fa[key])] += 1
    total = len(common)
    print(f"Connections found by both tools: {total}")
    for name, n in counts.items():
        pct = 100 * n / total if total else 0
        print(f"  {name:<8} {n:>4}  ({pct:.1f}%)")
    explained = counts["MATCH"] + counts["BLOCKED"] + counts["PARTIAL"]
    if total:
        print(f"Matching or explained: {explained}/{total} ({100 * explained / total:.1f}%)")


if __name__ == "__main__":
    main()
