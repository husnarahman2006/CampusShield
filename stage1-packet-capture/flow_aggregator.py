#!/usr/bin/env python3
"""
CampusShield - Flow Aggregator (Stage 1: Packet Capture & Flow Aggregation)

WHAT: Reads Suricata's eve.json and turns its "flow" events into clean
      flow records. A flow is one connection, identified by its 5-tuple:
      source IP, source port, destination IP, destination port, protocol.
      For each flow it records packets, bytes and duration in both directions.

WHY:  Packet capture is done by Suricata on the gateway's LAN interface
      (AF_PACKET, a kernel-level capture method). Suricata already groups
      packets into flows; this script extracts those flows in a fixed format.
      These flow records are:
        - the input for Stage 4 (the ML classifier needs packet counts,
          sizes and durations to detect VPN/tunnel traffic), and
        - the per-connection log that Stage 5 will store and report.

USAGE:
  sudo python3 flow_aggregator.py                 # read the whole file once
  sudo python3 flow_aggregator.py --follow        # live mode (like tail -f)
  sudo python3 flow_aggregator.py --csv out.csv   # also save results to CSV

sudo is needed because /var/log/suricata/eve.json is readable only by root.
"""

# Only Python standard library modules are used, so nothing needs installing.
import argparse   # reads command-line options like --follow and --csv
import csv        # writes the results as a CSV file
import json       # every line of eve.json is one JSON object
import os         # checks files and moves to the end of a file
import sys        # prints messages to the error stream and exits
import time       # waits while waiting for new log lines
from datetime import datetime  # converts Suricata's time strings to real times

DEFAULT_EVE = "/var/log/suricata/eve.json"

# Column order of every flow record (and of the CSV file).
FIELDS = [
    "start", "src_ip", "src_port", "dest_ip", "dest_port", "proto", "app_proto",
    "pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient",
    "duration_s", "avg_pkt_size", "state", "flow_id",
]


def parse_time(value):
    """Turn a Suricata timestamp (e.g. 2026-11-09T22:23:12.123456+0500) into a datetime, or None."""
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z")
    except (TypeError, ValueError):
        return None


def parse_line(line):
    """Turn one eve.json line into a flow record, or None if it is not a flow event."""
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return None                      # skip broken lines instead of crashing

    # eve.json also has tls, dns, alert, stats ... events. Stage 1 wants flows only.
    if event.get("event_type") != "flow":
        return None

    flow = event.get("flow", {})
    pkts_ts = flow.get("pkts_toserver", 0)    # packets client -> server
    pkts_tc = flow.get("pkts_toclient", 0)    # packets server -> client
    bytes_ts = flow.get("bytes_toserver", 0)
    bytes_tc = flow.get("bytes_toclient", 0)

    # Duration = end time - start time, in seconds.
    # Why: the ML classifier uses duration (VPN tunnels stay open for a long time).
    start, end = parse_time(flow.get("start")), parse_time(flow.get("end"))
    duration = round((end - start).total_seconds(), 3) if start and end else 0.0

    # Average packet size = all bytes / all packets.
    # Why: packet size is one of the main features for spotting encrypted tunnels.
    total_pkts = pkts_ts + pkts_tc
    avg_size = round((bytes_ts + bytes_tc) / total_pkts, 1) if total_pkts else 0.0

    return {
        "start": flow.get("start", ""),
        "src_ip": event.get("src_ip", ""),
        "src_port": event.get("src_port", ""),    # ICMP has no ports, so this may be empty
        "dest_ip": event.get("dest_ip", ""),
        "dest_port": event.get("dest_port", ""),
        "proto": event.get("proto", ""),          # TCP, UDP, ICMP ...
        "app_proto": event.get("app_proto", ""),  # tls, dns, http ... as Suricata detected it
        "pkts_toserver": pkts_ts,
        "pkts_toclient": pkts_tc,
        "bytes_toserver": bytes_ts,
        "bytes_toclient": bytes_tc,
        "duration_s": duration,
        "avg_pkt_size": avg_size,
        "state": flow.get("state", ""),           # e.g. closed, established
        "flow_id": event.get("flow_id", ""),      # same id as the SNI record of this connection
    }


def read_lines(path, follow):
    """Yield complete lines from the file. In follow mode, wait for new lines like tail -f."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        if follow:
            f.seek(0, os.SEEK_END)       # live mode: only new events
        buffer = ""
        while True:
            chunk = f.readline()
            if not chunk:
                if not follow:
                    break                # one-time mode: end of file, stop
                time.sleep(0.5)          # live mode: wait, then check again
                continue
            buffer += chunk
            if not buffer.endswith("\n"):
                continue                 # Suricata is still writing this line
            yield buffer
            buffer = ""


def show(r):
    """Print one flow as a readable line."""
    ts = r["start"][11:19]               # HH:MM:SS
    src = f"{r['src_ip']}:{r['src_port']}"
    dst = f"{r['dest_ip']}:{r['dest_port']}"
    print(f"{ts}  {r['proto']:<5} {src:<22} -> {dst:<22} {r['app_proto'] or '-':<6} "
          f"pkts {r['pkts_toserver']}/{r['pkts_toclient']}  "
          f"bytes {r['bytes_toserver']}/{r['bytes_toclient']}  {r['duration_s']}s", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Extract flow records from Suricata eve.json")
    parser.add_argument("--eve", default=DEFAULT_EVE, help="path to eve.json")
    parser.add_argument("--follow", action="store_true", help="keep reading new flows (live)")
    parser.add_argument("--csv", help="also write flows to this CSV file")
    parser.add_argument("--client", help="show only flows from this client IP, e.g. 192.168.74.20")
    args = parser.parse_args()

    if not os.path.exists(args.eve):
        sys.exit(f"eve.json not found: {args.eve}")

    writer, csv_file = None, None
    if args.csv:
        new_file = not os.path.exists(args.csv)
        csv_file = open(args.csv, "a", newline="", encoding="utf-8")   # append, never overwrite
        writer = csv.DictWriter(csv_file, fieldnames=FIELDS)
        if new_file:
            writer.writeheader()

    count = 0
    try:
        for line in read_lines(args.eve, args.follow):
            record = parse_line(line)
            if record is None:
                continue
            # --client filter: useful to see only the test client's traffic.
            if args.client and record["src_ip"] != args.client:
                continue
            show(record)
            if writer:
                writer.writerow(record)
                csv_file.flush()         # save now, so nothing is lost on Ctrl+C
            count += 1
    except KeyboardInterrupt:
        pass                             # Ctrl+C is the normal way to stop live mode
    finally:
        if csv_file:
            csv_file.close()
    print(f"\n[+] {count} flows", file=sys.stderr)


if __name__ == "__main__":
    main()
