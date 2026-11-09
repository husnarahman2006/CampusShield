#!/usr/bin/env python3
"""
CampusShield - SNI Extractor (Step 2, Stage 3: DPI / SNI)

WHAT: Reads Suricata's eve.json log, keeps only TLS events, and extracts
      who visited which domain: time, client IP, server IP, SNI, TLS version.
      Each domain is given a category (social-media, video-streaming, ...).

WHY:  HTTPS content is encrypted, but in the TLS "Client Hello" the browser
      still sends the website name in plain text (SNI = Server Name
      Indication), even with TLS 1.3. Suricata reads it and writes it to
      eve.json. This script turns those raw log lines into clean records
      that CampusShield can store (Step 3: PostgreSQL) and block on.

USAGE:
  sudo python3 sni_extractor.py                 # read the whole file once
  sudo python3 sni_extractor.py --follow        # live mode (like tail -f)
  sudo python3 sni_extractor.py --csv out.csv   # also save results to CSV
  sudo python3 sni_extractor.py --only-flagged  # hide uncategorized sites

sudo is needed because /var/log/suricata/eve.json is readable only by root.
"""

# Only Python standard library modules are used, so nothing needs installing.
import argparse   # reads command-line options like --follow and --csv
import csv        # writes the results as a spreadsheet-friendly CSV file
import json       # every line of eve.json is one JSON object
import os         # checks whether files exist, moves to the end of a file
import sys        # prints messages to the error stream and exits
import time       # waits (sleeps) while waiting for new log lines

# Default location where Suricata writes its JSON events on Ubuntu.
DEFAULT_EVE = "/var/log/suricata/eve.json"

# Domain -> category list.
# Why parent domains: one service uses many subdomains (www.facebook.com,
# m.facebook.com, static.xx.fbcdn.net). Matching the parent domain catches all.
# Why CDN domains too (fbcdn.net, googlevideo.com): the page itself may load
# from facebook.com, but images and videos come from these CDN domains.
# In Step 3 this list moves into the PostgreSQL database so the admin
# can edit it from the dashboard instead of changing code.
CATEGORIES = {
    "facebook.com": "social-media",
    "fbcdn.net": "social-media",
    "instagram.com": "social-media",
    "cdninstagram.com": "social-media",
    "tiktok.com": "social-media",
    "tiktokcdn.com": "social-media",
    "x.com": "social-media",
    "twitter.com": "social-media",
    "snapchat.com": "social-media",
    "youtube.com": "video-streaming",
    "googlevideo.com": "video-streaming",
    "ytimg.com": "video-streaming",
    "netflix.com": "video-streaming",
    "whatsapp.com": "messaging",
    "whatsapp.net": "messaging",
    "telegram.org": "messaging",
}

# Column order for the CSV file (also the fields of each record).
# flow_id is Suricata's unique id for one connection; it lets us link this
# record to other Suricata events (flow, alert) of the same connection.
FIELDS = ["timestamp", "src_ip", "dest_ip", "dest_port", "sni", "tls_version", "category", "flow_id"]


def categorize(sni):
    """Return the category of a domain, or 'uncategorized'."""
    # Domain names are case-insensitive, and a trailing dot is valid DNS,
    # so normalise before comparing.
    sni = sni.lower().rstrip(".")
    for domain, category in CATEGORIES.items():
        # Exact match (facebook.com) or a real subdomain (www.facebook.com).
        # We check "." + domain so that "notfacebook.com" does NOT match
        # "facebook.com" - this avoids false positives.
        if sni == domain or sni.endswith("." + domain):
            return category
    return "uncategorized"


def parse_line(line):
    """Turn one eve.json line into a record, or None if it is not useful."""
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        # A broken or half-written line must not crash the whole program.
        return None

    # eve.json also contains flow, dns, alert, stats ... events. We want TLS only.
    if event.get("event_type") != "tls":
        return None

    # .get() returns a default instead of crashing when a key is missing.
    tls = event.get("tls", {})
    sni = tls.get("sni")
    if not sni:
        # Some TLS connections have no SNI (e.g. direct-IP connections).
        # Those cannot be categorised by name, so they are skipped here.
        return None

    return {
        "timestamp": event.get("timestamp", ""),
        "src_ip": event.get("src_ip", ""),        # campus client
        "dest_ip": event.get("dest_ip", ""),      # website server
        "dest_port": event.get("dest_port", ""),  # usually 443 (HTTPS)
        "sni": sni,
        "tls_version": tls.get("version", ""),
        "category": categorize(sni),
        "flow_id": event.get("flow_id", ""),
    }


def read_lines(path, follow):
    """Yield complete lines from the file. In follow mode, wait for new lines like tail -f."""
    # errors="replace" stops one bad byte in the log from crashing the reader.
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        if follow:
            # Live mode only cares about NEW events, so jump to the end of the file.
            f.seek(0, os.SEEK_END)
        buffer = ""
        while True:
            chunk = f.readline()
            if not chunk:
                # No new data right now.
                if not follow:
                    break              # one-time mode: file finished, stop
                time.sleep(0.5)        # live mode: wait a little, then check again
                continue
            buffer += chunk
            # Suricata may still be writing a line; a complete line ends in "\n".
            # Keep collecting until the line is complete, then process it.
            if not buffer.endswith("\n"):
                continue
            yield buffer               # "yield" hands one line at a time to the caller
            buffer = ""


def show(record):
    """Print one record as a readable line on the screen."""
    ts = record["timestamp"][11:19]   # keep only HH:MM:SS from the full timestamp
    # :<15 and :<35 pad the text to a fixed width so columns line up.
    # flush=True prints immediately (important in live mode).
    print(f"{ts}  {record['src_ip']:<15} -> {record['sni']:<35} "
          f"{record['tls_version']:<8} [{record['category']}]", flush=True)


def main():
    # --- Read command-line options ---
    parser = argparse.ArgumentParser(description="Extract TLS SNI from Suricata eve.json")
    parser.add_argument("--eve", default=DEFAULT_EVE, help="path to eve.json")
    parser.add_argument("--follow", action="store_true", help="keep reading new events (live)")
    parser.add_argument("--csv", help="also write results to this CSV file")
    parser.add_argument("--only-flagged", action="store_true",
                        help="show only categorized (non 'uncategorized') domains")
    args = parser.parse_args()

    if not os.path.exists(args.eve):
        sys.exit(f"eve.json not found: {args.eve}")

    # --- Optional CSV output ---
    writer, csv_file = None, None
    if args.csv:
        new_file = not os.path.exists(args.csv)
        # "a" = append, so running the script again adds rows instead of erasing old ones.
        csv_file = open(args.csv, "a", newline="", encoding="utf-8")
        writer = csv.DictWriter(csv_file, fieldnames=FIELDS)
        if new_file:
            writer.writeheader()   # column names only once, at the top of a new file

    # --- Main loop: read -> parse -> filter -> show/save ---
    count = 0
    try:
        for line in read_lines(args.eve, args.follow):
            record = parse_line(line)
            if record is None:
                continue
            if args.only_flagged and record["category"] == "uncategorized":
                continue
            show(record)
            if writer:
                writer.writerow(record)
                csv_file.flush()   # save to disk now, so nothing is lost on Ctrl+C
            count += 1
    except KeyboardInterrupt:
        # Ctrl+C is the normal way to stop live mode; exit cleanly without an error trace.
        pass
    finally:
        # "finally" always runs, so the CSV file is always closed properly.
        if csv_file:
            csv_file.close()
    # Summary goes to stderr so it does not mix with the data output.
    print(f"\n[+] {count} TLS connections with SNI", file=sys.stderr)


# Run main() only when this file is executed directly,
# not when another Python file imports its functions (e.g. the Step 3 API).
if __name__ == "__main__":
    main()
