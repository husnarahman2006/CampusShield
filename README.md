# CampusShield: Next-Generation Smart Campus Firewall

CampusShield is a Layer-7 campus firewall that identifies and blocks social media and video streaming during class time **without decrypting traffic**. It reads the website name (Server Name Indication, SNI) from the TLS handshake, which stays visible even in TLS 1.3, and decides whether to allow or block the connection.

Final Year Project, BS Computer Science, Bahria University Islamabad.

## How it works

```
Student device ──> CampusShield gateway ──> Internet
                     │
                     ├─ Stage 1  Gateway: all client traffic passes through here
                     ├─ Stage 2  Identity & timetable: who is the user, is a class running?
                     ├─ Stage 3  Deep Packet Inspection: read the SNI, find the category, block
                     ├─ Stage 4  AI classifier: detect VPN / tunnel traffic with no SNI
                     └─ Stage 5  Action & reporting: role- and time-based decisions, dashboard
```

## Status

| Stage | Module | Status |
|---|---|---|
| 1 | Gateway (IP forwarding, NAT, stateful rules) | Done |
| 1 | Flow aggregation (5-tuple flow records) | Done |
| 2 | PostgreSQL database (users, sessions, timetable, categories, policies) | Done |
| 2 | Captive portal and timetable matcher | Planned |
| 3 | Suricata inspection on the LAN interface | Done |
| 3 | SNI extraction and categorisation | Done |
| 3 | SNI-based blocking (Suricata IPS mode, rules from the database) | Done |
| 4 | Machine-learning flow classifier | Planned (FYP-2) |
| 5 | Policy engine and Flutter dashboard | Planned (FYP-2) |

## Repository structure

| Path | Contents |
|---|---|
| `gateway/setup-gateway.sh` | Turns the Ubuntu VM into the campus gateway (`start`, `stop`, `status`) |
| `gateway/campusshield.service` | Boot service: starts the gateway and blocking after every reboot |
| `stage1-packet-capture/flow_aggregator.py` | Extracts flow records (packets, bytes, duration) from Suricata |
| `stage2-identity-matcher/` | Docker Compose file and database schema / starting data |
| `stage3-dpi-sni/sni_extractor.py` | Extracts the SNI of every TLS connection and assigns a category |
| `stage3-dpi-sni/generate_block_rules.py` | Builds Suricata block rules from the database |
| `stage3-dpi-sni/blocking.sh` | Turns blocking on or off (`enable`, `disable`, `status`) |
| `config/suricata/suricata.yaml` | Suricata configuration used by the gateway |
| `docs/` | Setup guides and project documents |

Every script contains comments that explain what each part does and why.

## Lab setup

| Machine | Role | Address |
|---|---|---|
| Ubuntu 24.04 VM | CampusShield gateway | LAN `192.168.74.10` (ens160), WAN via VMware NAT (ens33) |
| Kali Linux VM | Campus client used for testing | `192.168.74.20`, gateway `192.168.74.10` |

Tools: Suricata 7.0.3, PostgreSQL 16 (Docker), Python 3, iptables, VMware Workstation.

## Quick start (on the gateway/ubuntu)

```bash
# 1. Database
cd stage2-identity-matcher
cp .env.example .env            # set a password in .env
docker compose up -d
cd ..

# 2. Gateway and blocking
sudo ./gateway/setup-gateway.sh start
sudo ./stage3-dpi-sni/blocking.sh enable
sudo ./stage3-dpi-sni/blocking.sh status

# 3. Start automatically after every reboot
sudo cp gateway/campusshield.service /etc/systemd/system/
sudo systemctl enable --now campusshield
```

## Test from the client (on kali)

```bash
curl -m 10 -sI https://www.facebook.com  && echo ALLOW || echo BLOCK   # BLOCK
curl -m 10 -sI https://www.bahria.edu.pk && echo ALLOW || echo BLOCK   # ALLOW
```

Every blocked connection is recorded by Suricata in `/var/log/suricata/eve.json` with the client address, the SNI and the rule that blocked it.

## Author

Husna Rahman, supervised by Mr. Ihtisham Ullah.
