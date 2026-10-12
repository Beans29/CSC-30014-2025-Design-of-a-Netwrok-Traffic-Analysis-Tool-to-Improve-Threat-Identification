# Passive Network Intrusion Detection System (NIDS)

A lightweight, passive network intrusion detection system with a live web dashboard. It sniffs traffic on a network interface, flags suspicious behaviour using rule-based detection, stores alerts in a local SQLite database, and displays everything in a real-time Flask dashboard.

Developed as my final year project for BSc (Hons) Computer Science (Cybersecurity) at Keele University.

<!-- Add a screenshot of the dashboard here, e.g. ![Dashboard](docs/dashboard.png) -->

## Features

- **Passive monitoring**: packets are only observed, never modified or injected.
- **Rule-based detection** for common network attacks and risky behaviour (see below).
- **Host discovery**: tracks IP/MAC pairs and when each host was last seen.
- **Asynchronous database writes**: a dedicated worker thread keeps packet processing fast.
- **Live dashboard**: alert table, charts, host list, uptime and search, refreshing every 3 seconds.
- **CSV export** of alerts from the dashboard.
- **Dark/light theme** toggle.
- **Privacy-minded design**: packets are not stored in memory (`store=0`) and alerts are automatically deleted after 7 days (GDPR-style data minimisation).
- **Offline-ready frontend**: Bootstrap, Chart.js and Font Awesome are served locally, so no CDN is needed.

## Detection Rules

| # | Detection | Severity | Logic |
|---|-----------|----------|-------|
| 1 | ARP spoofing | Critical | Gateway IP is seen with a different MAC address than previously observed |
| 2 | Blacklisted destination | Critical | Traffic to an IP listed in `blacklist.txt` |
| 3 | Land attack | Critical | Source and destination IP and port are identical |
| 4 | Volume spike | Investigative | More than 500 packets from one source IP within 10 seconds |
| 5 | Insecure protocols | Warning | Telnet (port 23) or FTP (port 21) traffic |
| 6 | Null scan | Warning | TCP packet with no flags set |
| 7 | Xmas scan | Warning | TCP packet with FIN, PSH and URG flags set |
| 8 | Port scan | Warning | More than 15 unique destination ports from one source within 10 seconds |

The default gateway is discovered automatically from Scapy's routing table.

## Architecture

```
┌──────────────┐    queue     ┌───────────────┐        ┌──────────────┐
│  sniffer.py  │ ───────────► │  DB worker    │ ─────► │  SQLite DB   │
│ (Scapy, root)│              │   (thread)    │        │ nids_logs.db │
└──────────────┘              └───────────────┘        └──────┬───────┘
                                                              │ read
                              ┌───────────────┐        ┌──────▼───────┐
                              │ Browser       │ ◄───── │   app.py     │
                              │ (index.html)  │  JSON  │ Flask :8880  │
                              └───────────────┘        └──────────────┘
```

The sniffer and the dashboard are two separate processes that communicate only through the SQLite database (WAL mode is enabled so reads and writes don't block each other).

## Project Structure

```
.
├── sniffer.py          # Packet capture and detection engine
├── app.py              # Flask web server and JSON API
├── blacklist.txt       # Blacklisted IPs, one per line (# for comments)
├── nids_logs.db        # SQLite database (created on first run)
├── templates/
│   └── index.html      # Dashboard page
└── static/
    ├── css/            # bootstrap.min.css, all.min.css
    ├── js/             # chart.js, bootstrap.bundle.min.js
    └── webfonts/       # Font Awesome fonts
```

## Requirements

- Python 3.8+
- Linux or macOS (packet capture needs raw socket access)
- Root/administrator privileges for the sniffer
- Python packages: `scapy`, `flask`

## Installation

```bash
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>

python3 -m venv venv
source venv/bin/activate
pip install scapy flask
```

## Configuration

**Network interface.** In `sniffer.py`, the interface defaults to `en0` on macOS and `eth0` otherwise. Change `IFACE_SNIFF` if yours differs (for example `wlan0`). You can list interfaces with `ip link` or `ifconfig`.

**Blacklist.** Create `blacklist.txt` next to `sniffer.py` with one IP per line:

```
# Known bad hosts
203.0.113.50
198.51.100.23
```

If the file is missing, a default list containing only `8.8.8.8` is used (handy for testing).

## Usage

Run the sniffer (needs root) in one terminal:

```bash
sudo python3 sniffer.py
```

Run the dashboard in another:

```bash
python3 app.py
```

Then open `http://localhost:8880` in your browser, or `http://<device-ip>:8880` from another machine on the same network.

If you use a virtual environment, run the sniffer with its interpreter, e.g. `sudo ./venv/bin/python sniffer.py`.

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Dashboard page |
| `GET /api/alerts` | Latest 50 alerts |
| `GET /api/stats` | Alert counts by type and protocol, top 5 source IPs, host count, uptime |
| `GET /api/hosts` | Discovered hosts (IP, MAC, last seen) |

## Database Schema

- `alerts`: `id`, `timestamp`, `src_ip`, `dst_ip`, `protocol`, `alert_type`, `description`
- `hosts`: `ip` (primary key), `mac`, `last_seen`
- `metadata`: `key`, `value` (stores the sniffer start time for uptime)

## Testing the Detections

Only test on networks you own or have explicit permission to test. From a separate machine on the same network, you can trigger some alerts with tools such as `nmap`:

```bash
nmap -sN <target-ip>      # Null scan
nmap -sX <target-ip>      # Xmas scan
nmap -p 1-100 <target-ip> # Port scan
```

Visiting or pinging an IP listed in `blacklist.txt` will trigger the blacklist alert.

## Limitations

- Detection is signature/threshold based, so it cannot catch novel attacks and may produce false positives (for example, legitimate traffic bursts triggering the volume rule).
- Thresholds (500 packets/10 s, 15 ports/10 s) are hard-coded and may need tuning for your network.
- The sniffer only sees traffic that reaches the monitored interface; on switched networks, use a mirror/SPAN port for wider visibility.
- The dashboard has no authentication and listens on `0.0.0.0`, so only run it on trusted networks or place it behind a reverse proxy with access control.
- IPv6 traffic is not analysed.

## Future Work

- Configurable thresholds via a config file
- Authentication for the dashboard
- IPv6 support
- Additional detections (DNS tunnelling, SYN floods, ICMP floods)
- Email/Telegram alert notifications

## Ethical Use

This tool is intended for learning, research and defending networks you own or are authorised to monitor. Monitoring network traffic you do not have permission to inspect may be illegal.

## Acknowledgements

- [Scapy](https://scapy.net/)
- [Flask](https://flask.palletsprojects.com/)
- [Bootstrap](https://getbootstrap.com/)
- [Chart.js](https://www.chartjs.org/)
- [Font Awesome](https://fontawesome.com/)

## Author

Edward Baines, Keele University

## License

Add a licence here (e.g. MIT) and include a `LICENSE` file in the repo.
