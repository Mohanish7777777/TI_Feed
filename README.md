# 🛡️ Threat Intel Master Feed

[![Threat Intel Aggregator](https://github.com/YOUR_USERNAME/YOUR_REPO/actions/workflows/threat-intel-aggregator.yml/badge.svg)](https://github.com/YOUR_USERNAME/YOUR_REPO/actions/workflows/threat-intel-aggregator.yml)
![IOC Count](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/.github/badges/ioc-count.json)

Auto-aggregated threat intelligence master feed pulling from **23 open-source feeds**, deduplicated and normalised into a single unified dataset. Refreshed every **6 hours** via GitHub Actions.

---

## 📥 Consume the Feed

| Format | URL | Best for |
|---|---|---|
| **JSON** (full metadata) | `feeds/latest/master_feed.json` | API integrations, enrichment pipelines |
| **CSV** (flat) | `feeds/latest/master_feed.csv` | SIEM ingest (QRadar, Splunk), Excel |
| **STIX 2.1** | `feeds/latest/master_feed.stix2.json` | TAXII / threat sharing platforms |
| **Plain IPs** | `feeds/latest/by_type/ipv4.txt` | Firewall blocklists, EDR |
| **Plain Domains** | `feeds/latest/by_type/domain.txt` | DNS sinkhole, proxy filters |
| **Plain URLs** | `feeds/latest/by_type/url.txt` | Web proxy, NGFW |
| **Hashes** | `feeds/latest/by_type/sha256.txt` | EDR / AV hash blocklists |

Raw URL pattern (replace branch/path as needed):
```
https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/feeds/latest/by_type/ipv4.txt
```

---

## 🔄 Sources (23 feeds)

| # | Feed | Category | Confidence |
|---|---|---|---|
| 1 | blocklist.de — all | attack | medium |
| 2 | blocklist.de — ssh | ssh-brute-force | medium |
| 3 | blocklist.de — mail | mail-attack | medium |
| 4 | blocklist.de — apache | web-attack | medium |
| 5 | blocklist.de — imap | imap-attack | medium |
| 6 | blocklist.de — ftp | ftp-attack | medium |
| 7 | blocklist.de — bots | botnet | medium |
| 8 | blocklist.de — strongips | persistent-attacker | **high** |
| 9 | blocklist.de — bruteforcelogin | web-brute-force | medium |
| 10 | EmergingThreats — compromised-ips | compromised | **high** |
| 11 | abuse.ch — Feodo Tracker | c2 / botnet C2 | **high** |
| 12 | abuse.ch — URLhaus (recent) | malware-url | **high** |
| 13 | abuse.ch — ThreatFox (recent) | threat (multi-type) | **high** |
| 14 | Jamesbrine — iplist | malicious-ip | medium |
| 15 | Jamesbrine — csv | malicious-ip | medium |
| 16 | Capelabs ThreatMesh | threat | medium |
| 17 | Spydisec stats | threat | medium |
| 18 | LinuxTracker — Hancitor IPs | malware-c2 | **high** |
| 19 | Bert-JanP Open Source Intel | aggregated | medium |
| 20 | Ziyadnz — hourly IPv4 | malicious-ip | medium |
| 21 | AlphaMountain community threat | threat (domains) | varies |
| 22 | Botvrij.eu | malicious-domain | medium |
| 23 | TweetFeed.live | osint / twitter | low |

---

## 🗂️ IOC Schema

Each IOC in `master_feed.json` has this structure:

```json
{
  "value":       "185.220.101.45",
  "ioc_type":    "ipv4",
  "sources":     ["blocklist.de/ssh", "ziyadnz/hourly-ipv4"],
  "tags":        ["blocklist.de", "ssh", "ziyadnz", "hourly"],
  "category":    "ssh-brute-force",
  "confidence":  "high",
  "first_seen":  "2026-04-24T06:00:00Z",
  "last_seen":   "2026-04-24T12:00:00Z",
  "description": "",
  "tlp":         "WHITE"
}
```

**Confidence logic:**
- `low` — single low-quality source (e.g. TweetFeed)
- `medium` — single medium-quality source
- `high` — 3+ sources corroborate, or source is inherently high-confidence (abuse.ch)

---

## 🚀 Running Locally

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO
cd YOUR_REPO
pip install -r requirements.txt

# Run with defaults (JSON + CSV + TXT, 10 workers)
python threat_intel_aggregator.py

# All formats, faster
python threat_intel_aggregator.py --formats json csv txt stix2 --workers 20

# List all configured feeds
python threat_intel_aggregator.py --list-feeds
```

Output will be in `./master_feed/`.

---

## ⚙️ Workflow Schedule

| Trigger | When |
|---|---|
| **Scheduled** | Every 6 hours (`0 */6 * * *`) |
| **Manual** | GitHub Actions UI → "Run workflow" (choose formats & workers) |
| **Push** | On changes to `threat_intel_aggregator.py` or the workflow file |

To change the schedule, edit `.github/workflows/threat-intel-aggregator.yml`:
```yaml
schedule:
  - cron: "0 */6 * * *"   # ← change this
```

---

## 📦 Archive

Daily snapshots are kept in `feeds/archive/YYYY-MM-DD/` for 7 days, then automatically pruned by the workflow.

---

## ⚠️ Legal & Usage

All feeds are sourced from publicly available, open-source threat intelligence. Review each upstream feed's license before using in commercial products. This aggregator does not modify, fabricate, or enhance any IOC — it only normalises and deduplicates.

TLP: WHITE — freely shareable.
