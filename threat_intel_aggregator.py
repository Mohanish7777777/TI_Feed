#!/usr/bin/env python3
"""
=============================================================================
  Threat Intel Master Feed Aggregator
  Fetches, parses, normalises, deduplicates and merges all known feeds into
  a single master feed with per-IOC metadata.
=============================================================================
"""

import re
import csv
import json
import time
import hashlib
import logging
import ipaddress
import requests
import argparse
import urllib.parse
from io import StringIO
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("ThreatIntelAggregator")

# ---------------------------------------------------------------------------
# IOC Types & Patterns
# ---------------------------------------------------------------------------
IOC_PATTERNS = {
    "ipv4":   re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "ipv6":   re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b'),
    "sha256": re.compile(r'\b[0-9a-fA-F]{64}\b'),
    "sha1":   re.compile(r'\b[0-9a-fA-F]{40}\b'),
    "md5":    re.compile(r'\b[0-9a-fA-F]{32}\b'),
    "url":    re.compile(
        r'https?://[^\s\'"<>]+',
        re.IGNORECASE
    ),
    "domain": re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
        r'+[a-zA-Z]{2,6}\b'
    ),
    "email":  re.compile(
        r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
    ),
    "cve":    re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE),
}

# Private/reserved ranges to skip when validating IPs
PRIVATE_RANGES = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
]

BENIGN_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "cloudflare.com", "github.com", "example.com", "localhost",
    "youtube.com", "facebook.com", "twitter.com", "wikipedia.org",
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class IOCRecord:
    value: str
    ioc_type: str
    sources: list = field(default_factory=list)
    tags: list = field(default_factory=list)
    category: str = ""          # e.g. ssh, mail, c2, malware, phishing
    confidence: str = "medium"  # low / medium / high
    first_seen: str = ""
    last_seen: str = ""
    description: str = ""
    tlp: str = "WHITE"

    # Merge another record into this one (same IOC, multiple sources)
    def merge(self, other: "IOCRecord"):
        for src in other.sources:
            if src not in self.sources:
                self.sources.append(src)
        for tag in other.tags:
            if tag not in self.tags:
                self.tags.append(tag)
        if other.category and not self.category:
            self.category = other.category
        if other.description and not self.description:
            self.description = other.description
        # Elevate confidence when seen in multiple sources
        if len(self.sources) >= 3:
            self.confidence = "high"
        elif len(self.sources) >= 2:
            self.confidence = "medium"
        # Track first/last seen
        if other.first_seen and (
            not self.first_seen or other.first_seen < self.first_seen
        ):
            self.first_seen = other.first_seen
        if other.last_seen and (
            not self.last_seen or other.last_seen > self.last_seen
        ):
            self.last_seen = other.last_seen


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------
NOW_ISO = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalise_ip(value: str) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(value.strip())
        if isinstance(addr, ipaddress.IPv4Address):
            for net in PRIVATE_RANGES:
                if addr in net:
                    return None
        return str(addr)
    except ValueError:
        return None


def normalise_domain(value: str) -> Optional[str]:
    d = value.strip().lower().rstrip(".")
    # Must have at least one dot and valid TLD
    if "." not in d or len(d) > 253:
        return None
    if d in BENIGN_DOMAINS:
        return None
    # Reject pure IPs parsed as domains
    try:
        ipaddress.ip_address(d)
        return None
    except ValueError:
        pass
    return d


def normalise_url(value: str) -> Optional[str]:
    try:
        p = urllib.parse.urlparse(value.strip())
        if p.scheme not in ("http", "https"):
            return None
        return value.strip()
    except Exception:
        return None


def normalise_hash(value: str, ioc_type: str) -> Optional[str]:
    return value.strip().lower()


NORMALISE = {
    "ipv4":   normalise_ip,
    "ipv6":   lambda v: str(ipaddress.ip_address(v.strip())) if v else None,
    "domain": normalise_domain,
    "url":    normalise_url,
    "sha256": lambda v: normalise_hash(v, "sha256"),
    "sha1":   lambda v: normalise_hash(v, "sha1"),
    "md5":    lambda v: normalise_hash(v, "md5"),
    "email":  lambda v: v.strip().lower(),
    "cve":    lambda v: v.strip().upper(),
}


def detect_and_normalise(raw: str) -> list[tuple[str, str]]:
    """Return list of (ioc_type, normalised_value) tuples for a raw string."""
    raw = raw.strip()
    results = []

    # Priority order: sha256 > sha1 > md5 > url > ipv4 > ipv6 > email > domain
    for ioc_type in ["cve", "sha256", "sha1", "md5", "url", "ipv4", "ipv6", "email", "domain"]:
        pattern = IOC_PATTERNS[ioc_type]
        for match in pattern.finditer(raw):
            val = match.group()
            try:
                norm = NORMALISE[ioc_type](val)
            except Exception:
                norm = None
            if norm:
                results.append((ioc_type, norm))

    # Deduplicate within this line
    seen = set()
    unique = []
    for t, v in results:
        if v not in seen:
            seen.add(v)
            unique.append((t, v))
    return unique


def make_record(value, ioc_type, source_name, category="", tags=None,
                description="", confidence="medium", tlp="WHITE") -> IOCRecord:
    return IOCRecord(
        value=value,
        ioc_type=ioc_type,
        sources=[source_name],
        tags=tags or [],
        category=category,
        confidence=confidence,
        first_seen=NOW_ISO,
        last_seen=NOW_ISO,
        description=description,
        tlp=tlp,
    )


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------
SESSION = requests.Session()
# Some feeds (e.g. blocklist.de) reject non-browser UAs; use a realistic one
SESSION.headers.update({
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/plain,text/html,application/json,*/*",
    "Accept-Encoding": "gzip, deflate, br",
})

# Per-domain UA overrides (some feeds require specific headers)
DOMAIN_HEADERS = {
    "feodotracker.abuse.ch": {"User-Agent": "ThreatIntelAggregator/1.0"},
    "urlhaus.abuse.ch":      {"User-Agent": "ThreatIntelAggregator/1.0"},
    "threatfox.abuse.ch":    {"User-Agent": "ThreatIntelAggregator/1.0"},
    "api.tweetfeed.live":    {"Accept": "application/json"},
}


def fetch(url: str, timeout: int = 30, retries: int = 2) -> Optional[str]:
    """Fetch a URL with retries and per-domain header overrides."""
    hostname = urllib.parse.urlparse(url).hostname or ""
    extra_headers = DOMAIN_HEADERS.get(hostname, {})
    for attempt in range(1, retries + 2):
        try:
            r = SESSION.get(url, timeout=timeout, headers=extra_headers)
            r.raise_for_status()
            return r.text
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code in (403, 429):
                wait = 2 ** attempt
                log.warning(
                    f"[FETCH {e.response.status_code}] {url} "
                    f"(attempt {attempt}/{retries+1}) — retry in {wait}s"
                )
                if attempt <= retries:
                    time.sleep(wait)
                    continue
            log.warning(f"[FETCH FAILED] {url} → {e}")
            return None
        except Exception as e:
            log.warning(f"[FETCH FAILED] {url} → {e}")
            return None
    return None


# ---------------------------------------------------------------------------
# Feed definitions
# ---------------------------------------------------------------------------
"""
Each feed entry is a dict with:
  name        : human-readable feed name
  url         : download URL
  fmt         : parser format key
  category    : IOC category label
  ioc_type    : override if feed contains only one IOC type
  tags        : list of tags
  confidence  : low / medium / high
  tlp         : TLP colour
  field       : CSV column name / JSON key (format-specific)
"""

FEEDS = [
    # ── blocklist.de ────────────────────────────────────────────────────────
    {
        "name": "blocklist.de/all",
        "url": "https://lists.blocklist.de/lists/all.txt",
        "fmt": "plaintext_ip",
        "category": "attack",
        "tags": ["blocklist.de", "brute-force"],
        "confidence": "medium",
    },
    {
        "name": "blocklist.de/ssh",
        "url": "https://lists.blocklist.de/lists/ssh.txt",
        "fmt": "plaintext_ip",
        "category": "ssh-brute-force",
        "tags": ["blocklist.de", "ssh"],
        "confidence": "medium",
    },
    {
        "name": "blocklist.de/mail",
        "url": "https://lists.blocklist.de/lists/mail.txt",
        "fmt": "plaintext_ip",
        "category": "mail-attack",
        "tags": ["blocklist.de", "spam", "mail"],
        "confidence": "medium",
    },
    {
        "name": "blocklist.de/apache",
        "url": "https://lists.blocklist.de/lists/apache.txt",
        "fmt": "plaintext_ip",
        "category": "web-attack",
        "tags": ["blocklist.de", "apache", "rfi", "ddos"],
        "confidence": "medium",
    },
    {
        "name": "blocklist.de/imap",
        "url": "https://lists.blocklist.de/lists/imap.txt",
        "fmt": "plaintext_ip",
        "category": "imap-attack",
        "tags": ["blocklist.de", "imap", "pop3"],
        "confidence": "medium",
    },
    {
        "name": "blocklist.de/ftp",
        "url": "https://lists.blocklist.de/lists/ftp.txt",
        "fmt": "plaintext_ip",
        "category": "ftp-attack",
        "tags": ["blocklist.de", "ftp"],
        "confidence": "medium",
    },
    {
        "name": "blocklist.de/bots",
        "url": "https://lists.blocklist.de/lists/bots.txt",
        "fmt": "plaintext_ip",
        "category": "botnet",
        "tags": ["blocklist.de", "bot", "irc-bot"],
        "confidence": "medium",
    },
    {
        "name": "blocklist.de/strongips",
        "url": "https://lists.blocklist.de/lists/strongips.txt",
        "fmt": "plaintext_ip",
        "category": "persistent-attacker",
        "tags": ["blocklist.de", "persistent"],
        "confidence": "high",
    },
    {
        "name": "blocklist.de/bruteforcelogin",
        "url": "https://lists.blocklist.de/lists/bruteforcelogin.txt",
        "fmt": "plaintext_ip",
        "category": "web-brute-force",
        "tags": ["blocklist.de", "wordpress", "joomla", "brute-force"],
        "confidence": "medium",
    },
    # ── Emerging Threats ────────────────────────────────────────────────────
    {
        "name": "EmergingThreats/compromised-ips",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "fmt": "plaintext_ip",
        "category": "compromised",
        "tags": ["emerging-threats", "compromised"],
        "confidence": "high",
    },
    # ── Feodo Tracker ───────────────────────────────────────────────────────
    {
        "name": "abuse.ch/feodotracker",
        "url": "https://feodotracker.abuse.ch/blocklist/?download=ipblocklist",
        "fmt": "plaintext_ip",
        "category": "c2",
        "tags": ["abuse.ch", "feodo", "botnet", "c2"],
        "confidence": "high",
    },
    # ── Jamesbrine ──────────────────────────────────────────────────────────
    {
        "name": "jamesbrine/iplist",
        "url": "https://jamesbrine.com.au/iplist.txt",
        "fmt": "plaintext_ip",
        "category": "malicious-ip",
        "tags": ["jamesbrine"],
        "confidence": "medium",
    },
    {
        "name": "jamesbrine/csv",
        "url": "https://jamesbrine.com.au/csv",
        "fmt": "csv_generic",
        "category": "malicious-ip",
        "tags": ["jamesbrine"],
        "confidence": "medium",
    },
    # ── Capelabs ThreatMesh ─────────────────────────────────────────────────
    {
        "name": "capelabs/threatmesh",
        "url": "https://raw.githubusercontent.com/capelabs/threatmesh-feed/refs/heads/main/feed.txt",
        "fmt": "plaintext_generic",
        "category": "threat",
        "tags": ["capelabs", "threatmesh"],
        "confidence": "medium",
    },
    # ── Spydisec ────────────────────────────────────────────────────────────
    {
        "name": "spydisec/stats",
        "url": "https://raw.githubusercontent.com/spydisec/spydithreatintel/refs/heads/main/stats.json",
        "fmt": "json_stats",
        "category": "threat",
        "tags": ["spydisec"],
        "confidence": "medium",
    },
    # ── LinuxTracker Hancitor ────────────────────────────────────────────────
    {
        "name": "linuxtracker/hancitor-ips",
        "url": "https://raw.githubusercontent.com/LinuxTracker/Blocklists/master/HancitorIPs.txt",
        "fmt": "plaintext_ip",
        "category": "malware-c2",
        "tags": ["hancitor", "malware", "c2"],
        "confidence": "high",
    },
    # ── Bert-JanP Open Source Threat Intel ──────────────────────────────────
    {
        "name": "bert-janp/threat-intel-feeds",
        "url": "https://raw.githubusercontent.com/Bert-JanP/Open-Source-Threat-Intel-Feeds/refs/heads/main/ThreatIntelFeeds.csv",
        "fmt": "csv_bert_janp",
        "category": "threat",
        "tags": ["bert-janp", "aggregated"],
        "confidence": "medium",
    },
    # ── Ziyadnz IP Feeds ─────────────────────────────────────────────────────
    {
        "name": "ziyadnz/hourly-ipv4",
        "url": "https://raw.githubusercontent.com/ziyadnz/threat-intel-ip-feeds/main/output/hourlyIPv4.txt",
        "fmt": "plaintext_ip",
        "category": "malicious-ip",
        "tags": ["ziyadnz", "hourly"],
        "confidence": "medium",
    },
    # ── AlphaMountain Community Threat ──────────────────────────────────────
    {
        "name": "alphamountain/community-threat",
        "url": "https://files.alphamountain.ai/alphaMountain-community-threat-1000.csv",
        "fmt": "csv_alphamountain",
        "category": "threat",
        "tags": ["alphamountain"],
        "confidence": "medium",
    },
    # ── Botvrij ─────────────────────────────────────────────────────────────
    {
        "name": "botvrij.eu",
        "url": "https://www.botvrij.eu/data/ioclist.domain.raw",
        "fmt": "plaintext_generic",
        "category": "malicious-domain",
        "tags": ["botvrij"],
        "confidence": "medium",
    },
    # ── TweetFeed.live ───────────────────────────────────────────────────────
    {
        "name": "tweetfeed.live/today",
        "url": "https://api.tweetfeed.live/v1/today",
        "fmt": "json_tweetfeed",
        "category": "threat",
        "tags": ["tweetfeed", "twitter", "osint"],
        "confidence": "low",
    },
    # ── URLhaus ─────────────────────────────────────────────────────────────
    {
        "name": "abuse.ch/urlhaus-recent",
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "fmt": "csv_urlhaus",
        "category": "malware-url",
        "tags": ["abuse.ch", "urlhaus", "malware", "url"],
        "confidence": "high",
    },
    # ── ThreatFox recent IOCs ────────────────────────────────────────────────
    {
        "name": "abuse.ch/threatfox-recent",
        "url": "https://threatfox.abuse.ch/export/csv/recent/",
        "fmt": "csv_threatfox",
        "category": "threat",
        "tags": ["abuse.ch", "threatfox"],
        "confidence": "high",
    },
]


# ---------------------------------------------------------------------------
# Parsers  (fmt → function(text, feed_def) → list[IOCRecord])
# ---------------------------------------------------------------------------

def parse_plaintext_ip(text: str, feed: dict) -> list:
    """Plain text files with one IP per line (comments with # or ;)."""
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        ip = normalise_ip(line.split()[0])
        if ip:
            records.append(make_record(ip, "ipv4", feed["name"],
                                       feed.get("category", ""),
                                       feed.get("tags", []),
                                       confidence=feed.get("confidence", "medium")))
    return records


def parse_plaintext_generic(text: str, feed: dict) -> list:
    """Generic plaintext – auto-detect IOC type per line."""
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        for ioc_type, value in detect_and_normalise(line):
            records.append(make_record(value, ioc_type, feed["name"],
                                       feed.get("category", ""),
                                       feed.get("tags", []),
                                       confidence=feed.get("confidence", "medium")))
    return records


def parse_csv_generic(text: str, feed: dict) -> list:
    """CSV where we auto-detect IOCs in every cell."""
    records = []
    try:
        reader = csv.reader(StringIO(text))
        for row in reader:
            for cell in row:
                for ioc_type, value in detect_and_normalise(cell):
                    records.append(make_record(value, ioc_type, feed["name"],
                                               feed.get("category", ""),
                                               feed.get("tags", []),
                                               confidence=feed.get("confidence", "medium")))
    except Exception as e:
        log.warning(f"[PARSE ERROR] {feed['name']}: {e}")
    return records


def parse_csv_bert_janp(text: str, feed: dict) -> list:
    """
    Bert-JanP ThreatIntelFeeds.csv — columns include FeedURL, Type, etc.
    We extract the feed URLs themselves as metadata references (not IOCs),
    but we do scan for any embedded IOCs in description columns.
    """
    records = []
    try:
        reader = csv.DictReader(StringIO(text))
        for row in reader:
            # Extract IOCs from all string fields
            for key, val in row.items():
                if val:
                    for ioc_type, value in detect_and_normalise(val):
                        # Skip URLs that are feed URLs themselves
                        if ioc_type == "url" and "github.com" in value:
                            continue
                        records.append(make_record(value, ioc_type, feed["name"],
                                                   feed.get("category", ""),
                                                   feed.get("tags", []),
                                                   confidence=feed.get("confidence", "medium")))
    except Exception as e:
        log.warning(f"[PARSE ERROR] {feed['name']}: {e}")
    return records


def parse_csv_alphamountain(text: str, feed: dict) -> list:
    """AlphaMountain CSV — domain,score format."""
    records = []
    try:
        reader = csv.reader(StringIO(text))
        for i, row in enumerate(reader):
            if i == 0:
                continue  # skip header
            if not row:
                continue
            domain = normalise_domain(row[0])
            if domain:
                score = float(row[1]) if len(row) > 1 else 0.0
                conf = "high" if score >= 80 else "medium" if score >= 50 else "low"
                rec = make_record(domain, "domain", feed["name"],
                                  feed.get("category", ""),
                                  feed.get("tags", []),
                                  confidence=conf)
                rec.description = f"alphamountain score: {score}"
                records.append(rec)
    except Exception as e:
        log.warning(f"[PARSE ERROR] {feed['name']}: {e}")
    return records


def parse_csv_urlhaus(text: str, feed: dict) -> list:
    """URLhaus CSV export — has id, dateadded, url, url_status, threat, tags, urlhaus_link."""
    records = []
    try:
        lines = [l for l in text.splitlines() if not l.startswith("#")]
        reader = csv.DictReader(StringIO("\n".join(lines)))
        for row in reader:
            url = normalise_url(row.get("url", ""))
            if url:
                tags = feed.get("tags", []) + [
                    t.strip() for t in (row.get("tags") or "").split(",") if t.strip()
                ]
                threat = row.get("threat", "")
                rec = make_record(url, "url", feed["name"],
                                  threat or feed.get("category", ""),
                                  tags, confidence="high",
                                  description=f"status={row.get('url_status','')} threat={threat}")
                rec.first_seen = row.get("dateadded", NOW_ISO)
                rec.last_seen = row.get("dateadded", NOW_ISO)
                records.append(rec)
                # Also extract domain/IP from URL
                parsed = urllib.parse.urlparse(url)
                host = parsed.hostname or ""
                ip = normalise_ip(host)
                if ip:
                    records.append(make_record(ip, "ipv4", feed["name"],
                                               threat or feed.get("category", ""),
                                               tags, confidence="high"))
                else:
                    dom = normalise_domain(host)
                    if dom:
                        records.append(make_record(dom, "domain", feed["name"],
                                                   threat or feed.get("category", ""),
                                                   tags, confidence="high"))
    except Exception as e:
        log.warning(f"[PARSE ERROR] {feed['name']}: {e}")
    return records


def parse_csv_threatfox(text: str, feed: dict) -> list:
    """ThreatFox recent CSV — ioc_id, ioc, threat_type, malware, confidence_level …"""
    records = []
    try:
        lines = [l for l in text.splitlines() if not l.startswith("#")]
        reader = csv.DictReader(StringIO("\n".join(lines)))
        for row in reader:
            raw_ioc = (row.get("ioc") or "").strip().strip('"')
            if not raw_ioc:
                continue
            conf_raw = row.get("confidence_level", "50")
            try:
                conf_val = int(conf_raw)
            except Exception:
                conf_val = 50
            conf = "high" if conf_val >= 75 else "medium" if conf_val >= 40 else "low"
            threat = row.get("threat_type", "")
            malware = row.get("malware", "")
            tags = feed.get("tags", []) + [t for t in [threat, malware] if t]
            for ioc_type, value in detect_and_normalise(raw_ioc):
                rec = make_record(value, ioc_type, feed["name"],
                                  threat or feed.get("category", ""),
                                  tags, confidence=conf,
                                  description=f"malware={malware}")
                rec.first_seen = row.get("first_seen", NOW_ISO)
                records.append(rec)
    except Exception as e:
        log.warning(f"[PARSE ERROR] {feed['name']}: {e}")
    return records


def parse_json_stats(text: str, feed: dict) -> list:
    """Spydisec stats.json — discover any IOCs in the JSON blob."""
    records = []
    try:
        data = json.loads(text)
        flat = json.dumps(data)   # flatten so regex can scan it
        for ioc_type, value in detect_and_normalise(flat):
            records.append(make_record(value, ioc_type, feed["name"],
                                       feed.get("category", ""),
                                       feed.get("tags", []),
                                       confidence=feed.get("confidence", "medium")))
    except Exception as e:
        log.warning(f"[PARSE ERROR] {feed['name']}: {e}")
    return records


def parse_json_tweetfeed(text: str, feed: dict) -> list:
    """TweetFeed API — returns list of {value, type, tags, tweet, user, date}."""
    records = []
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            data = data.get("data", data.get("results", []))
        for entry in data:
            raw = entry.get("value", "") or entry.get("ioc", "")
            ioc_type = (entry.get("type") or "").lower()
            tweet_tags = entry.get("tags", [])
            all_tags = feed.get("tags", []) + (
                tweet_tags if isinstance(tweet_tags, list) else [tweet_tags]
            )
            date = entry.get("date", NOW_ISO)
            for det_type, value in detect_and_normalise(raw):
                # Prefer declared type if consistent
                final_type = ioc_type if ioc_type in IOC_PATTERNS else det_type
                rec = make_record(value, final_type, feed["name"],
                                  feed.get("category", ""),
                                  all_tags, confidence="low",
                                  description=entry.get("tweet", ""))
                rec.first_seen = date
                rec.last_seen = date
                records.append(rec)
    except Exception as e:
        log.warning(f"[PARSE ERROR] {feed['name']}: {e}")
    return records


PARSERS = {
    "plaintext_ip":      parse_plaintext_ip,
    "plaintext_generic": parse_plaintext_generic,
    "csv_generic":       parse_csv_generic,
    "csv_bert_janp":     parse_csv_bert_janp,
    "csv_alphamountain": parse_csv_alphamountain,
    "csv_urlhaus":       parse_csv_urlhaus,
    "csv_threatfox":     parse_csv_threatfox,
    "json_stats":        parse_json_stats,
    "json_tweetfeed":    parse_json_tweetfeed,
}


# ---------------------------------------------------------------------------
# Core aggregation engine
# ---------------------------------------------------------------------------

def fetch_and_parse(feed: dict) -> list:
    log.info(f"[FETCH] {feed['name']} ← {feed['url']}")
    text = fetch(feed["url"])
    if not text:
        return []
    parser = PARSERS.get(feed["fmt"])
    if not parser:
        log.warning(f"[SKIP] Unknown parser '{feed['fmt']}' for {feed['name']}")
        return []
    try:
        records = parser(text, feed)
        log.info(f"[OK]   {feed['name']} → {len(records):,} records")
        return records
    except Exception as e:
        log.error(f"[ERROR] {feed['name']}: {e}")
        return []


def aggregate(
    feeds: list = FEEDS,
    max_workers: int = 10,
    skip_private: bool = True,
) -> dict:
    """
    Fetch all feeds in parallel, merge and deduplicate.
    Returns a dict of {normalised_value: IOCRecord}.
    """
    all_records: list[IOCRecord] = []

    with ThreadPoolExecutor(max_workers=max_workers) as exe:
        futures = {exe.submit(fetch_and_parse, f): f for f in feeds}
        for future in as_completed(futures):
            records = future.result()
            all_records.extend(records)

    log.info(f"Total raw records fetched: {len(all_records):,}")

    # Merge by (ioc_type, value) → deduplicate
    master: dict[str, IOCRecord] = {}
    for rec in all_records:
        key = f"{rec.ioc_type}:{rec.value}"
        if key in master:
            master[key].merge(rec)
        else:
            master[key] = rec

    log.info(f"Unique IOCs after deduplication: {len(master):,}")
    return master


# ---------------------------------------------------------------------------
# Export functions
# ---------------------------------------------------------------------------

def export_json(master: dict, path: str):
    data = {
        "generated_at": NOW_ISO,
        "total_iocs": len(master),
        "iocs": [asdict(rec) for rec in master.values()],
    }
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
    log.info(f"[EXPORT] JSON → {path}")


def export_csv(master: dict, path: str):
    fieldnames = [
        "value", "ioc_type", "category", "confidence", "tlp",
        "sources", "tags", "first_seen", "last_seen", "description"
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for rec in master.values():
            row = asdict(rec)
            row["sources"] = "|".join(rec.sources)
            row["tags"] = "|".join(rec.tags)
            writer.writerow({k: row[k] for k in fieldnames})
    log.info(f"[EXPORT] CSV → {path}")


def export_plaintext_by_type(master: dict, out_dir: str):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    buckets: dict[str, list] = {}
    for rec in master.values():
        buckets.setdefault(rec.ioc_type, []).append(rec.value)
    for ioc_type, values in buckets.items():
        file_path = out / f"{ioc_type}.txt"
        file_path.write_text("\n".join(sorted(values)), encoding="utf-8")
        log.info(f"[EXPORT] Plaintext → {file_path} ({len(values):,} entries)")


def export_stix2_bundle(master: dict, path: str):
    """Minimal STIX 2.1 bundle (indicators only, no external library needed)."""
    indicators = []
    type_map = {
        "ipv4":   "ipv4-addr:value = '{}'",
        "ipv6":   "ipv6-addr:value = '{}'",
        "domain": "domain-name:value = '{}'",
        "url":    "url:value = '{}'",
        "md5":    "file:hashes.MD5 = '{}'",
        "sha1":   "file:hashes.'SHA-1' = '{}'",
        "sha256": "file:hashes.'SHA-256' = '{}'",
        "email":  "email-message:from_ref.value = '{}'",
    }
    for rec in master.values():
        pattern_tmpl = type_map.get(rec.ioc_type)
        if not pattern_tmpl:
            continue
        uid = "indicator--" + hashlib.md5(
            f"{rec.ioc_type}:{rec.value}".encode()
        ).hexdigest()
        indicators.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": uid,
            "created": rec.first_seen or NOW_ISO,
            "modified": rec.last_seen or NOW_ISO,
            "name": f"{rec.ioc_type}: {rec.value}",
            "description": rec.description,
            "pattern": f"[{pattern_tmpl.format(rec.value)}]",
            "pattern_type": "stix",
            "valid_from": rec.first_seen or NOW_ISO,
            "labels": rec.tags,
            "confidence": {"low": 30, "medium": 60, "high": 90}.get(rec.confidence, 60),
            "external_references": [
                {"source_name": s} for s in rec.sources
            ],
        })
    bundle = {
        "type": "bundle",
        "id": "bundle--" + hashlib.md5(NOW_ISO.encode()).hexdigest(),
        "spec_version": "2.1",
        "objects": indicators,
    }
    Path(path).write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    log.info(f"[EXPORT] STIX2 bundle → {path} ({len(indicators):,} indicators)")


def print_summary(master: dict):
    from collections import Counter
    type_counts = Counter(rec.ioc_type for rec in master.values())
    cat_counts  = Counter(rec.category for rec in master.values())
    conf_counts = Counter(rec.confidence for rec in master.values())
    src_counts: Counter = Counter()
    for rec in master.values():
        for s in rec.sources:
            src_counts[s] += 1

    print("\n" + "="*62)
    print("  THREAT INTEL MASTER FEED — SUMMARY")
    print("="*62)
    print(f"  Generated at : {NOW_ISO}")
    print(f"  Total IOCs   : {len(master):,}")
    print()
    print("  By IOC type:")
    for t, c in type_counts.most_common():
        print(f"    {t:<12} {c:>8,}")
    print()
    print("  By confidence:")
    for t, c in conf_counts.most_common():
        print(f"    {t:<12} {c:>8,}")
    print()
    print("  Top 10 categories:")
    for t, c in cat_counts.most_common(10):
        print(f"    {t:<30} {c:>8,}")
    print()
    print("  Top 10 sources (by IOC count):")
    for s, c in src_counts.most_common(10):
        print(f"    {s:<40} {c:>8,}")
    print("="*62 + "\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Threat Intel Master Feed Aggregator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python threat_intel_aggregator.py
  python threat_intel_aggregator.py --out-dir ./feeds --formats json csv stix2 txt
  python threat_intel_aggregator.py --workers 20 --formats json
  python threat_intel_aggregator.py --list-feeds
        """,
    )
    parser.add_argument(
        "--out-dir", default="./master_feed",
        help="Output directory (default: ./master_feed)"
    )
    parser.add_argument(
        "--formats", nargs="+",
        choices=["json", "csv", "stix2", "txt"],
        default=["json", "csv", "txt"],
        help="Export formats (default: json csv txt)"
    )
    parser.add_argument(
        "--workers", type=int, default=10,
        help="Parallel fetch threads (default: 10)"
    )
    parser.add_argument(
        "--list-feeds", action="store_true",
        help="Print all configured feeds and exit"
    )
    parser.add_argument(
        "--no-summary", action="store_true",
        help="Skip printing summary table"
    )
    args = parser.parse_args()

    if args.list_feeds:
        print(f"\n{'#':<4} {'Name':<40} {'Format':<22} {'Category'}")
        print("-" * 90)
        for i, f in enumerate(FEEDS, 1):
            print(f"{i:<4} {f['name']:<40} {f['fmt']:<22} {f.get('category','')}")
        print(f"\nTotal: {len(FEEDS)} feeds configured\n")
        return

    t0 = time.time()
    master = aggregate(feeds=FEEDS, max_workers=args.workers)

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    if "json" in args.formats:
        export_json(master, str(out / "master_feed.json"))
    if "csv" in args.formats:
        export_csv(master, str(out / "master_feed.csv"))
    if "txt" in args.formats:
        export_plaintext_by_type(master, str(out / "by_type"))
    if "stix2" in args.formats:
        export_stix2_bundle(master, str(out / "master_feed.stix2.json"))

    elapsed = time.time() - t0
    log.info(f"Done in {elapsed:.1f}s")

    if not args.no_summary:
        print_summary(master)


if __name__ == "__main__":
    main()
