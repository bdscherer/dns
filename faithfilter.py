#!/usr/bin/env python3
"""
FaithFilter DNS filtering service
---------------------------------

A self-hosted DNS forwarder with content filtering, designed for families,
schools and small organisations.  Features:

* Block individual sites via a personal blocklist file.
* Subscribe to any number of blocklist *sources* -- plain-text files that
  live locally or online (hosts-file format or one-domain-per-line).  Each
  source is tagged with a category (``adult``, ``ads``, ``custom``, ...) and
  is refreshed automatically on a configurable schedule.
* Ad blocking via the same source mechanism (category ``ads``).
* Monitoring: attempts to reach adult / adult-adjacent content -- detected
  by category match or by a keyword scan of the queried domain -- are
  recorded as alerts, together with any extra keywords you configure.
* Weekly e-mail report summarising the recorded alerts per device, domain
  and keyword, delivered over SMTP.
* Safe-search enforcement for Google, Bing, DuckDuckGo and YouTube
  (moderate/strict), plus a generic rewrite mechanism for any other
  service that offers a "restricted DNS" entry point.
* Optional HTTP API for management and reporting.

Usage:

    sudo python3 faithfilter.py --config config.yaml

Requires the packages in requirements.txt (dnslib, Flask, PyYAML).
"""

import argparse
import datetime
import hashlib
import json
import logging
import os
import re
import smtplib
import socket
import threading
import time
import urllib.request
from email.message import EmailMessage
from typing import Dict, Iterable, List, Optional, Set, Tuple

import yaml
from dnslib import A, AAAA, DNSRecord, QTYPE, RCODE, RR
from dnslib.server import BaseResolver, DNSLogger, DNSServer

try:
    # Flask is optional; the service still runs in DNS-only mode when the
    # HTTP API is disabled in the configuration.
    from flask import Flask, jsonify, request
except ImportError:  # pragma: no cover
    Flask = None  # type: ignore


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Keywords that mark a queried domain as adult / adult-adjacent even when it
# is not present on any blocklist.  Users can extend this via
# monitoring.extra_keywords and suppress false positives via
# monitoring.keyword_exceptions in the configuration file.
DEFAULT_ADULT_KEYWORDS = [
    "porn", "xxx", "sex", "nude", "naked", "hentai", "milf", "erotic",
    "escort", "camgirl", "stripchat", "onlyfans", "nsfw", "xvideo",
    "xhamster", "redtube", "fetish", "bdsm", "hookup", "adultfriend",
]

# Domains for which keyword matching makes no sense (infrastructure noise).
KEYWORD_SKIP_SUFFIXES = (".arpa",)

# Built-in safe-search providers.  Each entry lists the trigger domains
# (matched exactly or as a parent of the query) and the safe host whose
# address is returned instead.  ``fallback_ip`` is used when the safe host
# cannot be resolved via the upstream servers.
SAFE_SEARCH_PROVIDERS: Dict[str, Dict] = {
    "google": {
        # Matches google.com and every regional Google domain (google.co.uk,
        # google.de, ...) via the regex below in SafeSearchEngine.
        "domains": ["google.com"],
        "regex": re.compile(r"^(www\.)?google\.(com?\.)?[a-z]{2,3}$"),
        "target": "forcesafesearch.google.com",
        "fallback_ip": "216.239.38.120",
    },
    "bing": {
        "domains": ["bing.com", "www.bing.com"],
        "target": "strict.bing.com",
        "fallback_ip": "204.79.197.220",
    },
    "duckduckgo": {
        "domains": ["duckduckgo.com", "www.duckduckgo.com", "duck.com"],
        "target": "safe.duckduckgo.com",
        "fallback_ip": "52.250.42.157",
    },
}

YOUTUBE_DOMAINS = [
    "youtube.com", "www.youtube.com", "m.youtube.com",
    "youtubei.googleapis.com", "youtube.googleapis.com",
    "www.youtube-nocookie.com",
]
YOUTUBE_TARGETS = {
    "moderate": {"target": "restrictmoderate.youtube.com",
                 "fallback_ip": "216.239.38.119"},
    "strict": {"target": "restrict.youtube.com",
               "fallback_ip": "216.239.38.120"},
}

# Suppress duplicate alerts for the same client+domain+reason within this
# window (DNS clients typically retry and re-resolve aggressively).
ALERT_THROTTLE_SECONDS = 300

_HOSTS_IP_PREFIXES = ("0.0.0.0", "127.0.0.1", "255.255.255.255", "::", "::1", "fe80::1")
_HOSTS_NOISE = {"localhost", "localhost.localdomain", "local", "broadcasthost",
                "ip6-localhost", "ip6-loopback", "ip6-localnet",
                "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters",
                "ip6-allhosts", "0.0.0.0"}

_DOMAIN_RE = re.compile(r"^(?:[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?\.)+[a-z0-9][a-z0-9-]*$")


# ---------------------------------------------------------------------------
# List parsing and fetching
# ---------------------------------------------------------------------------

def parse_domain_lines(lines: Iterable[str]) -> Set[str]:
    """Parse blocklist text into a set of domains.

    Supports two formats transparently:

    * plain domain lists  -- one domain per line
    * hosts files         -- ``0.0.0.0 domain`` / ``127.0.0.1 domain``

    Comments (``#`` to end of line) and blank lines are ignored.
    """
    domains: Set[str] = set()
    for raw in lines:
        line = raw.split("#", 1)[0].strip().lower()
        if not line:
            continue
        fields = line.split()
        if len(fields) >= 2 and fields[0].startswith(_HOSTS_IP_PREFIXES):
            candidates = fields[1:]
        else:
            candidates = fields[:1]
        for cand in candidates:
            cand = cand.strip(".")
            if cand in _HOSTS_NOISE:
                continue
            if _DOMAIN_RE.match(cand):
                domains.add(cand)
    return domains


def load_domains_from_file(path: str) -> Set[str]:
    """Load a domain set from a local file (empty set if missing)."""
    if not path or not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return parse_domain_lines(f)


def load_lines_from_file(path: str) -> List[str]:
    """Load non-empty, non-comment lines from a text file."""
    items: List[str] = []
    if not path or not os.path.exists(path):
        return items
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.split("#", 1)[0].strip().lower()
            if line:
                items.append(line)
    return items


class BlocklistManager:
    """Loads and refreshes categorised domain sets from files and URLs.

    Remote sources are cached on disk so that a failed download falls back
    to the most recent good copy instead of silently unblocking everything.
    """

    def __init__(self, config: Dict, logger: logging.Logger):
        self.config = config
        self.logger = logger
        blocking = config.get("blocking", {})
        self.cache_dir = blocking.get("cache_dir", "lists_cache")
        self.refresh_hours = float(blocking.get("refresh_hours", 24))
        self.my_blocklist_file = (blocking.get("my_blocklist")
                                  or config.get("blocklist", {}).get("file")
                                  or "blocklist.txt")
        self.whitelist_file = (blocking.get("whitelist")
                               or config.get("whitelist", {}).get("file")
                               or "whitelist.txt")
        self.sources: List[Dict] = [s for s in blocking.get("sources", [])
                                    if s.get("enabled", True)]
        self._lock = threading.Lock()
        # domain -> category ("custom" for the personal list).  Personal
        # entries are loaded last so they win over source categories.
        self._domains: Dict[str, str] = {}
        self._whitelist: Set[str] = set()
        self._source_counts: Dict[str, int] = {}
        self._stop = threading.Event()
        self.reload(download=False)

    # -- loading ------------------------------------------------------------

    def _cache_path(self, url: str) -> str:
        digest = hashlib.sha256(url.encode()).hexdigest()[:16]
        return os.path.join(self.cache_dir, f"{digest}.txt")

    def _fetch_source(self, source: Dict, download: bool) -> Set[str]:
        """Return the domain set for one source, downloading if requested."""
        name = source.get("name", "unnamed")
        if source.get("file"):
            return load_domains_from_file(source["file"])
        url = source.get("url")
        if not url:
            return set()
        cache = self._cache_path(url)
        if download:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "FaithFilter/1.0"})
                with urllib.request.urlopen(req, timeout=60) as resp:
                    data = resp.read().decode("utf-8", errors="ignore")
                os.makedirs(self.cache_dir, exist_ok=True)
                tmp = cache + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    f.write(data)
                os.replace(tmp, cache)
                self.logger.info("Downloaded source '%s' (%d bytes)", name, len(data))
            except Exception as exc:
                self.logger.warning("Download of source '%s' failed (%s); "
                                    "using cached copy if available", name, exc)
        return load_domains_from_file(cache)

    def reload(self, download: bool = False) -> None:
        """(Re)load every list.  With ``download=True`` remote sources are
        re-fetched; otherwise cached copies are used."""
        domains: Dict[str, str] = {}
        counts: Dict[str, int] = {}
        for source in self.sources:
            name = source.get("name", "unnamed")
            category = source.get("category", "custom")
            entries = self._fetch_source(source, download)
            counts[name] = len(entries)
            for d in entries:
                domains[d] = category
        personal = load_domains_from_file(self.my_blocklist_file)
        counts["my_blocklist"] = len(personal)
        for d in personal:
            # Keep the adult/ads categorisation when a source already lists
            # the domain, so monitoring alerts still fire for it.
            domains.setdefault(d, "custom")
        whitelist = load_domains_from_file(self.whitelist_file)
        with self._lock:
            self._domains = domains
            self._whitelist = whitelist
            self._source_counts = counts
        self.logger.info("Loaded %d blocked domains (%s) and %d whitelist entries",
                         len(domains),
                         ", ".join(f"{k}: {v}" for k, v in counts.items()),
                         len(whitelist))

    # -- lookups ------------------------------------------------------------

    @staticmethod
    def _match_suffix(domain: str, table) -> Optional[str]:
        """Return the entry matching ``domain`` or any parent domain."""
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            if candidate in table:
                return candidate
        return None

    def blocked_category(self, domain: str) -> Optional[str]:
        """Category name if the domain (or a parent) is blocked, else None."""
        with self._lock:
            match = self._match_suffix(domain, self._domains)
            return self._domains[match] if match else None

    def is_whitelisted(self, domain: str) -> bool:
        with self._lock:
            return self._match_suffix(domain, self._whitelist) is not None

    # -- state for the API ----------------------------------------------------

    def stats(self) -> Dict:
        with self._lock:
            return {
                "total_blocked_domains": len(self._domains),
                "whitelist_entries": len(self._whitelist),
                "sources": dict(self._source_counts),
            }

    def personal_list(self) -> List[str]:
        return sorted(load_domains_from_file(self.my_blocklist_file))

    def whitelist(self) -> List[str]:
        return sorted(load_domains_from_file(self.whitelist_file))

    def add_personal(self, domain: str) -> None:
        domain = domain.strip().lower().strip(".")
        with open(self.my_blocklist_file, "a", encoding="utf-8") as f:
            f.write(f"{domain}\n")
        with self._lock:
            self._domains[domain] = "custom"

    def remove_personal(self, domain: str) -> bool:
        domain = domain.strip().lower().strip(".")
        current = load_domains_from_file(self.my_blocklist_file)
        if domain not in current:
            return False
        current.discard(domain)
        with open(self.my_blocklist_file, "w", encoding="utf-8") as f:
            for d in sorted(current):
                f.write(f"{d}\n")
        with self._lock:
            if self._domains.get(domain) == "custom":
                del self._domains[domain]
        return True

    def add_whitelist(self, domain: str) -> None:
        domain = domain.strip().lower().strip(".")
        with open(self.whitelist_file, "a", encoding="utf-8") as f:
            f.write(f"{domain}\n")
        with self._lock:
            self._whitelist.add(domain)

    def remove_whitelist(self, domain: str) -> bool:
        domain = domain.strip().lower().strip(".")
        current = load_domains_from_file(self.whitelist_file)
        if domain not in current:
            return False
        current.discard(domain)
        with open(self.whitelist_file, "w", encoding="utf-8") as f:
            for d in sorted(current):
                f.write(f"{d}\n")
        with self._lock:
            self._whitelist.discard(domain)
        return True

    # -- background refresh ---------------------------------------------------

    def start_refresh_thread(self) -> None:
        def loop() -> None:
            # Initial download shortly after startup so a fresh install gets
            # its lists without waiting a full refresh interval.
            self.reload(download=True)
            while not self._stop.wait(self.refresh_hours * 3600):
                self.reload(download=True)

        if self.sources and any(s.get("url") for s in self.sources):
            threading.Thread(target=loop, name="list-refresh", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()


# ---------------------------------------------------------------------------
# Alert log (adult content / keyword hits)
# ---------------------------------------------------------------------------

class AlertLog:
    """Records monitoring alerts to a JSONL file for the weekly report."""

    def __init__(self, path: str, logger: logging.Logger):
        self.path = path
        self.logger = logger
        self._lock = threading.Lock()
        self._recent: Dict[Tuple[str, str, str], float] = {}

    def add(self, client: str, domain: str, reason: str, detail: str) -> None:
        key = (client, domain, reason)
        now = time.time()
        with self._lock:
            last = self._recent.get(key, 0)
            if now - last < ALERT_THROTTLE_SECONDS:
                return
            self._recent[key] = now
            if len(self._recent) > 10000:
                cutoff = now - ALERT_THROTTLE_SECONDS
                self._recent = {k: v for k, v in self._recent.items() if v > cutoff}
        entry = {
            "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "client": client,
            "domain": domain,
            "reason": reason,   # "adult_domain" | "keyword"
            "detail": detail,   # category or the matched keyword
        }
        try:
            if os.path.dirname(self.path):
                os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with self._lock:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")
        except OSError as exc:
            self.logger.error("Could not write alert log: %s", exc)

    def read_since(self, since: datetime.datetime) -> List[Dict]:
        alerts: List[Dict] = []
        if not os.path.exists(self.path):
            return alerts
        with open(self.path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    ts = datetime.datetime.fromisoformat(entry["time"])
                except (ValueError, KeyError):
                    continue
                if ts >= since:
                    alerts.append(entry)
        return alerts


# ---------------------------------------------------------------------------
# Keyword monitor
# ---------------------------------------------------------------------------

class KeywordMonitor:
    """Scans queried domains for adult keywords and user-defined keywords."""

    def __init__(self, config: Dict, logger: logging.Logger):
        mon = config.get("monitoring", {})
        self.logger = logger
        self.block_matches = bool(mon.get("block_keyword_matches", False))
        self.keywords_file = mon.get("keywords_file")
        adult = list(DEFAULT_ADULT_KEYWORDS) if mon.get("adult_keywords_enabled", True) else []
        self._base_adult = adult
        self._extra = [k.strip().lower() for k in mon.get("extra_keywords", []) if k.strip()]
        self._exceptions = [k.strip().lower() for k in mon.get("keyword_exceptions", [])
                            if k.strip()]
        # Common false positives for "sex" as a substring.
        self._exceptions += ["essex", "sussex", "middlesex", "sexton"]
        self.reload()

    def reload(self) -> None:
        file_keywords = load_lines_from_file(self.keywords_file) if self.keywords_file else []
        self.keywords: List[str] = sorted(set(self._base_adult + self._extra + file_keywords))

    def match(self, domain: str) -> Optional[str]:
        """Return the first keyword found in ``domain``, or None."""
        if domain.endswith(KEYWORD_SKIP_SUFFIXES):
            return None
        scrubbed = domain
        for exc in self._exceptions:
            scrubbed = scrubbed.replace(exc, "")
        for kw in self.keywords:
            if kw in scrubbed:
                return kw
        return None

    def add_keyword(self, keyword: str) -> None:
        keyword = keyword.strip().lower()
        if not keyword:
            return
        if self.keywords_file:
            with open(self.keywords_file, "a", encoding="utf-8") as f:
                f.write(f"{keyword}\n")
        if keyword not in self.keywords:
            self.keywords.append(keyword)
            self.keywords.sort()


# ---------------------------------------------------------------------------
# Safe-search engine
# ---------------------------------------------------------------------------

class SafeSearchEngine:
    """Maps search/video domains to their provider's restricted endpoint.

    The restricted endpoint is resolved through the upstream servers and the
    result cached for an hour; if resolution fails the documented fallback
    IP is used, so enforcement keeps working without outbound connectivity.
    """

    def __init__(self, config: Dict, forwarder, logger: logging.Logger):
        self.logger = logger
        self.forwarder = forwarder
        ss = config.get("safe_search", {})
        # Backward compatibility with the old flat config keys.
        legacy = config.get("dns", {})
        self.rules: List[Dict] = []

        def add_rule(domains, target, fallback_ip, label, regex=None):
            self.rules.append({"domains": [d.lower() for d in domains],
                               "regex": regex, "target": target,
                               "fallback_ip": fallback_ip, "label": label})

        for name, provider in SAFE_SEARCH_PROVIDERS.items():
            enabled = ss.get(name, ss.get("enabled_default", None))
            if enabled is None:
                enabled = bool(legacy.get("safe_search", False)) if name == "google" else False
            if enabled:
                add_rule(provider["domains"], provider["target"],
                         provider["fallback_ip"], name, provider.get("regex"))

        youtube_mode = str(ss.get("youtube", legacy.get("youtube_mode", "off"))).lower()
        if youtube_mode in YOUTUBE_TARGETS:
            t = YOUTUBE_TARGETS[youtube_mode]
            add_rule(YOUTUBE_DOMAINS, t["target"], t["fallback_ip"],
                     f"youtube_{youtube_mode}")

        for custom in ss.get("custom_rewrites", []) or []:
            if custom.get("domains") and custom.get("target"):
                add_rule(custom["domains"], custom["target"],
                         custom.get("fallback_ip"),
                         custom.get("name", custom["target"]))

        self._cache: Dict[str, Tuple[str, float]] = {}
        self._lock = threading.Lock()

    def match(self, qname: str) -> Optional[Dict]:
        for rule in self.rules:
            if rule["regex"] and rule["regex"].match(qname):
                return rule
            for d in rule["domains"]:
                if qname == d or qname.endswith("." + d):
                    return rule
        return None

    def resolve_target(self, rule: Dict) -> Optional[str]:
        """IPv4 address for the rule's safe host (cached, with fallback)."""
        target = rule["target"]
        now = time.time()
        with self._lock:
            cached = self._cache.get(target)
            if cached and now - cached[1] < 3600:
                return cached[0]
        ip: Optional[str] = None
        try:
            query = DNSRecord.question(target, "A")
            reply = self.forwarder(query)
            if reply:
                for rr in reply.rr:
                    if rr.rtype == QTYPE.A:
                        ip = str(rr.rdata)
                        break
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.debug("Safe-search target resolution failed: %s", exc)
        if not ip:
            ip = rule.get("fallback_ip")
        if ip:
            with self._lock:
                self._cache[target] = (ip, now)
        return ip


# ---------------------------------------------------------------------------
# DNS resolver
# ---------------------------------------------------------------------------

def parse_upstream(entry: str) -> Tuple[str, int]:
    """Parse ``host`` or ``host:port`` upstream entries."""
    if ":" in entry and entry.count(":") == 1:
        host, port = entry.rsplit(":", 1)
        return host, int(port)
    return entry, 53


class FaithFilterResolver(BaseResolver):
    """DNS resolver implementing whitelist, safe search, monitoring and
    category-based blocking."""

    def __init__(self, config: Dict, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.blocklists = BlocklistManager(config, logger)
        alert_file = config.get("monitoring", {}).get(
            "alert_log_file", "logs/alerts.jsonl")
        self.alerts = AlertLog(alert_file, logger)
        self.keywords = KeywordMonitor(config, logger)
        self.safe_search = SafeSearchEngine(config, self._forward_query, logger)
        self.block_response = str(config.get("dns", {}).get(
            "block_response", "nxdomain")).lower()
        self.stats: Dict[str, int] = {
            "total_queries": 0,
            "blocked": 0,
            "blocked_ads": 0,
            "blocked_adult": 0,
            "safe_search_rewrites": 0,
            "alerts": 0,
        }
        self.recent_queries: List[Dict] = []
        self._recent_lock = threading.Lock()

    # -- helpers --------------------------------------------------------------

    def log_query(self, client_ip: str, domain: str, action: str) -> None:
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        entry = {"time": timestamp, "client": client_ip,
                 "domain": domain, "action": action}
        with self._recent_lock:
            self.recent_queries.append(entry)
            if len(self.recent_queries) > 1000:
                self.recent_queries.pop(0)
        log_file = self.config.get("logs", {}).get("query_log_file")
        if log_file:
            try:
                if os.path.dirname(log_file):
                    os.makedirs(os.path.dirname(log_file), exist_ok=True)
                with open(log_file, "a", encoding="utf-8") as f:
                    f.write(f"{timestamp} {client_ip} {domain} {action}\n")
            except OSError as exc:
                self.logger.error("Could not write query log: %s", exc)

    def _forward_query(self, request: DNSRecord) -> Optional[DNSRecord]:
        query_data = request.pack()
        upstreams = self.config.get("dns", {}).get("upstream_dns", ["1.1.1.1", "8.8.8.8"])
        timeout = self.config.get("dns", {}).get("forward_timeout", 5)
        for upstream in upstreams:
            host, port = parse_upstream(str(upstream))
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(timeout)
                s.sendto(query_data, (host, port))
                data, _ = s.recvfrom(8192)
                s.close()
                return DNSRecord.parse(data)
            except Exception as exc:
                self.logger.warning("Forwarding to %s failed: %s", upstream, exc)
                continue
        return None

    def _blocked_reply(self, request: DNSRecord) -> DNSRecord:
        reply = request.reply()
        if self.block_response == "zero_ip":
            q = request.q
            if q.qtype == QTYPE.A:
                reply.add_answer(RR(rname=q.qname, rtype=QTYPE.A, rclass=1,
                                    ttl=60, rdata=A("0.0.0.0")))
            elif q.qtype == QTYPE.AAAA:
                reply.add_answer(RR(rname=q.qname, rtype=QTYPE.AAAA, rclass=1,
                                    ttl=60, rdata=AAAA("::")))
            # other qtypes: empty NOERROR answer
        else:
            reply.header.rcode = RCODE.NXDOMAIN
        return reply

    def _safe_search_reply(self, request: DNSRecord, rule: Dict) -> DNSRecord:
        q = request.q
        if q.qtype == QTYPE.AAAA:
            # Returning a real AAAA record would let clients bypass the
            # rewrite over IPv6; answer with an empty NOERROR instead.
            return request.reply()
        ip = self.safe_search.resolve_target(rule)
        reply = request.reply()
        if ip:
            reply.add_answer(RR(rname=q.qname, rtype=QTYPE.A, rclass=1,
                                ttl=300, rdata=A(ip)))
        return reply

    def _record_alert(self, client_ip: str, domain: str,
                      reason: str, detail: str) -> None:
        self.stats["alerts"] += 1
        self.alerts.add(client_ip, domain, reason, detail)

    # -- main entry point -------------------------------------------------------

    def resolve(self, request: DNSRecord, handler: object) -> DNSRecord:
        self.stats["total_queries"] += 1
        qname = str(request.q.qname).rstrip(".").lower()
        client_ip = (handler.client_address[0]
                     if hasattr(handler, "client_address") else "unknown")

        # 1. Whitelist bypasses every filter.
        if self.blocklists.is_whitelisted(qname):
            self.log_query(client_ip, qname, "whitelisted")
            resp = self._forward_query(request)
            return resp if resp else request.reply(rcode=RCODE.SERVFAIL)

        # 2. Safe-search / restricted-mode rewrites.
        rule = self.safe_search.match(qname)
        if rule:
            self.stats["safe_search_rewrites"] += 1
            self.log_query(client_ip, qname, f"safe_search:{rule['label']}")
            return self._safe_search_reply(request, rule)

        # 3. Blocklist lookup (categorised).
        category = self.blocklists.blocked_category(qname)
        if category:
            self.stats["blocked"] += 1
            if category == "ads":
                self.stats["blocked_ads"] += 1
            elif category == "adult":
                self.stats["blocked_adult"] += 1
                self._record_alert(client_ip, qname, "adult_domain", category)
            self.log_query(client_ip, qname, f"blocked:{category}")
            return self._blocked_reply(request)

        # 4. Keyword monitoring for domains not on any list.
        keyword = self.keywords.match(qname)
        if keyword:
            self._record_alert(client_ip, qname, "keyword", keyword)
            if self.keywords.block_matches:
                self.log_query(client_ip, qname, f"blocked:keyword:{keyword}")
                self.stats["blocked"] += 1
                return self._blocked_reply(request)
            self.log_query(client_ip, qname, f"flagged:keyword:{keyword}")
        else:
            self.log_query(client_ip, qname, "allowed")

        # 5. Forward everything else upstream.
        resp = self._forward_query(request)
        return resp if resp else request.reply(rcode=RCODE.SERVFAIL)


# ---------------------------------------------------------------------------
# Weekly e-mail reporter
# ---------------------------------------------------------------------------

WEEKDAYS = ["monday", "tuesday", "wednesday", "thursday", "friday",
            "saturday", "sunday"]


def build_report(alerts: List[Dict], period_start: datetime.datetime,
                 period_end: datetime.datetime) -> str:
    """Render the weekly alert summary as plain text."""
    lines = [
        "FaithFilter weekly activity report",
        f"Period: {period_start:%Y-%m-%d %H:%M} to {period_end:%Y-%m-%d %H:%M} UTC",
        "",
    ]
    if not alerts:
        lines.append("No adult-content or keyword alerts were recorded this week.")
        return "\n".join(lines)

    adult = [a for a in alerts if a.get("reason") == "adult_domain"]
    keyword = [a for a in alerts if a.get("reason") == "keyword"]
    lines.append(f"Total alerts: {len(alerts)} "
                 f"({len(adult)} adult-domain, {len(keyword)} keyword)")
    lines.append("")

    def top(counter: Dict[str, int], n: int = 15) -> List[Tuple[str, int]]:
        return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:n]

    by_client: Dict[str, int] = {}
    for a in alerts:
        by_client[a.get("client", "?")] = by_client.get(a.get("client", "?"), 0) + 1
    lines.append("By device (client IP):")
    for client, count in top(by_client):
        lines.append(f"  {client:<20} {count} attempt(s)")
    lines.append("")

    if adult:
        by_domain: Dict[str, int] = {}
        for a in adult:
            by_domain[a["domain"]] = by_domain.get(a["domain"], 0) + 1
        lines.append("Adult / adult-adjacent domains requested:")
        for domain, count in top(by_domain):
            lines.append(f"  {domain:<45} {count}x")
        lines.append("")

    if keyword:
        by_kw: Dict[str, int] = {}
        for a in keyword:
            by_kw[a.get("detail", "?")] = by_kw.get(a.get("detail", "?"), 0) + 1
        lines.append("Keyword matches:")
        for kw, count in top(by_kw):
            lines.append(f"  {kw:<25} {count}x")
        lines.append("")
        lines.append("Keyword match details (up to 50):")
        for a in keyword[:50]:
            lines.append(f"  {a['time'][:16]} {a.get('client', '?'):<16} "
                         f"{a['domain']} (keyword: {a.get('detail')})")

    return "\n".join(lines)


class Reporter:
    """Sends the weekly alert summary over SMTP on a schedule."""

    def __init__(self, config: Dict, alerts: AlertLog, logger: logging.Logger):
        self.cfg = config.get("email", {})
        self.alerts = alerts
        self.logger = logger
        self.enabled = bool(self.cfg.get("enabled", False))
        self.state_file = self.cfg.get("state_file", "logs/report_state.json")
        self._stop = threading.Event()

    # -- state ------------------------------------------------------------

    def _last_sent(self) -> Optional[datetime.datetime]:
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                return datetime.datetime.fromisoformat(json.load(f)["last_sent"])
        except (OSError, ValueError, KeyError):
            return None

    def _mark_sent(self, when: datetime.datetime) -> None:
        if os.path.dirname(self.state_file):
            os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
        with open(self.state_file, "w", encoding="utf-8") as f:
            json.dump({"last_sent": when.isoformat()}, f)

    # -- sending ------------------------------------------------------------

    def _smtp_password(self) -> str:
        env = self.cfg.get("password_env")
        if env and os.environ.get(env):
            return os.environ[env]
        return self.cfg.get("password", "")

    def send_report(self, force: bool = False) -> bool:
        """Build and send the report now.  Returns True when sent."""
        now = datetime.datetime.now(datetime.timezone.utc)
        last = self._last_sent() or (now - datetime.timedelta(days=7))
        alerts = self.alerts.read_since(last)
        if not alerts and not self.cfg.get("send_if_empty", True) and not force:
            self._mark_sent(now)
            return False
        body = build_report(alerts, last, now)
        subject = (f"FaithFilter weekly report: {len(alerts)} alert(s)"
                   if alerts else "FaithFilter weekly report: no alerts")

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self.cfg.get("from", self.cfg.get("username", "faithfilter@localhost"))
        recipients = self.cfg.get("to", [])
        if isinstance(recipients, str):
            recipients = [recipients]
        msg["To"] = ", ".join(recipients)
        msg.set_content(body)

        host = self.cfg.get("smtp_host", "localhost")
        port = int(self.cfg.get("smtp_port", 587))
        try:
            if self.cfg.get("use_ssl", False):
                smtp: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=30)
            else:
                smtp = smtplib.SMTP(host, port, timeout=30)
                if self.cfg.get("use_tls", True):
                    smtp.starttls()
            username = self.cfg.get("username")
            if username:
                smtp.login(username, self._smtp_password())
            smtp.send_message(msg)
            smtp.quit()
        except Exception as exc:
            self.logger.error("Failed to send weekly report: %s", exc)
            return False
        self._mark_sent(now)
        self.logger.info("Weekly report sent to %s (%d alerts)",
                         recipients, len(alerts))
        return True

    # -- scheduling ------------------------------------------------------------

    def _due(self, now: datetime.datetime) -> bool:
        day = str(self.cfg.get("report_day", "sunday")).lower()
        hour = int(self.cfg.get("report_hour", 8))
        try:
            target_weekday = WEEKDAYS.index(day)
        except ValueError:
            target_weekday = 6
        if now.weekday() != target_weekday or now.hour != hour:
            return False
        last = self._last_sent()
        return last is None or (now - last) > datetime.timedelta(days=1)

    def start_scheduler(self) -> None:
        if not self.enabled:
            return

        def loop() -> None:
            while not self._stop.wait(60):
                now = datetime.datetime.now(datetime.timezone.utc)
                if self._due(now):
                    self.send_report()

        threading.Thread(target=loop, name="report-scheduler", daemon=True).start()
        self.logger.info("Weekly e-mail reports enabled (every %s at %02d:00 UTC)",
                         self.cfg.get("report_day", "sunday"),
                         int(self.cfg.get("report_hour", 8)))

    def stop(self) -> None:
        self._stop.set()


# ---------------------------------------------------------------------------
# HTTP API
# ---------------------------------------------------------------------------

def create_api_server(resolver: FaithFilterResolver, reporter: Reporter,
                      config: Dict):
    app = Flask(__name__)
    api_key = config.get("http_api", {}).get("api_key")

    @app.before_request
    def check_key():
        if api_key and request.headers.get("X-API-Key") != api_key:
            return jsonify({"error": "invalid or missing X-API-Key"}), 401

    @app.route("/api/status")
    def status():
        return jsonify({
            "stats": resolver.stats,
            "lists": resolver.blocklists.stats(),
            "keywords": len(resolver.keywords.keywords),
            "safe_search_rules": [r["label"] for r in resolver.safe_search.rules],
        })

    @app.route("/api/queries")
    def queries():
        limit = int(request.args.get("limit", 100))
        with resolver._recent_lock:
            return jsonify(resolver.recent_queries[-limit:])

    @app.route("/api/alerts")
    def alerts():
        days = float(request.args.get("days", 7))
        since = (datetime.datetime.now(datetime.timezone.utc)
                 - datetime.timedelta(days=days))
        return jsonify(resolver.alerts.read_since(since))

    @app.route("/api/blocklist", methods=["GET", "POST"])
    def blocklist_route():
        if request.method == "GET":
            return jsonify(resolver.blocklists.personal_list())
        data = request.get_json(silent=True) or {}
        domain = (data.get("domain") or "").strip().lower()
        if not domain:
            return jsonify({"error": "domain is required"}), 400
        resolver.blocklists.add_personal(domain)
        return jsonify({"added": domain})

    @app.route("/api/blocklist/<domain>", methods=["DELETE"])
    def remove_from_blocklist(domain):
        if resolver.blocklists.remove_personal(domain):
            return jsonify({"removed": domain})
        return jsonify({"error": "domain not found"}), 404

    @app.route("/api/whitelist", methods=["GET", "POST"])
    def whitelist_route():
        if request.method == "GET":
            return jsonify(resolver.blocklists.whitelist())
        data = request.get_json(silent=True) or {}
        domain = (data.get("domain") or "").strip().lower()
        if not domain:
            return jsonify({"error": "domain is required"}), 400
        resolver.blocklists.add_whitelist(domain)
        return jsonify({"added": domain})

    @app.route("/api/whitelist/<domain>", methods=["DELETE"])
    def remove_from_whitelist(domain):
        if resolver.blocklists.remove_whitelist(domain):
            return jsonify({"removed": domain})
        return jsonify({"error": "domain not found"}), 404

    @app.route("/api/keywords", methods=["GET", "POST"])
    def keywords_route():
        if request.method == "GET":
            return jsonify(resolver.keywords.keywords)
        data = request.get_json(silent=True) or {}
        keyword = (data.get("keyword") or "").strip().lower()
        if not keyword:
            return jsonify({"error": "keyword is required"}), 400
        resolver.keywords.add_keyword(keyword)
        return jsonify({"added": keyword})

    @app.route("/api/reload", methods=["POST"])
    def reload_lists():
        resolver.blocklists.reload(download=False)
        resolver.keywords.reload()
        return jsonify({"reloaded": True})

    @app.route("/api/refresh", methods=["POST"])
    def refresh_sources():
        resolver.blocklists.reload(download=True)
        return jsonify({"refreshed": True,
                        "lists": resolver.blocklists.stats()})

    @app.route("/api/report/preview")
    def report_preview():
        now = datetime.datetime.now(datetime.timezone.utc)
        since = reporter._last_sent() or (now - datetime.timedelta(days=7))
        alerts = resolver.alerts.read_since(since)
        return build_report(alerts, since, now), 200, {
            "Content-Type": "text/plain; charset=utf-8"}

    @app.route("/api/report/send", methods=["POST"])
    def report_send():
        sent = reporter.send_report(force=True)
        return jsonify({"sent": sent})

    return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def start_dns_server(resolver: FaithFilterResolver, config: Dict) -> List[DNSServer]:
    listen_ip = config.get("dns", {}).get("listen_ip", "0.0.0.0")
    listen_port = int(config.get("dns", {}).get("listen_port", 53))
    # Disable dnslib's per-query stdout logging; we log queries ourselves.
    dns_logger = DNSLogger("-request,-reply,-truncated,-error", False)
    servers = [DNSServer(resolver, port=listen_port, address=listen_ip,
                         logger=dns_logger)]
    if config.get("dns", {}).get("listen_tcp", True):
        servers.append(DNSServer(resolver, port=listen_port, address=listen_ip,
                                 logger=dns_logger, tcp=True))
    for server in servers:
        server.start_thread()
    return servers


def main() -> None:
    parser = argparse.ArgumentParser(description="FaithFilter DNS filtering service")
    parser.add_argument("--config", required=True, help="Path to YAML configuration file")
    parser.add_argument("--send-report", action="store_true",
                        help="Send the weekly report immediately and exit")
    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

    log_level_name = config.get("logs", {}).get("log_level", "INFO")
    logging.basicConfig(level=getattr(logging, log_level_name.upper(), logging.INFO),
                        format="%(asctime)s [%(levelname)s] %(message)s")
    logger = logging.getLogger("FaithFilter")

    resolver = FaithFilterResolver(config, logger)
    reporter = Reporter(config, resolver.alerts, logger)

    if args.send_report:
        ok = reporter.send_report(force=True)
        raise SystemExit(0 if ok else 1)

    servers = start_dns_server(resolver, config)
    logger.info("FaithFilter DNS server listening on %s:%s",
                config.get("dns", {}).get("listen_ip", "0.0.0.0"),
                config.get("dns", {}).get("listen_port", 53))

    resolver.blocklists.start_refresh_thread()
    reporter.start_scheduler()

    if config.get("http_api", {}).get("enable", False):
        if Flask is None:
            logger.error("Flask is not installed but http_api.enable is true. "
                         "Install Flask or disable the API.")
        else:
            app = create_api_server(resolver, reporter, config)
            host = config.get("http_api", {}).get("host", "127.0.0.1")
            port = int(config.get("http_api", {}).get("port", 5000))
            threading.Thread(target=app.run, kwargs={"host": host, "port": port},
                             daemon=True).start()
            logger.info("FaithFilter HTTP API listening on %s:%s", host, port)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down FaithFilter")
        resolver.blocklists.stop()
        reporter.stop()
        for server in servers:
            server.stop()


if __name__ == "__main__":
    main()
