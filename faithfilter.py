#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
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
import base64
import copy
import datetime
import fnmatch
import getpass
import html as html_lib
import hashlib
import io
import ipaddress
import json
import logging
import os
import re
import secrets
import smtplib
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
import zipfile
from collections import OrderedDict
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

import yaml
from dnslib import A, AAAA, DNSRecord, QTYPE, RCODE, RR
from dnslib.server import BaseResolver, DNSLogger, DNSServer

__version__ = "2.3.0"

try:
    # Flask is optional; the service still runs in DNS-only mode when the
    # HTTP API is disabled in the configuration.
    from flask import (Flask, Response, jsonify, redirect, request,
                       send_file, session)
except ImportError:  # pragma: no cover
    Flask = None  # type: ignore


# ---------------------------------------------------------------------------
# Built-in default configuration
# ---------------------------------------------------------------------------
#
# The program is fully usable with no configuration file at all: these
# defaults enable adult-content and ad blocking, all safe-search
# enforcement, and the management API on localhost.  A config.yaml placed
# next to the program (or passed with --config) is deep-merged over these
# defaults, so it only needs to contain the settings being changed.

DEFAULT_CONFIG: Dict = {
    "dns": {
        "listen_ip": "0.0.0.0",
        "listen_port": 53,
        "listen_tcp": True,
        "upstream_dns": ["1.1.1.1", "8.8.8.8"],
        "forward_timeout": 5,
        "block_response": "nxdomain",
        "block_cname_cloaking": True,
        "cache": {
            "enabled": True,
            "max_entries": 20000,
            "serve_stale": True,
        },
    },
    "blocking": {
        "my_blocklist": "blocklist.txt",
        "whitelist": "whitelist.txt",
        "sources": [
            {"name": "adult-content", "category": "adult",
             "url": "https://raw.githubusercontent.com/StevenBlack/hosts/"
                    "master/alternates/porn-only/hosts"},
            {"name": "ads-and-trackers", "category": "ads",
             "url": "https://raw.githubusercontent.com/StevenBlack/hosts/"
                    "master/hosts"},
            # DNS-over-HTTPS resolvers, VPN and proxy services: blocking
            # these prevents devices from routing around the filter.
            {"name": "bypass-doh-vpn-proxy", "category": "bypass",
             "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/"
                    "main/wildcard/doh-vpn-proxy-bypass-onlydomains.txt"},
        ],
        # Answer NXDOMAIN for browser/OS "canary" domains, which tells
        # Firefox to turn off its built-in DoH and disables iCloud Private
        # Relay, keeping devices on this resolver.
        "block_doh_canary": True,
        "refresh_hours": 24,
        "cache_dir": "lists_cache",
    },
    "clients": {
        # Friendly names for devices, shown in reports and the dashboard:
        #   names:
        #     "192.168.1.20": "Emma's iPad"
        "names": {},
        # Temporary pause/unfiltered overrides are persisted here so they
        # survive a restart.
        "overrides_file": "logs/overrides.json",
        # Per-device policy groups. Clients not matching any group use the
        # implicit defaults (full filtering, safe search on, no curfew).
        #
        #   groups:
        #     - name: "kids"
        #       members: ["192.168.1.20", "192.168.1.32/28"]
        #       filtering: "full"        # full | monitor_only | off
        #       safe_search: true
        #       curfew:
        #         - days: ["sun", "mon", "tue", "wed", "thu"]
        #           from: "21:30"
        #           to: "06:30"
        "groups": [],
    },
    "block_page": {
        # Serve a "this site was blocked" web page instead of a dead
        # connection. Requires port 80 to be free; HTTPS sites still show a
        # certificate warning first (inherent to DNS-level blocking).
        "enabled": False,
        "port": 80,
        "ip": "",              # auto-detected when empty
        "unblock_requests_file": "logs/unblock_requests.jsonl",
    },
    "notifications": {
        "instant_alerts": True,          # e-mail on adult/bypass attempts
        "instant_min_minutes": 60,       # at most one such mail per client/hour
        "notify_on_start": False,        # e-mail when the service starts
        "refresh_failure_threshold": 3,  # e-mail after N failed refreshes
    },
    "monitoring": {
        "adult_keywords_enabled": True,
        "extra_keywords": [],
        "keywords_file": "keywords.txt",
        "keyword_exceptions": [],
        "block_keyword_matches": False,
        "alert_log_file": "logs/alerts.jsonl",
        # Alerts and unblock requests older than this are purged daily.
        "alert_retention_days": 90,
    },
    "accountability": {
        # Turn the filter into an accountability tool: each person's activity
        # is summarised and e-mailed to their chosen accountability partners
        # (allies), and partners get instant alerts + tamper notices.
        #
        #   people:
        #     - name: "Sam"
        #       devices: ["192.168.1.30", "192.168.1.31"]
        #       allies: ["mentor@example.com", "spouse@example.com"]
        #       self_report: false
        "enabled": False,
        "people": [],
        # A device with no DNS activity for this long is flagged as possibly
        # bypassing the filter (or simply off) in the report.
        "dark_device_hours": 48,
        "audit_log_file": "logs/audit.jsonl",
        "search_log_file": "logs/searches.jsonl",
    },
    "extension": {
        # Optional browser extension that reports search terms and visited
        # URLs (the piece DNS can't see) to /api/extension/events. Give the
        # extension this key; each install is tagged with a client IP.
        "enabled": False,
        "key": "",
    },
    "safe_search": {
        "google": True,
        "bing": True,
        "duckduckgo": True,
        "youtube": "strict",
        "custom_rewrites": [],
    },
    "email": {
        "enabled": False,
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        "use_tls": True,
        "use_ssl": False,
        "username": "",
        "password_env": "FAITHFILTER_SMTP_PASSWORD",
        "from": "",
        "to": [],
        "report_day": "sunday",
        "report_hour": 8,
        # "local" schedules the report in the server's local time zone;
        # "utc" keeps the old behaviour. Curfews are always local time.
        "report_timezone": "local",
        "send_if_empty": True,
        "state_file": "logs/report_state.json",
    },
    "stats": {
        # Long-term per-device statistics (SQLite) powering the dashboard
        # trends view and week-over-week lines in the report.
        "enabled": True,
        "db_file": "logs/stats.db",
        "retention_days": 365,
    },
    "updates": {
        # Check GitHub daily for a newer tagged release; surfaces on the
        # dashboard and in the weekly report (never auto-installs).
        "check": True,
        "repo": "bdscherer/dns",
    },
    "sync": {
        # Follower mode for a secondary server (e.g. a Raspberry Pi):
        # periodically pulls blocklist/whitelist/keywords from the primary's
        # /api/backup endpoint so both servers enforce the same rules.
        # Requires http_api.api_key to be set on the primary.
        "enabled": False,
        "primary_url": "",         # e.g. "http://192.168.1.53:5000"
        "api_key": "",
        "interval_minutes": 60,
        "include_config": False,   # also pull config.yaml (restart needed)
    },
    "logs": {
        "query_log_file": "logs/queries.log",
        "log_level": "INFO",
        "max_log_mb": 20,      # rotate query/alert logs beyond this size
        "log_backups": 3,      # rotated copies to keep (.1, .2, ...)
        # Auto-delete rotated query logs older than this many days;
        # alert/unblock entries use monitoring.alert_retention_days.
        "retention_days": 30,
    },
    "http_api": {
        "enable": True,
        "host": "127.0.0.1",
        "port": 5000,
        # Dashboard password. Leave empty to auto-generate one on first run
        # (stored in admin_password.txt next to the config).
        "password": "",
        "api_key": "",         # optional X-API-Key for scripts
        "doh": True,           # serve DNS-over-HTTPS at /dns-query
        "cert_file": "",       # enable HTTPS for dashboard + DoH
        "key_file": "",
    },
    "dot": {
        # DNS-over-TLS listener (Android "Private DNS"). Requires a real
        # certificate for the hostname devices are configured with.
        "enabled": False,
        "port": 853,
        "cert_file": "",
        "key_file": "",
    },
}


def deep_merge(base: Dict, override: Dict) -> Dict:
    """Merge ``override`` into a copy of ``base``.

    Dictionaries merge recursively; lists and scalars in the override
    replace the base value entirely.
    """
    merged = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


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

# "Canary" domains: answering NXDOMAIN for these makes Firefox disable its
# built-in DNS-over-HTTPS and disables iCloud Private Relay, so devices keep
# using this resolver instead of tunnelling around it.
DOH_CANARY_DOMAINS = {
    "use-application-dns.net",
    "mask.icloud.com",
    "mask-h2.icloud.com",
}

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


def rotate_if_needed(path: str, max_bytes: int, backups: int) -> None:
    """Size-based log rotation: path -> path.1 -> path.2 ... path.<backups>."""
    try:
        if max_bytes <= 0 or not os.path.exists(path) \
                or os.path.getsize(path) < max_bytes:
            return
        for i in range(backups - 1, 0, -1):
            src, dst = f"{path}.{i}", f"{path}.{i + 1}"
            if os.path.exists(src):
                os.replace(src, dst)
        if backups > 0:
            os.replace(path, f"{path}.1")
    except OSError:
        pass


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
        # Compiled wildcard/regex rules from the personal blocklist.
        self._patterns: List[re.Pattern] = []
        self._whitelist: Set[str] = set()
        self._source_counts: Dict[str, int] = {}
        self._stop = threading.Event()
        # Refresh health: consecutive failures per source, and a callback
        # (set by main) fired when a source keeps failing.
        self._fail_counts: Dict[str, int] = {}
        self.failure_threshold = int(config.get("notifications", {}).get(
            "refresh_failure_threshold", 3))
        self.on_refresh_failure: Optional[Callable[[str, str], None]] = None
        self.last_refresh: Optional[datetime.datetime] = None
        self.last_refresh_ok = True
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
                self._fail_counts[name] = 0
            except Exception as exc:
                self.logger.warning("Download of source '%s' failed (%s); "
                                    "using cached copy if available", name, exc)
                self._fail_counts[name] = self._fail_counts.get(name, 0) + 1
                if (self._fail_counts[name] == self.failure_threshold
                        and self.on_refresh_failure):
                    self.on_refresh_failure(name, str(exc))
        return load_domains_from_file(cache)

    @staticmethod
    def compile_pattern(line: str) -> Optional[re.Pattern]:
        """Compile a personal-blocklist pattern rule.

        ``/regex/`` lines are treated as regular expressions and lines
        containing ``*`` as shell-style wildcards; both are matched against
        the full query name.  Returns None for invalid patterns.
        """
        try:
            if len(line) > 2 and line.startswith("/") and line.endswith("/"):
                return re.compile(line[1:-1])
            if "*" in line:
                return re.compile(fnmatch.translate(line))
        except re.error:
            return None
        return None

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
        # The personal blocklist may also contain wildcard ("*.x.com",
        # "*tiktok*") and regex ("/.../") rules alongside plain domains.
        patterns: List[re.Pattern] = []
        personal: Set[str] = set()
        for line in load_lines_from_file(self.my_blocklist_file):
            pattern = self.compile_pattern(line)
            if pattern is not None:
                patterns.append(pattern)
            else:
                personal.update(parse_domain_lines([line]))
        counts["my_blocklist"] = len(personal) + len(patterns)
        for d in personal:
            # Keep the adult/ads categorisation when a source already lists
            # the domain, so monitoring alerts still fire for it.
            domains.setdefault(d, "custom")
        whitelist = load_domains_from_file(self.whitelist_file)
        with self._lock:
            self._domains = domains
            self._patterns = patterns
            self._whitelist = whitelist
            self._source_counts = counts
        if download:
            self.last_refresh = datetime.datetime.now(datetime.timezone.utc)
            self.last_refresh_ok = all(v == 0 for v in self._fail_counts.values())
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
            if match:
                return self._domains[match]
            for pattern in self._patterns:
                if pattern.match(domain):
                    return "custom"
        return None

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

    def __init__(self, path: str, logger: logging.Logger,
                 max_bytes: int = 20 * 1024 * 1024, backups: int = 3):
        self.path = path
        self.logger = logger
        self.max_bytes = max_bytes
        self.backups = backups
        self._lock = threading.Lock()
        self._recent: Dict[Tuple[str, str, str], float] = {}

    def add(self, client: str, domain: str, reason: str, detail: str,
            person: str = "") -> None:
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
            "reason": reason,   # "adult_domain" | "keyword" | "bypass_attempt"
            "detail": detail,   # category or the matched keyword
            "person": person,   # attribution when known (e.g. token endpoint)
        }
        try:
            if os.path.dirname(self.path):
                os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with self._lock:
                rotate_if_needed(self.path, self.max_bytes, self.backups)
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
# Notifier: shared SMTP sender for reports, instant alerts and health mail
# ---------------------------------------------------------------------------

class Notifier:
    """Sends e-mail via the configured SMTP account, with optional
    per-key throttling so alert storms don't flood the inbox."""

    def __init__(self, config: Dict, logger: logging.Logger):
        self.cfg = config.get("email", {})
        self.logger = logger
        self._lock = threading.Lock()
        self._last: Dict[str, float] = {}

    @property
    def enabled(self) -> bool:
        return bool(self.cfg.get("enabled", False))

    def _password(self) -> str:
        env = self.cfg.get("password_env")
        if env and os.environ.get(env):
            return os.environ[env]
        return self.cfg.get("password", "")

    def send(self, subject: str, body: str,
             recipients: Optional[List[str]] = None) -> bool:
        if not self.enabled:
            return False
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self.cfg.get("from") or self.cfg.get("username", "faithfilter@localhost")
        if recipients is None:
            recipients = self.cfg.get("to", [])
        if isinstance(recipients, str):
            recipients = [recipients]
        if not recipients:
            return False
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
                smtp.login(username, self._password())
            smtp.send_message(msg)
            smtp.quit()
            return True
        except Exception as exc:
            self.logger.error("Failed to send e-mail '%s': %s", subject, exc)
            return False

    def send_throttled(self, key: str, min_interval_seconds: float,
                       subject: str, body: str,
                       recipients: Optional[List[str]] = None) -> bool:
        """Send unless a mail with the same key went out too recently."""
        now = time.time()
        with self._lock:
            if now - self._last.get(key, 0) < min_interval_seconds:
                return False
            self._last[key] = now
        return self.send(subject, body, recipients)


# ---------------------------------------------------------------------------
# DNS response cache
# ---------------------------------------------------------------------------

class DNSCache:
    """TTL cache of upstream responses with optional serve-stale.

    Responses are stored packed (wire format) so a cached answer can't be
    mutated; the transaction ID is patched on the way out.  When every
    upstream fails, a stale entry (up to a day old) is served instead of
    SERVFAIL so the network keeps working through outages.
    """

    STALE_KEEP_SECONDS = 86400

    def __init__(self, max_entries: int = 20000, serve_stale: bool = True):
        self.max_entries = max_entries
        self.serve_stale = serve_stale
        self._lock = threading.Lock()
        # key -> (packed_response, fresh_until, stale_until)
        self._store: "OrderedDict[Tuple[str, int], Tuple[bytes, float, float]]" = OrderedDict()
        self.hits = 0
        self.misses = 0
        self.stale_served = 0

    @staticmethod
    def _key(request: DNSRecord) -> Tuple[str, int]:
        return (str(request.q.qname).lower(), request.q.qtype)

    def get(self, request: DNSRecord, allow_stale: bool = False) -> Optional[DNSRecord]:
        now = time.time()
        with self._lock:
            entry = self._store.get(self._key(request))
            if not entry:
                self.misses += 1
                return None
            packed, fresh_until, stale_until = entry
            if now < fresh_until:
                self._store.move_to_end(self._key(request))
                self.hits += 1
            elif allow_stale and self.serve_stale and now < stale_until:
                self.stale_served += 1
            else:
                self.misses += 1
                return None
        response = DNSRecord.parse(packed)
        response.header.id = request.header.id
        return response

    def put(self, request: DNSRecord, response: DNSRecord) -> None:
        if response.header.rcode not in (RCODE.NOERROR, RCODE.NXDOMAIN):
            return
        ttls = [rr.ttl for rr in response.rr] or [300]
        ttl = max(10, min(min(ttls), 3600))
        now = time.time()
        with self._lock:
            self._store[self._key(request)] = (
                response.pack(), now + ttl, now + self.STALE_KEEP_SECONDS)
            self._store.move_to_end(self._key(request))
            while len(self._store) > self.max_entries:
                self._store.popitem(last=False)

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {"entries": len(self._store), "hits": self.hits,
                    "misses": self.misses, "stale_served": self.stale_served}


# ---------------------------------------------------------------------------
# Per-device policies (groups, filtering levels, curfews)
# ---------------------------------------------------------------------------

DAY_ALIASES = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4,
               "sat": 5, "sun": 6}


class ClientPolicies:
    """Resolves a client IP to its policy group and evaluates curfews.

    Group settings (all optional):
      members:      list of IPs or CIDR networks
      filtering:    "full" (default) | "monitor_only" | "off"
      safe_search:  true (default) / false
      curfew:       list of {days: [...], from: "HH:MM", to: "HH:MM"} windows
                    during which ALL internet (DNS) access is blocked.
                    Windows may cross midnight. Times are server-local.
    """

    DEFAULT_GROUP: Dict = {"name": "default", "filtering": "full",
                           "safe_search": True, "curfew": []}

    def __init__(self, config: Dict, logger: logging.Logger):
        self.logger = logger
        self.groups: List[Dict] = []
        for group in config.get("clients", {}).get("groups", []) or []:
            networks = []
            for member in group.get("members", []) or []:
                try:
                    networks.append(ipaddress.ip_network(str(member), strict=False))
                except ValueError:
                    logger.warning("Ignoring invalid client group member %r "
                                   "in group %r", member, group.get("name"))
            self.groups.append({**group, "_networks": networks})

    def group_for(self, client_ip: str) -> Dict:
        try:
            addr = ipaddress.ip_address(client_ip)
        except ValueError:
            return self.DEFAULT_GROUP
        for group in self.groups:
            if any(addr in net for net in group["_networks"]):
                return group
        return self.DEFAULT_GROUP

    @staticmethod
    def _parse_hhmm(value: str) -> Optional[int]:
        try:
            hours, minutes = str(value).split(":")
            return int(hours) * 60 + int(minutes)
        except (ValueError, AttributeError):
            return None

    @classmethod
    def curfew_active(cls, group: Dict,
                      now: Optional[datetime.datetime] = None) -> bool:
        windows = group.get("curfew", []) or []
        if not windows:
            return False
        now = now or datetime.datetime.now()
        minutes_now = now.hour * 60 + now.minute
        weekday = now.weekday()
        for window in windows:
            days = [DAY_ALIASES.get(str(d).lower()[:3]) for d in
                    (window.get("days") or list(DAY_ALIASES))]
            start = cls._parse_hhmm(window.get("from", ""))
            end = cls._parse_hhmm(window.get("to", ""))
            if start is None or end is None:
                continue
            if start <= end:
                if weekday in days and start <= minutes_now < end:
                    return True
            else:
                # Window crosses midnight: evening part belongs to the listed
                # day; the after-midnight part belongs to the following day.
                if weekday in days and minutes_now >= start:
                    return True
                prev_day = (weekday - 1) % 7
                if prev_day in days and minutes_now < end:
                    return True
        return False


# ---------------------------------------------------------------------------
# Temporary per-device overrides ("pause internet" / "bonus time")
# ---------------------------------------------------------------------------

class Overrides:
    """Time-limited per-client overrides, persisted across restarts.

    Modes:
      "pause"      - block ALL internet access for the device
      "unfiltered" - disable every filter for the device
    """

    MODES = ("pause", "unfiltered")

    def __init__(self, path: str, logger: logging.Logger):
        self.path = path
        self.logger = logger
        self._lock = threading.Lock()
        self._entries: Dict[str, Dict] = {}
        try:
            if path and os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    self._entries = json.load(f)
        except (OSError, ValueError):
            self._entries = {}

    def _save(self) -> None:
        try:
            if os.path.dirname(self.path):
                os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self._entries, f)
        except OSError as exc:
            self.logger.error("Could not persist overrides: %s", exc)

    def set(self, client: str, mode: str, minutes: float) -> Dict:
        if mode not in self.MODES:
            raise ValueError(f"mode must be one of {self.MODES}")
        until = (datetime.datetime.now(datetime.timezone.utc)
                 + datetime.timedelta(minutes=minutes))
        entry = {"mode": mode, "until": until.isoformat()}
        with self._lock:
            self._entries[client] = entry
            self._save()
        return {"client": client, **entry}

    def cancel(self, client: str) -> bool:
        with self._lock:
            if client in self._entries:
                del self._entries[client]
                self._save()
                return True
        return False

    def active(self, client: str) -> Optional[str]:
        """Return the active mode for a client, pruning expired entries."""
        with self._lock:
            entry = self._entries.get(client)
            if not entry:
                return None
            try:
                until = datetime.datetime.fromisoformat(entry["until"])
            except (ValueError, KeyError):
                del self._entries[client]
                self._save()
                return None
            if datetime.datetime.now(datetime.timezone.utc) >= until:
                del self._entries[client]
                self._save()
                return None
            return entry["mode"]

    def list(self) -> List[Dict]:
        now = datetime.datetime.now(datetime.timezone.utc)
        result = []
        with self._lock:
            for client, entry in self._entries.items():
                try:
                    until = datetime.datetime.fromisoformat(entry["until"])
                except (ValueError, KeyError):
                    continue
                if until > now:
                    result.append({"client": client, "mode": entry["mode"],
                                   "until": entry["until"]})
        return result


# ---------------------------------------------------------------------------
# Long-term statistics (SQLite)
# ---------------------------------------------------------------------------

class StatsDB:
    """Per-day, per-device counters for trends and week-over-week lines.

    Queries increment in-memory counters that a background thread flushes
    to SQLite, so the hot path never touches the disk.
    """

    def __init__(self, db_file: str, logger: logging.Logger,
                 flush_interval: float = 30.0):
        self.logger = logger
        self._lock = threading.Lock()
        self._pending: Dict[Tuple[str, str, str], int] = {}
        self._stop = threading.Event()
        if os.path.dirname(db_file):
            os.makedirs(os.path.dirname(db_file), exist_ok=True)
        self._db = sqlite3.connect(db_file, check_same_thread=False)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS stats ("
            " day TEXT NOT NULL, client TEXT NOT NULL, kind TEXT NOT NULL,"
            " count INTEGER NOT NULL DEFAULT 0,"
            " PRIMARY KEY (day, client, kind))")
        # Hour-of-day activity for the accountability report (late-night
        # patterns are themselves a signal).
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS hourly ("
            " day TEXT NOT NULL, client TEXT NOT NULL, hour INTEGER NOT NULL,"
            " count INTEGER NOT NULL DEFAULT 0,"
            " PRIMARY KEY (day, client, hour))")
        self._db.commit()
        self._pending_hourly: Dict[Tuple[str, str, int], int] = {}
        if flush_interval > 0:
            threading.Thread(target=self._flush_loop, args=(flush_interval,),
                             name="stats-flush", daemon=True).start()

    @staticmethod
    def _kind_for(action: str) -> Optional[str]:
        if action.startswith("blocked"):
            return "blocked"
        if action.startswith("flagged"):
            return "flagged"
        return None

    def record(self, client: str, action: str) -> None:
        now = datetime.datetime.now()
        day = now.date().isoformat()
        with self._lock:
            self._pending[(day, client, "total")] = \
                self._pending.get((day, client, "total"), 0) + 1
            kind = self._kind_for(action)
            if kind:
                self._pending[(day, client, kind)] = \
                    self._pending.get((day, client, kind), 0) + 1
            hkey = (day, client, now.hour)
            self._pending_hourly[hkey] = self._pending_hourly.get(hkey, 0) + 1

    def flush(self) -> None:
        with self._lock:
            pending, self._pending = self._pending, {}
            hourly, self._pending_hourly = self._pending_hourly, {}
            if not pending and not hourly:
                return
            try:
                for (day, client, kind), count in pending.items():
                    self._db.execute(
                        "INSERT INTO stats (day, client, kind, count) "
                        "VALUES (?, ?, ?, ?) "
                        "ON CONFLICT(day, client, kind) "
                        "DO UPDATE SET count = count + excluded.count",
                        (day, client, kind, count))
                for (day, client, hour), count in hourly.items():
                    self._db.execute(
                        "INSERT INTO hourly (day, client, hour, count) "
                        "VALUES (?, ?, ?, ?) "
                        "ON CONFLICT(day, client, hour) "
                        "DO UPDATE SET count = count + excluded.count",
                        (day, client, hour, count))
                self._db.commit()
            except sqlite3.Error as exc:
                self.logger.error("Stats flush failed: %s", exc)

    def _flush_loop(self, interval: float) -> None:
        while not self._stop.wait(interval):
            self.flush()

    def trends(self, days: int = 30) -> List[Dict]:
        """Per-day, per-client counters for the last N days."""
        self.flush()
        since = (datetime.date.today()
                 - datetime.timedelta(days=days - 1)).isoformat()
        with self._lock:
            rows = self._db.execute(
                "SELECT day, client, kind, count FROM stats "
                "WHERE day >= ? ORDER BY day", (since,)).fetchall()
        merged: Dict[Tuple[str, str], Dict] = {}
        for day, client, kind, count in rows:
            entry = merged.setdefault((day, client),
                                      {"day": day, "client": client,
                                       "total": 0, "blocked": 0, "flagged": 0})
            entry[kind] = count
        return list(merged.values())

    def totals_between(self, start: datetime.date,
                       end: datetime.date) -> Dict[str, int]:
        """Summed total/blocked counters for [start, end)."""
        self.flush()
        with self._lock:
            rows = self._db.execute(
                "SELECT kind, SUM(count) FROM stats "
                "WHERE day >= ? AND day < ? GROUP BY kind",
                (start.isoformat(), end.isoformat())).fetchall()
        return {kind: total or 0 for kind, total in rows}

    def totals_for_clients(self, clients: List[str], start: datetime.date,
                           end: datetime.date) -> Dict[str, int]:
        """Summed counters for a set of devices over [start, end)."""
        if not clients:
            return {}
        self.flush()
        placeholders = ",".join("?" * len(clients))
        with self._lock:
            rows = self._db.execute(
                f"SELECT kind, SUM(count) FROM stats "
                f"WHERE day >= ? AND day < ? AND client IN ({placeholders}) "
                f"GROUP BY kind",
                [start.isoformat(), end.isoformat(), *clients]).fetchall()
        return {kind: total or 0 for kind, total in rows}

    def hourly_pattern(self, clients: List[str], start: datetime.date,
                       end: datetime.date) -> List[int]:
        """24-slot activity histogram for a set of devices over [start, end)."""
        pattern = [0] * 24
        if not clients:
            return pattern
        self.flush()
        placeholders = ",".join("?" * len(clients))
        with self._lock:
            rows = self._db.execute(
                f"SELECT hour, SUM(count) FROM hourly "
                f"WHERE day >= ? AND day < ? AND client IN ({placeholders}) "
                f"GROUP BY hour",
                [start.isoformat(), end.isoformat(), *clients]).fetchall()
        for hour, total in rows:
            if 0 <= hour < 24:
                pattern[hour] = total or 0
        return pattern

    def last_seen(self, clients: List[str]) -> Dict[str, Optional[str]]:
        """Most recent active day per device (None if never seen)."""
        result: Dict[str, Optional[str]] = {c: None for c in clients}
        if not clients:
            return result
        self.flush()
        placeholders = ",".join("?" * len(clients))
        with self._lock:
            rows = self._db.execute(
                f"SELECT client, MAX(day) FROM stats "
                f"WHERE client IN ({placeholders}) GROUP BY client",
                list(clients)).fetchall()
        for client, day in rows:
            result[client] = day
        return result

    def purge(self, retention_days: int) -> None:
        cutoff = (datetime.date.today()
                  - datetime.timedelta(days=retention_days)).isoformat()
        with self._lock:
            self._db.execute("DELETE FROM stats WHERE day < ?", (cutoff,))
            self._db.execute("DELETE FROM hourly WHERE day < ?", (cutoff,))
            self._db.commit()

    def stop(self) -> None:
        self._stop.set()
        self.flush()


# ---------------------------------------------------------------------------
# Content categories (for accountability reporting)
# ---------------------------------------------------------------------------

# Maps a report category to substrings found in the domain name.  This is a
# best-effort classifier layered on top of the blocklist categories so the
# accountability report can say *what kind* of content was requested, not
# just "blocked".  Ordered by priority (first match wins).
CATEGORY_KEYWORDS: List[Tuple[str, Tuple[str, ...]]] = [
    ("adult", ("porn", "xxx", "sex", "nude", "naked", "hentai", "milf",
               "erotic", "escort", "camgirl", "onlyfans", "xvideo",
               "xhamster", "redtube", "fetish", "nsfw", "adult")),
    ("dating", ("tinder", "bumble", "grindr", "okcupid", "match.com",
                "hookup", "ashleymadison", "adultfriend")),
    ("gambling", ("casino", "poker", "bet365", "betting", "gambl", "slots",
                  "wager", "sportsbook", "draftkings", "fanduel")),
    ("violence", ("gore", "liveleak", "bestgore")),
    ("social", ("facebook", "instagram", "tiktok", "snapchat", "twitter",
                "x.com", "reddit", "discord", "tumblr", "9gag")),
    ("streaming", ("youtube", "netflix", "hulu", "twitch", "disneyplus",
                   "primevideo", "hbomax")),
    ("gaming", ("steampowered", "roblox", "epicgames", "minecraft",
                "leagueoflegends", "battle.net", "xbox", "playstation")),
]


def classify_domain(domain: str, blocklist_category: Optional[str] = None) -> str:
    """Return a report category for a domain.

    A blocklist category of ``adult``/``bypass`` wins outright; otherwise the
    domain name is matched against CATEGORY_KEYWORDS; failing that the
    blocklist category (e.g. ``ads``) or ``other`` is used.
    """
    if blocklist_category == "adult":
        return "adult"
    if blocklist_category == "bypass":
        return "bypass"
    lowered = domain.lower()
    for category, needles in CATEGORY_KEYWORDS:
        if any(n in lowered for n in needles):
            return category
    if blocklist_category and blocklist_category not in ("custom",):
        return blocklist_category
    return "other"


# ---------------------------------------------------------------------------
# Audit log (tamper-evidence for accountability)
# ---------------------------------------------------------------------------

class AuditLog:
    """Records changes that weaken filtering, so an accountability partner
    can see if protections were paused, whitelisted or bypassed."""

    def __init__(self, path: str, logger: logging.Logger,
                 max_bytes: int = 5 * 1024 * 1024, backups: int = 3):
        self.path = path
        self.logger = logger
        self.max_bytes = max_bytes
        self.backups = backups
        self._lock = threading.Lock()

    def add(self, event: str, detail: str, client: str = "",
            actor: str = "") -> None:
        entry = {
            "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "event": event,      # e.g. "override_pause", "whitelist_add"
            "detail": detail,
            "client": client,
            "actor": actor,
        }
        try:
            if os.path.dirname(self.path):
                os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with self._lock:
                rotate_if_needed(self.path, self.max_bytes, self.backups)
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")
        except OSError as exc:
            self.logger.error("Could not write audit log: %s", exc)

    def read_since(self, since: datetime.datetime) -> List[Dict]:
        entries: List[Dict] = []
        if not os.path.exists(self.path):
            return entries
        with open(self.path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    ts = datetime.datetime.fromisoformat(entry["time"])
                except (ValueError, KeyError):
                    continue
                if ts >= since:
                    entries.append(entry)
        return entries


# ---------------------------------------------------------------------------
# Search / URL log (fed by the browser extension)
# ---------------------------------------------------------------------------

class SearchLog:
    """Stores browser search terms and visited URLs reported by the optional
    extension — the piece DNS alone cannot see."""

    def __init__(self, path: str, logger: logging.Logger, keywords=None,
                 max_bytes: int = 20 * 1024 * 1024, backups: int = 3):
        self.path = path
        self.logger = logger
        self.keywords = [k.lower() for k in (keywords or [])]
        self.max_bytes = max_bytes
        self.backups = backups
        self._lock = threading.Lock()

    def add(self, client: str, kind: str, engine: str, query: str,
            url: str = "") -> Dict:
        flagged = any(k in query.lower() for k in self.keywords)
        entry = {
            "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "client": client,
            "kind": kind,          # "search" | "visit"
            "engine": engine,
            "query": query[:300],
            "url": url[:500],
            "flagged": flagged,
        }
        try:
            if os.path.dirname(self.path):
                os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with self._lock:
                rotate_if_needed(self.path, self.max_bytes, self.backups)
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")
        except OSError as exc:
            self.logger.error("Could not write search log: %s", exc)
        return entry

    def read_since(self, since: datetime.datetime,
                   clients: Optional[List[str]] = None) -> List[Dict]:
        entries: List[Dict] = []
        if not os.path.exists(self.path):
            return entries
        with open(self.path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    ts = datetime.datetime.fromisoformat(entry["time"])
                except (ValueError, KeyError):
                    continue
                if ts >= since and (clients is None
                                    or entry.get("client") in clients):
                    entries.append(entry)
        return entries


# ---------------------------------------------------------------------------
# Accountability: people, their devices, and their allies
# ---------------------------------------------------------------------------

class Person:
    def __init__(self, spec: Dict):
        self.name = str(spec.get("name", "Unknown"))
        self.devices = [str(d) for d in (spec.get("devices") or [])]
        allies = spec.get("allies") or []
        self.allies = [allies] if isinstance(allies, str) else [str(a) for a in allies]
        self.self_report = bool(spec.get("self_report", False))


class Accountability:
    """Loads the people/allies model and builds per-person reports."""

    def __init__(self, config: Dict, logger: logging.Logger):
        cfg = config.get("accountability", {})
        self.enabled = bool(cfg.get("enabled", False))
        self.logger = logger
        self.dark_after_hours = float(cfg.get("dark_device_hours", 48))
        # Public hostname devices use to reach this server's DoH/DoT endpoint
        # (for per-device setup profiles), e.g. "dns.example.com".
        self.base_domain = str(cfg.get("base_domain", "")).strip()
        self.people = [Person(p) for p in (cfg.get("people") or [])]

    def person_for(self, client_ip: str) -> Optional[Person]:
        for person in self.people:
            if client_ip in person.devices:
                return person
        return None

    def by_name(self, name: str) -> Optional[Person]:
        for person in self.people:
            if person.name == name:
                return person
        return None

    @staticmethod
    def _clean_streak_days(person_alerts: List[Dict]) -> int:
        """Consecutive days up to today with no adult/bypass alerts."""
        bad_days = set()
        for alert in person_alerts:
            if alert.get("reason") in ("adult_domain", "bypass_attempt"):
                bad_days.add(alert["time"][:10])
        streak = 0
        day = datetime.date.today()
        # Cap at a year so a fresh install doesn't claim an implausible run.
        while day.isoformat() not in bad_days and streak < 365:
            streak += 1
            day -= datetime.timedelta(days=1)
        return streak


class DeviceTokens:
    """Stable per-person secret tokens for per-device DoH/DoT endpoints.

    A token identifies a person regardless of the source IP, so a phone on
    cellular that uses ``/p/<token>/dns-query`` still has its activity
    attributed to that person's accountability report. Tokens are generated
    once and persisted.
    """

    def __init__(self, path: str, logger: logging.Logger):
        self.path = path
        self.logger = logger
        self._lock = threading.Lock()
        self._by_person: Dict[str, str] = {}
        try:
            if path and os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    self._by_person = json.load(f)
        except (OSError, ValueError):
            self._by_person = {}

    def _save(self) -> None:
        try:
            if os.path.dirname(self.path):
                os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self._by_person, f)
            if os.name == "posix":
                os.chmod(self.path, 0o600)
        except OSError as exc:
            self.logger.error("Could not persist device tokens: %s", exc)

    def token_for(self, person_name: str) -> str:
        with self._lock:
            token = self._by_person.get(person_name)
            if not token:
                token = secrets.token_urlsafe(9)
                self._by_person[person_name] = token
                self._save()
            return token

    def person_for_token(self, token: str) -> Optional[str]:
        if not token:
            return None
        with self._lock:
            for name, tok in self._by_person.items():
                if secrets.compare_digest(tok, token):
                    return name
        return None


# ---------------------------------------------------------------------------
# Update checker
# ---------------------------------------------------------------------------

class UpdateChecker:
    """Checks GitHub once a day for a newer tagged release.

    Never installs anything; the result is shown on the dashboard and in
    the weekly report's health section.
    """

    def __init__(self, config: Dict, logger: logging.Logger):
        cfg = config.get("updates", {})
        self.enabled = bool(cfg.get("check", True))
        self.repo = cfg.get("repo", "bdscherer/dns")
        self.logger = logger
        self.latest_version: Optional[str] = None
        self.update_available = False
        self._stop = threading.Event()

    @staticmethod
    def _as_tuple(version: str) -> Tuple:
        parts = []
        for piece in version.lstrip("vV").split("."):
            digits = "".join(ch for ch in piece if ch.isdigit())
            parts.append(int(digits) if digits else 0)
        return tuple(parts)

    def check_once(self) -> None:
        url = f"https://api.github.com/repos/{self.repo}/releases/latest"
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "FaithFilter/" + __version__,
                              "Accept": "application/vnd.github+json"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                tag = json.load(resp).get("tag_name", "")
        except Exception:
            return  # no releases yet, rate-limited, or offline: stay quiet
        if not tag:
            return
        self.latest_version = tag.lstrip("vV")
        self.update_available = (self._as_tuple(tag)
                                 > self._as_tuple(__version__))
        if self.update_available:
            self.logger.info("A newer FaithFilter release is available: %s "
                             "(running %s)", self.latest_version, __version__)

    def start(self) -> None:
        if not self.enabled:
            return

        def loop() -> None:
            self.check_once()
            while not self._stop.wait(86400):
                self.check_once()

        threading.Thread(target=loop, name="update-check", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()


# ---------------------------------------------------------------------------
# Data retention
# ---------------------------------------------------------------------------

def _prune_jsonl_by_age(path: str, max_age_days: float) -> None:
    """Rewrite a JSONL file keeping only entries newer than the cutoff."""
    if not path or not os.path.exists(path):
        return
    cutoff = (datetime.datetime.now(datetime.timezone.utc)
              - datetime.timedelta(days=max_age_days))
    kept: List[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            try:
                ts = datetime.datetime.fromisoformat(json.loads(line)["time"])
                if ts >= cutoff:
                    kept.append(line)
            except (ValueError, KeyError):
                continue
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.writelines(kept)
    os.replace(tmp, path)


def purge_old_data(config: Dict, stats: Optional[StatsDB],
                   logger: logging.Logger) -> None:
    """Apply the retention policy: browsing history is sensitive, so old
    logs are deleted rather than kept forever."""
    log_days = float(config.get("logs", {}).get("retention_days", 30))
    query_log = config.get("logs", {}).get("query_log_file")
    if query_log and log_days > 0:
        cutoff = time.time() - log_days * 86400
        directory = os.path.dirname(query_log) or "."
        base = os.path.basename(query_log)
        try:
            for name in os.listdir(directory):
                if name.startswith(base + "."):
                    full = os.path.join(directory, name)
                    if os.path.getmtime(full) < cutoff:
                        os.remove(full)
                        logger.info("Retention: removed old log %s", full)
        except OSError as exc:
            logger.warning("Retention sweep failed: %s", exc)

    alert_days = float(config.get("monitoring", {}).get(
        "alert_retention_days", 90))
    if alert_days > 0:
        try:
            _prune_jsonl_by_age(config.get("monitoring", {}).get(
                "alert_log_file"), alert_days)
            _prune_jsonl_by_age(config.get("block_page", {}).get(
                "unblock_requests_file"), alert_days)
        except OSError as exc:
            logger.warning("Alert retention failed: %s", exc)

    if stats:
        stats.purge(int(config.get("stats", {}).get("retention_days", 365)))


# ---------------------------------------------------------------------------
# Backup application and follower sync (secondary server support)
# ---------------------------------------------------------------------------

BACKUP_MEMBERS = ("config.yaml", "blocklist.txt", "whitelist.txt",
                  "keywords.txt")


def backup_targets(config: Dict) -> Dict[str, Optional[str]]:
    blocking = config.get("blocking", {})
    return {
        "config.yaml": config.get("_config_path"),
        "blocklist.txt": blocking.get("my_blocklist"),
        "whitelist.txt": blocking.get("whitelist"),
        "keywords.txt": config.get("monitoring", {}).get("keywords_file"),
    }


def apply_backup_zip(data: bytes, config: Dict,
                     include_config: bool = True) -> List[str]:
    """Write the recognised members of a backup zip to their configured
    locations.  Returns the list of restored file names."""
    targets = backup_targets(config)
    restored: List[str] = []
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for arcname in zf.namelist():
            if arcname not in BACKUP_MEMBERS:
                continue
            if arcname == "config.yaml" and not include_config:
                continue
            path = targets.get(arcname)
            if not path:
                continue
            if os.path.dirname(path):
                os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(zf.read(arcname))
            restored.append(arcname)
    return restored


class SyncFollower:
    """Keeps a secondary server's lists in step with the primary.

    Pulls the primary's /api/backup (authenticated with an API key) on an
    interval and applies blocklist/whitelist/keywords locally, so a
    Raspberry Pi running as DNS 2 enforces the same rules as DNS 1.
    """

    def __init__(self, config: Dict, resolver: "FaithFilterResolver",
                 logger: logging.Logger):
        cfg = config.get("sync", {})
        self.config = config
        self.resolver = resolver
        self.logger = logger
        self.primary_url = str(cfg.get("primary_url", "")).rstrip("/")
        self.api_key = cfg.get("api_key", "")
        self.interval = max(5, float(cfg.get("interval_minutes", 60))) * 60
        self.include_config = bool(cfg.get("include_config", False))
        self.last_sync: Optional[datetime.datetime] = None
        self.last_error: Optional[str] = None
        self._stop = threading.Event()

    def sync_once(self) -> bool:
        try:
            req = urllib.request.Request(
                self.primary_url + "/api/backup",
                headers={"X-API-Key": self.api_key,
                         "User-Agent": "FaithFilter/" + __version__})
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = resp.read()
            restored = apply_backup_zip(data, self.config,
                                        self.include_config)
            if "config.yaml" in restored:
                self._preserve_sync_section()
            self.resolver.blocklists.reload(download=False)
            self.resolver.keywords.reload()
            self.last_sync = datetime.datetime.now(datetime.timezone.utc)
            self.last_error = None
            self.logger.info("Synced %s from primary %s",
                             ", ".join(restored) or "nothing",
                             self.primary_url)
            return True
        except Exception as exc:
            self.last_error = str(exc)
            self.logger.warning("Sync from primary failed: %s", exc)
            return False

    def _preserve_sync_section(self) -> None:
        """Re-apply this follower's own sync settings after pulling the
        primary's config.yaml, which would otherwise disable the sync on
        the next restart (the primary has sync.enabled: false)."""
        path = self.config.get("_config_path")
        if not path or not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                pulled = yaml.safe_load(f) or {}
            pulled["sync"] = {
                "enabled": True,
                "primary_url": self.primary_url,
                "api_key": self.api_key,
                "interval_minutes": self.interval / 60,
                "include_config": self.include_config,
            }
            with open(path, "w", encoding="utf-8") as f:
                yaml.safe_dump(pulled, f, default_flow_style=False,
                               sort_keys=False)
        except (OSError, yaml.YAMLError) as exc:
            self.logger.warning("Could not preserve sync settings in "
                                "pulled config: %s", exc)

    def start(self) -> None:
        if not self.primary_url:
            self.logger.error("sync.enabled is true but sync.primary_url "
                              "is not set")
            return

        def loop() -> None:
            self.sync_once()
            while not self._stop.wait(self.interval):
                self.sync_once()

        threading.Thread(target=loop, name="sync-follower",
                         daemon=True).start()
        self.logger.info("Follower sync enabled: pulling lists from %s "
                         "every %d minutes",
                         self.primary_url, int(self.interval / 60))

    def stop(self) -> None:
        self._stop.set()


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


def detect_local_ip() -> str:
    """Best-effort detection of this machine's primary LAN IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("1.1.1.1", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


class FaithFilterResolver(BaseResolver):
    """DNS resolver implementing whitelist, safe search, monitoring and
    category-based blocking."""

    def __init__(self, config: Dict, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.start_time = datetime.datetime.now(datetime.timezone.utc)
        logs_cfg = config.get("logs", {})
        self.log_max_bytes = int(float(logs_cfg.get("max_log_mb", 20)) * 1024 * 1024)
        self.log_backups = int(logs_cfg.get("log_backups", 3))
        self.blocklists = BlocklistManager(config, logger)
        alert_file = config.get("monitoring", {}).get(
            "alert_log_file", "logs/alerts.jsonl")
        self.alerts = AlertLog(alert_file, logger,
                               self.log_max_bytes, self.log_backups)
        self.keywords = KeywordMonitor(config, logger)
        self.safe_search = SafeSearchEngine(config, self._forward_query, logger)
        self.policies = ClientPolicies(config, logger)
        clients_cfg = config.get("clients", {})
        self.client_names: Dict[str, str] = {
            str(ip): str(name)
            for ip, name in (clients_cfg.get("names") or {}).items()}
        self.overrides = Overrides(
            clients_cfg.get("overrides_file", "logs/overrides.json"), logger)
        stats_cfg = config.get("stats", {})
        self.statsdb: Optional[StatsDB] = None
        if stats_cfg.get("enabled", True):
            self.statsdb = StatsDB(stats_cfg.get("db_file", "logs/stats.db"),
                                   logger)
        self.notifier = Notifier(config, logger)
        self.notifications = config.get("notifications", {})
        # Accountability layer (people/allies, audit trail, search log).
        self.accountability = Accountability(config, logger)
        acct_cfg = config.get("accountability", {})
        self.audit = AuditLog(acct_cfg.get("audit_log_file",
                                           "logs/audit.jsonl"), logger)
        self.search_log = SearchLog(
            acct_cfg.get("search_log_file", "logs/searches.jsonl"), logger,
            keywords=self.keywords.keywords)
        self.device_tokens = DeviceTokens(
            acct_cfg.get("device_tokens_file", "logs/device_tokens.json"),
            logger)
        self.blocklists.on_refresh_failure = self._refresh_failure_alert
        cache_cfg = config.get("dns", {}).get("cache", {})
        self.cache: Optional[DNSCache] = None
        if cache_cfg.get("enabled", True):
            self.cache = DNSCache(int(cache_cfg.get("max_entries", 20000)),
                                  bool(cache_cfg.get("serve_stale", True)))
        self.block_response = str(config.get("dns", {}).get(
            "block_response", "nxdomain")).lower()
        self.block_cname_cloaking = bool(config.get("dns", {}).get(
            "block_cname_cloaking", True))
        self.block_doh_canary = bool(config.get("blocking", {}).get(
            "block_doh_canary", True))
        bp_cfg = config.get("block_page", {})
        self.block_page_ip: Optional[str] = None
        if bp_cfg.get("enabled", False):
            self.block_page_ip = bp_cfg.get("ip") or detect_local_ip()
        self.stats: Dict[str, int] = {
            "total_queries": 0,
            "blocked": 0,
            "blocked_ads": 0,
            "blocked_adult": 0,
            "blocked_bypass": 0,
            "blocked_curfew": 0,
            "blocked_cname": 0,
            "safe_search_rewrites": 0,
            "alerts": 0,
        }
        self.recent_queries: List[Dict] = []
        self._recent_lock = threading.Lock()

    def _refresh_failure_alert(self, source_name: str, error: str) -> None:
        self.notifier.send(
            "FaithFilter warning: blocklist refresh failing",
            f"The blocklist source '{source_name}' has failed to refresh "
            f"{self.blocklists.failure_threshold} times in a row.\n"
            f"Last error: {error}\n\n"
            "The cached copy is still being enforced, but it will grow stale "
            "until the download succeeds again.")

    # -- helpers --------------------------------------------------------------

    def client_label(self, client_ip: str) -> str:
        name = self.client_names.get(client_ip)
        return f"{name} ({client_ip})" if name else client_ip

    def log_query(self, client_ip: str, domain: str, action: str) -> None:
        if self.statsdb:
            self.statsdb.record(client_ip, action)
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
                rotate_if_needed(log_file, self.log_max_bytes, self.log_backups)
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

    def _forward_cached(self, request: DNSRecord) -> Optional[DNSRecord]:
        """Forward through the TTL cache, serving stale on upstream failure."""
        if self.cache:
            cached = self.cache.get(request)
            if cached:
                return cached
        response = self._forward_query(request)
        if response is not None:
            if self.cache:
                self.cache.put(request, response)
            return response
        if self.cache:
            return self.cache.get(request, allow_stale=True)
        return None

    def _blocked_reply(self, request: DNSRecord) -> DNSRecord:
        reply = request.reply()
        if self.block_page_ip:
            # Answer A queries with this server so the browser lands on the
            # block page; suppress AAAA so IPv6 doesn't dodge it.
            q = request.q
            if q.qtype == QTYPE.A:
                reply.add_answer(RR(rname=q.qname, rtype=QTYPE.A, rclass=1,
                                    ttl=30, rdata=A(self.block_page_ip)))
            return reply
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
                      reason: str, detail: str,
                      person: Optional["Person"] = None) -> None:
        self.stats["alerts"] += 1
        # Prefer an explicit identity (per-device token endpoint); fall back
        # to the IP-based device lookup.
        person = person or self.accountability.person_for(client_ip)
        self.alerts.add(client_ip, domain, reason, detail,
                        person=person.name if person else "")
        if (reason in ("adult_domain", "bypass_attempt")
                and self.notifications.get("instant_alerts", True)):
            interval = float(self.notifications.get(
                "instant_min_minutes", 60)) * 60
            kind = ("adult content" if reason == "adult_domain"
                    else "a filter-bypass service (VPN/proxy/DoH)")
            label = person.name if person else self.client_label(client_ip)
            self.notifier.send_throttled(
                f"instant:{label}", interval,
                f"FaithFilter alert: {label} tried to reach {kind}",
                f"Device {label} attempted to access {domain} "
                f"({reason}: {detail}).\n\n"
                "Further attempts from this device within the next hour are "
                "throttled; the weekly report will contain the full list.")
            # Notify the person's accountability partners directly.
            if person and person.allies:
                self.notifier.send_throttled(
                    f"ally:{person.name}:{reason}", interval,
                    f"Accountability alert for {person.name}",
                    f"{person.name} ({label}) attempted to access {kind}:\n"
                    f"  {domain}\n\nThis is an automated accountability alert. "
                    "The full weekly report will follow.",
                    recipients=person.allies)

    @staticmethod
    def _servfail(request: DNSRecord) -> DNSRecord:
        """SERVFAIL reply (dnslib's reply() takes no rcode argument)."""
        reply = request.reply()
        reply.header.rcode = RCODE.SERVFAIL
        return reply

    def _cname_blocked(self, response: DNSRecord) -> Optional[str]:
        """Category if a CNAME in the response chains to a blocked domain
        (ad networks hide trackers behind first-party subdomains)."""
        if not self.block_cname_cloaking:
            return None
        for rr in response.rr:
            if rr.rtype == QTYPE.CNAME:
                target = str(rr.rdata).rstrip(".").lower()
                if self.blocklists.is_whitelisted(target):
                    continue
                category = self.blocklists.blocked_category(target)
                if category:
                    return category
        return None

    # -- main entry point -------------------------------------------------------

    def resolve(self, request: DNSRecord, handler: object) -> DNSRecord:
        self.stats["total_queries"] += 1
        qname = str(request.q.qname).rstrip(".").lower()
        client_ip = (handler.client_address[0]
                     if hasattr(handler, "client_address") else "unknown")
        # Per-device token/DoH endpoints attach a Person so activity is
        # attributed to them even off the home network.
        identity: Optional["Person"] = getattr(
            handler, "faithfilter_identity", None)
        group = self.policies.group_for(client_ip)
        filtering = str(group.get("filtering", "full")).lower()

        # Temporary overrides trump the group policy.
        override = self.overrides.active(client_ip)
        if override == "pause":
            self.stats["blocked"] += 1
            self.log_query(client_ip, qname, "blocked:paused")
            return self._blocked_reply(request)
        if override == "unfiltered":
            filtering = "off"

        enforce = filtering == "full"          # blocking active
        monitor = filtering in ("full", "monitor_only")

        # 0a. Unfiltered devices skip everything.
        if filtering == "off":
            self.log_query(client_ip, qname, "allowed:unfiltered")
            resp = self._forward_cached(request)
            return resp if resp else self._servfail(request)

        # 0b. DoH/Private-Relay canaries: NXDOMAIN keeps devices on this
        # resolver instead of tunnelling their DNS elsewhere.
        if self.block_doh_canary and qname in DOH_CANARY_DOMAINS:
            self.log_query(client_ip, qname, "blocked:doh_canary")
            reply = request.reply()
            reply.header.rcode = RCODE.NXDOMAIN
            return reply

        # 0c. Curfew: all internet access blocked during the window.
        if enforce and ClientPolicies.curfew_active(group):
            self.stats["blocked"] += 1
            self.stats["blocked_curfew"] += 1
            self.log_query(client_ip, qname, "blocked:curfew")
            return self._blocked_reply(request)

        # 1. Whitelist bypasses the remaining filters.
        if self.blocklists.is_whitelisted(qname):
            self.log_query(client_ip, qname, "whitelisted")
            resp = self._forward_cached(request)
            return resp if resp else self._servfail(request)

        # 2. Safe-search / restricted-mode rewrites (per-group opt-out).
        if group.get("safe_search", True):
            rule = self.safe_search.match(qname)
            if rule:
                self.stats["safe_search_rewrites"] += 1
                self.log_query(client_ip, qname, f"safe_search:{rule['label']}")
                return self._safe_search_reply(request, rule)

        # 3. Blocklist lookup (categorised).
        category = self.blocklists.blocked_category(qname)
        if category:
            if monitor:
                if category == "adult":
                    self._record_alert(client_ip, qname, "adult_domain",
                                       category, person=identity)
                elif category == "bypass":
                    self._record_alert(client_ip, qname, "bypass_attempt",
                                       category, person=identity)
            if enforce:
                self.stats["blocked"] += 1
                self.stats["blocked_" + category] = \
                    self.stats.get("blocked_" + category, 0) + 1
                self.log_query(client_ip, qname, f"blocked:{category}")
                return self._blocked_reply(request)
            self.log_query(client_ip, qname, f"flagged:{category}")

        # 4. Keyword monitoring for domains not on any list.
        elif monitor:
            keyword = self.keywords.match(qname)
            if keyword:
                self._record_alert(client_ip, qname, "keyword", keyword,
                                   person=identity)
                if enforce and self.keywords.block_matches:
                    self.log_query(client_ip, qname, f"blocked:keyword:{keyword}")
                    self.stats["blocked"] += 1
                    return self._blocked_reply(request)
                self.log_query(client_ip, qname, f"flagged:keyword:{keyword}")
            else:
                self.log_query(client_ip, qname, "allowed")
        else:
            self.log_query(client_ip, qname, "allowed")

        # 5. Forward upstream (cached), then check the CNAME chain for
        # cloaked trackers before handing the answer back.
        resp = self._forward_cached(request)
        if resp is None:
            return self._servfail(request)
        if enforce:
            cname_category = self._cname_blocked(resp)
            if cname_category:
                self.stats["blocked"] += 1
                self.stats["blocked_cname"] += 1
                if cname_category == "adult":
                    self._record_alert(client_ip, qname, "adult_domain",
                                       f"cname:{cname_category}",
                                       person=identity)
                self.log_query(client_ip, qname,
                               f"blocked:cname:{cname_category}")
                return self._blocked_reply(request)
        return resp


# ---------------------------------------------------------------------------
# Weekly e-mail reporter
# ---------------------------------------------------------------------------

WEEKDAYS = ["monday", "tuesday", "wednesday", "thursday", "friday",
            "saturday", "sunday"]


def build_report(alerts: List[Dict], period_start: datetime.datetime,
                 period_end: datetime.datetime,
                 names: Optional[Dict[str, str]] = None) -> str:
    """Render the weekly alert summary as plain text."""
    names = names or {}

    def label(client: str) -> str:
        return (f"{names[client]} ({client})"
                if client in names else client)

    lines = [
        "FaithFilter weekly activity report",
        f"Period: {period_start:%Y-%m-%d %H:%M} to {period_end:%Y-%m-%d %H:%M} UTC",
        "",
    ]
    if not alerts:
        lines.append("No adult-content, bypass or keyword alerts were "
                     "recorded this week.")
        return "\n".join(lines)

    adult = [a for a in alerts if a.get("reason") == "adult_domain"]
    bypass = [a for a in alerts if a.get("reason") == "bypass_attempt"]
    keyword = [a for a in alerts if a.get("reason") == "keyword"]
    lines.append(f"Total alerts: {len(alerts)} "
                 f"({len(adult)} adult-domain, {len(bypass)} bypass-attempt, "
                 f"{len(keyword)} keyword)")
    lines.append("")

    def top(counter: Dict[str, int], n: int = 15) -> List[Tuple[str, int]]:
        return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:n]

    by_client: Dict[str, int] = {}
    for a in alerts:
        by_client[a.get("client", "?")] = by_client.get(a.get("client", "?"), 0) + 1
    lines.append("By device:")
    for client, count in top(by_client):
        lines.append(f"  {label(client):<34} {count} attempt(s)")
    lines.append("")

    if bypass:
        by_domain_b: Dict[str, int] = {}
        for a in bypass:
            by_domain_b[a["domain"]] = by_domain_b.get(a["domain"], 0) + 1
        lines.append("Filter-bypass services requested (VPN/proxy/DoH):")
        for domain, count in top(by_domain_b):
            lines.append(f"  {domain:<45} {count}x")
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
            lines.append(f"  {a['time'][:16]} {label(a.get('client', '?')):<24} "
                         f"{a['domain']} (keyword: {a.get('detail')})")

    return "\n".join(lines)


def _sparkline(pattern: List[int]) -> str:
    """Render a 24-hour activity histogram as a compact text sparkline."""
    blocks = " ▁▂▃▄▅▆▇█"
    peak = max(pattern) or 1
    out = "".join(blocks[min(8, (v * 8 + peak - 1) // peak)] for v in pattern)
    return out


def build_accountability_report(
        person: "Person", alerts: List[Dict], searches: List[Dict],
        audit: List[Dict], period_start: datetime.datetime,
        period_end: datetime.datetime, streak_days: int,
        hourly: Optional[List[int]] = None,
        dark_devices: Optional[List[str]] = None,
        blocklist_lookup: Optional[Callable[[str], Optional[str]]] = None) -> str:
    """Render one person's accountability report for their allies.

    This is the heart of the "rival to Covenant Eyes" product: it turns raw
    DNS activity into an accountability partner's briefing — category
    breakdown, time-of-day pattern, clean streak, evasion attempts, search
    terms (from the browser extension), and tamper events.
    """
    adult = [a for a in alerts if a.get("reason") == "adult_domain"]
    bypass = [a for a in alerts if a.get("reason") == "bypass_attempt"]
    keyword = [a for a in alerts if a.get("reason") == "keyword"]
    needs_convo = bool(adult or bypass
                       or any(e.get("event", "").startswith("override")
                              for e in audit)
                       or dark_devices)

    lines = [
        f"FaithFilter accountability report for {person.name}",
        f"Period: {period_start:%Y-%m-%d} to {period_end:%Y-%m-%d}",
        "",
        f"Clean streak: {streak_days} day(s) with no flagged activity.",
        f"Status: {'NEEDS A CONVERSATION' if needs_convo else 'All clear'}",
        "",
    ]

    # Highlights first — the part an ally reads in 10 seconds.
    highlights: List[str] = []
    if adult:
        highlights.append(f"- {len(adult)} adult-content request(s)")
    if bypass:
        highlights.append(f"- {len(bypass)} attempt(s) to use a VPN/proxy/"
                          "encrypted DNS (bypassing the filter)")
    for event in audit:
        if event.get("event", "").startswith("override"):
            highlights.append(f"- Filtering was changed: {event.get('detail')}")
    for device in (dark_devices or []):
        highlights.append(f"- Device {device} went quiet — it may be off or "
                          "bypassing the filter")
    if highlights:
        lines.append("Highlights:")
        lines.extend(highlights)
        lines.append("")

    # Category breakdown across all flagged/blocked activity.
    categories: Dict[str, int] = {}
    for a in alerts:
        cat = classify_domain(a.get("domain", ""),
                              blocklist_lookup(a["domain"])
                              if blocklist_lookup else None)
        categories[cat] = categories.get(cat, 0) + 1
    if categories:
        lines.append("Activity by category:")
        for cat, count in sorted(categories.items(), key=lambda kv: -kv[1]):
            lines.append(f"  {cat:<12} {count}")
        lines.append("")

    if hourly and any(hourly):
        lines.append("Activity by hour (00 -> 23):")
        lines.append("  " + _sparkline(hourly))
        late = sum(hourly[0:5])
        if late:
            lines.append(f"  Note: {late} request(s) between midnight and 5am.")
        lines.append("")

    if adult:
        by_domain: Dict[str, int] = {}
        for a in adult:
            by_domain[a["domain"]] = by_domain.get(a["domain"], 0) + 1
        lines.append("Adult / adult-adjacent domains:")
        for domain, count in sorted(by_domain.items(), key=lambda kv: -kv[1])[:20]:
            lines.append(f"  {domain:<45} {count}x")
        lines.append("")

    if searches:
        lines.append(f"Search terms seen ({len(searches)}; from the browser "
                     "extension):")
        for s in searches[:40]:
            flag = " (!)" if s.get("flagged") else ""
            lines.append(f"  {s.get('time', '')[:16]} [{s.get('engine', '?')}] "
                         f"{s.get('query', '')}{flag}")
        lines.append("")

    if bypass:
        by_b: Dict[str, int] = {}
        for a in bypass:
            by_b[a["domain"]] = by_b.get(a["domain"], 0) + 1
        lines.append("Filter-bypass services requested:")
        for domain, count in sorted(by_b.items(), key=lambda kv: -kv[1])[:20]:
            lines.append(f"  {domain:<45} {count}x")
        lines.append("")

    if audit:
        lines.append("Filter change history (tamper log):")
        for event in audit[-30:]:
            lines.append(f"  {event.get('time', '')[:16]} "
                         f"{event.get('event')}: {event.get('detail')}")
        lines.append("")

    if not (adult or bypass or keyword or searches):
        lines.append("No flagged web activity this period. Keep it up!")

    lines.append("")
    lines.append("You are receiving this because you are an accountability "
                 f"partner for {person.name}.")
    return "\n".join(lines)


class Reporter:
    """Sends the weekly alert summary over SMTP on a schedule."""

    def __init__(self, config: Dict, alerts: AlertLog, logger: logging.Logger,
                 notifier: Optional[Notifier] = None,
                 health_text: Optional[Callable[[], str]] = None,
                 names: Optional[Dict[str, str]] = None,
                 statsdb: Optional[StatsDB] = None,
                 resolver: Optional["FaithFilterResolver"] = None):
        self.cfg = config.get("email", {})
        self.alerts = alerts
        self.logger = logger
        self.notifier = notifier or Notifier(config, logger)
        self.health_text = health_text
        self.names = names or {}
        self.statsdb = statsdb
        # The resolver exposes the accountability model, audit log and
        # search log used for per-person ally reports.
        self.resolver = resolver
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

    def build_body(self) -> Tuple[str, int]:
        """Render the pending report; returns (text, alert count)."""
        now = datetime.datetime.now(datetime.timezone.utc)
        last = self._last_sent() or (now - datetime.timedelta(days=7))
        alerts = self.alerts.read_since(last)
        body = build_report(alerts, last, now, self.names)
        if self.statsdb:
            today = datetime.date.today()
            this_week = self.statsdb.totals_between(
                today - datetime.timedelta(days=7), today + datetime.timedelta(days=1))
            prev_week = self.statsdb.totals_between(
                today - datetime.timedelta(days=14),
                today - datetime.timedelta(days=7))
            body += ("\n\nWeek over week:\n"
                     f"  Queries: {this_week.get('total', 0)} "
                     f"(previous week {prev_week.get('total', 0)})\n"
                     f"  Blocked: {this_week.get('blocked', 0)} "
                     f"(previous week {prev_week.get('blocked', 0)})")
        if self.health_text:
            body += "\n\n" + self.health_text()
        return body, len(alerts)

    def accountability_reports(self, period_start: datetime.datetime,
                               period_end: datetime.datetime) -> List[Dict]:
        """Build one accountability report per person for their allies.

        Returns a list of {person, recipients, subject, body} dicts so the
        same code can send them or preview them via the API.
        """
        out: List[Dict] = []
        res = self.resolver
        if not res or not res.accountability.enabled:
            return out
        all_alerts = res.alerts.read_since(period_start)
        all_audit = res.audit.read_since(period_start)
        for person in res.accountability.people:
            devices = set(person.devices)
            # Match by device IP or by attributed person name (the latter
            # covers off-network devices using the person's token endpoint).
            p_alerts = [a for a in all_alerts
                        if a.get("client") in devices
                        or a.get("person") == person.name]
            p_audit = [e for e in all_audit if e.get("client") in devices]
            p_search = res.search_log.read_since(period_start,
                                                 list(devices))
            streak = res.accountability._clean_streak_days(p_alerts)
            hourly = (res.statsdb.hourly_pattern(
                list(devices), period_start.date(), period_end.date()
                + datetime.timedelta(days=1)) if res.statsdb else None)
            dark = self._dark_devices(person)
            body = build_accountability_report(
                person, p_alerts, p_search, p_audit, period_start,
                period_end, streak, hourly, dark,
                blocklist_lookup=res.blocklists.blocked_category)
            recipients = list(person.allies)
            if person.self_report and devices:
                pass  # self-report goes to allies list only unless configured
            flagged = sum(1 for a in p_alerts
                          if a.get("reason") in ("adult_domain", "bypass_attempt"))
            subject = (f"Accountability report for {person.name}: "
                       f"{flagged} flagged" if flagged
                       else f"Accountability report for {person.name}: all clear")
            out.append({"person": person.name, "recipients": recipients,
                        "subject": subject, "body": body})
        return out

    def _dark_devices(self, person) -> List[str]:
        """Devices that haven't been seen within the dark-device window."""
        res = self.resolver
        if not res or not res.statsdb:
            return []
        threshold = datetime.date.today() - datetime.timedelta(
            days=max(1, int(res.accountability.dark_after_hours / 24)))
        dark = []
        last = res.statsdb.last_seen(person.devices)
        for device, day in last.items():
            if day is None:
                continue  # never seen at all — likely just not configured yet
            try:
                if datetime.date.fromisoformat(day) < threshold:
                    dark.append(res.client_label(device))
            except ValueError:
                continue
        return dark

    def send_report(self, force: bool = False) -> bool:
        """Build and send the report now.  Returns True when sent."""
        now = datetime.datetime.now(datetime.timezone.utc)
        body, alert_count = self.build_body()
        if not alert_count and not self.cfg.get("send_if_empty", True) and not force:
            self._mark_sent(now)
            return False
        subject = (f"FaithFilter weekly report: {alert_count} alert(s)"
                   if alert_count else "FaithFilter weekly report: no alerts")
        if not self.notifier.send(subject, body):
            return False
        # Per-person accountability reports to each person's allies.
        last = self._last_sent() or (now - datetime.timedelta(days=7))
        for report in self.accountability_reports(last, now):
            if report["recipients"]:
                self.notifier.send(report["subject"], report["body"],
                                   recipients=report["recipients"])
                self.logger.info("Accountability report sent for %s to %s",
                                 report["person"], report["recipients"])
        self._mark_sent(now)
        self.logger.info("Weekly report sent (%d alerts)", alert_count)
        return True

    # -- scheduling ------------------------------------------------------------

    def _due(self, now: datetime.datetime) -> bool:
        day = str(self.cfg.get("report_day", "sunday")).lower()
        hour = int(self.cfg.get("report_hour", 8))
        # Schedule in server-local time by default so report_hour matches
        # the clock on the wall (curfews are local too); "utc" opts out.
        if str(self.cfg.get("report_timezone", "local")).lower() != "utc":
            check = now.astimezone()
        else:
            check = now
        try:
            target_weekday = WEEKDAYS.index(day)
        except ValueError:
            target_weekday = 6
        if check.weekday() != target_weekday or check.hour != hour:
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


def build_health_text(resolver: "FaithFilterResolver",
                      updates: Optional[UpdateChecker] = None) -> str:
    """Service-health section appended to the weekly report."""
    now = datetime.datetime.now(datetime.timezone.utc)
    uptime = now - resolver.start_time
    lists = resolver.blocklists.stats()
    lines = [
        "Filter health:",
        f"  Version: {__version__}"
        + (f" - UPDATE AVAILABLE: {updates.latest_version}"
           if updates and updates.update_available else ""),
        f"  Uptime: {uptime.days}d {uptime.seconds // 3600}h "
        f"(started {resolver.start_time:%Y-%m-%d %H:%M} UTC)",
        f"  Queries handled: {resolver.stats['total_queries']} "
        f"({resolver.stats['blocked']} blocked)",
        f"  Blocked domains loaded: {lists['total_blocked_domains']}",
    ]
    if resolver.blocklists.last_refresh:
        status = "ok" if resolver.blocklists.last_refresh_ok else "FAILING"
        lines.append(f"  Last source refresh: "
                     f"{resolver.blocklists.last_refresh:%Y-%m-%d %H:%M} UTC "
                     f"({status})")
    if resolver.cache:
        c = resolver.cache.stats()
        lines.append(f"  DNS cache: {c['entries']} entries, {c['hits']} hits, "
                     f"{c['stale_served']} stale answers served")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Block page (served on port 80 for blocked domains)
# ---------------------------------------------------------------------------

BLOCK_PAGE_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Site blocked</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
 body{{font-family:system-ui,sans-serif;background:#f4f5f7;margin:0;
      display:flex;justify-content:center;align-items:center;min-height:100vh}}
 .card{{background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.12);
      padding:2rem;max-width:26rem;text-align:center}}
 h1{{font-size:1.3rem;margin:0 0 .5rem}} .d{{color:#b00;font-weight:600}}
 input,textarea{{width:100%;box-sizing:border-box;margin:.25rem 0;padding:.5rem;
      border:1px solid #ccc;border-radius:6px}}
 button{{margin-top:.5rem;padding:.5rem 1.2rem;border:0;border-radius:6px;
      background:#2563eb;color:#fff;font-size:1rem;cursor:pointer}}
 .ok{{color:#059669;font-weight:600}}
</style></head><body><div class="card">
<h1>&#128683; This site was blocked</h1>
<p><span class="d">{domain}</span> is blocked by the FaithFilter policy
on this network.</p>
{message}
<form method="post" action="/request-unblock">
<input type="hidden" name="domain" value="{domain}">
<input name="name" placeholder="Your name" maxlength="60">
<textarea name="reason" placeholder="Why should this site be unblocked?"
 rows="3" maxlength="500"></textarea>
<button type="submit">Request unblock</button>
</form></div></body></html>"""


class BlockPageServer:
    """Tiny HTTP server that explains blocks and takes unblock requests."""

    def __init__(self, config: Dict, notifier: Notifier,
                 logger: logging.Logger):
        cfg = config.get("block_page", {})
        self.port = int(cfg.get("port", 80))
        self.requests_file = cfg.get("unblock_requests_file",
                                     "logs/unblock_requests.jsonl")
        self.notifier = notifier
        self.logger = logger
        self._server: Optional[ThreadingHTTPServer] = None

    def read_requests(self, limit: int = 100) -> List[Dict]:
        entries: List[Dict] = []
        if os.path.exists(self.requests_file):
            with open(self.requests_file, "r", encoding="utf-8",
                      errors="ignore") as f:
                for line in f:
                    try:
                        entries.append(json.loads(line))
                    except ValueError:
                        continue
        return entries[-limit:]

    def start(self) -> None:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):  # silence stdout noise
                pass

            def _page(self, message: str = "") -> None:
                host = (self.headers.get("Host") or "this site").split(":")[0]
                # Escape the client-supplied Host header before reflecting it
                # into the page (prevents reflected XSS). ``message`` is
                # server-generated markup and is intentionally not escaped.
                html = BLOCK_PAGE_HTML.format(
                    domain=html_lib.escape(host), message=message)
                body = html.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                self._page()

            def do_POST(self):
                if self.path != "/request-unblock":
                    self._page()
                    return
                length = min(int(self.headers.get("Content-Length", 0)), 10000)
                data = parse_qs(self.rfile.read(length).decode("utf-8",
                                                               errors="ignore"))
                entry = {
                    "time": datetime.datetime.now(
                        datetime.timezone.utc).isoformat(),
                    "client": self.client_address[0],
                    "domain": (data.get("domain") or [""])[0][:200],
                    "name": (data.get("name") or [""])[0][:60],
                    "reason": (data.get("reason") or [""])[0][:500],
                }
                try:
                    if os.path.dirname(outer.requests_file):
                        os.makedirs(os.path.dirname(outer.requests_file),
                                    exist_ok=True)
                    with open(outer.requests_file, "a", encoding="utf-8") as f:
                        f.write(json.dumps(entry) + "\n")
                except OSError as exc:
                    outer.logger.error("Could not save unblock request: %s", exc)
                outer.notifier.send_throttled(
                    "unblock-request", 300,
                    f"FaithFilter: unblock requested for {entry['domain']}",
                    f"{entry['name'] or entry['client']} asked to unblock "
                    f"{entry['domain']}:\n\n{entry['reason']}\n\n"
                    "Review it on the FaithFilter dashboard.")
                self._page('<p class="ok">Request sent &#10003;</p>')

        try:
            self._server = ThreadingHTTPServer(("0.0.0.0", self.port), Handler)
        except OSError as exc:
            self.logger.error("Block page server could not bind port %d: %s",
                              self.port, exc)
            return
        threading.Thread(target=self._server.serve_forever,
                         name="block-page", daemon=True).start()
        self.logger.info("Block page server listening on port %d", self.port)

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()


# ---------------------------------------------------------------------------
# DNS-over-TLS listener (Android "Private DNS")
# ---------------------------------------------------------------------------

class DoTServer:
    """Minimal DNS-over-TLS server: TLS-wrapped TCP with 2-byte framing."""

    def __init__(self, resolver: "FaithFilterResolver", config: Dict,
                 logger: logging.Logger):
        cfg = config.get("dot", {})
        self.resolver = resolver
        self.logger = logger
        self.port = int(cfg.get("port", 853))
        self.cert_file = cfg.get("cert_file")
        self.key_file = cfg.get("key_file")
        self._stop = threading.Event()

    def start(self) -> bool:
        if not (self.cert_file and self.key_file
                and os.path.exists(self.cert_file)
                and os.path.exists(self.key_file)):
            self.logger.error("DoT enabled but cert_file/key_file missing")
            return False
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert_file, self.key_file)

        def sni_callback(sslsock, server_name, ctx):
            # Stash the requested hostname so we can attribute the connection
            # to a person (per-person subdomain token.base_domain).
            try:
                sslsock.faithfilter_sni = server_name
            except Exception:
                pass

        context.sni_callback = sni_callback
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", self.port))
        sock.listen(16)

        def identity_for_sni(server_name: Optional[str]):
            """Map a per-person subdomain (token.base_domain) from the TLS
            SNI to that Person, so Android Private DNS attributes correctly."""
            if not server_name:
                return None
            label = server_name.split(".")[0]
            name = self.resolver.device_tokens.person_for_token(label)
            return self.resolver.accountability.by_name(name) if name else None

        def handle(conn: ssl.SSLSocket, addr) -> None:
            person = identity_for_sni(getattr(conn, "faithfilter_sni", None))

            class FakeHandler:
                client_address = addr
                faithfilter_identity = person
            try:
                conn.settimeout(30)
                while not self._stop.is_set():
                    header = conn.recv(2)
                    if len(header) < 2:
                        return
                    length = int.from_bytes(header, "big")
                    data = b""
                    while len(data) < length:
                        chunk = conn.recv(length - len(data))
                        if not chunk:
                            return
                        data += chunk
                    reply = self.resolver.resolve(DNSRecord.parse(data),
                                                  FakeHandler())
                    packed = reply.pack()
                    conn.sendall(len(packed).to_bytes(2, "big") + packed)
            except Exception:
                pass
            finally:
                conn.close()

        def accept_loop() -> None:
            while not self._stop.is_set():
                try:
                    client, addr = sock.accept()
                    tls = context.wrap_socket(client, server_side=True)
                    threading.Thread(target=handle, args=(tls, addr),
                                     daemon=True).start()
                except Exception as exc:
                    if not self._stop.is_set():
                        self.logger.debug("DoT accept error: %s", exc)

        threading.Thread(target=accept_loop, name="dot-server",
                         daemon=True).start()
        self.logger.info("DNS-over-TLS listening on port %d", self.port)
        return True

    def stop(self) -> None:
        self._stop.set()


# ---------------------------------------------------------------------------
# HTTP API
# ---------------------------------------------------------------------------

DASHBOARD_HTML = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>FaithFilter dashboard</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
 body{font-family:system-ui,sans-serif;background:#f4f5f7;margin:0;color:#111}
 header{background:#1e293b;color:#fff;padding:.8rem 1.2rem;display:flex;
   justify-content:space-between;align-items:center}
 header h1{font-size:1.1rem;margin:0}
 main{max-width:70rem;margin:1rem auto;padding:0 1rem;display:grid;
   grid-template-columns:repeat(auto-fit,minmax(20rem,1fr));gap:1rem}
 section{background:#fff;border-radius:10px;box-shadow:0 1px 6px rgba(0,0,0,.08);
   padding:1rem}
 h2{font-size:.95rem;margin:0 0 .6rem;color:#334155}
 .stats{display:flex;flex-wrap:wrap;gap:.6rem}
 .stat{background:#f1f5f9;border-radius:8px;padding:.5rem .8rem;min-width:6rem}
 .stat b{display:block;font-size:1.2rem}
 table{width:100%;border-collapse:collapse;font-size:.82rem}
 td,th{padding:.25rem .4rem;border-bottom:1px solid #eee;text-align:left;
   word-break:break-all}
 .blocked{color:#b91c1c}.flagged{color:#b45309}.allowed{color:#047857}
 input{padding:.4rem;border:1px solid #ccc;border-radius:6px}
 button{padding:.4rem .8rem;border:0;border-radius:6px;background:#2563eb;
   color:#fff;cursor:pointer;margin:.1rem}
 button.warn{background:#dc2626} button.ghost{background:#64748b}
 form.inline{display:flex;gap:.4rem;margin:.4rem 0}
 form.inline input{flex:1}
 ul{margin:.3rem 0;padding-left:1rem;max-height:12rem;overflow-y:auto;
   font-size:.85rem}
 li button{padding:0 .45rem;font-size:.75rem;background:#dc2626}
 #msg{position:fixed;bottom:1rem;right:1rem;background:#111;color:#fff;
   padding:.6rem 1rem;border-radius:8px;display:none}
 .bar{background:#e2e8f0;border-radius:4px;height:.6rem;overflow:hidden}
 .bar i{display:block;height:100%;background:#2563eb}
 .bar i.r{background:#dc2626}
 .pill{background:#fef3c7;color:#92400e;border-radius:999px;
   padding:.1rem .5rem;font-size:.75rem}
 #ver{font-size:.75rem;opacity:.8;margin-left:.6rem}
 .upd{background:#fbbf24;color:#111;border-radius:999px;padding:.1rem .5rem;
   font-size:.75rem;margin-left:.4rem}
</style></head><body>
<header><h1>&#128737;&#65039; FaithFilter<span id="ver"></span><span id="upd">
</span></h1>
<div>
<button class="ghost" onclick="act('/api/refresh')">Refresh sources</button>
<button class="ghost" onclick="act('/api/test-email')">Test e-mail</button>
<button class="ghost" onclick="location='/api/backup'">Backup</button>
<form style="display:inline" method="post" action="/logout">
<button class="warn">Log out</button></form>
</div></header>
<main>
<section style="grid-column:1/-1"><h2>Status</h2><div class="stats" id="stats">
</div></section>
<section style="grid-column:1/-1"><h2>Devices (last 7 days)</h2>
<table id="devices"><tbody></tbody></table>
<form class="inline" onsubmit="return manualOverride(this)">
<input name="ip" placeholder="IP address" required style="max-width:10rem">
<input name="mins" placeholder="minutes" value="60" style="max-width:6rem">
<button name="mode" value="pause">Pause</button>
<button name="mode" value="unfiltered">Allow unfiltered</button>
</form></section>
<section style="grid-column:1/-1"><h2>Trends (14 days)</h2>
<table id="trends"><tbody></tbody></table></section>
<section><h2>My blocked sites</h2>
<form class="inline" onsubmit="return addItem('/api/blocklist','domain',this)">
<input placeholder="domain, *.wildcard or /regex/" name="v" required>
<button>Block</button></form><ul id="blocklist"></ul></section>
<section><h2>Whitelist (always allowed)</h2>
<form class="inline" onsubmit="return addItem('/api/whitelist','domain',this)">
<input placeholder="domain.com" name="v" required>
<button>Allow</button></form><ul id="whitelist"></ul></section>
<section><h2>Monitored keywords</h2>
<form class="inline" onsubmit="return addItem('/api/keywords','keyword',this)">
<input placeholder="keyword" name="v" required>
<button>Watch</button></form><ul id="keywords"></ul></section>
<section><h2>Unblock requests</h2><table id="unblock"><tbody></tbody></table>
</section>
<section style="grid-column:1/-1"><h2>Accountability</h2>
<div id="people"></div>
<h2 style="margin-top:.8rem">Set up a device (follows the person onto cellular)</h2>
<div id="devices" style="font-size:.85rem"></div>
<h2 style="margin-top:.8rem">Search terms (last 7 days)</h2>
<table id="searches"><tbody></tbody></table>
<h2 style="margin-top:.8rem">Filter change / tamper log</h2>
<table id="audit"><tbody></tbody></table></section>
<section style="grid-column:1/-1"><h2>Recent alerts</h2>
<table id="alerts"><tbody></tbody></table></section>
<section style="grid-column:1/-1"><h2>Recent queries</h2>
<table id="queries"><tbody></tbody></table></section>
</main><div id="msg"></div>
<script>
const $=id=>document.getElementById(id);
function msg(t){const m=$('msg');m.textContent=t;m.style.display='block';
 setTimeout(()=>m.style.display='none',3000);}
async function act(url){const r=await fetch(url,{method:'POST'});
 msg(r.ok?'Done':'Failed ('+r.status+')');refresh();}
async function addItem(url,field,form){
 const v=form.v.value.trim();if(!v)return false;
 await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({[field]:v})});form.v.value='';refresh();return false;}
async function delItem(url){await fetch(url,{method:'DELETE'});refresh();}
function esc(s){const d=document.createElement('div');
 d.textContent=s==null?'':String(s);return d.innerHTML;}
function fillList(id,items,delBase){$(id).innerHTML=items.map(d=>
 '<li>'+esc(d)+(delBase?' <button onclick="delItem(\\''+delBase+
 encodeURIComponent(d)+'\\')">x</button>':'')+'</li>').join('');}
function cls(a){return a.startsWith('blocked')?'blocked':
 a.startsWith('flagged')?'flagged':'allowed';}
let NAMES={};
function nm(c){return NAMES[c]?NAMES[c]+' ('+c+')':c;}
async function setOverride(client,mode,minutes){
 client=decodeURIComponent(client);
 await fetch('/api/override',{method:'POST',
  headers:{'Content-Type':'application/json'},
  body:JSON.stringify({client:client,mode:mode,minutes:minutes})});
 msg(mode==='pause'?'Paused':'Unfiltered time granted');refresh();}
async function cancelOverride(client){
 await fetch('/api/override/'+client,{method:'DELETE'});
 msg('Override cancelled');refresh();}
function manualOverride(form){
 const mode=document.activeElement&&document.activeElement.value==='unfiltered'
  ?'unfiltered':'pause';
 setOverride(form.ip.value.trim(),mode,parseFloat(form.mins.value)||60);
 return false;}
async function refresh(){
 try{
  const s=await (await fetch('/api/status')).json();
  NAMES=s.client_names||{};
  $('ver').textContent='v'+s.version;
  $('upd').innerHTML=s.update_available?
   '<span class="upd">update '+esc(s.latest_version)+' available</span>':'';
  const st=s.stats,c=s.cache||{};
  $('stats').innerHTML=[
   ['Queries',st.total_queries],['Blocked',st.blocked],
   ['Ads blocked',st.blocked_ads],['Adult blocked',st.blocked_adult],
   ['Bypass blocked',st.blocked_bypass||0],['Alerts',st.alerts],
   ['Safe-search hits',st.safe_search_rewrites],
   ['Domains loaded',s.lists.total_blocked_domains],
   ['Cache entries',c.entries||0],
   ['Uptime (h)',Math.floor(s.uptime_seconds/3600)],
  ].map(x=>'<div class="stat"><b>'+esc(x[1])+'</b>'+esc(x[0])+'</div>').join('');
  fillList('blocklist',await (await fetch('/api/blocklist')).json(),
   '/api/blocklist/');
  fillList('whitelist',await (await fetch('/api/whitelist')).json(),
   '/api/whitelist/');
  fillList('keywords',await (await fetch('/api/keywords')).json(),null);
  const dv=await (await fetch('/api/clients')).json();
  $('devices').tBodies[0].innerHTML=dv.map(d=>{
   const o=d.override;
   return '<tr><td>'+esc(nm(d.client))+'</td><td>'+esc(d.today_total)+
    ' today</td><td class="blocked">'+esc(d.today_blocked)+' blocked</td>'+
    '<td>'+(o?'<span class="pill">'+esc(o.mode)+' until '+
    esc(o.until.slice(11,16))+'</span> <button class="ghost" '+
    'onclick="cancelOverride(\\''+encodeURIComponent(d.client)+'\\')">Resume'+
    '</button>':
    '<button class="warn" onclick="setOverride(\\''+
    encodeURIComponent(d.client)+'\\',\\'pause\\',60)">Pause 1h</button>'+
    '<button onclick="setOverride(\\''+encodeURIComponent(d.client)+
    '\\',\\'unfiltered\\',30)">Allow 30m</button>')+'</td></tr>';
  }).join('')||'<tr><td>No devices seen yet</td></tr>';
  const tr=await (await fetch('/api/trends?days=14')).json();
  const byDay={};
  tr.forEach(e=>{const d=byDay[e.day]||(byDay[e.day]={t:0,b:0});
   d.t+=e.total;d.b+=e.blocked;});
  const days=Object.keys(byDay).sort();
  const max=Math.max(1,...days.map(d=>byDay[d].t));
  $('trends').tBodies[0].innerHTML=days.map(d=>
   '<tr><td>'+esc(d)+'</td><td style="width:45%"><div class="bar">'+
   '<i style="width:'+(100*byDay[d].t/max)+'%"></i></div></td><td>'+
   esc(byDay[d].t)+' queries</td><td style="width:20%"><div class="bar">'+
   '<i class="r" style="width:'+(100*byDay[d].b/max)+'%"></i></div></td>'+
   '<td class="blocked">'+esc(byDay[d].b)+' blocked</td></tr>').join('')||
   '<tr><td>No data yet</td></tr>';
  const al=await (await fetch('/api/alerts?days=7')).json();
  $('alerts').tBodies[0].innerHTML=al.slice(-30).reverse().map(a=>
   '<tr><td>'+esc(a.time.slice(0,16))+'</td><td>'+esc(nm(a.client))+'</td><td>'+
   esc(a.domain)+'</td><td class="blocked">'+esc(a.reason)+' ('+esc(a.detail)+
   ')</td></tr>').join('')||'<tr><td>No alerts this week</td></tr>';
  const q=await (await fetch('/api/queries?limit=30')).json();
  $('queries').tBodies[0].innerHTML=q.reverse().map(e=>
   '<tr><td>'+esc(e.time.slice(11,19))+'</td><td>'+esc(nm(e.client))+'</td><td>'+
   esc(e.domain)+'</td><td class="'+cls(e.action)+'">'+esc(e.action)+
   '</td></tr>').join('');
  const u=await (await fetch('/api/unblock-requests')).json();
  $('unblock').tBodies[0].innerHTML=u.slice(-15).reverse().map(r=>
   '<tr><td>'+esc(r.time.slice(0,16))+'</td><td>'+esc(r.name||r.client)+
   '</td><td>'+esc(r.domain)+'</td><td>'+esc(r.reason)+'</td>'+
   '<td><button onclick="addUnblock(\\''+encodeURIComponent(r.domain)+
   '\\')">Allow</button></td></tr>').join('')||
   '<tr><td>No requests</td></tr>';
  const ppl=await (await fetch('/api/people')).json();
  $('people').innerHTML=ppl.map(p=>
   '<div class="stat" style="display:inline-block;margin:.2rem">'+
   '<b>'+esc(p.streak_days)+'d</b>'+esc(p.name)+' clean streak<br>'+
   '<span style="font-size:.7rem;color:#64748b">'+
   esc((p.devices||[]).join(', '))+' &rarr; '+
   esc((p.allies||[]).join(', '))+'</span></div>').join('')||
   '<span style="color:#64748b">No people configured. Add an '+
   '<b>accountability</b> section in config.yaml.</span>';
  const dev=await (await fetch('/api/devices')).json();
  if(!dev.base_domain){
   $('devices').innerHTML='<span style="color:#64748b">Set '+
    '<b>accountability.base_domain</b> (your server\\'s public DoH hostname) '+
    'in config.yaml to generate per-device setup profiles.</span>';
  }else{
   $('devices').innerHTML=(dev.people||[]).map(d=>
    '<div style="margin:.3rem 0;padding:.3rem 0;border-bottom:1px solid #eee">'+
    '<b>'+esc(d.name)+'</b> &nbsp;'+
    ['apple','android','windows','linux'].map(pl=>
     '<a href="/api/devices/'+encodeURIComponent(d.name)+'/'+pl+
     '" style="margin-right:.5rem">'+pl+'</a>').join('')+
    '<br><span style="font-size:.7rem;color:#64748b">'+esc(d.doh_url)+
    '</span></div>').join('')||'<span style="color:#64748b">No people yet.</span>';
  }
  const se=await (await fetch('/api/searches?days=7')).json();
  $('searches').tBodies[0].innerHTML=se.slice(-30).reverse().map(s=>
   '<tr><td>'+esc(s.time.slice(0,16))+'</td><td>'+esc(nm(s.client))+
   '</td><td>'+esc(s.engine||s.kind)+'</td><td'+(s.flagged?
   ' class="blocked"':'')+'>'+esc(s.query||s.url)+(s.flagged?' (!)':'')+
   '</td></tr>').join('')||'<tr><td>No search data (needs the extension)</td></tr>';
  const au=await (await fetch('/api/audit?days=30')).json();
  $('audit').tBodies[0].innerHTML=au.slice(-20).reverse().map(e=>
   '<tr><td>'+esc(e.time.slice(0,16))+'</td><td>'+esc(e.event)+
   '</td><td>'+esc(e.detail)+'</td></tr>').join('')||
   '<tr><td>No filter changes recorded</td></tr>';
 }catch(e){msg('Refresh failed');}
}
async function addUnblock(domain){
 await fetch('/api/whitelist',{method:'POST',
  headers:{'Content-Type':'application/json'},
  body:JSON.stringify({domain:decodeURIComponent(domain)})});
 msg('Whitelisted');refresh();}
refresh();setInterval(refresh,10000);
</script></body></html>"""

LOGIN_PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>FaithFilter login</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:system-ui,sans-serif;background:#f4f5f7;display:flex;
justify-content:center;align-items:center;min-height:100vh;margin:0}
form{background:#fff;padding:2rem;border-radius:12px;
box-shadow:0 2px 12px rgba(0,0,0,.12);width:18rem}
input{width:100%;box-sizing:border-box;padding:.5rem;margin:.5rem 0;
border:1px solid #ccc;border-radius:6px}
button{width:100%;padding:.5rem;border:0;border-radius:6px;background:#2563eb;
color:#fff;font-size:1rem;cursor:pointer}.e{color:#b00}</style></head><body>
<form method="post" action="/login"><h2>FaithFilter</h2>%ERROR%
<input type="password" name="password" placeholder="Admin password" autofocus>
<button type="submit">Sign in</button></form></body></html>"""


def get_admin_password(config: Dict, logger: logging.Logger) -> str:
    """Return the dashboard password, generating and persisting one on
    first run so the management interface is never left unprotected."""
    password = config.get("http_api", {}).get("password")
    if password:
        return str(password)
    path = config.get("http_api", {}).get(
        "password_file", os.path.join(app_dir(), "admin_password.txt"))
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                stored = f.read().strip()
            if stored:
                return stored
        password = secrets.token_urlsafe(9)
        with open(path, "w", encoding="utf-8") as f:
            f.write(password + "\n")
        if os.name == "posix":
            os.chmod(path, 0o600)
        logger.info("Generated dashboard password (stored in %s)", path)
        return password
    except OSError as exc:
        logger.error("Could not persist dashboard password (%s); "
                     "using a session-only password", exc)
        return secrets.token_urlsafe(9)


# ---------------------------------------------------------------------------
# Per-device setup profiles (Apple / Android / Windows / Linux)
# ---------------------------------------------------------------------------

def device_endpoints(base_domain: str, token: str) -> Dict[str, str]:
    """Return the per-person endpoint strings for each platform.

    ``base_domain`` is the public authority devices reach this server at,
    e.g. ``dns.example.com`` (optionally ``host:port``).
    """
    base = base_domain.strip().rstrip("/")
    return {
        "doh_url": f"https://{base}/p/{token}/dns-query" if base else "",
        # Android Private DNS / systemd-resolved use a hostname (DoT). A
        # per-person subdomain requires wildcard DNS + cert; the plain base
        # domain applies the whole-network policy.
        "dot_person": f"{token}.{base.split(':')[0]}" if base else "",
        "dot_network": base.split(":")[0] if base else "",
    }


APPLE_MOBILECONFIG = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" \
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>Name</key><string>FaithFilter DNS</string>
      <key>PayloadDescription</key>
      <string>Encrypted DNS filtering for {person}</string>
      <key>PayloadDisplayName</key><string>FaithFilter DNS ({person})</string>
      <key>PayloadIdentifier</key>
      <string>net.faithfilter.dns.{token}</string>
      <key>PayloadType</key>
      <string>com.apple.dnsSettings.managed</string>
      <key>PayloadUUID</key><string>{payload_uuid}</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>DNSSettings</key>
      <dict>
        <key>DNSProtocol</key><string>HTTPS</string>
        <key>ServerURL</key><string>{doh_url}</string>
      </dict>
      <key>ProhibitDisablement</key><{prohibit}/>
    </dict>
  </array>
  <key>PayloadDisplayName</key><string>FaithFilter DNS ({person})</string>
  <key>PayloadIdentifier</key><string>net.faithfilter.{token}</string>
  <key>PayloadRemovalDisallowed</key><false/>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadUUID</key><string>{profile_uuid}</string>
  <key>PayloadVersion</key><integer>1</integer>
</dict></plist>
"""


def build_apple_mobileconfig(person: str, doh_url: str, token: str,
                             prohibit_disable: bool = False) -> str:
    """An Apple .mobileconfig that sets encrypted (DoH) DNS on iOS/macOS."""
    return APPLE_MOBILECONFIG.format(
        person=html_lib.escape(person), token=html_lib.escape(token),
        doh_url=html_lib.escape(doh_url),
        prohibit="true" if prohibit_disable else "false",
        payload_uuid=uuid.uuid5(uuid.NAMESPACE_URL, "ff-payload-" + token),
        profile_uuid=uuid.uuid5(uuid.NAMESPACE_URL, "ff-profile-" + token))


def build_android_card(person: str, endpoints: Dict[str, str]) -> str:
    """Plain-text Android Private DNS setup instructions."""
    host = endpoints["dot_person"] or endpoints["dot_network"] or \
        "(set accountability.base_domain first)"
    return (
        f"FaithFilter — Android setup for {person}\n"
        f"{'=' * 40}\n\n"
        "Android filters DNS system-wide (Wi-Fi and cellular) via Private DNS:\n\n"
        "  1. Settings -> Network & internet -> Private DNS\n"
        "  2. Choose 'Private DNS provider hostname'\n"
        f"  3. Enter:  {host}\n"
        "  4. Save.\n\n"
        "Lock it so it can't be changed: use Google Family Link on the\n"
        "child's account to block changing network settings.\n\n"
        "Note: the per-person hostname needs wildcard DNS + TLS on the\n"
        "server; otherwise use the base domain (whole-network policy) and\n"
        "install the browser extension for per-person search visibility.\n")


WINDOWS_SETUP_PS1 = r"""# FaithFilter per-device setup for Windows 11 (encrypted DNS / DoH)
# Personalized for: {person}
# Run in an ELEVATED PowerShell:  Set-ExecutionPolicy -Scope Process Bypass; .\setup.ps1
$ErrorActionPreference = "Stop"
$DohTemplate = "{doh_url}"
$ServerHost  = "{server_host}"

Write-Host "Configuring FaithFilter encrypted DNS for {person}..."
if (-not $DohTemplate -or -not $ServerHost) {{
  Write-Error "This server has no public base_domain configured yet."
  exit 1
}}
# Resolve the server's IP (Windows maps DoH templates to a server IP).
$ip = (Resolve-DnsName -Name $ServerHost -Type A -ErrorAction Stop |
       Select-Object -First 1 -ExpandProperty IPAddress)
Write-Host "Server $ServerHost -> $ip"
# Register the DoH template for that IP and require encryption.
netsh dns add encryption server=$ip dohtemplate=$DohTemplate autoupgrade=yes udpfallback=no | Out-Null
# Point every active adapter at it.
Get-DnsClientServerAddress -AddressFamily IPv4 |
  Where-Object {{ $_.ServerAddresses }} |
  ForEach-Object {{ Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses $ip }}
Clear-DnsClientCache
Write-Host "Done. All DNS now goes to FaithFilter over HTTPS."
Write-Host "To lock it, use a Standard (non-admin) child account so system DNS can't be changed."
"""


def build_windows_ps1(person: str, endpoints: Dict[str, str]) -> str:
    return WINDOWS_SETUP_PS1.format(
        person=person.replace('"', "'"), doh_url=endpoints["doh_url"],
        server_host=endpoints["dot_network"])


LINUX_SETUP_SH = r"""#!/usr/bin/env bash
# FaithFilter per-device setup for Linux (systemd-resolved, DNS-over-TLS)
# Personalized for: {person}
# Run with sudo:  sudo ./setup-faithfilter.sh
set -euo pipefail
DOT_HOST="{dot_host}"
if [ -z "$DOT_HOST" ]; then
  echo "This server has no public base_domain configured yet." >&2
  exit 1
fi
IP="$(getent hosts "$DOT_HOST" | awk '{{print $1}}' | head -n1)"
if [ -z "$IP" ]; then echo "Could not resolve $DOT_HOST" >&2; exit 1; fi
echo "Configuring systemd-resolved DoT to $DOT_HOST ($IP) for {person}..."
mkdir -p /etc/systemd/resolved.conf.d
cat > /etc/systemd/resolved.conf.d/faithfilter.conf <<EOF
[Resolve]
DNS=$IP#$DOT_HOST
DNSOverTLS=yes
Domains=~.
EOF
systemctl restart systemd-resolved
echo "Done. All DNS now goes to FaithFilter over TLS."
echo "Lock it by restricting sudo/root on this account."
"""


def build_linux_sh(person: str, endpoints: Dict[str, str]) -> str:
    host = endpoints["dot_person"] or endpoints["dot_network"]
    return LINUX_SETUP_SH.format(person=person.replace('"', "'"),
                                 dot_host=host)


DEVICE_PLATFORMS = {
    "apple": ("faithfilter-{token}.mobileconfig",
              "application/x-apple-aspen-config"),
    "android": ("faithfilter-{token}-android.txt", "text/plain"),
    "windows": ("faithfilter-{token}-setup.ps1", "text/plain"),
    "linux": ("faithfilter-{token}-setup.sh", "text/plain"),
}


def build_device_profile(platform: str, person: str, token: str,
                         base_domain: str,
                         prohibit_disable: bool = False):
    """Return (filename, mimetype, body) for a person+platform, or None."""
    if platform not in DEVICE_PLATFORMS:
        return None
    endpoints = device_endpoints(base_domain, token)
    if platform == "apple":
        body = build_apple_mobileconfig(person, endpoints["doh_url"], token,
                                        prohibit_disable)
    elif platform == "android":
        body = build_android_card(person, endpoints)
    elif platform == "windows":
        body = build_windows_ps1(person, endpoints)
    else:
        body = build_linux_sh(person, endpoints)
    filename, mimetype = DEVICE_PLATFORMS[platform]
    return filename.format(token=token), mimetype, body


def create_api_server(resolver: FaithFilterResolver, reporter: Reporter,
                      config: Dict,
                      block_page: Optional[BlockPageServer] = None,
                      logger: Optional[logging.Logger] = None,
                      updates: Optional[UpdateChecker] = None):
    logger = logger or logging.getLogger("FaithFilter")
    app = Flask(__name__)
    api_cfg = config.get("http_api", {})
    api_key = api_cfg.get("api_key")
    admin_password = get_admin_password(config, logger)
    app.secret_key = hashlib.sha256(
        ("faithfilter:" + admin_password).encode()).digest()
    # Harden the session cookie. Secure is set only when the dashboard is
    # served over HTTPS, so cookies still work on a plain-HTTP LAN install.
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=bool(api_cfg.get("cert_file")
                                   and api_cfg.get("key_file")),
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,  # cap request bodies
    )
    doh_enabled = bool(api_cfg.get("doh", True))

    # The extension endpoint authenticates with its own shared key, so it
    # is exempt from the dashboard session/API-key check.
    OPEN_PATHS = {"/login", "/dns-query", "/favicon.ico",
                  "/api/extension/events"}
    extension_cfg = config.get("extension", {})
    extension_key = extension_cfg.get("key")

    @app.before_request
    def check_auth():
        if request.path in OPEN_PATHS:
            return None
        # Per-person DoH endpoints (/p/<token>/dns-query) authenticate with
        # the token in the path, so they bypass the dashboard login.
        if request.path.startswith("/p/") and request.path.endswith(
                "/dns-query"):
            return None
        supplied_key = request.headers.get("X-API-Key")
        if api_key and supplied_key and secrets.compare_digest(
                supplied_key, api_key):
            return None
        if session.get("authed"):
            return None
        if request.path.startswith("/api"):
            return jsonify({"error": "authentication required"}), 401
        return redirect("/login")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            supplied = request.form.get("password", "")
            if secrets.compare_digest(supplied, admin_password):
                session["authed"] = True
                return redirect("/")
            return LOGIN_PAGE.replace(
                "%ERROR%", '<p class="e">Wrong password</p>'), 401
        return LOGIN_PAGE.replace("%ERROR%", "")

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect("/login")

    @app.route("/")
    def dashboard():
        return DASHBOARD_HTML

    def _serve_doh(identity_person=None):
        """Shared RFC 8484 DoH handler; identity_person attributes the query
        to a specific person (per-device token endpoints)."""
        try:
            if request.method == "GET":
                encoded = request.args.get("dns", "")
                padding = "=" * (-len(encoded) % 4)
                wire = base64.urlsafe_b64decode(encoded + padding)
            else:
                wire = request.get_data()
            record = DNSRecord.parse(wire)
        except Exception:
            return jsonify({"error": "invalid DNS message"}), 400

        class FakeHandler:
            client_address = (request.remote_addr or "unknown", 0)
            faithfilter_identity = identity_person

        reply = resolver.resolve(record, FakeHandler())
        # dnslib's pack() returns a bytearray; WSGI requires bytes.
        return Response(bytes(reply.pack()),
                        content_type="application/dns-message")

    if doh_enabled:
        @app.route("/dns-query", methods=["GET", "POST"])
        def dns_query():
            """RFC 8484 DNS-over-HTTPS endpoint (whole-network)."""
            return _serve_doh()

        @app.route("/p/<token>/dns-query", methods=["GET", "POST"])
        def dns_query_person(token):
            """Per-person DoH endpoint: the token identifies whose device
            this is, so a phone on cellular is still filtered and its
            activity attributed to that person's accountability report."""
            name = resolver.device_tokens.person_for_token(token)
            person = resolver.accountability.by_name(name) if name else None
            if person is None:
                return jsonify({"error": "unknown device token"}), 404
            return _serve_doh(person)

    @app.route("/api/extension/events", methods=["POST"])
    def extension_events():
        """Receive search terms / visited URLs from the browser extension.

        Authenticated with the extension key; the reporting device is
        identified by its source IP so it lines up with DNS activity.
        """
        if not extension_cfg.get("enabled", False):
            return jsonify({"error": "extension reporting disabled"}), 403
        # A key is mandatory when the endpoint is enabled, so it can never be
        # left open to unauthenticated writes.
        if not extension_key:
            return jsonify({"error": "server has no extension key set"}), 503
        supplied = request.headers.get("X-Extension-Key") or ""
        if not secrets.compare_digest(supplied, extension_key):
            return jsonify({"error": "invalid extension key"}), 401
        data = request.get_json(silent=True) or {}
        events = data.get("events") or []
        client = request.remote_addr or "unknown"
        stored = 0
        for ev in events[:200]:
            kind = "search" if ev.get("query") else "visit"
            entry = resolver.search_log.add(
                client, kind, str(ev.get("engine", ""))[:40],
                str(ev.get("query", "")), str(ev.get("url", "")))
            stored += 1
            # A flagged search from a monitored person alerts their allies.
            if entry["flagged"]:
                person = resolver.accountability.person_for(client)
                if person and person.allies:
                    resolver.notifier.send_throttled(
                        f"ally-search:{person.name}", 3600,
                        f"Accountability alert for {person.name}: flagged search",
                        f"{person.name} searched for something flagged:\n\n"
                        f"  [{entry['engine']}] {entry['query']}\n",
                        recipients=person.allies)
        return jsonify({"stored": stored})

    @app.route("/api/people")
    def people():
        rows = []
        for person in resolver.accountability.people:
            rows.append({"name": person.name, "devices": person.devices,
                         "allies": person.allies,
                         "streak_days": resolver.accountability._clean_streak_days(
                             resolver.alerts.read_since(
                                 datetime.datetime.now(datetime.timezone.utc)
                                 - datetime.timedelta(days=400)))})
        return jsonify(rows)

    @app.route("/api/devices")
    def devices_route():
        """People with their per-device endpoints, for the setup page."""
        base_domain = resolver.accountability.base_domain
        rows = []
        for person in resolver.accountability.people:
            token = resolver.device_tokens.token_for(person.name)
            endpoints = device_endpoints(base_domain, token)
            rows.append({
                "name": person.name,
                "configured": bool(base_domain),
                "doh_url": endpoints["doh_url"],
                "dot_hostname": endpoints["dot_person"] or endpoints["dot_network"],
                "platforms": list(DEVICE_PLATFORMS.keys()),
            })
        return jsonify({"base_domain": base_domain, "people": rows})

    @app.route("/api/devices/<person>/<platform>")
    def device_profile(person, platform):
        p = resolver.accountability.by_name(person)
        if p is None:
            return jsonify({"error": "unknown person"}), 404
        base_domain = resolver.accountability.base_domain
        if not base_domain:
            return jsonify({"error": "set accountability.base_domain first"}), 400
        token = resolver.device_tokens.token_for(p.name)
        prohibit = bool(request.args.get("lock"))
        built = build_device_profile(platform, p.name, token, base_domain,
                                     prohibit)
        if built is None:
            return jsonify({"error": "unknown platform"}), 404
        filename, mimetype, body = built
        resolver.audit.add("device_profile",
                           f"{platform} profile generated for {p.name}",
                           actor="dashboard")
        return Response(body, mimetype=mimetype, headers={
            "Content-Disposition": f'attachment; filename="{filename}"'})

    @app.route("/api/audit")
    def audit_route():
        days = float(request.args.get("days", 30))
        since = (datetime.datetime.now(datetime.timezone.utc)
                 - datetime.timedelta(days=days))
        return jsonify(resolver.audit.read_since(since))

    @app.route("/api/searches")
    def searches_route():
        days = float(request.args.get("days", 7))
        since = (datetime.datetime.now(datetime.timezone.utc)
                 - datetime.timedelta(days=days))
        return jsonify(resolver.search_log.read_since(since))

    @app.route("/api/accountability/preview")
    def accountability_preview():
        now = datetime.datetime.now(datetime.timezone.utc)
        since = now - datetime.timedelta(days=7)
        reports = reporter.accountability_reports(since, now)
        if not reports:
            return ("Accountability is disabled or no people are configured.\n"
                    "See the 'accountability' section in config.yaml.", 200,
                    {"Content-Type": "text/plain; charset=utf-8"})
        text = "\n\n" + ("=" * 70 + "\n\n").join(
            r["body"] for r in reports)
        return text, 200, {"Content-Type": "text/plain; charset=utf-8"}

    @app.route("/api/status")
    def status():
        return jsonify({
            "version": __version__,
            "update_available": bool(updates and updates.update_available),
            "latest_version": updates.latest_version if updates else None,
            "stats": resolver.stats,
            "lists": resolver.blocklists.stats(),
            "keywords": len(resolver.keywords.keywords),
            "safe_search_rules": [r["label"] for r in resolver.safe_search.rules],
            "cache": resolver.cache.stats() if resolver.cache else None,
            "client_names": resolver.client_names,
            "uptime_seconds": int(
                (datetime.datetime.now(datetime.timezone.utc)
                 - resolver.start_time).total_seconds()),
            "last_refresh": (resolver.blocklists.last_refresh.isoformat()
                             if resolver.blocklists.last_refresh else None),
            "refresh_ok": resolver.blocklists.last_refresh_ok,
        })

    @app.route("/api/health")
    def health():
        return build_health_text(resolver, updates), 200, {
            "Content-Type": "text/plain; charset=utf-8"}

    @app.route("/api/clients")
    def clients():
        """Devices seen in the last 7 days with names, today's counters and
        any active override — powers the dashboard Devices panel."""
        overrides = {o["client"]: o for o in resolver.overrides.list()}
        rows: Dict[str, Dict] = {}
        if resolver.statsdb:
            today = datetime.date.today().isoformat()
            for entry in resolver.statsdb.trends(days=7):
                row = rows.setdefault(entry["client"], {
                    "client": entry["client"],
                    "name": resolver.client_names.get(entry["client"]),
                    "today_total": 0, "today_blocked": 0})
                if entry["day"] == today:
                    row["today_total"] = entry["total"]
                    row["today_blocked"] = entry["blocked"]
        for client in set(list(overrides) + list(resolver.client_names)):
            rows.setdefault(client, {
                "client": client,
                "name": resolver.client_names.get(client),
                "today_total": 0, "today_blocked": 0})
        for client, row in rows.items():
            row["override"] = overrides.get(client)
        return jsonify(sorted(rows.values(), key=lambda r: r["client"]))

    @app.route("/api/trends")
    def trends():
        if not resolver.statsdb:
            return jsonify([])
        days = min(365, max(1, int(request.args.get("days", 30))))
        return jsonify(resolver.statsdb.trends(days))

    @app.route("/api/overrides")
    def overrides_list():
        return jsonify(resolver.overrides.list())

    @app.route("/api/override", methods=["POST"])
    def override_set():
        data = request.get_json(silent=True) or {}
        client = (data.get("client") or "").strip()
        mode = (data.get("mode") or "").strip().lower()
        minutes = float(data.get("minutes", 60))
        if not client or mode not in Overrides.MODES:
            return jsonify({"error": "client and mode "
                            f"({'/'.join(Overrides.MODES)}) required"}), 400
        result = resolver.overrides.set(client, mode, minutes)
        # Tamper-evidence: weakening filtering is recorded for the ally report.
        resolver.audit.add(
            f"override_{mode}",
            f"{resolver.client_label(client)} set to {mode} for {minutes:g} min",
            client=client, actor="dashboard")
        return jsonify(result)

    @app.route("/api/override/<client>", methods=["DELETE"])
    def override_cancel(client):
        if resolver.overrides.cancel(client):
            resolver.audit.add("override_cancel",
                               f"{resolver.client_label(client)} override "
                               "cancelled", client=client, actor="dashboard")
            return jsonify({"cancelled": client})
        return jsonify({"error": "no override for that client"}), 404

    @app.route("/api/unblock-requests")
    def unblock_requests():
        if block_page is None:
            return jsonify([])
        return jsonify(block_page.read_requests(
            int(request.args.get("limit", 100))))

    @app.route("/api/test-email", methods=["POST"])
    def test_email():
        ok = resolver.notifier.send(
            "FaithFilter test e-mail",
            "This is a test message from your FaithFilter server. "
            "If you can read this, e-mail reporting works.")
        return jsonify({"sent": ok}), (200 if ok else 502)

    @app.route("/api/backup")
    def backup():
        """Download config + lists as a zip archive."""
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for arcname, path in backup_targets(config).items():
                if path and os.path.exists(path):
                    zf.write(path, arcname)
        buffer.seek(0)
        stamp = datetime.datetime.now().strftime("%Y%m%d")
        return send_file(buffer, mimetype="application/zip",
                         as_attachment=True,
                         download_name=f"faithfilter-backup-{stamp}.zip")

    @app.route("/api/restore", methods=["POST"])
    def restore():
        """Restore lists (and config) from a backup zip."""
        upload = request.files.get("backup")
        if upload is None:
            return jsonify({"error": "multipart field 'backup' required"}), 400
        restored = apply_backup_zip(upload.read(), config)
        resolver.blocklists.reload(download=False)
        resolver.keywords.reload()
        return jsonify({"restored": restored,
                        "note": "config.yaml changes need a restart"})

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
        resolver.audit.add("whitelist_add", f"{domain} was allow-listed",
                           actor="dashboard")
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

def app_dir() -> str:
    """Directory containing the program: next to the executable when frozen
    into a standalone binary (PyInstaller), else next to this script."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def resolve_config_paths(config: Dict, base: str) -> None:
    """Anchor relative paths in the config to the config file's directory.

    Services (systemd, NSSM, Task Scheduler) often start with an unrelated
    working directory; without this, logs and lists would land there.
    """
    def fix(d: Dict, key: str) -> None:
        value = d.get(key)
        if isinstance(value, str) and value and not os.path.isabs(value):
            d[key] = os.path.join(base, value)

    blocking = config.setdefault("blocking", {})
    fix(blocking, "my_blocklist")
    fix(blocking, "whitelist")
    fix(blocking, "cache_dir")
    for source in blocking.get("sources", []) or []:
        fix(source, "file")
    # Legacy top-level keys from old configs.
    fix(config.get("blocklist", {}) or {}, "file")
    fix(config.get("whitelist", {}) or {}, "file")
    monitoring = config.setdefault("monitoring", {})
    fix(monitoring, "keywords_file")
    fix(monitoring, "alert_log_file")
    fix(config.setdefault("email", {}), "state_file")
    fix(config.setdefault("logs", {}), "query_log_file")
    acct = config.setdefault("accountability", {})
    fix(acct, "audit_log_file")
    fix(acct, "search_log_file")


DATA_FILE_HEADERS = {
    "my_blocklist": "# FaithFilter personal blocklist - one domain per line.\n"
                    "# Subdomains of listed domains are blocked automatically.\n",
    "whitelist": "# FaithFilter whitelist - these domains always resolve,\n"
                 "# overriding every blocklist. One domain per line.\n",
    "keywords_file": "# FaithFilter monitored keywords - one per line. Any queried\n"
                     "# domain containing a keyword is recorded in the weekly report.\n",
}


def ensure_data_files(config: Dict, logger: logging.Logger) -> None:
    """Create starter blocklist/whitelist/keywords files on first run."""
    paths = {
        "my_blocklist": config.get("blocking", {}).get("my_blocklist"),
        "whitelist": config.get("blocking", {}).get("whitelist"),
        "keywords_file": config.get("monitoring", {}).get("keywords_file"),
    }
    for kind, path in paths.items():
        if not path or os.path.exists(path):
            continue
        try:
            if os.path.dirname(path):
                os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(DATA_FILE_HEADERS[kind])
            logger.info("Created starter file %s", path)
        except OSError as exc:
            logger.warning("Could not create %s: %s", path, exc)


def run_setup(config_path: str) -> None:
    """Interactive first-run wizard: writes a minimal config.yaml holding
    only the answers, everything else stays on built-in defaults."""

    def ask(prompt: str, default: str = "") -> str:
        suffix = f" [{default}]" if default else ""
        answer = input(f"{prompt}{suffix}: ").strip()
        return answer or default

    def ask_yes_no(prompt: str, default: bool = True) -> bool:
        answer = ask(prompt + (" (Y/n)" if default else " (y/N)"))
        if not answer:
            return default
        return answer.lower().startswith("y")

    print("FaithFilter setup")
    print("=" * 40)
    print("Blocking, monitoring and safe-search are enabled by default;")
    print("this wizard only configures the settings that need your input.\n")

    overrides: Dict = {}

    if ask_yes_no("Enable the weekly e-mail report?"):
        email: Dict = {"enabled": True}
        email["username"] = ask("Your e-mail address (SMTP login)")
        email["smtp_host"] = ask("SMTP server", "smtp.gmail.com")
        email["smtp_port"] = int(ask("SMTP port", "587"))
        print("For Gmail, create an App Password at "
              "https://myaccount.google.com/apppasswords")
        password = getpass.getpass("SMTP password / app password "
                                   "(stored in config.yaml): ").strip()
        if password:
            email["password"] = password
        email["from"] = f"FaithFilter <{email['username']}>"
        email["to"] = [ask("Send the report to", email["username"])]
        email["report_day"] = ask("Report day", "sunday").lower()
        email["report_hour"] = int(ask("Report hour (0-23, UTC)", "8"))
        overrides["email"] = email
    print()

    youtube = ask("YouTube restricted mode - off, moderate or strict",
                  "strict").lower()
    if youtube != "strict":
        overrides.setdefault("safe_search", {})["youtube"] = youtube

    keywords = ask("Extra keywords to monitor (comma-separated, optional)")
    if keywords:
        overrides.setdefault("monitoring", {})["extra_keywords"] = [
            k.strip().lower() for k in keywords.split(",") if k.strip()]
    if ask_yes_no("Block keyword matches too (instead of only reporting)?",
                  default=False):
        overrides.setdefault("monitoring", {})["block_keyword_matches"] = True

    with open(config_path, "w", encoding="utf-8") as f:
        f.write("# FaithFilter settings - created by --setup.\n"
                "# Only overrides are stored here; every other option uses the\n"
                "# built-in defaults (see README.md for the full reference).\n")
        yaml.safe_dump(overrides, f, default_flow_style=False, sort_keys=False)
    if os.name == "posix":
        os.chmod(config_path, 0o600)  # the file may hold the SMTP password
    print(f"\nSettings saved to {config_path}")
    print("Start the server now with the same command minus --setup.")


def install_service(config_path: str) -> None:
    """Install FaithFilter as an auto-starting service.

    Linux: writes and enables a systemd unit.  Windows: registers a
    Scheduled Task that runs at boot as SYSTEM.
    """
    if getattr(sys, "frozen", False):
        command = f'"{os.path.abspath(sys.executable)}"'
    else:
        command = (f'"{sys.executable}" "{os.path.abspath(__file__)}"')
    command += f' --config "{os.path.abspath(config_path)}"'

    if os.name == "nt":
        result = subprocess.run(
            ["schtasks", "/Create", "/F", "/TN", "FaithFilter",
             "/SC", "ONSTART", "/RU", "SYSTEM", "/RL", "HIGHEST",
             "/TR", command],
            capture_output=True, text=True)
        if result.returncode == 0:
            print("Installed scheduled task 'FaithFilter' (runs at boot as "
                  "SYSTEM).\nStart it now with:  schtasks /Run /TN FaithFilter")
        else:
            print("Failed to install the scheduled task (run this from an "
                  "Administrator terminal):\n" + result.stderr.strip())
            raise SystemExit(1)
        return

    unit_path = "/etc/systemd/system/faithfilter.service"
    unit = (
        "[Unit]\n"
        "Description=FaithFilter DNS filtering service\n"
        "After=network-online.target\nWants=network-online.target\n\n"
        "[Service]\n"
        f"ExecStart={command}\n"
        f"WorkingDirectory={os.path.dirname(os.path.abspath(config_path)) or '/'}\n"
        "Restart=always\nRestartSec=5\nUser=root\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )
    try:
        with open(unit_path, "w", encoding="utf-8") as f:
            f.write(unit)
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", "--now", "faithfilter"],
                       check=True)
        print(f"Installed and started systemd service ({unit_path}).\n"
              "Watch logs with:  journalctl -u faithfilter -f")
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"Failed to install the systemd service (run with sudo?): {exc}")
        raise SystemExit(1)


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
    parser.add_argument("--config", default=None,
                        help="Path to YAML configuration file "
                             "(default: config.yaml next to the program)")
    parser.add_argument("--send-report", action="store_true",
                        help="Send the weekly report immediately and exit")
    parser.add_argument("--setup", action="store_true",
                        help="Run the interactive setup wizard and exit")
    parser.add_argument("--install-service", action="store_true",
                        help="Install as an auto-starting service "
                             "(systemd on Linux, Scheduled Task on Windows)")
    args = parser.parse_args()

    config_path = args.config or os.path.join(app_dir(), "config.yaml")
    if args.setup:
        run_setup(config_path)
        return
    if args.install_service:
        install_service(config_path)
        return

    user_config: Dict = {}
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            user_config = yaml.safe_load(f) or {}
    elif args.config:
        # An explicitly named file that doesn't exist is an error; the
        # implicit default just means "run with built-in settings".
        parser.error(f"configuration file not found: {config_path}")
    config = deep_merge(DEFAULT_CONFIG, user_config)
    base_dir = os.path.dirname(os.path.abspath(config_path)) or app_dir()
    resolve_config_paths(config, base_dir)
    config["_config_path"] = os.path.abspath(config_path)
    config.setdefault("http_api", {}).setdefault(
        "password_file", os.path.join(base_dir, "admin_password.txt"))

    log_level_name = config.get("logs", {}).get("log_level", "INFO")
    logging.basicConfig(level=getattr(logging, log_level_name.upper(), logging.INFO),
                        format="%(asctime)s [%(levelname)s] %(message)s")
    logger = logging.getLogger("FaithFilter")

    ensure_data_files(config, logger)
    resolver = FaithFilterResolver(config, logger)
    updates = UpdateChecker(config, logger)
    reporter = Reporter(
        config, resolver.alerts, logger, resolver.notifier,
        health_text=lambda: build_health_text(resolver, updates),
        names=resolver.client_names, statsdb=resolver.statsdb,
        resolver=resolver)

    if args.send_report:
        ok = reporter.send_report(force=True)
        raise SystemExit(0 if ok else 1)

    servers = start_dns_server(resolver, config)
    if resolver.accountability.enabled:
        resolver.audit.add("service_start",
                           f"FaithFilter {__version__} started")
    logger.info("FaithFilter DNS server listening on %s:%s",
                config.get("dns", {}).get("listen_ip", "0.0.0.0"),
                config.get("dns", {}).get("listen_port", 53))

    resolver.blocklists.start_refresh_thread()
    reporter.start_scheduler()
    updates.start()

    # Daily retention sweep (old logs are sensitive; delete, don't hoard).
    retention_stop = threading.Event()

    def retention_loop() -> None:
        purge_old_data(config, resolver.statsdb, logger)
        while not retention_stop.wait(86400):
            purge_old_data(config, resolver.statsdb, logger)

    threading.Thread(target=retention_loop, name="retention",
                     daemon=True).start()

    sync: Optional[SyncFollower] = None
    if config.get("sync", {}).get("enabled", False):
        sync = SyncFollower(config, resolver, logger)
        sync.start()

    block_page: Optional[BlockPageServer] = None
    if config.get("block_page", {}).get("enabled", False):
        block_page = BlockPageServer(config, resolver.notifier, logger)
        block_page.start()
        logger.info("Blocked domains answer with %s (block page)",
                    resolver.block_page_ip)

    dot_server: Optional[DoTServer] = None
    if config.get("dot", {}).get("enabled", False):
        dot_server = DoTServer(resolver, config, logger)
        dot_server.start()

    if config.get("http_api", {}).get("enable", False):
        if Flask is None:
            logger.error("Flask is not installed but http_api.enable is true. "
                         "Install Flask or disable the API.")
        else:
            app = create_api_server(resolver, reporter, config,
                                    block_page, logger, updates)
            host = config.get("http_api", {}).get("host", "127.0.0.1")
            port = int(config.get("http_api", {}).get("port", 5000))
            run_kwargs: Dict = {"host": host, "port": port,
                                "threaded": True}
            cert = config.get("http_api", {}).get("cert_file")
            key = config.get("http_api", {}).get("key_file")
            if cert and key:
                run_kwargs["ssl_context"] = (cert, key)
            threading.Thread(target=app.run, kwargs=run_kwargs,
                             daemon=True).start()
            if host == "0.0.0.0" and not (cert and key):
                logger.warning("Dashboard is reachable across the LAN (host "
                               "0.0.0.0) over plain HTTP; set cert_file/"
                               "key_file for HTTPS, or bind host to 127.0.0.1.")
            logger.info("FaithFilter dashboard/API listening on %s:%s%s",
                        host, port, " (HTTPS)" if cert and key else "")

    if config.get("notifications", {}).get("notify_on_start", False):
        threading.Thread(
            target=resolver.notifier.send,
            args=("FaithFilter started",
                  "The FaithFilter DNS service just (re)started. If you did "
                  "not expect this, check the machine it runs on."),
            daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down FaithFilter")
        resolver.blocklists.stop()
        reporter.stop()
        updates.stop()
        retention_stop.set()
        if sync:
            sync.stop()
        if resolver.statsdb:
            resolver.statsdb.stop()
        if block_page:
            block_page.stop()
        if dot_server:
            dot_server.stop()
        for server in servers:
            server.stop()


if __name__ == "__main__":
    main()
