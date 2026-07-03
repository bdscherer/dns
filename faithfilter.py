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
import base64
import copy
import datetime
import fnmatch
import getpass
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
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
import zipfile
from collections import OrderedDict
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

import yaml
from dnslib import A, AAAA, DNSRecord, QTYPE, RCODE, RR
from dnslib.server import BaseResolver, DNSLogger, DNSServer

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
        "send_if_empty": True,
        "state_file": "logs/report_state.json",
    },
    "logs": {
        "query_log_file": "logs/queries.log",
        "log_level": "INFO",
        "max_log_mb": 20,      # rotate query/alert logs beyond this size
        "log_backups": 3,      # rotated copies to keep (.1, .2, ...)
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

    def send(self, subject: str, body: str) -> bool:
        if not self.enabled:
            return False
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self.cfg.get("from") or self.cfg.get("username", "faithfilter@localhost")
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
                       subject: str, body: str) -> bool:
        """Send unless a mail with the same key went out too recently."""
        now = time.time()
        with self._lock:
            if now - self._last.get(key, 0) < min_interval_seconds:
                return False
            self._last[key] = now
        return self.send(subject, body)


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
        self.notifier = Notifier(config, logger)
        self.notifications = config.get("notifications", {})
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
                      reason: str, detail: str) -> None:
        self.stats["alerts"] += 1
        self.alerts.add(client_ip, domain, reason, detail)
        if (reason in ("adult_domain", "bypass_attempt")
                and self.notifications.get("instant_alerts", True)):
            interval = float(self.notifications.get(
                "instant_min_minutes", 60)) * 60
            kind = ("adult content" if reason == "adult_domain"
                    else "a filter-bypass service (VPN/proxy/DoH)")
            self.notifier.send_throttled(
                f"instant:{client_ip}", interval,
                f"FaithFilter alert: {client_ip} tried to reach {kind}",
                f"Device {client_ip} attempted to access {domain} "
                f"({reason}: {detail}).\n\n"
                "Further attempts from this device within the next hour are "
                "throttled; the weekly report will contain the full list.")

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
        group = self.policies.group_for(client_ip)
        filtering = str(group.get("filtering", "full")).lower()
        enforce = filtering == "full"          # blocking active
        monitor = filtering in ("full", "monitor_only")

        # 0a. Unfiltered devices skip everything.
        if filtering == "off":
            self.log_query(client_ip, qname, "allowed:unfiltered")
            resp = self._forward_cached(request)
            return resp if resp else request.reply(rcode=RCODE.SERVFAIL)

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
            return resp if resp else request.reply(rcode=RCODE.SERVFAIL)

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
                    self._record_alert(client_ip, qname, "adult_domain", category)
                elif category == "bypass":
                    self._record_alert(client_ip, qname, "bypass_attempt", category)
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
                self._record_alert(client_ip, qname, "keyword", keyword)
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
            return request.reply(rcode=RCODE.SERVFAIL)
        if enforce:
            cname_category = self._cname_blocked(resp)
            if cname_category:
                self.stats["blocked"] += 1
                self.stats["blocked_cname"] += 1
                if cname_category == "adult":
                    self._record_alert(client_ip, qname, "adult_domain",
                                       f"cname:{cname_category}")
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

    def __init__(self, config: Dict, alerts: AlertLog, logger: logging.Logger,
                 notifier: Optional[Notifier] = None,
                 health_text: Optional[Callable[[], str]] = None):
        self.cfg = config.get("email", {})
        self.alerts = alerts
        self.logger = logger
        self.notifier = notifier or Notifier(config, logger)
        self.health_text = health_text
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
        body = build_report(alerts, last, now)
        if self.health_text:
            body += "\n\n" + self.health_text()
        return body, len(alerts)

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
        self._mark_sent(now)
        self.logger.info("Weekly report sent (%d alerts)", alert_count)
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


def build_health_text(resolver: "FaithFilterResolver") -> str:
    """Service-health section appended to the weekly report."""
    now = datetime.datetime.now(datetime.timezone.utc)
    uptime = now - resolver.start_time
    lists = resolver.blocklists.stats()
    lines = [
        "Filter health:",
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
                html = BLOCK_PAGE_HTML.format(domain=host, message=message)
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
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", self.port))
        sock.listen(16)

        def handle(conn: ssl.SSLSocket, addr) -> None:
            class FakeHandler:
                client_address = addr
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
</style></head><body>
<header><h1>&#128737;&#65039; FaithFilter</h1>
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
async function refresh(){
 try{
  const s=await (await fetch('/api/status')).json();
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
  const al=await (await fetch('/api/alerts?days=7')).json();
  $('alerts').tBodies[0].innerHTML=al.slice(-30).reverse().map(a=>
   '<tr><td>'+esc(a.time.slice(0,16))+'</td><td>'+esc(a.client)+'</td><td>'+
   esc(a.domain)+'</td><td class="blocked">'+esc(a.reason)+' ('+esc(a.detail)+
   ')</td></tr>').join('')||'<tr><td>No alerts this week</td></tr>';
  const q=await (await fetch('/api/queries?limit=30')).json();
  $('queries').tBodies[0].innerHTML=q.reverse().map(e=>
   '<tr><td>'+esc(e.time.slice(11,19))+'</td><td>'+esc(e.client)+'</td><td>'+
   esc(e.domain)+'</td><td class="'+cls(e.action)+'">'+esc(e.action)+
   '</td></tr>').join('');
  const u=await (await fetch('/api/unblock-requests')).json();
  $('unblock').tBodies[0].innerHTML=u.slice(-15).reverse().map(r=>
   '<tr><td>'+esc(r.time.slice(0,16))+'</td><td>'+esc(r.name||r.client)+
   '</td><td>'+esc(r.domain)+'</td><td>'+esc(r.reason)+'</td>'+
   '<td><button onclick="addUnblock(\\''+encodeURIComponent(r.domain)+
   '\\')">Allow</button></td></tr>').join('')||
   '<tr><td>No requests</td></tr>';
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


def create_api_server(resolver: FaithFilterResolver, reporter: Reporter,
                      config: Dict,
                      block_page: Optional[BlockPageServer] = None,
                      logger: Optional[logging.Logger] = None):
    logger = logger or logging.getLogger("FaithFilter")
    app = Flask(__name__)
    api_cfg = config.get("http_api", {})
    api_key = api_cfg.get("api_key")
    admin_password = get_admin_password(config, logger)
    app.secret_key = hashlib.sha256(
        ("faithfilter:" + admin_password).encode()).digest()
    doh_enabled = bool(api_cfg.get("doh", True))

    OPEN_PATHS = {"/login", "/dns-query", "/favicon.ico"}

    @app.before_request
    def check_auth():
        if request.path in OPEN_PATHS:
            return None
        if api_key and request.headers.get("X-API-Key") == api_key:
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

    if doh_enabled:
        @app.route("/dns-query", methods=["GET", "POST"])
        def dns_query():
            """RFC 8484 DNS-over-HTTPS endpoint."""
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

            reply = resolver.resolve(record, FakeHandler())
            # dnslib's pack() returns a bytearray; WSGI requires bytes.
            return Response(bytes(reply.pack()),
                            content_type="application/dns-message")

    @app.route("/api/status")
    def status():
        return jsonify({
            "stats": resolver.stats,
            "lists": resolver.blocklists.stats(),
            "keywords": len(resolver.keywords.keywords),
            "safe_search_rules": [r["label"] for r in resolver.safe_search.rules],
            "cache": resolver.cache.stats() if resolver.cache else None,
            "uptime_seconds": int(
                (datetime.datetime.now(datetime.timezone.utc)
                 - resolver.start_time).total_seconds()),
            "last_refresh": (resolver.blocklists.last_refresh.isoformat()
                             if resolver.blocklists.last_refresh else None),
            "refresh_ok": resolver.blocklists.last_refresh_ok,
        })

    @app.route("/api/health")
    def health():
        return build_health_text(resolver), 200, {
            "Content-Type": "text/plain; charset=utf-8"}

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
        blocking = config.get("blocking", {})
        candidates = {
            "config.yaml": config.get("_config_path"),
            "blocklist.txt": blocking.get("my_blocklist"),
            "whitelist.txt": blocking.get("whitelist"),
            "keywords.txt": config.get("monitoring", {}).get("keywords_file"),
        }
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for arcname, path in candidates.items():
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
        blocking = config.get("blocking", {})
        targets = {
            "config.yaml": config.get("_config_path"),
            "blocklist.txt": blocking.get("my_blocklist"),
            "whitelist.txt": blocking.get("whitelist"),
            "keywords.txt": config.get("monitoring", {}).get("keywords_file"),
        }
        restored = []
        with zipfile.ZipFile(io.BytesIO(upload.read())) as zf:
            for arcname in zf.namelist():
                path = targets.get(arcname)
                if not path:
                    continue
                with open(path, "wb") as f:
                    f.write(zf.read(arcname))
                restored.append(arcname)
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
    reporter = Reporter(config, resolver.alerts, logger, resolver.notifier,
                        health_text=lambda: build_health_text(resolver))

    if args.send_report:
        ok = reporter.send_report(force=True)
        raise SystemExit(0 if ok else 1)

    servers = start_dns_server(resolver, config)
    logger.info("FaithFilter DNS server listening on %s:%s",
                config.get("dns", {}).get("listen_ip", "0.0.0.0"),
                config.get("dns", {}).get("listen_port", 53))

    resolver.blocklists.start_refresh_thread()
    reporter.start_scheduler()

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
                                    block_page, logger)
            host = config.get("http_api", {}).get("host", "127.0.0.1")
            port = int(config.get("http_api", {}).get("port", 5000))
            run_kwargs: Dict = {"host": host, "port": port}
            cert = config.get("http_api", {}).get("cert_file")
            key = config.get("http_api", {}).get("key_file")
            if cert and key:
                run_kwargs["ssl_context"] = (cert, key)
            threading.Thread(target=app.run, kwargs=run_kwargs,
                             daemon=True).start()
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
        if block_page:
            block_page.stop()
        if dot_server:
            dot_server.stop()
        for server in servers:
            server.stop()


if __name__ == "__main__":
    main()
