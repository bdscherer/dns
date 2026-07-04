#!/usr/bin/env python3
"""Offline test suite for FaithFilter.

Runs the resolver against a fake upstream DNS server on localhost so no
internet access is needed:

    python3 test_faithfilter.py
"""

import datetime
import json
import logging
import os
import shutil
import socket
import tempfile
import time
import unittest

from dnslib import A, DNSRecord, QTYPE, RCODE, RR
from dnslib.server import BaseResolver, DNSLogger, DNSServer

import faithfilter
from faithfilter import (
    DEFAULT_CONFIG, AlertLog, BlocklistManager, ClientPolicies, DNSCache,
    FaithFilterResolver, KeywordMonitor, Notifier, Overrides, Reporter,
    StatsDB, UpdateChecker, apply_backup_zip, build_report,
    create_api_server, deep_merge, parse_domain_lines, purge_old_data,
    rotate_if_needed,
)

UPSTREAM_PORT = 15353
DNS_PORT = 15354
UPSTREAM_IP = "10.99.99.99"  # what the fake upstream answers for everything

logging.basicConfig(level=logging.CRITICAL)
LOGGER = logging.getLogger("test")


class FakeUpstream(BaseResolver):
    """Answers every A query with UPSTREAM_IP; 'cloaked.example' gets a
    CNAME chain pointing at a blocked ad tracker."""

    def resolve(self, request, handler):
        from dnslib import CNAME
        reply = request.reply()
        qname = str(request.q.qname).rstrip(".").lower()
        if qname == "cloaked.example" and request.q.qtype == QTYPE.A:
            reply.add_answer(RR(rname=request.q.qname, rtype=QTYPE.CNAME,
                                rclass=1, ttl=60,
                                rdata=CNAME("tracker.adnetwork.example")))
            reply.add_answer(RR(rname="tracker.adnetwork.example",
                                rtype=QTYPE.A, rclass=1, ttl=60,
                                rdata=A(UPSTREAM_IP)))
            return reply
        if request.q.qtype == QTYPE.A:
            reply.add_answer(RR(rname=request.q.qname, rtype=QTYPE.A,
                                rclass=1, ttl=60, rdata=A(UPSTREAM_IP)))
        return reply


def query(name: str, qtype: str = "A", port: int = DNS_PORT) -> DNSRecord:
    q = DNSRecord.question(name, qtype)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    s.sendto(q.pack(), ("127.0.0.1", port))
    data, _ = s.recvfrom(8192)
    s.close()
    return DNSRecord.parse(data)


def answer_ips(reply: DNSRecord):
    return [str(rr.rdata) for rr in reply.rr if rr.rtype == QTYPE.A]


class ParserTests(unittest.TestCase):
    def test_plain_and_hosts_formats(self):
        text = [
            "# comment",
            "",
            "plain-domain.com",
            "0.0.0.0 hosts-style.com   # trailing comment",
            "127.0.0.1 also-hosts.net extra-hosts.org",
            "0.0.0.0 0.0.0.0",          # noise line in StevenBlack lists
            "127.0.0.1 localhost",
            "not a domain at all !!!",
        ]
        domains = parse_domain_lines(text)
        self.assertEqual(domains, {
            "plain-domain.com", "hosts-style.com",
            "also-hosts.net", "extra-hosts.org",
        })


class DefaultConfigTests(unittest.TestCase):
    def test_deep_merge_overrides_nested_scalars(self):
        merged = deep_merge(DEFAULT_CONFIG, {
            "dns": {"listen_port": 5353},
            "email": {"enabled": True, "username": "me@example.com"},
        })
        self.assertEqual(merged["dns"]["listen_port"], 5353)
        self.assertEqual(merged["dns"]["listen_ip"], "0.0.0.0")   # kept
        self.assertTrue(merged["email"]["enabled"])
        self.assertEqual(merged["email"]["smtp_host"], "smtp.gmail.com")

    def test_deep_merge_replaces_lists(self):
        merged = deep_merge(DEFAULT_CONFIG,
                            {"blocking": {"sources": []}})
        self.assertEqual(merged["blocking"]["sources"], [])
        # and the original defaults are untouched
        self.assertEqual(len(DEFAULT_CONFIG["blocking"]["sources"]), 3)

    def test_defaults_build_a_working_resolver(self):
        # The built-in configuration alone (no config file, no downloaded
        # lists) must construct a resolver with all safe-search rules on.
        tmp = tempfile.mkdtemp()
        try:
            cfg = deep_merge(DEFAULT_CONFIG, {
                "blocking": {"my_blocklist": os.path.join(tmp, "b.txt"),
                             "whitelist": os.path.join(tmp, "w.txt"),
                             "cache_dir": os.path.join(tmp, "cache")},
                "monitoring": {"keywords_file": None,
                               "alert_log_file": os.path.join(tmp, "a.jsonl")},
                "logs": {"query_log_file": None},
            })
            resolver = FaithFilterResolver(cfg, LOGGER)
            labels = [r["label"] for r in resolver.safe_search.rules]
            self.assertEqual(labels, ["google", "bing", "duckduckgo",
                                      "youtube_strict"])
        finally:
            shutil.rmtree(tmp)


class KeywordTests(unittest.TestCase):
    def make(self, **mon):
        return KeywordMonitor({"monitoring": mon}, LOGGER)

    def test_adult_keyword_detected(self):
        km = self.make()
        self.assertEqual(km.match("free-porn-videos.example"), "porn")
        self.assertIsNone(km.match("wikipedia.org"))

    def test_exceptions_suppress_false_positives(self):
        km = self.make()
        self.assertIsNone(km.match("visitessex.co.uk"))
        self.assertIsNone(km.match("sussex.ac.uk"))

    def test_extra_keywords(self):
        km = self.make(extra_keywords=["casino"])
        self.assertEqual(km.match("bigwin-casino.example"), "casino")


class ReportTests(unittest.TestCase):
    def test_empty_report(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        text = build_report([], now - datetime.timedelta(days=7), now)
        self.assertIn("No adult-content, bypass or keyword alerts", text)

    def test_report_aggregation(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        alerts = [
            {"time": now.isoformat(), "client": "192.168.1.10",
             "domain": "bad-adult-site.example", "reason": "adult_domain",
             "detail": "adult"},
            {"time": now.isoformat(), "client": "192.168.1.10",
             "domain": "bad-adult-site.example", "reason": "adult_domain",
             "detail": "adult"},
            {"time": now.isoformat(), "client": "192.168.1.11",
             "domain": "casino-fun.example", "reason": "keyword",
             "detail": "casino"},
        ]
        text = build_report(alerts, now - datetime.timedelta(days=7), now)
        self.assertIn("Total alerts: 3 (2 adult-domain, 0 bypass-attempt, "
                      "1 keyword)", text)
        self.assertIn("192.168.1.10", text)
        self.assertIn("bad-adult-site.example", text)
        self.assertIn("casino", text)


class AlertLogTests(unittest.TestCase):
    def test_write_read_and_throttle(self):
        tmp = tempfile.mkdtemp()
        try:
            log = AlertLog(os.path.join(tmp, "alerts.jsonl"), LOGGER)
            log.add("1.2.3.4", "x.example", "keyword", "porn")
            log.add("1.2.3.4", "x.example", "keyword", "porn")  # throttled
            log.add("1.2.3.5", "x.example", "keyword", "porn")
            since = (datetime.datetime.now(datetime.timezone.utc)
                     - datetime.timedelta(minutes=1))
            self.assertEqual(len(log.read_since(since)), 2)
        finally:
            shutil.rmtree(tmp)


class UnitTests(unittest.TestCase):
    def test_rotate_if_needed(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, "x.log")
            with open(path, "w") as f:
                f.write("A" * 100)
            rotate_if_needed(path, max_bytes=50, backups=2)
            self.assertTrue(os.path.exists(path + ".1"))
            self.assertFalse(os.path.exists(path))
        finally:
            shutil.rmtree(tmp)

    def test_dns_cache_fresh_and_stale(self):
        cache = DNSCache(max_entries=10)
        request = faithfilter.DNSRecord.question("cached.example", "A")
        response = request.reply()
        response.add_answer(RR(rname=request.q.qname, rtype=QTYPE.A,
                               rclass=1, ttl=60, rdata=A("1.2.3.4")))
        self.assertIsNone(cache.get(request))
        cache.put(request, response)
        hit = cache.get(request)
        self.assertIsNotNone(hit)
        self.assertEqual(str(hit.rr[0].rdata), "1.2.3.4")
        # Force expiry: fresh lookups miss, stale lookups still serve.
        key = ("cached.example.", QTYPE.A)
        packed, _, stale_until = cache._store[key]
        cache._store[key] = (packed, 0, stale_until)
        self.assertIsNone(cache.get(request))
        self.assertIsNotNone(cache.get(request, allow_stale=True))

    def test_client_policies_group_matching(self):
        policies = ClientPolicies({"clients": {"groups": [
            {"name": "kids", "members": ["10.0.0.5", "10.0.1.0/24"],
             "filtering": "full"},
            {"name": "parents", "members": ["10.0.0.9"], "filtering": "off"},
        ]}}, LOGGER)
        self.assertEqual(policies.group_for("10.0.0.5")["name"], "kids")
        self.assertEqual(policies.group_for("10.0.1.77")["name"], "kids")
        self.assertEqual(policies.group_for("10.0.0.9")["name"], "parents")
        self.assertEqual(policies.group_for("10.0.2.1")["name"], "default")
        self.assertEqual(policies.group_for("garbage")["name"], "default")

    def test_curfew_windows_including_midnight(self):
        group = {"curfew": [{"days": ["mon"], "from": "21:30", "to": "06:30"}]}
        monday_22 = datetime.datetime(2026, 6, 29, 22, 0)     # Monday
        monday_20 = datetime.datetime(2026, 6, 29, 20, 0)
        tuesday_5 = datetime.datetime(2026, 6, 30, 5, 0)      # after midnight
        tuesday_12 = datetime.datetime(2026, 6, 30, 12, 0)
        self.assertTrue(ClientPolicies.curfew_active(group, monday_22))
        self.assertFalse(ClientPolicies.curfew_active(group, monday_20))
        self.assertTrue(ClientPolicies.curfew_active(group, tuesday_5))
        self.assertFalse(ClientPolicies.curfew_active(group, tuesday_12))

    def test_personal_blocklist_patterns(self):
        tmp = tempfile.mkdtemp()
        try:
            bl = os.path.join(tmp, "bl.txt")
            with open(bl, "w") as f:
                f.write("*tiktok*\n/^bad[0-9]+\\.com$/\nplain.example\n")
            mgr = BlocklistManager({"blocking": {
                "my_blocklist": bl,
                "whitelist": os.path.join(tmp, "none.txt"),
                "cache_dir": tmp, "sources": []}}, LOGGER)
            self.assertEqual(mgr.blocked_category("www.tiktok.com"), "custom")
            self.assertEqual(mgr.blocked_category("bad123.com"), "custom")
            self.assertEqual(mgr.blocked_category("plain.example"), "custom")
            self.assertIsNone(mgr.blocked_category("harmless.org"))
        finally:
            shutil.rmtree(tmp)

    def test_notifier_throttling(self):
        sent = []

        class Recording(Notifier):
            def send(self, subject, body):
                sent.append(subject)
                return True

        notifier = Recording({"email": {"enabled": True}}, LOGGER)
        self.assertTrue(notifier.send_throttled("k", 60, "first", "b"))
        self.assertFalse(notifier.send_throttled("k", 60, "second", "b"))
        self.assertTrue(notifier.send_throttled("other", 60, "third", "b"))
        self.assertEqual(sent, ["first", "third"])

    def test_report_includes_health_text(self):
        tmp = tempfile.mkdtemp()
        try:
            alerts = AlertLog(os.path.join(tmp, "a.jsonl"), LOGGER)
            reporter = Reporter(
                {"email": {"state_file": os.path.join(tmp, "s.json")}},
                alerts, LOGGER, health_text=lambda: "Filter health:\n  OK")
            body, count = reporter.build_body()
            self.assertEqual(count, 0)
            self.assertIn("Filter health:", body)
        finally:
            shutil.rmtree(tmp)


class FeatureTests(unittest.TestCase):
    """Overrides, stats, retention, update check, backup apply, names."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def path(self, name):
        return os.path.join(self.tmp, name)

    def test_overrides_set_expire_cancel(self):
        ov = Overrides(self.path("ov.json"), LOGGER)
        ov.set("10.0.0.5", "pause", 60)
        self.assertEqual(ov.active("10.0.0.5"), "pause")
        self.assertIsNone(ov.active("10.0.0.6"))
        # Persistence across "restart"
        ov2 = Overrides(self.path("ov.json"), LOGGER)
        self.assertEqual(ov2.active("10.0.0.5"), "pause")
        self.assertTrue(ov2.cancel("10.0.0.5"))
        self.assertIsNone(ov2.active("10.0.0.5"))
        # Expiry
        ov2.set("10.0.0.7", "unfiltered", -1)
        self.assertIsNone(ov2.active("10.0.0.7"))
        with self.assertRaises(ValueError):
            ov2.set("10.0.0.8", "bogus", 10)

    def test_statsdb_record_trends_and_totals(self):
        db = StatsDB(self.path("stats.db"), LOGGER, flush_interval=0)
        db.record("10.0.0.5", "allowed")
        db.record("10.0.0.5", "blocked:ads")
        db.record("10.0.0.6", "flagged:keyword:x")
        rows = db.trends(days=1)
        by_client = {r["client"]: r for r in rows}
        self.assertEqual(by_client["10.0.0.5"]["total"], 2)
        self.assertEqual(by_client["10.0.0.5"]["blocked"], 1)
        self.assertEqual(by_client["10.0.0.6"]["flagged"], 1)
        today = datetime.date.today()
        totals = db.totals_between(today, today + datetime.timedelta(days=1))
        self.assertEqual(totals["total"], 3)
        db.stop()

    def test_retention_purges_old_alerts_and_logs(self):
        alerts_file = self.path("alerts.jsonl")
        old = (datetime.datetime.now(datetime.timezone.utc)
               - datetime.timedelta(days=200)).isoformat()
        new = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with open(alerts_file, "w") as f:
            f.write(json.dumps({"time": old, "client": "x", "domain": "d",
                                "reason": "keyword", "detail": "k"}) + "\n")
            f.write(json.dumps({"time": new, "client": "x", "domain": "d",
                                "reason": "keyword", "detail": "k"}) + "\n")
        rotated = self.path("queries.log.1")
        with open(rotated, "w") as f:
            f.write("old\n")
        os.utime(rotated, (time.time() - 90 * 86400,) * 2)
        config = {"logs": {"query_log_file": self.path("queries.log"),
                           "retention_days": 30},
                  "monitoring": {"alert_log_file": alerts_file,
                                 "alert_retention_days": 90}}
        purge_old_data(config, None, LOGGER)
        self.assertFalse(os.path.exists(rotated))
        with open(alerts_file) as f:
            lines = f.readlines()
        self.assertEqual(len(lines), 1)
        self.assertIn(new, lines[0])

    def test_update_version_comparison(self):
        self.assertGreater(UpdateChecker._as_tuple("v2.2.0"),
                           UpdateChecker._as_tuple("2.1.0"))
        self.assertGreater(UpdateChecker._as_tuple("2.10.0"),
                           UpdateChecker._as_tuple("2.9.9"))
        self.assertEqual(UpdateChecker._as_tuple("v1.0"),
                         UpdateChecker._as_tuple("1.0"))

    def test_apply_backup_zip_writes_lists_only_by_default(self):
        import io as io_mod
        import zipfile as zf_mod
        buffer = io_mod.BytesIO()
        with zf_mod.ZipFile(buffer, "w") as zf:
            zf.writestr("blocklist.txt", "synced.example\n")
            zf.writestr("config.yaml", "dns: {}\n")
            zf.writestr("evil.sh", "#!/bin/sh\n")   # must be ignored
        config = {"blocking": {"my_blocklist": self.path("bl.txt"),
                               "whitelist": self.path("wl.txt")},
                  "monitoring": {"keywords_file": self.path("kw.txt")},
                  "_config_path": self.path("config.yaml")}
        restored = apply_backup_zip(buffer.getvalue(), config,
                                    include_config=False)
        self.assertEqual(restored, ["blocklist.txt"])
        self.assertFalse(os.path.exists(self.path("config.yaml")))
        self.assertFalse(os.path.exists(self.path("evil.sh")))
        with open(self.path("bl.txt")) as f:
            self.assertIn("synced.example", f.read())

    def test_sync_preserves_follower_sync_section(self):
        from faithfilter import SyncFollower
        import yaml as yaml_mod
        config_path = self.path("config.yaml")
        config = {"sync": {"enabled": True,
                           "primary_url": "http://primary:5000",
                           "api_key": "k", "interval_minutes": 60},
                  "_config_path": config_path}
        follower = SyncFollower(config, None, LOGGER)
        # Simulate a pulled primary config that has sync disabled.
        with open(config_path, "w") as f:
            yaml_mod.safe_dump({"sync": {"enabled": False},
                                "dns": {"listen_port": 53}}, f)
        follower._preserve_sync_section()
        with open(config_path) as f:
            result = yaml_mod.safe_load(f)
        self.assertTrue(result["sync"]["enabled"])
        self.assertEqual(result["sync"]["primary_url"], "http://primary:5000")
        self.assertEqual(result["dns"]["listen_port"], 53)

    def test_report_uses_device_names(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        alerts = [{"time": now.isoformat(), "client": "192.168.1.20",
                   "domain": "bad.example", "reason": "adult_domain",
                   "detail": "adult"}]
        text = build_report(alerts, now - datetime.timedelta(days=7), now,
                            names={"192.168.1.20": "Emma's iPad"})
        self.assertIn("Emma's iPad (192.168.1.20)", text)


class EndToEndTests(unittest.TestCase):
    """Full resolver behind a UDP socket, forwarding to a fake upstream."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.upstream = DNSServer(FakeUpstream(), port=UPSTREAM_PORT,
                                 address="127.0.0.1", logger=DNSLogger("-request,-reply,-truncated,-error", False))
        cls.upstream.start_thread()

        def path(name):
            return os.path.join(cls.tmp, name)

        with open(path("blocklist.txt"), "w") as f:
            f.write("mybadsite.com\n")
        with open(path("whitelist.txt"), "w") as f:
            f.write("goodsite.com\n")
        # An adult source and an ads source, both hosts-format local files.
        with open(path("adult.txt"), "w") as f:
            f.write("0.0.0.0 nasty-adult-site.example\n")
        with open(path("ads.txt"), "w") as f:
            f.write("0.0.0.0 tracker.adnetwork.example\n")
        with open(path("bypass.txt"), "w") as f:
            f.write("sneaky-vpn.example\n")
        with open(path("config.yaml"), "w") as f:
            f.write("# test config marker\n")

        cls.config = {
            "dns": {
                "listen_ip": "127.0.0.1",
                "listen_port": DNS_PORT,
                "listen_tcp": False,
                "upstream_dns": [f"127.0.0.1:{UPSTREAM_PORT}"],
                "forward_timeout": 3,
                "block_response": "nxdomain",
            },
            "blocking": {
                "my_blocklist": path("blocklist.txt"),
                "whitelist": path("whitelist.txt"),
                "cache_dir": path("cache"),
                "sources": [
                    {"name": "adult", "category": "adult", "file": path("adult.txt")},
                    {"name": "ads", "category": "ads", "file": path("ads.txt")},
                    {"name": "bypass", "category": "bypass", "file": path("bypass.txt")},
                ],
            },
            "_config_path": path("config.yaml"),
            "http_api": {"password": "test-password",
                         "password_file": path("admin_password.txt")},
            "monitoring": {
                "extra_keywords": ["forbiddenword"],
                "alert_log_file": path("alerts.jsonl"),
            },
            "safe_search": {
                "google": True,
                "bing": True,
                "duckduckgo": True,
                "youtube": "strict",
            },
            "logs": {"query_log_file": path("queries.log")},
        }
        cls.resolver = FaithFilterResolver(cls.config, LOGGER)
        cls.server = DNSServer(cls.resolver, port=DNS_PORT, address="127.0.0.1",
                               logger=DNSLogger("-request,-reply,-truncated,-error", False))
        cls.server.start_thread()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cls.upstream.stop()
        shutil.rmtree(cls.tmp)

    def test_allowed_domain_forwards_upstream(self):
        reply = query("neutralsite.example")
        self.assertEqual(reply.header.rcode, RCODE.NOERROR)
        self.assertEqual(answer_ips(reply), [UPSTREAM_IP])

    def test_personal_blocklist_returns_nxdomain(self):
        reply = query("mybadsite.com")
        self.assertEqual(reply.header.rcode, RCODE.NXDOMAIN)

    def test_subdomain_of_blocked_domain_is_blocked(self):
        reply = query("cdn.static.mybadsite.com")
        self.assertEqual(reply.header.rcode, RCODE.NXDOMAIN)

    def test_ads_source_blocks_silently(self):
        before = len(self.resolver.alerts.read_since(
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(minutes=5)))
        reply = query("tracker.adnetwork.example")
        self.assertEqual(reply.header.rcode, RCODE.NXDOMAIN)
        after = len(self.resolver.alerts.read_since(
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(minutes=5)))
        self.assertEqual(before, after)

    def test_adult_source_blocks_and_alerts(self):
        reply = query("nasty-adult-site.example")
        self.assertEqual(reply.header.rcode, RCODE.NXDOMAIN)
        alerts = self.resolver.alerts.read_since(
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(minutes=5))
        self.assertTrue(any(a["domain"] == "nasty-adult-site.example"
                            and a["reason"] == "adult_domain" for a in alerts))

    def test_keyword_alerted_but_not_blocked(self):
        reply = query("my-forbiddenword-blog.example")
        self.assertEqual(reply.header.rcode, RCODE.NOERROR)
        self.assertEqual(answer_ips(reply), [UPSTREAM_IP])
        alerts = self.resolver.alerts.read_since(
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(minutes=5))
        self.assertTrue(any(a["detail"] == "forbiddenword" for a in alerts))

    def test_adult_keyword_alerts_on_unlisted_domain(self):
        query("random-porn-site.example")
        alerts = self.resolver.alerts.read_since(
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(minutes=5))
        self.assertTrue(any(a["domain"] == "random-porn-site.example"
                            and a["reason"] == "keyword" for a in alerts))

    def test_whitelist_bypasses_blocklist(self):
        # goodsite.com is whitelisted, so it forwards even if also blocked.
        reply = query("goodsite.com")
        self.assertEqual(answer_ips(reply), [UPSTREAM_IP])

    def test_google_safesearch_rewrite(self):
        # The safe host (forcesafesearch.google.com) is resolved through the
        # fake upstream, so the rewrite answer must be the upstream's IP.
        for name in ("www.google.com", "google.com", "google.co.uk"):
            reply = query(name)
            self.assertEqual(answer_ips(reply), [UPSTREAM_IP],
                             f"expected safe-search rewrite for {name}")

    def test_safesearch_falls_back_to_static_ip(self):
        from faithfilter import SafeSearchEngine
        engine = SafeSearchEngine({"safe_search": {"google": True}},
                                  lambda q: None, LOGGER)
        rule = engine.match("www.google.com")
        self.assertIsNotNone(rule)
        self.assertEqual(engine.resolve_target(rule), "216.239.38.120")

    def test_bing_and_duckduckgo_rewrites(self):
        # The fake upstream answers strict.bing.com etc. with UPSTREAM_IP,
        # which proves the safe host is resolved through upstream DNS.
        self.assertEqual(answer_ips(query("www.bing.com")), [UPSTREAM_IP])
        self.assertEqual(answer_ips(query("duckduckgo.com")), [UPSTREAM_IP])

    def test_youtube_strict_rewrite(self):
        reply = query("m.youtube.com")
        self.assertEqual(len(answer_ips(reply)), 1)

    def test_aaaa_suppressed_for_safesearch_domains(self):
        reply = query("www.google.com", "AAAA")
        self.assertEqual(reply.header.rcode, RCODE.NOERROR)
        self.assertEqual(len(reply.rr), 0)

    def test_report_includes_activity(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        alerts = self.resolver.alerts.read_since(now - datetime.timedelta(minutes=5))
        text = build_report(alerts, now - datetime.timedelta(days=7), now)
        self.assertIn("nasty-adult-site.example", text)

    def test_doh_canary_returns_nxdomain(self):
        for name in ("use-application-dns.net", "mask.icloud.com"):
            reply = query(name)
            self.assertEqual(reply.header.rcode, RCODE.NXDOMAIN, name)

    def test_bypass_domain_blocked_and_alerted(self):
        reply = query("client3.sneaky-vpn.example")
        self.assertEqual(reply.header.rcode, RCODE.NXDOMAIN)
        alerts = self.resolver.alerts.read_since(
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(minutes=5))
        self.assertTrue(any(a["reason"] == "bypass_attempt" for a in alerts))

    def test_cname_cloaking_blocked(self):
        # cloaked.example itself is unlisted, but the fake upstream answers
        # it with a CNAME to a blocked ad tracker.
        reply = query("cloaked.example")
        self.assertEqual(reply.header.rcode, RCODE.NXDOMAIN)

    def test_cache_serves_repeat_queries(self):
        before = self.resolver.cache.stats()["hits"]
        query("cache-me.example")
        query("cache-me.example")
        self.assertGreater(self.resolver.cache.stats()["hits"], before)

    def test_pause_override_blocks_everything(self):
        self.resolver.overrides.set("127.0.0.1", "pause", 60)
        try:
            reply = query("paused-while-testing.example")
            self.assertEqual(reply.header.rcode, RCODE.NXDOMAIN)
        finally:
            self.resolver.overrides.cancel("127.0.0.1")
        reply = query("resumed-after-testing.example")
        self.assertEqual(reply.header.rcode, RCODE.NOERROR)
        self.assertEqual(answer_ips(reply), [UPSTREAM_IP])

    def test_unfiltered_override_skips_blocklist(self):
        self.resolver.overrides.set("127.0.0.1", "unfiltered", 60)
        try:
            reply = query("mybadsite.com")
            self.assertEqual(reply.header.rcode, RCODE.NOERROR)
            self.assertEqual(answer_ips(reply), [UPSTREAM_IP])
        finally:
            self.resolver.overrides.cancel("127.0.0.1")
        reply = query("mybadsite.com")
        self.assertEqual(reply.header.rcode, RCODE.NXDOMAIN)


class ApiTests(unittest.TestCase):
    """Dashboard auth, DoH endpoint and backup, via the Flask test client."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()

        def path(name):
            return os.path.join(cls.tmp, name)

        with open(path("blocklist.txt"), "w") as f:
            f.write("mybadsite.com\n")
        with open(path("config.yaml"), "w") as f:
            f.write("# marker\n")
        cls.config = {
            "dns": {"upstream_dns": [], "forward_timeout": 1},
            "blocking": {"my_blocklist": path("blocklist.txt"),
                         "whitelist": path("whitelist.txt"),
                         "cache_dir": path("cache"), "sources": []},
            "monitoring": {"alert_log_file": path("alerts.jsonl")},
            "logs": {"query_log_file": None},
            "_config_path": path("config.yaml"),
            "http_api": {"password": "test-password",
                         "password_file": path("admin_password.txt")},
        }
        resolver = FaithFilterResolver(cls.config, LOGGER)
        reporter = Reporter(cls.config, resolver.alerts, LOGGER)
        cls.app = create_api_server(resolver, reporter, cls.config,
                                    None, LOGGER)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def setUp(self):
        # Fresh (unauthenticated) session per test.
        self.client = self.app.test_client()

    def login(self):
        return self.client.post("/login", data={"password": "test-password"})

    def test_api_requires_auth(self):
        self.assertEqual(self.client.get("/api/status").status_code, 401)
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)   # redirect to /login

    def test_wrong_password_rejected(self):
        response = self.client.post("/login", data={"password": "nope"})
        self.assertEqual(response.status_code, 401)

    def test_login_grants_access(self):
        self.assertEqual(self.login().status_code, 302)
        self.assertEqual(self.client.get("/api/status").status_code, 200)
        page = self.client.get("/")
        self.assertIn(b"FaithFilter dashboard", page.data)

    def test_doh_endpoint_is_open_and_filters(self):
        wire = faithfilter.DNSRecord.question("mybadsite.com", "A").pack()
        encoded = __import__("base64").urlsafe_b64encode(wire).decode().rstrip("=")
        response = self.client.get(f"/dns-query?dns={encoded}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content_type, "application/dns-message")
        reply = faithfilter.DNSRecord.parse(response.data)
        self.assertEqual(reply.header.rcode, RCODE.NXDOMAIN)

    def test_backup_returns_zip_with_lists(self):
        import zipfile as zf_mod
        self.login()
        response = self.client.get("/api/backup")
        self.assertEqual(response.status_code, 200)
        with zf_mod.ZipFile(__import__("io").BytesIO(response.data)) as zf:
            names = set(zf.namelist())
        self.assertIn("blocklist.txt", names)
        self.assertIn("config.yaml", names)

    def test_override_endpoints(self):
        self.login()
        response = self.client.post("/api/override", json={
            "client": "192.168.1.44", "mode": "pause", "minutes": 5})
        self.assertEqual(response.status_code, 200)
        listed = self.client.get("/api/overrides").get_json()
        self.assertTrue(any(o["client"] == "192.168.1.44" for o in listed))
        response = self.client.delete("/api/override/192.168.1.44")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.get("/api/overrides").get_json(), [])
        response = self.client.post("/api/override", json={
            "client": "x", "mode": "bogus"})
        self.assertEqual(response.status_code, 400)

    def test_clients_and_trends_endpoints(self):
        self.login()
        self.assertEqual(self.client.get("/api/trends").status_code, 200)
        self.assertEqual(self.client.get("/api/clients").status_code, 200)

    def test_status_reports_version(self):
        self.login()
        status = self.client.get("/api/status").get_json()
        self.assertEqual(status["version"], faithfilter.__version__)


if __name__ == "__main__":
    unittest.main(verbosity=2)
