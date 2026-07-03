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
import unittest

from dnslib import A, DNSRecord, QTYPE, RCODE, RR
from dnslib.server import BaseResolver, DNSLogger, DNSServer

import faithfilter
from faithfilter import (
    AlertLog, BlocklistManager, FaithFilterResolver, KeywordMonitor,
    build_report, parse_domain_lines,
)

UPSTREAM_PORT = 15353
DNS_PORT = 15354
UPSTREAM_IP = "10.99.99.99"  # what the fake upstream answers for everything

logging.basicConfig(level=logging.CRITICAL)
LOGGER = logging.getLogger("test")


class FakeUpstream(BaseResolver):
    """Answers every A query with UPSTREAM_IP."""

    def resolve(self, request, handler):
        reply = request.reply()
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
        self.assertIn("No adult-content or keyword alerts", text)

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
        self.assertIn("Total alerts: 3 (2 adult-domain, 1 keyword)", text)
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
                ],
            },
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
