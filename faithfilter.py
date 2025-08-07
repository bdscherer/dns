#!/usr/bin/env python3
"""
FaithFilter DNS filtering service
--------------------------------

This script implements the core functionality of FaithFilter, a DNS
forwarder with built‑in content filtering.  It inspects incoming DNS
queries, blocks domains found in a configurable blocklist, enforces
Google SafeSearch by rewriting specific domains to Google's SafeSearch
VIP address, and can redirect YouTube traffic to Google’s restricted
servers to limit exposure to explicit videos.  Queries that do not
match any filtering rule are forwarded to upstream DNS servers and the
responses are relayed back to the client.

An optional HTTP API is provided for basic management tasks such as
viewing query logs and updating blocklists and whitelists.  Refer to
the README.md file for deployment instructions and further details.

Usage:

    python3 faithfilter.py --config config.yaml

This program requires the Python packages listed in requirements.txt
(dnslib, Flask, PyYAML).  See the accompanying documentation for
installation instructions.
"""

import argparse
import datetime
import logging
import os
import socket
import threading
import time
from typing import Dict, List, Optional, Tuple

import yaml
from dnslib import DNSRecord, QTYPE, RR, A, AAAA, RCODE
from dnslib.server import DNSServer, BaseResolver, DNSLogger

try:
    # Flask is optional; the service will still run in DNS‑only mode if
    # disabled via configuration.  Importing here allows us to avoid
    # raising ImportError when the HTTP API is disabled.
    from flask import Flask, jsonify, request
except ImportError:
    Flask = None  # type: ignore


def load_domains_from_file(path: str) -> List[str]:
    """Load domain list from a text file.

    Each non‑empty, non‑comment line is stripped of surrounding whitespace
    and converted to lowercase.  Returns a list of domains.  If the file
    does not exist, returns an empty list.
    """
    domains: List[str] = []
    if not path:
        return domains
    if not os.path.exists(path):
        return domains
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip().lower()
            if not line or line.startswith("#"):
                continue
            domains.append(line)
    return domains


class FaithFilterResolver(BaseResolver):
    """Custom DNS resolver implementing block/whitelist and rewriting rules."""

    def __init__(self, config: Dict, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.blocklist: List[str] = []
        self.whitelist: List[str] = []
        self.stats: Dict[str, int] = {
            "total_queries": 0,
            "blocked": 0,
            "safe_search": 0,
            "youtube_rewrite": 0,
        }
        # In‑memory log of recent queries for API consumption
        self.recent_queries: List[Dict] = []
        # Load lists initially
        self.reload_lists()

    def reload_lists(self) -> None:
        """Reload blocklist and whitelist from files specified in config."""
        blocklist_path = self.config.get("blocklist", {}).get("file")
        whitelist_path = self.config.get("whitelist", {}).get("file")
        self.blocklist = load_domains_from_file(blocklist_path)
        self.whitelist = load_domains_from_file(whitelist_path)
        self.logger.info(
            "Loaded %d blocklist entries and %d whitelist entries",
            len(self.blocklist),
            len(self.whitelist),
        )

    def _is_listed(self, domain: str, lst: List[str]) -> bool:
        """Check if domain or any parent domain is in list."""
        domain = domain.lower()
        parts = domain.split(".")
        for i in range(len(parts)):
            candidate = ".".join(parts[i:])
            if candidate in lst:
                return True
        return False

    def is_whitelisted(self, domain: str) -> bool:
        return self._is_listed(domain, self.whitelist)

    def is_blocked(self, domain: str) -> bool:
        return self._is_listed(domain, self.blocklist)

    def log_query(self, client_ip: str, domain: str, action: str) -> None:
        """Append query information to log file and in‑memory list."""
        timestamp = datetime.datetime.utcnow().isoformat() + "Z"
        log_entry = {
            "time": timestamp,
            "client": client_ip,
            "domain": domain,
            "action": action,
        }
        # Append to in‑memory log (keep only last 1000)
        self.recent_queries.append(log_entry)
        if len(self.recent_queries) > 1000:
            self.recent_queries.pop(0)
        # Append to file
        log_file = self.config.get("logs", {}).get("query_log_file")
        if log_file:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"{timestamp} {client_ip} {domain} {action}\n")

    def _forward_query(self, request: DNSRecord) -> Optional[DNSRecord]:
        """Forward query to upstream DNS servers and return response."""
        query_data = request.pack()
        upstreams = self.config.get("dns", {}).get("upstream_dns", [])
        timeout = self.config.get("dns", {}).get("forward_timeout", 5)
        for upstream in upstreams:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(timeout)
                s.sendto(query_data, (upstream, 53))
                data, _ = s.recvfrom(4096)
                s.close()
                return DNSRecord.parse(data)
            except Exception as e:
                self.logger.warning("Forwarding to %s failed: %s", upstream, e)
                continue
        return None

    def _build_response(self, request: DNSRecord, ip: str) -> DNSRecord:
        """Construct a DNS response with an A or AAAA record pointing to ip."""
        reply = request.reply()
        q = request.q
        # Determine record type: respond with A for IPv4 addresses, AAAA for IPv6
        record_type = A if ":" not in ip else AAAA
        reply.add_answer(RR(rname=q.qname, rtype=QTYPE.A if record_type == A else QTYPE.AAAA,
                            rclass=1, ttl=60, rdata=record_type(ip)))
        return reply

    def resolve(self, request: DNSRecord, handler: object) -> DNSRecord:
        """
        Resolve DNS queries according to block/whitelist and rewriting rules.

        This method is called by dnslib for each incoming query.  It returns
        a DNSRecord containing the response.  Errors are signalled via
        NXDOMAIN (RCODE=3) when a domain is blocked.
        """
        self.stats["total_queries"] += 1
        qname = str(request.q.qname).rstrip(".").lower()
        client_ip = handler.client_address[0] if hasattr(handler, "client_address") else "unknown"

        # Check whitelist: if domain or parent is whitelisted, bypass other checks
        if self.is_whitelisted(qname):
            self.logger.debug("%s is whitelisted", qname)
            self.log_query(client_ip, qname, "whitelisted")
            resp = self._forward_query(request)
            if resp:
                return resp
            # Fallback NXDOMAIN if upstream fails
            return request.reply(rcode=RCODE.SERVFAIL)

        # Enforce Google SafeSearch if enabled
        if self.config.get("dns", {}).get("safe_search", False):
            # Apply to common google search domains; include ccTLDs if needed
            google_domains = [
                "www.google.com", "google.com", "www.google.", "google.",
            ]
            # If query domain exactly matches or is subdomain of google.* domain
            if qname == "google.com" or qname.endswith(".google.com") or qname.startswith("google.") or qname.startswith("www.google."):
                # Use SafeSearch VIP IP (216.239.38.120) as documented by Google
                safe_ip = "216.239.38.120"
                self.stats["safe_search"] += 1
                self.log_query(client_ip, qname, "safe_search")
                self.logger.debug("Rewriting %s to SafeSearch VIP %s", qname, safe_ip)
                return self._build_response(request, safe_ip)

        # Enforce YouTube restriction if configured
        youtube_mode = self.config.get("dns", {}).get("youtube_mode", "off").lower()
        if youtube_mode in ("moderate", "strict"):
            youtube_domains = [
                "youtube.com", "www.youtube.com", "m.youtube.com",
                "youtubei.googleapis.com", "youtube.googleapis.com",
                "www.youtube-nocookie.com",
            ]
            for yd in youtube_domains:
                if qname == yd or qname.endswith("." + yd):
                    # Map to restrictmoderate or restrict IPs
                    if youtube_mode == "moderate":
                        youtube_ip = "216.239.38.119"
                    else:  # strict
                        youtube_ip = "216.239.38.120"
                    self.stats["youtube_rewrite"] += 1
                    self.log_query(client_ip, qname, f"youtube_{youtube_mode}")
                    self.logger.debug("Rewriting %s to YouTube restricted IP %s", qname, youtube_ip)
                    return self._build_response(request, youtube_ip)

        # Block domains in blocklist
        if self.is_blocked(qname):
            self.stats["blocked"] += 1
            self.log_query(client_ip, qname, "blocked")
            self.logger.debug("Blocking domain %s", qname)
            # Return NXDOMAIN or 0.0.0.0; NXDOMAIN is more standards compliant
            reply = request.reply()
            reply.header.rcode = RCODE.NXDOMAIN
            return reply

        # Otherwise, forward to upstream DNS servers
        self.log_query(client_ip, qname, "allowed")
        resp = self._forward_query(request)
        if resp:
            return resp
        # If forwarding fails, return SERVFAIL
        return request.reply(rcode=RCODE.SERVFAIL)


def start_dns_server(resolver: FaithFilterResolver, config: Dict) -> DNSServer:
    """Start the DNS server and return the DNSServer instance."""
    listen_ip = config.get("dns", {}).get("listen_ip", "0.0.0.0")
    listen_port = int(config.get("dns", {}).get("listen_port", 53))
    # Use a quiet DNSLogger to avoid printing each query to stdout (we log manually)
    dns_logger = DNSLogger("", False)
    server = DNSServer(resolver, port=listen_port, address=listen_ip, logger=dns_logger)
    server.start_thread()
    return server


def create_api_server(resolver: FaithFilterResolver, config: Dict):
    """Instantiate and configure the Flask API server."""
    app = Flask(__name__)

    @app.route("/api/status")
    def status():
        """Return basic service statistics."""
        return jsonify({
            "stats": resolver.stats,
            "blocklist_count": len(resolver.blocklist),
            "whitelist_count": len(resolver.whitelist),
        })

    @app.route("/api/queries")
    def queries():
        """Return recent query log entries."""
        limit = int(request.args.get("limit", 100))
        return jsonify(resolver.recent_queries[-limit:])

    @app.route("/api/blocklist", methods=["GET", "POST"])
    def blocklist_route():
        if request.method == "GET":
            return jsonify(resolver.blocklist)
        data = request.get_json(silent=True) or {}
        domain = (data.get("domain") or "").strip().lower()
        if not domain:
            return jsonify({"error": "domain is required"}), 400
        if domain not in resolver.blocklist:
            resolver.blocklist.append(domain)
            # Persist to file
            bl_file = config.get("blocklist", {}).get("file")
            if bl_file:
                os.makedirs(os.path.dirname(bl_file), exist_ok=True)
                with open(bl_file, "a", encoding="utf-8") as f:
                    f.write(f"{domain}\n")
        return jsonify({"added": domain})

    @app.route("/api/blocklist/<domain>", methods=["DELETE"])
    def remove_from_blocklist(domain):
        domain = domain.strip().lower()
        if domain in resolver.blocklist:
            resolver.blocklist.remove(domain)
            # Rewrite the blocklist file with remaining entries
            bl_file = config.get("blocklist", {}).get("file")
            if bl_file:
                os.makedirs(os.path.dirname(bl_file), exist_ok=True)
                with open(bl_file, "w", encoding="utf-8") as f:
                    for d in resolver.blocklist:
                        f.write(f"{d}\n")
            return jsonify({"removed": domain})
        return jsonify({"error": "domain not found"}), 404

    @app.route("/api/whitelist", methods=["GET", "POST"])
    def whitelist_route():
        if request.method == "GET":
            return jsonify(resolver.whitelist)
        data = request.get_json(silent=True) or {}
        domain = (data.get("domain") or "").strip().lower()
        if not domain:
            return jsonify({"error": "domain is required"}), 400
        if domain not in resolver.whitelist:
            resolver.whitelist.append(domain)
            wl_file = config.get("whitelist", {}).get("file")
            if wl_file:
                os.makedirs(os.path.dirname(wl_file), exist_ok=True)
                with open(wl_file, "a", encoding="utf-8") as f:
                    f.write(f"{domain}\n")
        return jsonify({"added": domain})

    @app.route("/api/whitelist/<domain>", methods=["DELETE"])
    def remove_from_whitelist(domain):
        domain = domain.strip().lower()
        if domain in resolver.whitelist:
            resolver.whitelist.remove(domain)
            wl_file = config.get("whitelist", {}).get("file")
            if wl_file:
                os.makedirs(os.path.dirname(wl_file), exist_ok=True)
                with open(wl_file, "w", encoding="utf-8") as f:
                    for d in resolver.whitelist:
                        f.write(f"{d}\n")
            return jsonify({"removed": domain})
        return jsonify({"error": "domain not found"}), 404

    @app.route("/api/reload", methods=["POST"])
    def reload_lists():
        """Reload blocklist and whitelist from disk."""
        resolver.reload_lists()
        return jsonify({"reloaded": True})

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="FaithFilter DNS filtering service")
    parser.add_argument("--config", required=True, help="Path to YAML configuration file")
    args = parser.parse_args()

    # Read configuration
    with open(args.config, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

    # Set up logging
    log_level_name = config.get("logs", {}).get("log_level", "INFO")
    logging.basicConfig(level=getattr(logging, log_level_name.upper(), logging.INFO),
                        format="%(asctime)s [%(levelname)s] %(message)s")
    logger = logging.getLogger("FaithFilter")

    # Create resolver
    resolver = FaithFilterResolver(config, logger)

    # Start DNS server
    dns_server = start_dns_server(resolver, config)
    logger.info("FaithFilter DNS server listening on %s:%s", config.get("dns", {}).get("listen_ip", "0.0.0.0"), config.get("dns", {}).get("listen_port", 53))

    # If API is enabled and Flask is available, start HTTP server in separate thread
    if config.get("http_api", {}).get("enable", False):
        if Flask is None:
            logger.error("Flask is not installed but http_api.enable is true. Install Flask or disable the API.")
        else:
            app = create_api_server(resolver, config)
            host = config.get("http_api", {}).get("host", "127.0.0.1")
            port = int(config.get("http_api", {}).get("port", 5000))
            api_thread = threading.Thread(target=app.run, kwargs={"host": host, "port": port}, daemon=True)
            api_thread.start()
            logger.info("FaithFilter HTTP API server listening on %s:%s", host, port)

    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down FaithFilter")
        dns_server.stop()


if __name__ == "__main__":
    main()