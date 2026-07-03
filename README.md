# FaithFilter

FaithFilter is a self-hosted DNS filtering service for families, schools and
small organisations. Point your router (or individual devices) at it as
their DNS server and it will:

- **Block individual sites you choose** — a simple personal blocklist file,
  editable by hand or through the HTTP API. Subdomains are blocked
  automatically.
- **Subscribe to blocklist sources** — any number of plain-text lists,
  **local files or online URLs**, in either one-domain-per-line or
  hosts-file (`0.0.0.0 domain`) format. Online sources are downloaded
  automatically, cached on disk, and refreshed on a schedule.
- **Block ads and trackers** — just another blocklist source with the
  category `ads` (the default config subscribes to the StevenBlack hosts
  list).
- **Monitor adult and adult-adjacent activity** — attempts to reach a
  domain on an `adult`-category list, or any domain containing a built-in
  adult keyword or **your own keywords**, are recorded as alerts.
- **E-mail you a weekly report** — a per-device summary of adult-content
  attempts and keyword hits, sent over SMTP on the day/hour you choose.
- **Enforce safe/restricted search** — Google SafeSearch (all regional
  domains), Bing strict mode, DuckDuckGo safe mode, YouTube
  moderate/strict Restricted Mode, and a generic `custom_rewrites`
  mechanism for **any other service** that offers a restricted DNS entry
  point. IPv6 (AAAA) answers for rewritten domains are suppressed so the
  enforcement cannot be bypassed over IPv6.
- **Manage everything over an optional HTTP API** — status, query log,
  alerts, list management, keyword management, report preview/send.

## Files

```
faithfilter.py       ← the whole service (DNS server, filters, e-mail, API)
config.yaml          ← main configuration (fully commented)
test_config.yaml     ← config for local testing on port 5353
blocklist.txt        ← your personal list of blocked sites
whitelist.txt        ← domains that must always resolve
keywords.txt         ← your monitored keywords (one per line)
test_faithfilter.py  ← offline test suite (python3 test_faithfilter.py)
requirements.txt     ← Python dependencies (dnslib, Flask, PyYAML)
```

## Quick start

```sh
apt update && apt install -y python3 python3-pip
pip3 install -r requirements.txt

# Edit config.yaml (see below), then:
sudo python3 faithfilter.py --config config.yaml
```

Then set your router's DHCP DNS option (or each device's DNS server) to the
machine running FaithFilter. Port 53 must be reachable from your clients
and requires root to bind.

> **Important:** make sure clients cannot simply switch to another DNS
> server. On most routers you can add a firewall rule that blocks outbound
> UDP/TCP port 53 (and port 853 for DNS-over-TLS) from the LAN except from
> the FaithFilter host, and disable/redirect DNS-over-HTTPS in browsers via
> policy where possible.

## Configuration overview

`config.yaml` is fully commented; the highlights:

### Blocking individual sites

Add domains to `blocklist.txt` (one per line), call
`POST /api/blocklist {"domain": "example.com"}`, or hit `/api/reload` after
editing the file. `whitelist.txt` overrides every blocklist.

### Blocklist sources (local or online)

```yaml
blocking:
  sources:
    - name: "adult-content"
      category: "adult"       # blocked AND reported weekly
      url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts"
    - name: "ads-and-trackers"
      category: "ads"         # blocked silently
      url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
    - name: "my-extra-list"
      category: "custom"
      file: "/etc/faithfilter/extra.txt"   # local file source
  refresh_hours: 24
```

Sources are re-downloaded every `refresh_hours` and cached in
`lists_cache/`, so a temporary outage never empties your blocklists.
Millions of entries are fine — lookups are hash-based.

### Monitoring and keywords

```yaml
monitoring:
  adult_keywords_enabled: true      # built-in adult keyword scan
  extra_keywords: ["casino"]        # your own keywords
  keywords_file: "keywords.txt"     # ...or keep them in a file
  keyword_exceptions: []            # suppress false positives
  block_keyword_matches: false      # false = record only, true = block too
```

A query triggers an alert when the domain is on an `adult` source, or when
it contains a monitored keyword. Alerts are throttled (one per
client/domain per 5 minutes) and stored in `logs/alerts.jsonl`.

### Weekly e-mail report

```yaml
email:
  enabled: true
  smtp_host: "smtp.gmail.com"
  smtp_port: 587
  use_tls: true
  username: "you@gmail.com"
  password_env: "FAITHFILTER_SMTP_PASSWORD"   # export before starting
  from: "FaithFilter <you@gmail.com>"
  to: ["you@gmail.com"]
  report_day: "sunday"
  report_hour: 8            # UTC
  send_if_empty: true
```

For Gmail, create an [App Password](https://myaccount.google.com/apppasswords)
and export it: `export FAITHFILTER_SMTP_PASSWORD='xxxx xxxx xxxx xxxx'`.
Preview the pending report at `GET /api/report/preview`, or send one
immediately with `python3 faithfilter.py --config config.yaml --send-report`
(or `POST /api/report/send`).

### Safe search / restricted mode

```yaml
safe_search:
  google: true         # SafeSearch VIP, covers google.com + regional TLDs
  bing: true           # strict.bing.com
  duckduckgo: true     # safe.duckduckgo.com
  youtube: "strict"    # "off" | "moderate" | "strict"
  custom_rewrites:     # any other service with a safe DNS endpoint
    - name: "pixabay"
      domains: ["pixabay.com", "www.pixabay.com"]
      target: "safesearch.pixabay.com"
      fallback_ip: "104.18.20.183"
```

The restricted endpoint is resolved through your upstream DNS and cached;
if resolution fails, the documented `fallback_ip` keeps enforcement
working.

## HTTP API

Enable under `http_api:` (bind it to `127.0.0.1` or set `api_key`, which
clients must send as an `X-API-Key` header).

| Endpoint | Method | Description |
|---|---|---|
| `/api/status` | GET | Stats, list sizes, active safe-search rules. |
| `/api/queries?limit=N` | GET | Recent queries (time, client, domain, action). |
| `/api/alerts?days=N` | GET | Monitoring alerts from the last N days (default 7). |
| `/api/blocklist` | GET/POST | View personal blocklist / add `{"domain": ...}`. |
| `/api/blocklist/<domain>` | DELETE | Remove from personal blocklist. |
| `/api/whitelist` | GET/POST | Same, for the whitelist. |
| `/api/whitelist/<domain>` | DELETE | Remove from whitelist. |
| `/api/keywords` | GET/POST | View monitored keywords / add `{"keyword": ...}`. |
| `/api/reload` | POST | Reload local files (blocklist, whitelist, keywords). |
| `/api/refresh` | POST | Re-download online sources now. |
| `/api/report/preview` | GET | Plain-text preview of the pending weekly report. |
| `/api/report/send` | POST | Send the report immediately. |

## How a query is handled

1. **Whitelist** — whitelisted domains (and subdomains) bypass every filter
   and are forwarded upstream.
2. **Safe search** — queries for enforced services are answered with the
   provider's restricted endpoint; AAAA queries return empty.
3. **Blocklists** — personal list and all sources, with subdomain matching.
   `adult`-category hits raise an alert; the client gets NXDOMAIN (or
   `0.0.0.0` with `block_response: zero_ip`).
4. **Keywords** — remaining domains are scanned for monitored keywords;
   matches raise an alert and are optionally blocked.
5. **Forward** — everything else goes to the upstream DNS servers.

Every query is logged to `logs/queries.log`.

## Running as a systemd service

`/etc/systemd/system/faithfilter.service`:

```ini
[Unit]
Description=FaithFilter DNS filtering service
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/faithfilter/faithfilter.py --config /opt/faithfilter/config.yaml
WorkingDirectory=/opt/faithfilter
Environment=FAITHFILTER_SMTP_PASSWORD=your-app-password
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now faithfilter.service
journalctl -u faithfilter -f
```

## Testing

```sh
python3 test_faithfilter.py          # offline suite, no internet needed
python3 faithfilter.py --config test_config.yaml   # manual run on :5353
dig @127.0.0.1 -p 5353 exampleadult1.com           # → NXDOMAIN
dig @127.0.0.1 -p 5353 www.google.com              # → SafeSearch VIP
```

## Notes and limitations

- DNS filtering works per-network; devices on cellular data or using
  hard-coded DoH resolvers bypass it. Combine with router firewall rules.
- Keyword scanning sees only *domain names*, not page content or search
  terms inside URLs.
- The alert log and query log are plain files; rotate them with logrotate
  if your network is busy.
