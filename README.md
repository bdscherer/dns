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
- **Resist bypass attempts** — a built-in blocklist of DNS-over-HTTPS
  resolvers, VPNs and proxies (hits raise a `bypass_attempt` alert),
  NXDOMAIN for the Firefox DoH and iCloud Private Relay canary domains,
  and CNAME-cloaking detection that blocks domains whose CNAME chain leads
  to a blocked tracker.
- **Web dashboard** — password-protected (a password is auto-generated on
  first run): live stats, recent queries and alerts, list and keyword
  management, unblock requests, backup download, test e-mail. The JSON API
  behind it requires the same login (or an `X-API-Key`).
- **Per-device policies** — group devices by IP/CIDR; per group: full
  filtering, monitor-only, or unfiltered; safe search on/off; and
  **curfews** that block all internet access during set hours (may cross
  midnight).
- **Block page** — optionally answer blocked domains with a friendly
  "site blocked" page including an unblock-request form (requests show up
  on the dashboard and can e-mail you).
- **Instant + failure alerts** — optional immediate e-mail when a device
  hits adult content or a bypass service (throttled per device), a warning
  when blocklist downloads keep failing, an optional service-start notice,
  and a health section in every weekly report.
- **Fast and outage-proof** — DNS responses are cached for their TTL and
  served stale if every upstream is down; query and alert logs rotate by
  size automatically.
- **DNS-over-HTTPS / DNS-over-TLS service** — an RFC 8484 `/dns-query`
  endpoint and an optional DoT listener (Android "Private DNS"), so phones
  can keep using the filter even away from home (requires a certificate).
- **Device names** — map IPs to friendly names ("Emma's iPad") shown in
  reports, alerts and the dashboard.
- **Pause & bonus time** — one-click dashboard buttons to pause a device's
  internet or grant temporary unfiltered time, with automatic expiry
  (persisted across restarts).
- **Privacy-aware retention** — rotated query logs, alerts and unblock
  requests are auto-deleted after a configurable age; browsing history is
  not hoarded forever.
- **Trends** — per-day, per-device statistics (SQLite) with a dashboard
  trends view and week-over-week comparisons in the report.
- **Update awareness** — checks GitHub daily for a newer release and says
  so on the dashboard and in the weekly report (never auto-installs).
- **Secondary-server sync** — run a second FaithFilter (e.g. a Raspberry
  Pi) as DNS 2; follower mode pulls the primary's lists automatically so
  both enforce the same rules.

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

## Standalone executable (no Python required)

Every push to `main` builds self-contained executables via GitHub Actions
(`.github/workflows/build.yml`): `faithfilter.exe` **plus the windowed
`faithfilter-gui.exe` Control Panel** for Windows, and `faithfilter` for
Linux x64 and Linux ARM64 (Raspberry Pi 64-bit OS).
Download them from the repository's **Actions** tab (workflow artifacts) or,
for tagged releases (`git tag v1.0 && git push --tags`), from the
**Releases** page. Each artifact contains the executable plus template
`config.yaml`, `blocklist.txt`, `whitelist.txt` and `keywords.txt`.

**The executable is fully self-contained — no configuration files are
required.** All defaults (adult + ads blocklists, safe search, YouTube
strict, localhost API) are built in, and on first run it creates its own
`blocklist.txt`, `whitelist.txt` and `keywords.txt` next to itself:

```sh
sudo ./faithfilter                 # Linux
faithfilter.exe                    # Windows (run as Administrator)
```

To configure e-mail reports and other personal settings, run the built-in
wizard once — it asks a few questions and writes a minimal `config.yaml`
for you:

```sh
sudo ./faithfilter --setup         # or: faithfilter.exe --setup
```

If a `config.yaml` exists next to the executable it is merged over the
built-in defaults, so it only ever needs to contain the settings you
changed (the repository's `config.yaml` documents every available option).
Relative paths resolve against the executable's folder, so everything stays
in the install directory even when launched as a service.

To build one yourself instead (must be built on the OS you target —
PyInstaller does not cross-compile):

```sh
pip3 install -r requirements.txt pyinstaller
pyinstaller --onefile --name faithfilter faithfilter.py
# result: dist/faithfilter (or dist\faithfilter.exe on Windows)
```

### Windows: the Control Panel (recommended)

The Windows download includes **`faithfilter-gui.exe`** — a normal windowed
app (no console/"DOS" window) that configures and runs everything for you.
`faithfilter.exe` next to it is the background service the GUI launches;
you don't need to touch it directly.

1. Extract the zip to `C:\FaithFilter`.
2. **Right-click `faithfilter-gui.exe` → Run as administrator** (port 53
   needs admin; if you forget, the panel offers to relaunch elevated).
3. Fill in the tabs — Network, Blocking, Monitoring, Safe Search, Email,
   Alerts, Devices, Advanced — then click **Start service**. Settings are
   saved to `config.yaml`; **Open dashboard** shows live activity, and the
   **Status & Log** tab streams what the service is doing.

The GUI covers every configuration option. To have it start with Windows,
either tick nothing and leave the window open, or install the service to
run at boot with `faithfilter.exe --install-service` (the GUI can still
attach to view status).

On Linux/macOS the same panel runs with `python3 faithfilter_gui.py`
(needs Tk: `sudo apt install python3-tk`).

### Running the service directly (headless / Linux)

1. Extract the zip and (optionally) run `faithfilter.exe --setup` in a
   terminal to configure e-mail reports.
2. Port 53 must be free: if the **Internet Connection Sharing (ICS)**
   service is running, stop and disable it (`services.msc`).
3. Allow DNS through the firewall (admin prompt):
   ```bat
   netsh advfirewall firewall add rule name="FaithFilter DNS UDP" dir=in action=allow protocol=UDP localport=53
   netsh advfirewall firewall add rule name="FaithFilter DNS TCP" dir=in action=allow protocol=TCP localport=53
   ```
4. Test by double-clicking `faithfilter.exe` (or run it in an
   Administrator terminal to see the log output).
5. To run it permanently as a Windows service, use
   [NSSM](https://nssm.cc/): `nssm install FaithFilter C:\FaithFilter\faithfilter.exe`,
   then in the NSSM dialog set the startup directory to `C:\FaithFilter`
   and add `FAITHFILTER_SMTP_PASSWORD=<app password>` under
   *Environment* (or put a literal `password:` in `config.yaml` and
   restrict the file's permissions).

Then set your router's DHCP DNS option (or each device's DNS server) to the
machine running FaithFilter. Port 53 must be reachable from your clients
and requires root to bind.

> **Important:** make sure clients cannot simply switch to another DNS
> server. On most routers you can add a firewall rule that blocks outbound
> UDP/TCP port 53 (and port 853 for DNS-over-TLS) from the LAN except from
> the FaithFilter host, and disable/redirect DNS-over-HTTPS in browsers via
> policy where possible.

## Configuration overview

Every setting has a built-in default (see `DEFAULT_CONFIG` in
`faithfilter.py`), so `config.yaml` is optional and only needs the keys you
want to change. The repository's `config.yaml` is a fully commented
reference of every option; the highlights:

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

## Dashboard and HTTP API

Browse to `http://<server>:5000` and sign in. The password comes from
`http_api.password`, or — if left empty — is **auto-generated on first run**
and stored in `admin_password.txt` next to the config (the log says where).
Set `http_api.host: "0.0.0.0"` to reach the dashboard from other devices on
your LAN.

The dashboard shows live stats, recent queries and alerts, manages the
blocklist/whitelist/keywords, lists unblock requests (one click to
whitelist), downloads backups, refreshes sources and sends a test e-mail.

The JSON API requires either a logged-in session or an `X-API-Key` header
(`http_api.api_key`):

| Endpoint | Method | Description |
|---|---|---|
| `/api/status` | GET | Stats, list sizes, cache stats, refresh health. |
| `/api/health` | GET | Plain-text health summary. |
| `/api/queries?limit=N` | GET | Recent queries (time, client, domain, action). |
| `/api/alerts?days=N` | GET | Monitoring alerts from the last N days (default 7). |
| `/api/blocklist` | GET/POST | View personal blocklist / add `{"domain": ...}`. |
| `/api/blocklist/<domain>` | DELETE | Remove from personal blocklist. |
| `/api/whitelist` | GET/POST | Same, for the whitelist. |
| `/api/whitelist/<domain>` | DELETE | Remove from whitelist. |
| `/api/keywords` | GET/POST | View monitored keywords / add `{"keyword": ...}`. |
| `/api/unblock-requests` | GET | Unblock requests submitted via the block page. |
| `/api/reload` | POST | Reload local files (blocklist, whitelist, keywords). |
| `/api/refresh` | POST | Re-download online sources now. |
| `/api/report/preview` | GET | Plain-text preview of the pending weekly report. |
| `/api/report/send` | POST | Send the report immediately. |
| `/api/test-email` | POST | Send a test e-mail to verify SMTP settings. |
| `/api/backup` | GET | Download config + lists as a zip. |
| `/api/restore` | POST | Restore from a backup zip (multipart field `backup`). |
| `/api/clients` | GET | Devices seen recently: names, today's counters, overrides. |
| `/api/trends?days=N` | GET | Per-day, per-device statistics (default 30 days). |
| `/api/overrides` | GET | Active pause/unfiltered overrides. |
| `/api/override` | POST | `{"client": ip, "mode": "pause"\|"unfiltered", "minutes": N}`. |
| `/api/override/<client>` | DELETE | Cancel a device's override ("resume"). |
| `/dns-query` | GET/POST | DNS-over-HTTPS (RFC 8484); no auth required. |

## How a query is handled

1. **Device policy** — the client's group decides everything that follows:
   `off` forwards immediately, `monitor_only` records but never blocks,
   `full` (default) blocks and records. An active **curfew** blocks the
   query outright.
2. **Canaries** — `use-application-dns.net` and the iCloud Private Relay
   hosts get NXDOMAIN so devices keep using this resolver.
3. **Whitelist** — whitelisted domains (and subdomains) bypass every filter
   and are forwarded upstream.
4. **Safe search** — queries for enforced services are answered with the
   provider's restricted endpoint; AAAA queries return empty.
5. **Blocklists** — personal list (plain domains, `*wildcards*` and
   `/regex/` rules) and all sources, with subdomain matching. `adult` and
   `bypass` hits raise alerts; the client gets NXDOMAIN, `0.0.0.0`, or the
   block page depending on configuration.
6. **Keywords** — remaining domains are scanned for monitored keywords;
   matches raise an alert and are optionally blocked.
7. **Forward + CNAME check** — everything else is answered from the TTL
   cache or the upstream servers (stale cache entries are served if all
   upstreams are down), and responses whose CNAME chain leads to a blocked
   domain are blocked.

Every query is logged to `logs/queries.log` (rotated by size).

## Per-device policies, curfews and the block page

Give the kids' devices DHCP reservations on your router, name them, then
group them:

```yaml
clients:
  names:
    "192.168.1.20": "Emma's iPad"
    "192.168.1.10": "Dad's laptop"
  groups:
    - name: "kids"
      members: ["192.168.1.20", "192.168.1.21"]
      filtering: "full"
      safe_search: true
      curfew:
        - days: ["sun", "mon", "tue", "wed", "thu"]
          from: "21:30"
          to: "06:30"
    - name: "parents"
      members: ["192.168.1.10"]
      filtering: "off"

block_page:
  enabled: true      # blocked sites show a "site blocked" page with an
  port: 80           # unblock-request form instead of a dead connection
```

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

## Second server on a Raspberry Pi (no single point of failure)

If the FaithFilter box dies, home DNS dies with it. The fix is a cheap
second server — a **Raspberry Pi Zero 2 W** (~$15) is plenty — handed out
as DNS 2 by the router. Follower mode keeps its lists identical to the
primary automatically.

1. **On the primary**, set an API key in `config.yaml` and restart:
   ```yaml
   http_api:
     host: "0.0.0.0"          # the Pi must be able to reach it
     api_key: "pick-a-long-random-string"
   ```
2. **Flash the Pi** with Raspberry Pi OS Lite **64-bit** (Zero 2 W, Pi 3/4/5).
   Give it a static IP / DHCP reservation (example: `192.168.1.54`).
3. **Install FaithFilter on the Pi** — either download the
   `faithfilter-linux-arm64` build:
   ```sh
   sudo mkdir -p /opt/faithfilter && cd /opt/faithfilter
   # copy the 'faithfilter' binary here, then:
   sudo chmod +x faithfilter
   ```
   or, on a 32-bit original Pi Zero/Pi 1 (ARMv6 — no prebuilt binary), run
   from source instead:
   ```sh
   sudo apt install -y python3-pip git
   git clone https://github.com/bdscherer/dns.git /opt/faithfilter
   pip3 install -r /opt/faithfilter/requirements.txt
   ```
4. **Configure the Pi as a follower** — `/opt/faithfilter/config.yaml`:
   ```yaml
   sync:
     enabled: true
     primary_url: "http://192.168.1.53:5000"   # the primary's dashboard
     api_key: "pick-a-long-random-string"      # same value as step 1
     interval_minutes: 60
   email:
     enabled: false        # only the primary sends reports/alerts
   ```
   Blocklist *sources* download independently on the Pi; the sync pulls
   your personal blocklist, whitelist and keywords so edits on the
   primary's dashboard reach the Pi within the hour. Client groups and
   curfews live in `config.yaml` — copy that section over once, or set
   `include_config: true` to mirror the whole config (the follower
   automatically re-applies its own `sync:` section after each pull so
   the mirroring can't disable itself).
5. **Free port 53 and install the service** (same as the primary):
   ```sh
   sudo ./faithfilter --install-service      # or via python3 faithfilter.py
   ```
6. **On the router**, set **DNS 1** = primary IP, **DNS 2** = Pi IP.
   Devices will use the Pi automatically whenever the primary is down —
   and it enforces the same rules, so an outage never becomes an
   unfiltered window.

## Installing as a service in one command

```sh
sudo ./faithfilter --install-service      # Linux: systemd unit, enabled + started
faithfilter.exe --install-service        # Windows (admin): boot-time Scheduled Task
```

## Notes and limitations

- The bypass blocklist, canary NXDOMAINs and CNAME checks make evasion much
  harder, but a determined user with a device you don't control can still
  hard-code an IP or use cellular data. Router firewall rules that force
  LAN port 53/853 through this server remain worthwhile.
- Keyword scanning sees only *domain names*, not page content or search
  terms inside URLs.
- The block page can't suppress the browser certificate warning on HTTPS
  sites — that is inherent to DNS-level blocking.
- Serving DoH/DoT to phones outside your network requires a public
  hostname with a real TLS certificate (e.g. Let's Encrypt) and forwarding
  the relevant ports; keep the dashboard itself off the public internet.
