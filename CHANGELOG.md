# Changelog

All notable changes to FaithFilter are documented here. The project follows
[semantic versioning](https://semver.org/).

## [2.3.0]

Per-device protection so the filter follows a person onto cellular.

### Added
- **Per-person device endpoints**: each person gets a stable token and a
  personal DoH endpoint `https://<base_domain>/p/<token>/dns-query`. Queries
  through it are attributed to that person's accountability report even when
  the device is off the home network (e.g. a phone on cellular).
- **Device profile generator** for Apple (`.mobileconfig`), Android (Private
  DNS card), Windows (DoH PowerShell) and Linux (systemd-resolved DoT), with
  a dashboard "Set up a device" panel and `/api/devices` endpoints.
- **Production client installers** under `clients/`:
  `windows/setup-faithfilter.ps1`, `linux/setup-faithfilter.sh`, and an
  Android Private DNS guide, each with lock-down guidance.
- DoT **SNI-based attribution**: a per-person subdomain
  (`<token>.<base_domain>`) maps the Android Private DNS connection to the
  right person.
- `accountability.base_domain` config and a stable `device_tokens_file`.

### Fixed
- The SERVFAIL fallback used an unsupported `reply(rcode=...)` call and would
  raise if every upstream failed; it now returns SERVFAIL correctly.

## [2.2.0]

First public release under the AGPL-3.0 license.

### Added
- **Accountability-partner layer**: assign people → devices → allies; each
  ally receives that person's weekly report (category breakdown, time-of-day
  pattern, clean streak, evasion attempts, tamper log, search terms) and
  instant alerts. Network-layer accountability with no device slowdown.
- **Browser extension** (`extension/`, Manifest V3) reporting search terms
  and visited hostnames to `/api/extension/events` — the visibility DNS
  alone can't provide, with no VPN and no screenshots.
- **Audit/tamper log** and **dark-device detection** (a monitored device
  that stops appearing in DNS).
- **Native Windows GUI Control Panel** (`faithfilter-gui.exe`): every
  setting in a real window, starts/stops the service hidden — no console.
- Content **category classifier** (adult/gambling/dating/social/…) and
  hour-of-day statistics.
- API: `/api/people`, `/api/audit`, `/api/searches`,
  `/api/accountability/preview`, `/api/extension/events`.

### Security
- Escape the block-page `Host` header (reflected-XSS fix).
- Constant-time comparison for the API and extension keys.
- Extension endpoint now requires a key whenever it is enabled.
- Hardened session cookies (HttpOnly, SameSite=Lax, Secure under HTTPS),
  request-size cap, and a warning when the dashboard is exposed over plain
  HTTP.

## [2.1.0]

### Added
- Device names, temporary pause / bonus-time overrides with expiry.
- Long-term statistics (SQLite) with a dashboard trends view and
  week-over-week report lines.
- Daily data-retention purge for logs, alerts and stats.
- Daily GitHub release update check.
- Secondary-server follower sync (run a Raspberry Pi as DNS 2).

## [2.0.0]

### Added
- Categorized blocklist sources (local files or online URLs) with
  auto-refresh and disk caching; hosts-file and plain-domain formats.
- Ad/tracker blocking, DoH/VPN/proxy bypass blocking, browser DoH canaries,
  and CNAME-cloaking detection.
- Multi-provider safe search (Google, Bing, DuckDuckGo, YouTube) plus custom
  rewrites; adult/keyword monitoring with weekly e-mail reports and instant
  alerts.
- Password-protected dashboard and JSON API; per-device policy groups and
  curfews; block page with unblock requests.
- DNS cache with serve-stale, log rotation, TCP listener, DoH endpoint and
  DoT listener, one-command service install, backup/restore.
- Standalone executables (Windows, Linux x64, Linux ARM64), a `--setup`
  wizard, and built-in default configuration.
