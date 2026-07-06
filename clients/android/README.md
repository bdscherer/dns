# FaithFilter on Android

Android filters DNS **system-wide (Wi-Fi and cellular)** with its built-in
**Private DNS** — no app or root needed. This is the same mechanism NextDNS
and others use.

## Setup

1. Make sure the server is reachable as a **DoT endpoint**: a public
   hostname (`accountability.base_domain`), a valid TLS certificate
   (`dot.cert_file` / `dot.key_file`), `dot.enabled: true`, and port **853**
   forwarded. Android refuses self-signed certificates.
2. On the phone: **Settings → Network & internet → Private DNS**.
3. Choose **Private DNS provider hostname**.
4. Enter your hostname:
   - `dns.yourfamily.net` — filters the whole network's policy, **or**
   - `<token>.dns.yourfamily.net` — per-person (needs wildcard DNS + a
     wildcard/SAN certificate so the server can tell whose device it is).
     Copy the exact hostname from the dashboard (*Set up a device*).
5. Tap **Save**. Confirm it shows *Connected*.

## Lock it so it can't be turned off

Use **Google Family Link** on the child's account:

- Manage the device as a supervised account.
- Restrict changing network/Private DNS settings.

If Private DNS is removed anyway, the device stops sending queries to
FaithFilter and is flagged as a **dark device** in the accountability
report — so a bypass is visible, not silent.

## What Android can and can't do here

- **Can**: send every DNS query (all apps, cellular included) to
  FaithFilter, so blocking, safe-search enforcement and bypass detection all
  apply off your home network.
- **Can't**: Private DNS is DoT-hostname only — it can't carry a URL path
  token like the DoH endpoint. Per-person attribution therefore needs the
  token *subdomain* above (wildcard DNS + cert). For search-term visibility,
  add the browser extension (see [`../../extension/`](../../extension/)).

## A native app?

A dedicated Android app (a local VPN that applies policy on-device and shows
the child their own status) is on the roadmap but is a separate native
project with Play Store review and signing. Private DNS above already
delivers the core protection today without it.
