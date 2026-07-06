# Per-device protection for families without a home server

The main FaithFilter setup is **network-wide**: one box (a PC, a Raspberry
Pi) filters every device on the home Wi-Fi. That's the most complete option,
but it assumes someone can run a small server and change the router's DNS.

Many families can't or won't do that. This document is the plan for
**protecting individual devices** — a kid's phone, a laptop — **without a
home server, and even when the device leaves the house.** It covers what
exists today, what's buildable, and a recommended path.

---

## The core problem

A phone on cellular data never touches your home network, so home DNS
filtering doesn't apply. To follow a device everywhere you need the filtering
to be configured **on the device itself**, in a way the user can't trivially
switch off. Every option below is a different answer to "how do we point this
one device at a filter and keep it there."

There are three layers, best used together:

1. **A filtering DNS profile on the device** (the "what can it reach" layer).
2. **OS parental controls** locking that profile in place (the "can't turn
   it off" layer).
3. **Accountability reporting** so a partner sees activity (the "someone
   knows" layer).

---

## Layer 1 — Put a filtering resolver on the device

Modern phones and laptops can be told to send **all** their DNS to an
encrypted resolver (DNS-over-TLS / DNS-over-HTTPS), on Wi-Fi *and* cellular.
That resolver is your FaithFilter, reached from anywhere.

| Platform | Mechanism | Works on cellular? |
|---|---|---|
| **Android 9+** | Settings → Network → **Private DNS** → hostname | ✅ yes |
| **iOS / iPadOS** | Install a **DNS configuration profile** (.mobileconfig) | ✅ yes |
| **Windows 11** | Settings → DNS over HTTPS | Wi-Fi/ethernet |
| **macOS** | DNS profile (.mobileconfig) | ✅ yes |
| **Any browser** | Secure DNS (DoH) setting | that browser only |

For this to work, your FaithFilter must be reachable from the internet as a
DoH/DoT endpoint with a **real TLS certificate** for a hostname (e.g.
`dns.yourfamily.net`). FaithFilter already serves DoH (`/dns-query`) and DoT
(port 853) — see the DoH/DoT section in the main README. Practically that
means: a domain name, a dynamic-DNS record or static IP to your home, port
forwarding for 443/853, and a Let's Encrypt certificate.

> **Honest caveat:** exposing your home server to the internet is a step up
> in responsibility (keep it patched; keep the dashboard off the public
> side). Families who don't want to do this are exactly who the future
> **hosted service** is for — same device profiles, but pointed at a managed
> endpoint instead of your house.

### The easy button we can build: a profile generator

The friction above is "create a correct DNS profile." That's automatable.
**Planned feature:** a dashboard page that generates, for a chosen person:

- an **Android** Private DNS hostname to paste in, and
- a downloadable **Apple `.mobileconfig`** and **Windows** setup,

each pre-filled with that family's DoH/DoT endpoint and the person's token,
so setup is "open this link on the phone, tap install." This turns Layer 1
from a sysadmin task into a two-minute step. (Tracked in the roadmap below.)

---

## Layer 2 — Lock it so it can't be switched off

A DNS profile the user can delete isn't accountability. The device's own
parental-control system is what makes it stick — and it's free:

- **Apple Screen Time** (iOS/macOS): turn on **Content & Privacy
  Restrictions**, then *Don't Allow Changes* for VPN/DNS/Profiles. Removing a
  configuration profile then requires the Screen Time passcode (the parent's,
  not the child's). This is the key that keeps the DNS profile installed.
- **Android — Family Link**: parent-managed accounts can block changing
  network settings and prevent uninstalling managed apps; supervised devices
  can't remove a device-owner DNS config.
- **Windows** — a standard (non-admin) child account can't change system DNS;
  Microsoft Family Safety adds web filtering and reporting on top.

Used with Layer 1: the filter profile is installed, and Screen
Time/Family Link stops it being removed without the parent's passcode. If it
*is* removed, Layer 3 notices.

---

## Layer 3 — Accountability without a network

Even off your network, you still want the *report*. Two paths, both of which
FaithFilter already supports or can:

1. **The browser extension** (`extension/`) reports search terms and visited
   hostnames to your server's `/api/extension/events` from wherever the
   laptop is — no VPN, no slowdown. Install it on a managed browser profile
   (Layer 2) so it can't be quietly removed; if it is, the device goes
   **"dark"** and that itself is reported to the accountability partner.
2. **Device DNS pointed at your DoH endpoint** (Layer 1) means the device's
   queries flow through FaithFilter even on cellular, so its activity lands
   in that person's weekly ally report exactly like a home device.

The **dark-device detection** already built into FaithFilter is what makes
this trustworthy: a monitored device that stops sending queries (profile
removed, phone off, or bypassing) shows up as a gap the partner can ask
about.

---

## Recommended path by family type

- **"We have one PC that's always on."** Run FaithFilter at home for the
  whole network (main README), **and** add device DNS profiles (Layer 1) to
  the kids' phones so protection follows them out the door. Lock with Screen
  Time / Family Link.
- **"We don't want to run a server at all."** Start with the device's own
  free controls — **Apple Screen Time** or **Google Family Link** with their
  built-in web filtering — plus the browser extension pointed at a
  friend's/relative's FaithFilter if one exists. This is the least technical
  and covers a lot. Move to the hosted FaithFilter service when it exists for
  the full report.
- **"One specific device needs strong accountability"** (e.g. a teen's
  laptop): managed browser profile + FaithFilter extension + Screen Time
  lock, and point its DNS at your DoH endpoint. That's the closest to
  "Covenant Eyes coverage" without the device slowdown.

---

## Roadmap to make this turnkey

These are the buildable pieces that would make per-device protection genuinely
easy for non-technical families, in priority order:

1. **DNS profile generator** in the dashboard — per-person Android hostname +
   Apple `.mobileconfig` + Windows steps, pre-filled with the family's
   endpoint and the person's token. *(Biggest friction removed.)*
2. **Guided DoH/DoT exposure** — a setup checklist / script for the
   dynamic-DNS + Let's Encrypt + port-forward path, so "make my home server
   reachable safely" is a wizard, not tribal knowledge.
3. **Per-person DoH tokens** — distinct endpoint paths per person so a single
   home server cleanly separates each device's policy and report when
   accessed remotely (the same tokening a hosted multi-tenant service would
   use — so this work is reusable if a paid host is built later).
4. **Signed mobile config / MDM guidance** — documentation (and, for
   organisations, an MDM profile) so the config installs as a locked,
   non-removable profile.
5. **Hosted service** (separate, optional) — for families who can't self-host
   at all: the same device profiles pointed at a managed endpoint, billed as
   a convenience tier on top of this free core.

Items 1–4 keep the tool free and self-hosted while dramatically lowering the
skill required. Item 5 is the paid on-ramp for everyone else, and reuses the
tokening from item 3.
