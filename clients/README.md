# FaithFilter per-device clients

These configure a single device to send **all** its DNS to your FaithFilter
server over an encrypted channel (DoH/DoT), so the device stays filtered on
Wi-Fi **and cellular**, and its activity is attributed to the right person's
accountability report.

The easiest way to set a device up is from the **dashboard**: open the
Accountability section → *Set up a device* and click the platform link for
that person — it downloads a ready-to-use profile with the endpoint and the
person's token already filled in. The scripts here are the same thing for
people who prefer the command line or don't have dashboard access.

## Prerequisites (server side)

For any per-device client to reach your server from the internet you need:

1. A **public hostname** for the server (a domain or dynamic-DNS name),
   set as `accountability.base_domain` in `config.yaml`
   (e.g. `dns.yourfamily.net`).
2. A **valid TLS certificate** for that hostname (`http_api.cert_file` /
   `key_file`, and `dot.cert_file` / `key_file` for Android) — Let's Encrypt
   is free. Encrypted DNS clients refuse self-signed certs.
3. Port **443** (DoH) and, for Android, **853** (DoT) forwarded to the
   server.

Each person has a stable **token**; their DoH endpoint is
`https://<base_domain>/p/<token>/dns-query`. Find tokens/endpoints on the
dashboard or `GET /api/devices`.

## Contents

| Folder | Platform | Method |
|---|---|---|
| `windows/` | Windows 11 | System DoH (`setup-faithfilter.ps1`) |
| `linux/`   | Linux (systemd-resolved) | DNS-over-TLS (`setup-faithfilter.sh`) |
| `android/` | Android 9+ | Private DNS (DoT hostname) — see its README |
| Apple      | iOS / macOS | Download the `.mobileconfig` from the dashboard |

## Locking it down

A profile a child can delete isn't accountability. Pair each install with the
platform's parental controls so it can't be removed:

- **Apple**: Screen Time → Content & Privacy → *Don't Allow Changes* for
  VPN & DNS / Profiles.
- **Android**: Google Family Link — block changing network settings.
- **Windows**: use a Standard (non-admin) child account.
- **Linux**: don't give the account sudo/root.

If a device is unenrolled anyway, it stops sending queries and FaithFilter
flags it as a **dark device** in the accountability report.
