# Security Policy

FaithFilter is a security tool that people run on their home and school
networks, so we take vulnerability reports seriously.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

Instead, report privately via one of:

- GitHub's **[private vulnerability reporting](https://github.com/bdscherer/dns/security/advisories/new)**
  (Security tab → "Report a vulnerability"), or
- e-mail **bdscherer@gmail.com** with the subject line `FaithFilter security`.

Please include:

- a description of the issue and its impact,
- steps to reproduce (a proof of concept if you have one),
- the version/commit you tested, and
- any suggested remediation.

We aim to acknowledge reports within **72 hours** and to ship a fix or
mitigation for confirmed, high-severity issues as quickly as is practical.
We're happy to credit you in the release notes unless you'd prefer to remain
anonymous.

## Scope

In scope: the DNS resolver, the HTTP dashboard/API, the DoH/DoT endpoints,
the block-page server, the browser extension, and the configuration/secret
handling.

Out of scope: issues that require a user to run an untrusted config file
they authored, and denial of service from a client that is already trusted
to use the resolver.

## Running FaithFilter safely

FaithFilter is designed to run on a trusted LAN. A few defaults worth
knowing:

- The dashboard/API binds to `127.0.0.1` by default. If you set
  `http_api.host: "0.0.0.0"` to reach it from other devices, set a strong
  `http_api.password` and, ideally, `cert_file`/`key_file` for HTTPS — the
  service warns when it is exposed over plain HTTP.
- The dashboard password is auto-generated on first run and stored in
  `admin_password.txt`; keep that file readable only by the service account.
- Prefer the `FAITHFILTER_SMTP_PASSWORD` environment variable over putting
  the SMTP password in `config.yaml`.
- The DoH endpoint (`/dns-query`) is intentionally unauthenticated (it is a
  resolver); keep it off the public internet unless that is your intent.
