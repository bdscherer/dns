# FaithFilter αlpha

FaithFilter is a self‑hosted DNS filtering service designed to help parents,
schools and small organisations block access to adult content at the DNS
level.  It allows you to maintain your own blocklists and whitelists,
keeps a log of every DNS query for reporting, and can enforce **Google
SafeSearch** and **YouTube restricted modes** across your entire network.

This document explains how the system works and provides step‑by‑step
instructions for deploying the alpha version on a fresh Virtual Machine
running Ubuntu (or a similar Linux distribution).  FaithFilter has
minimal dependencies and can be run with Python 3.8+.

## Features

- **DNS‑level blocking of explicit domains** – FaithFilter maintains a
  blocklist of domains that serve pornography or other inappropriate
  material.  Domains on the list (and their sub‑domains) are returned
  as *NXDOMAIN* to the client.  The project deliberately keeps this
  alpha blocklist small by default; you are encouraged to integrate
  comprehensive community lists.  The unified porn blocklist at
  <https://github.com/columndeeply/hosts> merges over 12 million
  domains from various sources and includes redirects to “Safe
  Browsing” versions of common search engines【733584132698443†L0-L27】.

- **Configurable whitelist** – sometimes legitimate sites are swept up
  in broad blocklists.  Add domains to the whitelist to ensure they
  resolve normally.  Whitelist entries override the blocklist.

- **Google SafeSearch enforcement** – Google provides a “SafeSearch
  Virtual IP (VIP)” service.  If you map `www.google.com` and other
  country‑specific Google domains to `forcesafesearch.google.com`, all
  searches will be filtered for explicit results【981322123641601†L65-L160】.
  The VIP address currently resolves to `216.239.38.120`【981322123641601†L94-L104】.
  FaithFilter rewrites DNS requests for Google search domains to this
  VIP when SafeSearch is enabled.

- **YouTube restricted mode** – YouTube provides two levels of
  filtering: a “moderate” mode and a stricter “restrict” mode.  These
  are enforced by mapping common YouTube hostnames to Google‑owned
  IPs: `216.239.38.119` for the *restrict‑moderate* service and
  `216.239.38.120` for the *restrict* service【15477614038885†L90-L106】.  When
  YouTube mode is set to `moderate` or `strict` in the configuration,
  queries for YouTube domains are rewritten to the appropriate IP【15477614038885†L90-L106】.

- **HTTP API for management and reporting** – an optional Flask‑based
  API provides endpoints for viewing recent queries, inspecting or
  updating blocklists and whitelists, and reloading lists without
  restarting the DNS service.

- **Detailed logging** – every DNS query is timestamped and recorded
  with the client’s IP, the requested domain and the action taken
  (allowed, blocked, SafeSearch rewrite, YouTube rewrite or
  whitelisted).  Logs are stored in plain text for easy analysis.

## Directory Structure

```
faithfilter/
├─ faithfilter.py        ← main Python program implementing the DNS
│                           forwarder, filtering logic and optional API
├─ config.yaml           ← default configuration file (copy and edit)
├─ blocklist.txt         ← sample blocklist (one domain per line)
├─ whitelist.txt         ← sample whitelist
├─ requirements.txt      ← Python dependencies
└─ README.md             ← this document
```

## Prerequisites

- A Vultr VM or other Linux machine with root access.  The alpha
  version has been tested on **Ubuntu 22.04 LTS** but should work on
  any recent Linux distribution.
- Python 3.8 or newer.  Install `python3` and `python3‑pip` from your
  package manager if they are not present.
- TCP/UDP port 53 open in your server’s firewall.  Vultr’s default
  firewall usually permits DNS queries on port 53 but double‑check
  your security group rules.

## Installation Steps

1. **Create a VM on Vultr**.

   - Log in to your Vultr dashboard, click **Deploy New Server** and
     select a location near your users.  Choose **Ubuntu 22.04 x64** as
     the operating system and an instance size that meets your needs
     (even the smallest plan is sufficient for an alpha deployment).
   - After deployment completes, note the server’s public IP address
     and set a strong root password or SSH key.

2. **SSH into the server**.

   ```sh
   ssh root@your.vultr.ip.address
   ```

3. **Install dependencies**.

   Update system packages and install Python and pip:

   ```sh
   apt update && apt upgrade -y
   apt install -y python3 python3-pip git
   ```

4. **Download FaithFilter**.

   You can clone the repository or copy the provided files.  On your
   server run:

   ```sh
   # Clone the repository (replace with your own Git URL if you host it)
   git clone https://example.com/faithfilter.git
   cd faithfilter
   ```

   Alternatively, upload the contents of the `faithfilter` folder in
   this package to your server.

5. **Install Python packages**.

   Use `pip` to install the requirements into a virtual environment or
   system‑wide:

   ```sh
   pip3 install --upgrade pip
   pip3 install -r requirements.txt
   ```

6. **Review and edit `config.yaml`**.

   The supplied `config.yaml` controls listening IP/port, upstream
   resolvers, logging, SafeSearch/YouTube options and the HTTP API.  At
   minimum, verify that `listen_ip` is set to `0.0.0.0` and
   `listen_port` is `53` (the standard DNS port).  Ensure `safe_search`
   is `true` and choose a `youtube_mode` (`off`, `moderate` or
   `strict`).  The default upstream DNS servers are Cloudflare and
   Google Public DNS; adjust these if you prefer another resolver.

7. **Populate your blocklist**.

   The `blocklist.txt` file contains only a few placeholder domains.
   To effectively block adult content you should subscribe to a large
   community list.  For example, the unified porn blocklist by
   *columndeeply* merges more than 12 million domains and splits the
   list into manageable chunks【733584132698443†L0-L27】.  You can
   download one or more of these lists and append them to your
   `blocklist.txt`:

   ```sh
   curl -s https://raw.githubusercontent.com/columndeeply/hosts/main/hosts00 >> blocklist.txt
   curl -s https://raw.githubusercontent.com/columndeeply/hosts/main/hosts01 >> blocklist.txt
   # Repeat for hosts02…hosts05 as desired
   ```

   Remember that blocklist entries override the whitelist.  If you find
   legitimate sites being blocked, add them to `whitelist.txt`.

8. **Run FaithFilter**.

   Start the service with root privileges (port 53 requires elevated
   rights).  From the `faithfilter` directory, run:

   ```sh
   sudo python3 faithfilter.py --config config.yaml
   ```

   You should see log messages indicating that the DNS server is
   listening on port 53 and, if enabled, that the HTTP API is running on
   port 5000.  Leave this terminal open to watch log output or run
   FaithFilter inside a **tmux** session or as a background service.

9. **Point your devices to FaithFilter**.

   Configure the DHCP server on your router to hand out the IP address
   of your Vultr instance as the primary DNS server.  Alternatively,
   manually set the DNS server on individual devices to your Vultr
   server’s IP address.  Once clients are using FaithFilter, queries to
   adult domains will be blocked and Google/YouTube will be filtered
   according to your settings.

## Optional: Running as a Systemd Service

To keep FaithFilter running continuously and restart it on boot,
create a systemd unit file at `/etc/systemd/system/faithfilter.service`:

```ini
[Unit]
Description=FaithFilter DNS filtering service
After=network.target

[Service]
ExecStart=/usr/bin/python3 /path/to/faithfilter/faithfilter.py --config /path/to/faithfilter/config.yaml
Restart=always
User=root
WorkingDirectory=/path/to/faithfilter
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=faithfilter

[Install]
WantedBy=multi-user.target
```

Then reload systemd, enable and start the service:

```sh
sudo systemctl daemon-reload
sudo systemctl enable faithfilter.service
sudo systemctl start faithfilter.service
```

Logs will be available via `journalctl -u faithfilter -f`.

## HTTP API Usage

If `http_api.enable` is set to `true` and Flask is installed, FaithFilter
exposes several JSON endpoints.  The API is unauthenticated in the
alpha release; you should restrict access using a firewall or reverse
proxy.

| Endpoint | Method | Description |
|---|---|---|
| `/api/status` | GET | Returns basic statistics such as total queries handled, number of blocked domains, and counts of SafeSearch and YouTube rewrites. |
| `/api/queries?limit=N` | GET | Returns the last *N* queries recorded in memory (default 100). Each entry includes a timestamp, client IP, domain and action. |
| `/api/blocklist` | GET | Returns the current blocklist loaded in memory. |
| `/api/blocklist` | POST | Add a new domain to the blocklist. Body must be JSON: `{ "domain": "example.com" }`. The domain is appended to the blocklist file. |
| `/api/blocklist/<domain>` | DELETE | Remove a domain from the blocklist. |
| `/api/whitelist` | GET/POST | Same semantics as `/api/blocklist` but for the whitelist. |
| `/api/whitelist/<domain>` | DELETE | Remove a domain from the whitelist. |
| `/api/reload` | POST | Reload blocklist and whitelist from disk. Useful after manually editing the files. |

## How It Works

When a DNS request arrives, FaithFilter inspects the query name and
applies the following logic in order:

1. **Whitelist check** – if the domain or any of its parent domains
   appears in `whitelist.txt`, the request is forwarded directly to
   the upstream resolvers and the response is relayed back to the
   client.
2. **Google SafeSearch** – if SafeSearch is enabled and the query is
   for a Google search domain (for example `google.com` or
   `www.google.com`), FaithFilter returns a response pointing to
   Google’s SafeSearch VIP address.  According to Google’s
   documentation, mapping Google domains to `forcesafesearch.google.com`
   forces SafeSearch for all browsers and cannot be disabled by end
   users【981322123641601†L65-L160】.
3. **YouTube restricted mode** – if `youtube_mode` is set to `moderate`
   or `strict`, queries for YouTube domains (such as
   `www.youtube.com`, `youtube.googleapis.com` and their sub‑domains)
   are rewritten to one of Google’s restricted IP addresses:
   `216.239.38.119` for moderate mode and `216.239.38.120` for strict
   mode【15477614038885†L90-L106】.
4. **Blocklist check** – if the domain (or any parent domain) is
   present in `blocklist.txt`, FaithFilter responds with
   *NXDOMAIN* (a non‑existent domain error).  You can modify this
   behaviour in the code to return a sinkhole IP if you prefer.
5. **Forwarding** – all remaining queries are forwarded to the list of
   upstream DNS servers defined in `config.yaml`.  The first server to
   answer is used.  If all upstreams fail, FaithFilter returns a
   SERVFAIL response to the client.

Throughout this process every query is logged with its outcome.  The
log file can be rotated using standard log management tools or read by
the HTTP API.

## Next Steps

This alpha release provides the core functionality needed to filter
adult content at the DNS layer.  There are many opportunities for
improvement, including:

- Implementing TLS for encrypted DNS (DoH/DoT) so that clients can
  communicate securely with the filter.
- Providing a web dashboard for visualising logs and adjusting
  settings.
- Integrating automatic updates of external blocklists.
- Adding authentication to the HTTP API.

Please report bugs or contribute improvements via the project’s issue
tracker.  Together we can make the internet a safer place for
families.