#!/usr/bin/env bash
# FaithFilter per-device setup for Linux (systemd-resolved, DNS-over-TLS).
#
# Points this machine's system DNS at your FaithFilter server over DoT, so it
# stays filtered on any network.
#
#   sudo ./setup-faithfilter.sh dns.yourfamily.net
#   sudo ./setup-faithfilter.sh --uninstall
#
# For per-person attribution use the person's token subdomain as the
# hostname (e.g. <token>.dns.yourfamily.net); the plain base domain applies
# the whole-network policy. Get hostnames from the dashboard or /api/devices.
set -euo pipefail

DROPIN=/etc/systemd/resolved.conf.d/faithfilter.conf

if [ "${1:-}" = "--uninstall" ]; then
  rm -f "$DROPIN"
  systemctl restart systemd-resolved
  echo "Removed FaithFilter DNS configuration."
  exit 0
fi

DOT_HOST="${1:-}"
if [ -z "$DOT_HOST" ]; then
  echo "Usage: sudo $0 <dot-hostname>   (e.g. dns.yourfamily.net)" >&2
  exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "Please run with sudo." >&2
  exit 1
fi
if ! command -v systemctl >/dev/null || ! systemctl is-enabled systemd-resolved >/dev/null 2>&1; then
  echo "This script needs systemd-resolved (Ubuntu/Debian/Fedora default)." >&2
  exit 1
fi

IP="$(getent hosts "$DOT_HOST" | awk '{print $1}' | head -n1)"
if [ -z "$IP" ]; then echo "Could not resolve $DOT_HOST" >&2; exit 1; fi

echo "Configuring systemd-resolved DoT to $DOT_HOST ($IP)..."
mkdir -p "$(dirname "$DROPIN")"
cat > "$DROPIN" <<EOF
# Managed by FaithFilter setup-faithfilter.sh
[Resolve]
DNS=$IP#$DOT_HOST
DNSOverTLS=yes
Domains=~.
EOF
systemctl restart systemd-resolved

echo "Done. All DNS now goes to FaithFilter over TLS."
echo "Verify with:  resolvectl status | grep -A2 'Current DNS'"
echo "Lock it down: don't grant this account sudo/root."
echo "To undo:  sudo $0 --uninstall"
