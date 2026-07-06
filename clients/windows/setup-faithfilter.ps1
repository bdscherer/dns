# FaithFilter per-device setup for Windows 11 (encrypted DNS over HTTPS).
#
# Points this PC's system DNS at your FaithFilter server over DoH, so it is
# filtered on any network. Run in an ELEVATED PowerShell:
#
#   Set-ExecutionPolicy -Scope Process Bypass
#   .\setup-faithfilter.ps1 -DohTemplate "https://dns.yourfamily.net/p/<token>/dns-query"
#
# Get the exact DohTemplate for a person from the dashboard
# (Accountability -> Set up a device) or GET /api/devices.

param(
  [Parameter(Mandatory = $true)][string]$DohTemplate,
  [switch]$Uninstall
)
$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal] `
      [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Error "Please run this in an Administrator PowerShell."
  exit 1
}

# Extract the server hostname from the DoH URL.
$ServerHost = ([System.Uri]$DohTemplate).Host
$ip = (Resolve-DnsName -Name $ServerHost -Type A -ErrorAction Stop |
       Select-Object -First 1 -ExpandProperty IPAddress)

if ($Uninstall) {
  Write-Host "Removing FaithFilter DNS configuration..."
  try { netsh dns delete encryption server=$ip | Out-Null } catch {}
  Get-DnsClientServerAddress -AddressFamily IPv4 |
    ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ResetServerAddresses }
  Clear-DnsClientCache
  Write-Host "Reverted to automatic (DHCP) DNS."
  exit 0
}

Write-Host "FaithFilter: $ServerHost -> $ip (DoH)"
# Register the DoH template for the server IP and require encryption.
netsh dns add encryption server=$ip dohtemplate=$DohTemplate autoupgrade=yes udpfallback=no | Out-Null
# Point every active IPv4 adapter at it.
Get-DnsClientServerAddress -AddressFamily IPv4 |
  Where-Object { $_.ServerAddresses } |
  ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses $ip }
Clear-DnsClientCache

Write-Host "Done. All DNS now goes to FaithFilter over HTTPS."
Write-Host "Lock it down: use a Standard (non-admin) child account so system DNS can't be changed."
Write-Host "To undo:  .\setup-faithfilter.ps1 -DohTemplate '$DohTemplate' -Uninstall"
