#Requires -Version 5.1
<#
  Override mode for THIS PC.

  Adds the public resolver IPs (1.1.1.1, 8.8.8.8, ...) as local loopback addresses,
  so any program that queries them is answered by the local DNS server instead.
  Points this PC's DNS (IPv4 127.0.0.1 and IPv6 ::1) at the server, and the server
  blocks DoH so browsers cannot bypass it.

    powershell -ExecutionPolicy Bypass -File .\intercept_mode.ps1 -Enable
    powershell -ExecutionPolicy Bypass -File .\intercept_mode.ps1 -Disable
    powershell -ExecutionPolicy Bypass -File .\intercept_mode.ps1 -Status
    powershell -ExecutionPolicy Bypass -File .\intercept_mode.ps1 -Enable -Ips 1.1.1.1,8.8.8.8

  IMPORTANT: the DNS server must forward to a resolver that is NOT in the list
  (set "intercept_upstream", default 9.9.9.9), otherwise it would loop to itself.
#>
[CmdletBinding()]
param(
    [switch]$Enable,
    [switch]$Disable,
    [switch]$Status,
    [string[]]$Ips = @('1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4'),
    [switch]$KeepDns
)

$ErrorActionPreference = 'Stop'

if (-not ($Enable -or $Disable -or $Status)) { $Status = $true }

if ($Status) {
    Write-Host "Override mode status:"
    foreach ($ip in $Ips) {
        $found = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $ip -ErrorAction SilentlyContinue
        Write-Host ("  {0,-10} {1}" -f $ip, $(if ($found) { 'HIJACKED (loopback)' } else { 'normal' }))
    }
    Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
        $v4 = (Get-DnsClientServerAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4).ServerAddresses -join ', '
        $v6 = (Get-DnsClientServerAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv6).ServerAddresses -join ', '
        Write-Host ("  DNS {0,-20} v4=[{1}] v6=[{2}]" -f $_.Name, $v4, $v6)
    }
    return
}

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host "Administrator rights are required. Relaunching elevated..."
    $extra = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $extra += if ($Enable) { " -Enable" } else { " -Disable" }
    if ($KeepDns) { $extra += " -KeepDns" }
    Start-Process -FilePath (Get-Process -Id $PID).Path -Verb RunAs -ArgumentList $extra
    return
}

$idx = (Get-NetIPAddress -AddressFamily IPv4 -IPAddress '127.0.0.1').InterfaceIndex

if ($Enable) {
    foreach ($ip in $Ips) {
        if (-not (Get-NetIPAddress -AddressFamily IPv4 -IPAddress $ip -ErrorAction SilentlyContinue)) {
            New-NetIPAddress -InterfaceIndex $idx -IPAddress $ip -PrefixLength 32 | Out-Null
            Write-Host "Hijacked $ip -> loopback"
        } else {
            Write-Host "$ip already hijacked"
        }
    }
    if (-not $KeepDns) {
        Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
            Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses '127.0.0.1', '::1' -ErrorAction SilentlyContinue
        }
        Write-Host "Set this PC's DNS to 127.0.0.1 / ::1"
    }
    Write-Host "Override mode ON."
} else {
    foreach ($ip in $Ips) {
        Remove-NetIPAddress -AddressFamily IPv4 -IPAddress $ip -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "Released $ip"
    }
    if (-not $KeepDns) {
        Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
            Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue
        }
        Write-Host "Reset this PC's DNS to automatic"
    }
    Write-Host "Override mode OFF."
}
