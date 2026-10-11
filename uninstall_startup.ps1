#Requires -Version 5.1
<#
  Stops and removes the custom DNS server startup task, its firewall rules,
  and (optionally) the local CA certificate trusted during install.

    powershell -ExecutionPolicy Bypass -File .\uninstall_startup.ps1
    powershell -ExecutionPolicy Bypass -File .\uninstall_startup.ps1 -RemoveCert
    powershell -ExecutionPolicy Bypass -File .\uninstall_startup.ps1 -TaskName MyDNS
#>
[CmdletBinding()]
param(
    [string]$TaskName = "CustomDNS",
    [switch]$RemoveCert
)

$ErrorActionPreference = 'Stop'

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host "Administrator rights are required. Relaunching elevated..."
    $extra = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -TaskName `"$TaskName`""
    if ($RemoveCert) { $extra += " -RemoveCert" }
    Start-Process -FilePath (Get-Process -Id $PID).Path -Verb RunAs -ArgumentList $extra
    return
}

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($task) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed scheduled task '$TaskName'."
} else {
    Write-Host "No scheduled task named '$TaskName' was found."
}

foreach ($name in @('Custom DNS (UDP)', 'Custom DNS (TCP)', 'Custom DNS GUI (HTTP)', 'Custom DNS GUI (HTTPS)')) {
    if (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue) {
        Remove-NetFirewallRule -DisplayName $name
        Write-Host "Removed firewall rule '$name'."
    }
}

# ---- drop the hosts-file bootstrap entries ----
$hostsFile = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$lines = Get-Content -LiteralPath $hostsFile -ErrorAction SilentlyContinue
$kept  = $lines | Where-Object { $_ -notmatch '\bdns\.settings\b' }
if ($kept.Count -ne $lines.Count) {
    Set-Content -LiteralPath $hostsFile -Value $kept
    Write-Host "Removed 'dns.settings' from the hosts file."
}

if ($RemoveCert) {
    $certs = Get-ChildItem 'Cert:\LocalMachine\Root' | Where-Object { $_.Subject -like '*Custom DNS Local CA*' }
    foreach ($c in $certs) {
        Remove-Item -LiteralPath $c.PSPath -Force
        Write-Host "Removed trusted CA certificate $($c.Thumbprint)."
    }
}
