#Requires -Version 5.1
<#
  omotam uninstaller. Removes the startup service, firewall rules, hosts entry,
  the trusted local CA, and (by default) the installed files.

    powershell -ExecutionPolicy Bypass -File .\uninstall.ps1
    powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 -KeepFiles
    powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 -InstallDir "C:\ProgramData\omotam"
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:ProgramData 'omotam'),
    [string]$TaskName = 'omotam',
    [switch]$KeepFiles
)

$ErrorActionPreference = 'Stop'

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    $argsList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"",
        '-InstallDir', "`"$InstallDir`"", '-TaskName', "`"$TaskName`"")
    if ($KeepFiles) { $argsList += '-KeepFiles' }
    Start-Process -FilePath (Get-Process -Id $PID).Path -Verb RunAs -ArgumentList $argsList
    return
}

foreach ($tn in @($TaskName, 'omotam-tray')) {
    if (Get-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $tn -Confirm:$false
        Write-Host "Removed scheduled task '$tn'."
    }
}

foreach ($n in 'omotam DNS (UDP)', 'omotam DNS (TCP)', 'omotam GUI (HTTP)', 'omotam GUI (HTTPS)') {
    if (Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue) {
        Remove-NetFirewallRule -DisplayName $n
        Write-Host "Removed firewall rule '$n'."
    }
}

$hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$lines = Get-Content -LiteralPath $hosts
$kept = $lines | Where-Object { $_ -notmatch '\bdns\.settings\b' }
if ($kept.Count -ne $lines.Count) { [System.IO.File]::WriteAllLines($hosts, $kept, (New-Object System.Text.UTF8Encoding($false))); Write-Host "Removed 'dns.settings' from hosts." }

foreach ($c in (Get-ChildItem 'Cert:\LocalMachine\Root' | Where-Object { $_.Subject -like '*Omotam Local CA*' -or $_.Subject -like '*Custom DNS Local CA*' })) {
    Remove-Item -LiteralPath $c.PSPath -Force -ErrorAction SilentlyContinue
    Write-Host "Removed trusted CA $($c.Thumbprint)."
}

if (-not $KeepFiles -and (Test-Path -LiteralPath $InstallDir)) {
    Remove-Item -LiteralPath $InstallDir -Recurse -Force
    Write-Host "Removed $InstallDir."
} elseif ($KeepFiles) {
    Write-Host "Kept files in $InstallDir."
}

Write-Host "omotam uninstalled."
