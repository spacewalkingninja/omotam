#Requires -Version 5.1
<#
  Registers the custom DNS server to start automatically on this machine.

  Default: runs at system startup as SYSTEM (no login required), binding port 53.
  Use -LogonInsteadOfStartup to run at your logon with your account instead.

  Examples:
    powershell -ExecutionPolicy Bypass -File .\install_startup.ps1
    powershell -ExecutionPolicy Bypass -File .\install_startup.ps1 -LogonInsteadOfStartup
    powershell -ExecutionPolicy Bypass -File .\install_startup.ps1 -ConfigPath C:\dns\dns_hosts.json
#>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [string]$TaskName = "CustomDNS",
    [switch]$LogonInsteadOfStartup,
    [switch]$SetLocalDns
)

$ErrorActionPreference = 'Stop'

# ---- self-elevate ----
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host "Administrator rights are required. Relaunching elevated..."
    $extra = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -ConfigPath `"$ConfigPath`" -TaskName `"$TaskName`""
    if ($LogonInsteadOfStartup) { $extra += " -LogonInsteadOfStartup" }
    if ($SetLocalDns) { $extra += " -SetLocalDns" }
    Start-Process -FilePath (Get-Process -Id $PID).Path -Verb RunAs -ArgumentList $extra
    return
}

# ---- resolve paths ----
$scriptPath = Join-Path $PSScriptRoot 'dns_server.py'
if (-not (Test-Path -LiteralPath $scriptPath)) {
    throw "dns_server.py was not found next to this installer ($scriptPath)."
}
if (-not $ConfigPath) { $ConfigPath = Join-Path $PSScriptRoot 'dns_hosts.json' }
$ConfigPath = [System.IO.Path]::GetFullPath($ConfigPath)

# ---- locate pythonw ----
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { $py = Get-Command python3 -ErrorAction SilentlyContinue }
if (-not $py) { throw "Python was not found on PATH. Install Python first." }
$python  = $py.Source
$pythonw = Join-Path (Split-Path $python) 'pythonw.exe'
if (-not (Test-Path -LiteralPath $pythonw)) { $pythonw = $python }

# ---- make sure a config exists ----
if (-not (Test-Path -LiteralPath $ConfigPath)) {
    & $python -c "import sys, dns_server; dns_server.load_config(sys.argv[1])" $ConfigPath
    Write-Host "Created default config: $ConfigPath"
}

# ---- ensure a TLS certificate exists ----
$caPath = (& $python $scriptPath --config $ConfigPath --ensure-cert | Select-Object -Last 1)
if ($caPath) { $caPath = $caPath.Trim() }
if ($caPath -and (Test-Path -LiteralPath $caPath)) {
    Import-Certificate -FilePath $caPath -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
    Write-Host "Trusted local CA certificate so https:// is warning-free: $caPath"
}

# ---- read ports and open the firewall ----
$cfg        = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$dnsPort    = if ($cfg.port)         { [int]$cfg.port }         else { 53 }
$guiPort    = if ($cfg.gui_port)     { [int]$cfg.gui_port }     else { 8080 }
$guiTlsPort = if ($cfg.gui_tls_port) { [int]$cfg.gui_tls_port } else { 443 }
$tlsOn      = [bool]$cfg.gui_tls

$rules = @(
    @{ Name = 'Custom DNS (UDP)';      Proto = 'UDP'; Port = $dnsPort },
    @{ Name = 'Custom DNS (TCP)';      Proto = 'TCP'; Port = $dnsPort },
    @{ Name = 'Custom DNS GUI (HTTP)'; Proto = 'TCP'; Port = $guiPort }
)
if ($tlsOn) { $rules += @{ Name = 'Custom DNS GUI (HTTPS)'; Proto = 'TCP'; Port = $guiTlsPort } }
foreach ($rule in $rules) {
    if (Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue) { continue }
    New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -Action Allow `
        -Protocol $rule.Proto -LocalPort $rule.Port -Profile Any -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "Firewall opened: DNS UDP/TCP $dnsPort, GUI TCP $guiPort$(if ($tlsOn) { ", HTTPS TCP $guiTlsPort" })"

# ---- bootstrap the GUI hostname in the local hosts file ----
$guiHost = $cfg.gui_hostname
if ($guiHost -is [array]) { $guiHost = $guiHost[0] }
if ($guiHost) {
    $hostsFile = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    if (-not (Select-String -Path $hostsFile -Pattern ([Regex]::Escape($guiHost)) -Quiet)) {
        Add-Content -LiteralPath $hostsFile -Value "127.0.0.1`t$guiHost"
        Write-Host "Added hosts entry: 127.0.0.1 $guiHost (so this PC can always reach the GUI)"
    }
}

# ---- optionally make this PC use the server for all DNS ----
if ($SetLocalDns) {
    Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
        Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses '127.0.0.1' -ErrorAction SilentlyContinue
    }
    Write-Host "Set this PC's DNS servers to 127.0.0.1"
}

# ---- build the task ----
$action = New-ScheduledTaskAction `
    -Execute $pythonw `
    -Argument "`"$scriptPath`" --config `"$ConfigPath`"" `
    -WorkingDirectory $PSScriptRoot

if ($LogonInsteadOfStartup) {
    $trigger   = New-ScheduledTaskTrigger -AtLogOn
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Highest
    $where = "at logon for $($identity.Name)"
} else {
    $trigger   = New-ScheduledTaskTrigger -AtStartup
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $where = "at system startup as SYSTEM"
}

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Principal $taskPrincipal -Settings $settings `
    -Description "Custom DNS server for the local network" -Force | Out-Null

Start-ScheduledTask -TaskName $TaskName

Write-Host ""
Write-Host "Installed scheduled task '$TaskName' ($where)."
Write-Host "  pythonw : $pythonw"
Write-Host "  script  : $scriptPath"
Write-Host "  config  : $ConfigPath"
Write-Host ""
$guiHint = if ($tlsOn) { "https://" + ($cfg.gui_hostname) } else { "http://<this-pc-ip>:$guiPort" }
Write-Host "Web GUI: $guiHint   (also http://127.0.0.1:$guiPort)"
Write-Host "Point your devices' DNS at this PC's IP, then open $guiHint"
Write-Host ""
Write-Host "Firefox note: turn OFF DNS-over-HTTPS or custom names will not resolve."
Write-Host "  Settings > Privacy & Security > DNS over HTTPS > Off"
Write-Host "  (or about:config -> network.trr.mode = 5)"
Write-Host ""
Write-Host "To remove it later, run: powershell -ExecutionPolicy Bypass -File .\uninstall_startup.ps1"
