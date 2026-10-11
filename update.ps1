#Requires -Version 5.1
<#
  Omotam updater.

  Downloads the latest bundled runtime from the GitHub release, replaces the
  program files in place (keeping dns_hosts.json, certs and notes), and
  restarts the service. Invoked by the GUI "Update now" button or directly.

    powershell -ExecutionPolicy Bypass -File .\update.ps1
    powershell -ExecutionPolicy Bypass -File .\update.ps1 -RuntimeUrl .\dist\omotam-runtime.zip
#>
[CmdletBinding()]
param(
    [string]$InstallDir,
    [string]$TaskName = 'omotam',
    [string]$RuntimeUrl = 'https://github.com/spacewalkingninja/omotam/releases/latest/download/omotam-runtime.zip'
)

$ErrorActionPreference = 'Stop'

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    $argsList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"",
        '-TaskName', "`"$TaskName`"", '-RuntimeUrl', "`"$RuntimeUrl`"")
    if ($InstallDir) { $argsList += @('-InstallDir', "`"$InstallDir`"") }
    Start-Process -FilePath (Get-Process -Id $PID).Path -Verb RunAs -ArgumentList $argsList
    return
}

if (-not $InstallDir) {
    $InstallDir = $PSScriptRoot
    if (-not (Test-Path -LiteralPath (Join-Path $InstallDir 'dns_server.py'))) {
        $InstallDir = Join-Path $env:ProgramData 'omotam'
    }
}
$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)

function Show-Notice($title, $text) {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $ni = New-Object System.Windows.Forms.NotifyIcon
        $ni.Icon = [System.Drawing.SystemIcons]::Information
        $ni.Visible = $true
        $ni.ShowBalloonTip(8000, $title, $text, [System.Windows.Forms.ToolTipIcon]::Info)
        Start-Sleep -Seconds 6
        $ni.Dispose()
    } catch {}
}

Write-Host "Stopping Omotam service..."
$hadTask = [bool](Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
if ($hadTask) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

Write-Host "Downloading latest runtime..."
$zip = Join-Path $env:TEMP 'omotam-update.zip'
if ($RuntimeUrl -match '^https?://') {
    Invoke-WebRequest -Uri $RuntimeUrl -OutFile $zip -UseBasicParsing
} else {
    Copy-Item -LiteralPath $RuntimeUrl -Destination $zip -Force
}

Write-Host "Applying update to $InstallDir ..."
Expand-Archive -Path $zip -DestinationPath $InstallDir -Force
Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue

if ($hadTask) {
    Write-Host "Restarting service..."
    Start-ScheduledTask -TaskName $TaskName
}

$newVersion = 'latest'
$verConst = Select-String -Path (Join-Path $InstallDir 'dns_server.py') -Pattern '^VERSION\s*=' | Select-Object -First 1
if ($verConst) { $newVersion = ($verConst.Line -replace '.*"([^"]+)".*', '$1') }

Write-Host "Omotam updated to $newVersion."
Show-Notice 'Omotam' "Updated to version $newVersion."
