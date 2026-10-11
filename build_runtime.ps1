#Requires -Version 5.1
<#
  build_runtime.ps1 - dev tool.

  Downloads the official Python embeddable distribution, installs the
  cryptography wheel into it, bundles the omotam scripts, and produces
  dist\omotam-runtime.zip. That zip is the single artifact the installer
  downloads at install time.

    powershell -ExecutionPolicy Bypass -File .\build_runtime.ps1
    powershell -ExecutionPolicy Bypass -File .\build_runtime.ps1 -PythonVersion 3.11.9
#>
[CmdletBinding()]
param(
    [string]$PythonVersion = '3.11.9',
    [string]$Out = 'dist\omotam-runtime.zip'
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$work = Join-Path $root 'dist\build'
$payload = Join-Path $work 'payload'
$runtime = Join-Path $payload 'runtime'

Write-Host "Cleaning build dir..."
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $payload | Out-Null

Write-Host "Downloading Python $PythonVersion embeddable..."
$embed = Join-Path $work 'python-embed.zip'
$url = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-embed-amd64.zip"
Invoke-WebRequest -Uri $url -OutFile $embed -UseBasicParsing

Write-Host "Extracting runtime..."
Expand-Archive -Path $embed -DestinationPath $runtime -Force

Write-Host "Enabling site-packages..."
$pth = Get-ChildItem $runtime -Filter 'python*._pth' | Select-Object -First 1
$lines = Get-Content -LiteralPath $pth.FullName
$lines = $lines -replace '^#\s*import site', 'import site'
Set-Content -LiteralPath $pth.FullName -Value $lines

Write-Host "Installing cryptography into the bundled runtime..."
$site = Join-Path $runtime 'Lib\site-packages'
New-Item -ItemType Directory -Force -Path $site | Out-Null
& python -m pip install --target $site --upgrade --disable-pip-version-check --quiet cryptography

Write-Host "Copying omotam files..."
foreach ($f in 'dns_server.py', 'dns_mcp.py', 'intercept_mode.ps1', 'update.ps1', 'uninstall.ps1', 'dns_hosts.example.json') {
    Copy-Item -LiteralPath (Join-Path $root $f) -Destination $payload -Force
}

Write-Host "Verifying bundled runtime..."
& (Join-Path $runtime 'python.exe') -c "import ssl, cryptography, json, socket; print('runtime ok', cryptography.__version__)"

Write-Host "Packaging $Out ..."
$outPath = Join-Path $root $Out
New-Item -ItemType Directory -Force -Path (Split-Path $outPath) | Out-Null
if (Test-Path -LiteralPath $outPath) { Remove-Item -LiteralPath $outPath -Force }
Compress-Archive -Path (Join-Path $payload '*') -DestinationPath $outPath

$mb = [math]::Round((Get-Item $outPath).Length / 1MB, 1)
Write-Host "Done: $outPath ($mb MB)"
