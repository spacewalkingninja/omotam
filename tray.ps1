#Requires -Version 5.1
<#
  Omotam tray icon (user session).

  Shows a status icon in the notification area:
    - green  = Omotam running   (tooltip "Omotam on")
    - red    = Omotam stopped   (tooltip "Omotam off")
  Double-click opens the Omotam web UI. Right-click opens a menu with the
  service controls and settings.

  Started automatically at logon by the installer (scheduled task "omotam-tray").
#>
[CmdletBinding()]
param(
    [string]$TaskName = 'omotam',
    [string]$TrayTaskName = 'omotam-tray',
    [string]$InstallDir = $PSScriptRoot
)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

if (-not $InstallDir) { $InstallDir = Join-Path $env:ProgramData 'omotam' }
$script:ConfigPath = Join-Path $InstallDir 'dns_hosts.json'

function Get-Config {
    if (Test-Path -LiteralPath $script:ConfigPath) {
        try { return (Get-Content -LiteralPath $script:ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json) } catch {}
    }
    return $null
}

function Get-Cfg($cfg, $key, $default) {
    if ($cfg -and $cfg.PSObject.Properties[$key] -and $null -ne $cfg.$key) { return $cfg.$key }
    return $default
}

function Get-UiUrl {
    $cfg = Get-Config
    $hostName = Get-Cfg $cfg 'gui_hostname' 'dns.settings'
    if ($hostName -is [array]) { $hostName = $hostName[0] }
    $tls = Get-Cfg $cfg 'gui_tls' $true
    $port = Get-Cfg $cfg 'gui_port' 8080
    if ($tls) { return "https://$hostName/" }
    return "http://127.0.0.1:$port/"
}

function Get-ApiBase {
    $cfg = Get-Config
    return "http://127.0.0.1:" + (Get-Cfg $cfg 'gui_port' 8080)
}

function Get-ApiToken {
    $cfg = Get-Config
    $t = Get-Cfg $cfg 'api_token' $null
    if (-not $t) { $t = Get-Cfg $cfg 'gui_token' $null }
    return $t
}

function Invoke-Api {
    param([string]$Method, [string]$Path, $Body)
    $url = (Get-ApiBase) + $Path
    $headers = @{}
    $token = Get-ApiToken
    if ($token) { $headers['X-API-Token'] = $token }
    try {
        if ($Body) {
            return Invoke-RestMethod -Uri $url -Method $Method -Headers $headers -ContentType 'application/json' -Body ($Body | ConvertTo-Json) -TimeoutSec 10
        }
        return Invoke-RestMethod -Uri $url -Method $Method -Headers $headers -TimeoutSec 10
    } catch { return $null }
}

# --- state ------------------------------------------------------------------
$script:DnsPort = (Get-Cfg (Get-Config) 'port' 53)

function Test-OmotamRunning {
    try {
        $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        if ($t.State -eq 'Running') { return $true }
    } catch {}
    # fall back to probing the DNS / GUI port
    foreach ($p in @($script:DnsPort, (Get-Cfg (Get-Config) 'gui_port' 8080))) {
        try {
            $c = New-Object System.Net.Sockets.TcpClient
            $c.Connect('127.0.0.1', [int]$p); $c.Close(); return $true
        } catch {}
    }
    return $false
}

# --- icons ------------------------------------------------------------------
function New-DotIcon([int]$r, [int]$g, [int]$b) {
    $bmp = New-Object System.Drawing.Bitmap 32, 32
    $gr = [System.Drawing.Graphics]::FromImage($bmp)
    $gr.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $gr.Clear([System.Drawing.Color]::Transparent)
    $fill = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb($r, $g, $b))
    $ring = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(30, 30, 30)), 3
    $gr.FillEllipse($fill, 3, 3, 26, 26)
    $gr.DrawEllipse($ring, 3, 3, 26, 26)
    $white = New-Object System.Drawing.Pen ([System.Drawing.Color]::White), 3
    $white.StartCap = 'Round'; $white.EndCap = 'Round'
    $gr.DrawArc($white, 10, 10, 12, 12, 40, 260)
    $gr.Dispose()
    $h = $bmp.GetHicon()
    $icon = [System.Drawing.Icon]::FromHandle($h)
    $bmp.Dispose()
    return $icon
}

$script:IconOn  = New-DotIcon 46 204 113
$script:IconOff = New-DotIcon 231 76 60

# --- notify icon ------------------------------------------------------------
$ni = New-Object System.Windows.Forms.NotifyIcon
$ni.Visible = $true
$menu = New-Object System.Windows.Forms.ContextMenuStrip

function Add-MenuItem($text, $onClick) {
    $item = New-Object System.Windows.Forms.ToolStripMenuItem
    $item.Text = $text
    if ($onClick) { $item.Add_Click($onClick) }
    [void]$menu.Items.Add($item)
    return $item
}

$script:StateItem = Add-MenuItem 'Omotam: ...' $null
$script:StateItem.Enabled = $false
Add-MenuItem 'Open Omotam' { Start-Process (Get-UiUrl) } | Out-Null
Add-MenuItem 'Open control panel' { Start-Process (Get-UiUrl) } | Out-Null
Add-MenuItem '-' $null | Out-Null
Add-MenuItem 'Start service' { Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } | Out-Null
Add-MenuItem 'Restart service' {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
} | Out-Null
Add-MenuItem 'Stop service' { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } | Out-Null
Add-MenuItem '-' $null | Out-Null

$settings = New-Object System.Windows.Forms.ToolStripMenuItem
$settings.Text = 'Settings'
[void]$settings.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripMenuItem -Property @{
    Text = 'Start recording'; }))
$settings.DropDownItems[0].Add_Click({ Invoke-Api 'POST' '/api/settings' @{ record_queries = $true } | Out-Null }) 
[void]$settings.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripMenuItem -Property @{ Text = 'End recording' }))
$settings.DropDownItems[1].Add_Click({ Invoke-Api 'POST' '/api/settings' @{ record_queries = $false } | Out-Null })
[void]$settings.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripMenuItem -Property @{ Text = 'Check for updates' }))
$settings.DropDownItems[2].Add_Click({
    $u = Invoke-Api 'POST' '/api/update/check' $null
    if ($u -and $u.update_available) {
        $ni.ShowBalloonTip(8000, 'Omotam update', "Version $($u.latest) is available.", [System.Windows.Forms.ToolTipIcon]::Info)
    } else {
        $ni.ShowBalloonTip(4000, 'Omotam', 'You are up to date.', [System.Windows.Forms.ToolTipIcon]::Info)
    }
})
[void]$settings.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripMenuItem -Property @{ Text = 'Open config file' }))
$settings.DropDownItems[3].Add_Click({ Start-Process notepad.exe (Join-Path $InstallDir 'dns_hosts.json') })
[void]$settings.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripMenuItem -Property @{ Text = 'Open data folder' }))
$settings.DropDownItems[4].Add_Click({ Start-Process explorer.exe $InstallDir })
[void]$menu.Items.Add($settings)

Add-MenuItem '-' $null | Out-Null
Add-MenuItem 'Exit tray' {
    $ni.Visible = $false
    [System.Windows.Forms.Application]::Exit()
} | Out-Null

$ni.ContextMenuStrip = $menu
$ni.Add_DoubleClick({ Start-Process (Get-UiUrl) })

# --- refresh loop -----------------------------------------------------------
function Update-State {
    $running = Test-OmotamRunning
    if ($running) {
        $ni.Icon = $script:IconOn
        $ni.Text = 'Omotam on'
        $script:StateItem.Text = 'Omotam: on'
    } else {
        $ni.Icon = $script:IconOff
        $ni.Text = 'Omotam off'
        $script:StateItem.Text = 'Omotam: off'
    }
}

Update-State
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 5000
$timer.Add_Tick({ Update-State })
$timer.Start()

[System.Windows.Forms.Application]::Run()
