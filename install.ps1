#Requires -Version 5.1
<#
  omotam installer.

  Retro Windows 98 style GUI setup. Downloads the bundled Python runtime
  (from the GitHub release), installs it, optionally registers a boot service
  and the opencode MCP server, sets up HTTPS + firewall, and prints the URL.

    powershell -ExecutionPolicy Bypass -File .\install.ps1
    powershell -ExecutionPolicy Bypass -File .\install.ps1 -Silent -Service -Mcp -Tls
    powershell -ExecutionPolicy Bypass -File .\install.ps1 -Uninstall
    powershell -ExecutionPolicy Bypass -File .\install.ps1 -RuntimeUrl .\dist\omotam-runtime.zip -Silent -NoService -NoTls -NoMcp -InstallDir $env:TEMP\omotam-test
#>
[CmdletBinding()]
param(
    [string]$InstallDir,
    [string]$RuntimeUrl = 'https://github.com/spacewalkingninja/omotam/releases/latest/download/omotam-runtime.zip',
    [string]$TaskName = 'omotam',
    [switch]$Service,
    [switch]$NoService,
    [switch]$Tray,
    [switch]$NoTray,
    [switch]$Mcp,
    [switch]$NoMcp,
    [switch]$Tls,
    [switch]$NoTls,
    [switch]$Silent,
    [switch]$KeepRuntime,
    [switch]$NoFirewall,
    [switch]$Test,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- elevation
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) -and -not $Test) {
    $argsList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($InstallDir) { $argsList += @('-InstallDir', "`"$InstallDir`"") }
    if ($RuntimeUrl) { $argsList += @('-RuntimeUrl', "`"$RuntimeUrl`"") }
    if ($Service) { $argsList += '-Service' }
    if ($NoService) { $argsList += '-NoService' }
    if ($Tray) { $argsList += '-Tray' }
    if ($NoTray) { $argsList += '-NoTray' }
    if ($Mcp) { $argsList += '-Mcp' }
    if ($NoMcp) { $argsList += '-NoMcp' }
    if ($Tls) { $argsList += '-Tls' }
    if ($NoTls) { $argsList += '-NoTls' }
    if ($Silent) { $argsList += '-Silent' }
    if ($KeepRuntime) { $argsList += '-KeepRuntime' }
    if ($NoFirewall) { $argsList += '-NoFirewall' }
    if ($Test) { $argsList += '-Test' }
    if ($Uninstall) { $argsList += '-Uninstall' }
    Start-Process -FilePath (Get-Process -Id $PID).Path -Verb RunAs -ArgumentList $argsList
    return
}

if (-not $InstallDir) { $InstallDir = Join-Path $env:ProgramData 'omotam' }
$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)

# ---------------------------------------------------------------- helpers
function Add-FirewallRule($name, $proto, $port) {
    if (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue) { return }
    New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow `
        -Protocol $proto -LocalPort $port -Profile Any -ErrorAction SilentlyContinue | Out-Null
}

function Set-HostsEntry($hostname) {
    if (-not $hostname) { return }
    $hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    if (-not (Select-String -Path $hosts -Pattern ([Regex]::Escape($hostname)) -Quiet)) {
        Add-Content -LiteralPath $hosts -Value "127.0.0.1`t$hostname"
    }
}

function Set-OmotamMcpConfig($dir) {
    $cfgDir = Join-Path $env:USERPROFILE '.config\opencode'
    New-Item -ItemType Directory -Force -Path $cfgDir | Out-Null
    $cfgPath = Join-Path $cfgDir 'opencode.jsonc'
    $py = Join-Path $dir 'runtime\python.exe'
    $entry = [ordered]@{
        type    = 'local'
        command = @($py, (Join-Path $dir 'dns_mcp.py'))
        enabled = $true
        env     = [ordered]@{ DNS_API_URL = 'http://127.0.0.1:8080' }
    }
    if (Test-Path -LiteralPath $cfgPath) {
        $raw = Get-Content -LiteralPath $cfgPath -Raw
        $stripped = [Regex]::Replace($raw, '(?m)//.*$', '')
        $stripped = [Regex]::Replace($stripped, '(?s)/\*.*?\*/', '')
        $obj = $stripped.Trim() | ConvertFrom-Json
        if (-not $obj.PSObject.Properties['mcp']) {
            $obj | Add-Member -NotePropertyName mcp -NotePropertyValue ([pscustomobject]@{})
        }
        $obj.mcp | Add-Member -NotePropertyName dns -NotePropertyValue ([pscustomobject]$entry) -Force
        [System.IO.File]::WriteAllText($cfgPath, ($obj | ConvertTo-Json -Depth 20), (New-Object System.Text.UTF8Encoding($false)))
    } else {
        $obj = [pscustomobject]@{ '$schema' = 'https://opencode.ai/config.json'; mcp = [pscustomobject]@{ dns = [pscustomobject]$entry } }
        [System.IO.File]::WriteAllText($cfgPath, ($obj | ConvertTo-Json -Depth 20), (New-Object System.Text.UTF8Encoding($false)))
    }
}

function Get-ConfigValue($cfg, $key, $default) {
    if ($cfg.PSObject.Properties[$key]) { return $cfg.$key } else { return $default }
}

function Register-TrayTask($dir, $trayTask) {
    $user = if ($env:USERDOMAIN) { "$env:USERDOMAIN\$env:USERNAME" } else { $env:USERNAME }
    $tray = Join-Path $dir 'tray.ps1'
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$tray`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskName $trayTask -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Description 'Omotam tray icon' -Force | Out-Null
    Start-ScheduledTask -TaskName $trayTask -ErrorAction SilentlyContinue
}

function Remove-TrayTask($trayTask) {
    if (Get-ScheduledTask -TaskName $trayTask -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $trayTask -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $trayTask -Confirm:$false
    }
}

# ---------------------------------------------------------------- install core
function Invoke-OmotamInstall($opts, $status) {
    $dir = $opts.InstallDir
    & $status "Creating $dir ..."
    New-Item -ItemType Directory -Force -Path $dir | Out-Null

    $py     = Join-Path $dir 'runtime\python.exe'
    $pyw    = Join-Path $dir 'runtime\pythonw.exe'
    $server = Join-Path $dir 'dns_server.py'
    $cfg    = Join-Path $dir 'dns_hosts.json'

    if (-not (Test-Path -LiteralPath $py)) {
        & $status "Downloading runtime ..."
        $zip = Join-Path $env:TEMP 'omotam-runtime.zip'
        if ($opts.RuntimeUrl -match '^https?://') {
            Invoke-WebRequest -Uri $opts.RuntimeUrl -OutFile $zip -UseBasicParsing
        } else {
            Copy-Item -LiteralPath $opts.RuntimeUrl -Destination $zip -Force
        }
        & $status "Extracting runtime ..."
        Expand-Archive -Path $zip -DestinationPath $dir -Force
        if (-not $opts.KeepRuntime) { Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue }
    }

    if (-not (Test-Path -LiteralPath $cfg)) {
        Copy-Item -LiteralPath (Join-Path $dir 'dns_hosts.example.json') -Destination $cfg -Force
    }
    $config = Get-Content -LiteralPath $cfg -Raw | ConvertFrom-Json
    if (-not $config.PSObject.Properties['record_queries']) {
        $config | Add-Member -NotePropertyName record_queries -NotePropertyValue $false
    }
    if ($config.record_queries -ne $false -and $opts.ForceNoRecord) {
        $config.record_queries = $false
    }
    [System.IO.File]::WriteAllText($cfg, ($config | ConvertTo-Json -Depth 20), (New-Object System.Text.UTF8Encoding($false)))

    $guiHost = $config.gui_hostname
    if ($guiHost -is [array]) { $guiHost = $guiHost[0] }
    $dnsPort = if ($config.port) { [int]$config.port } else { 53 }
    $guiPort = if ($config.gui_port) { [int]$config.gui_port } else { 8080 }
    $tlsPort = if ($config.gui_tls_port) { [int]$config.gui_tls_port } else { 443 }

    & $status "Opening firewall ..."
    if ($opts.Firewall) {
        Add-FirewallRule 'omotam DNS (UDP)' 'UDP' $dnsPort
        Add-FirewallRule 'omotam DNS (TCP)' 'TCP' $dnsPort
        Add-FirewallRule 'omotam GUI (HTTP)' 'TCP' $guiPort
        if ($opts.Tls) { Add-FirewallRule 'omotam GUI (HTTPS)' 'TCP' $tlsPort }
    }

    if ($opts.Test) {
        & $status "Testing bundled runtime ..."
        Push-Location $dir
        & $py -c "import ssl, json, socket, cryptography; print('bundled deps OK', cryptography.__version__)"
        foreach ($f in 'dns_server.py', 'dns_mcp.py', 'update.ps1', 'uninstall.ps1') {
            if (-not (Test-Path -LiteralPath (Join-Path $dir $f))) { throw "missing $f after extract" }
        }
        Pop-Location
        return [pscustomobject]@{ Dir = $dir; GuiHost = $guiHost; GuiPort = $guiPort; Tls = $false }
    }

    if ($opts.Tls) {
        & $status "Generating HTTPS certificate ..."
        try {
            & $py $server --config $cfg --ensure-cert | Out-Null
            $ca = (& $py $server --config $cfg --print-ca | Select-Object -Last 1).Trim()
            if ($ca -and (Test-Path -LiteralPath $ca)) {
                Import-Certificate -FilePath $ca -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
            }
        } catch { & $status "TLS setup warning: $($_.Exception.Message)" }
        Set-HostsEntry $guiHost
    }

    if ($opts.Service) {
        & $status "Registering startup service ..."
        $action = New-ScheduledTaskAction -Execute $pyw -Argument "`"$server`" --config `"$cfg`"" -WorkingDirectory $dir
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $tprincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
            -Principal $tprincipal -Settings $settings -Description 'omotam DNS resolver' -Force | Out-Null
        Start-ScheduledTask -TaskName $TaskName
    }

    if ($opts.Tray) {
        & $status "Registering tray icon ..."
        try { Register-TrayTask $dir 'omotam-tray' } catch { & $status "Tray warning: $($_.Exception.Message)" }
    }

    if ($opts.Mcp) {
        & $status "Registering opencode MCP ..."
        try { Set-OmotamMcpConfig $dir } catch { & $status "MCP config warning: $($_.Exception.Message)" }
    }

    & $status "Done."
    return [pscustomobject]@{ Dir = $dir; GuiHost = $guiHost; GuiPort = $guiPort; Tls = [bool]$opts.Tls }
}

function Invoke-OmotamUninstall($status) {
    & $status "Stopping service ..."
    Remove-TrayTask 'omotam-tray'
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    foreach ($n in 'omotam DNS (UDP)', 'omotam DNS (TCP)', 'omotam GUI (HTTP)', 'omotam GUI (HTTPS)') {
        if (Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue) { Remove-NetFirewallRule -DisplayName $n }
    }
    $hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    [System.IO.File]::WriteAllLines($hosts, ((Get-Content -LiteralPath $hosts) | Where-Object { $_ -notmatch '\bdns\.settings\b' }), (New-Object System.Text.UTF8Encoding($false)))
    foreach ($c in (Get-ChildItem 'Cert:\LocalMachine\Root' | Where-Object { $_.Subject -like '*Custom DNS Local CA*' })) {
        Remove-Item -LiteralPath $c.PSPath -Force -ErrorAction SilentlyContinue
    }
    & $status "Removing files ..."
    if (Test-Path -LiteralPath $InstallDir) { Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue }
    & $status "Uninstalled."
}

# ---------------------------------------------------------------- silent path
if ($Silent) {
    $opts = [pscustomobject]@{
        InstallDir     = $InstallDir
        RuntimeUrl     = $RuntimeUrl
        Service        = -not $NoService -and ($Service -or -not ($Service -or $NoService))
        Tray           = -not $NoTray -and ($Tray -or -not ($Tray -or $NoTray))
        Mcp            = -not $NoMcp -and ($Mcp -or -not ($Mcp -or $NoMcp))
        Tls            = -not $NoTls -and ($Tls -or -not ($Tls -or $NoTls))
        KeepRuntime    = [bool]$KeepRuntime
        ForceNoRecord  = $true
        Firewall       = -not $NoFirewall
        Test           = [bool]$Test
    }
    $log = { param($m) Write-Host "[omotam] $m" }
    if ($Uninstall) { Invoke-OmotamUninstall $log }
    else {
        $res = Invoke-OmotamInstall $opts $log
        $url = if ($res.Tls) { "https://$($res.GuiHost)/" } else { "http://127.0.0.1:$($res.GuiPort)/" }
        Write-Host "[omotam] Installed to $($res.Dir)"
        Write-Host "[omotam] Open $url"
    }
    return
}

# ---------------------------------------------------------------- GUI (Win98)
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = 'omotam Setup'
$form.Size = New-Object System.Drawing.Size(470, 440)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.BackColor = [System.Drawing.Color]::FromArgb(192, 192, 192)
$form.Font = New-Object System.Drawing.Font('MS Sans Serif', 8)
$form.ForeColor = [System.Drawing.Color]::Black

$header = New-Object System.Windows.Forms.Panel
$header.Dock = 'Top'
$header.Height = 56
$header.Add_Paint({
    param($s, $e)
    $rect = New-Object System.Drawing.Rectangle(0, 0, $s.Width, $s.Height)
    $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush($rect,
        [System.Drawing.Color]::FromArgb(0, 0, 128), [System.Drawing.Color]::FromArgb(16, 132, 208), 0)
    $e.Graphics.FillRectangle($brush, $rect)
    $f = New-Object System.Drawing.Font('MS Sans Serif', 20, [System.Drawing.FontStyle]::Bold)
    $e.Graphics.DrawString('omotam Setup', $f, [System.Drawing.Brushes]::White, 16, 12)
    $brush.Dispose(); $f.Dispose()
})
$form.Controls.Add($header)

$y = 72
$lbl = New-Object System.Windows.Forms.Label
$lbl.Text = 'Install omotam DNS resolver to:'
$lbl.Location = New-Object System.Drawing.Point(16, $y)
$lbl.AutoSize = $true
$form.Controls.Add($lbl)

$txtDir = New-Object System.Windows.Forms.TextBox
$txtDir.Location = New-Object System.Drawing.Point(16, ($y + 18))
$txtDir.Size = New-Object System.Drawing.Size(330, 22)
$txtDir.Text = $InstallDir
$form.Controls.Add($txtDir)

$btnBrowse = New-Object System.Windows.Forms.Button
$btnBrowse.Text = 'Browse...'
$btnBrowse.Location = New-Object System.Drawing.Point(352, ($y + 17))
$btnBrowse.Size = New-Object System.Drawing.Size(80, 24)
$btnBrowse.Add_Click({
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.SelectedPath = $txtDir.Text
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $txtDir.Text = $dlg.SelectedPath }
})
$form.Controls.Add($btnBrowse)

$grp = New-Object System.Windows.Forms.GroupBox
$grp.Text = 'Options'
$grp.Location = New-Object System.Drawing.Point(16, ($y + 54))
$grp.Size = New-Object System.Drawing.Size(420, 158)
$form.Controls.Add($grp)

$chkService = New-Object System.Windows.Forms.CheckBox
$chkService.Text = 'Run as a background service on startup (recommended)'
$chkService.Location = New-Object System.Drawing.Point(12, 22)
$chkService.Size = New-Object System.Drawing.Size(395, 20)
$chkService.Checked = $true
$grp.Controls.Add($chkService)

$chkTray = New-Object System.Windows.Forms.CheckBox
$chkTray.Text = 'Add the Omotam tray icon (on/off, opens the UI)'
$chkTray.Location = New-Object System.Drawing.Point(12, 48)
$chkTray.Size = New-Object System.Drawing.Size(395, 20)
$chkTray.Checked = $true
$grp.Controls.Add($chkTray)

$chkMcp = New-Object System.Windows.Forms.CheckBox
$chkMcp.Text = 'Register omotam MCP server in opencode'
$chkMcp.Location = New-Object System.Drawing.Point(12, 74)
$chkMcp.Size = New-Object System.Drawing.Size(395, 20)
$chkMcp.Checked = $true
$grp.Controls.Add($chkMcp)

$chkTls = New-Object System.Windows.Forms.CheckBox
$chkTls.Text = 'Enable HTTPS (dns.settings) and trust the local certificate'
$chkTls.Location = New-Object System.Drawing.Point(12, 100)
$chkTls.Size = New-Object System.Drawing.Size(395, 20)
$chkTls.Checked = $true
$grp.Controls.Add($chkTls)

$chkRec = New-Object System.Windows.Forms.CheckBox
$chkRec.Text = 'Record DNS requests (off by default; can be enabled later in the GUI)'
$chkRec.Location = New-Object System.Drawing.Point(12, 126)
$chkRec.Size = New-Object System.Drawing.Size(395, 20)
$chkRec.Checked = $false
$grp.Controls.Add($chkRec)

$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Location = New-Object System.Drawing.Point(16, ($y + 220))
$lblStatus.Size = New-Object System.Drawing.Size(420, 20)
$lblStatus.Text = 'Ready to install.'
$form.Controls.Add($lblStatus)

$progress = New-Object System.Windows.Forms.ProgressBar
$progress.Location = New-Object System.Drawing.Point(16, ($y + 242))
$progress.Size = New-Object System.Drawing.Size(420, 16)
$progress.Style = 'Marquee'
$progress.MarqueeAnimationSpeed = 0
$form.Controls.Add($progress)

$btnInstall = New-Object System.Windows.Forms.Button
$btnInstall.Text = 'Install'
$btnInstall.Location = New-Object System.Drawing.Point(272, ($y + 244))
$btnInstall.Size = New-Object System.Drawing.Size(78, 26)
$form.Controls.Add($btnInstall)

$btnQuit = New-Object System.Windows.Forms.Button
$btnQuit.Text = 'Quit'
$btnQuit.Location = New-Object System.Drawing.Point(356, ($y + 244))
$btnQuit.Size = New-Object System.Drawing.Size(78, 26)
$btnQuit.Add_Click({ $form.Close() })
$form.Controls.Add($btnQuit)

$script:statusBlock = {
    param($m)
    $lblStatus.Text = $m
    $form.Refresh()
    [System.Windows.Forms.Application]::DoEvents()
}

$btnInstall.Add_Click({
    $btnInstall.Enabled = $false; $btnQuit.Enabled = $false; $btnBrowse.Enabled = $false
    $progress.MarqueeAnimationSpeed = 30
    try {
        $opts = [pscustomobject]@{
            InstallDir    = $txtDir.Text
            RuntimeUrl    = $RuntimeUrl
            Service       = $chkService.Checked
            Tray          = $chkTray.Checked
            Mcp           = $chkMcp.Checked
            Tls           = $chkTls.Checked
            KeepRuntime   = [bool]$KeepRuntime
            ForceNoRecord = -not $chkRec.Checked
            Firewall      = -not $NoFirewall
            Test          = $false
        }
        $res = Invoke-OmotamInstall $opts $script:statusBlock
        $progress.MarqueeAnimationSpeed = 0
        $url = if ($res.Tls) { "https://$($res.GuiHost)/" } else { "http://127.0.0.1:$($res.GuiPort)/" }
        [System.Windows.Forms.MessageBox]::Show(
            "omotam is installed.`n`nInstall dir: $($res.Dir)`nOpen: $url`n`nIf you enabled the service, DNS is now served on this machine.",
            'omotam Setup', 'OK', 'Information') | Out-Null
        $form.Close()
    } catch {
        $progress.MarqueeAnimationSpeed = 0
        [System.Windows.Forms.MessageBox]::Show("Install failed:`n`n$($_.Exception.Message)", 'omotam Setup', 'OK', 'Error') | Out-Null
        $btnInstall.Enabled = $true; $btnQuit.Enabled = $true; $btnBrowse.Enabled = $true
    }
})

[void]$form.ShowDialog()
