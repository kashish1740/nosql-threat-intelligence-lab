<#
.SYNOPSIS
  Read-only security scan of this Windows PC for the Threat Intelligence Lab dashboard.

.DESCRIPTION
  Collects, without changing anything:
    - Windows version and the most recent installed updates
    - installed programs and their versions
    - Microsoft Defender status and the threats Defender has detected
    - Windows Firewall profiles
    - programs listening on network ports, and the public IPs this PC is connected to
  and sends them to the dashboard (http://localhost:8000 by default), which stores the scan in
  MongoDB (threat_lab.pc_scans) and checks it against threat intelligence. Nothing is sent anywhere else.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\scan-pc.ps1
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\scan-pc.ps1 -OutFile scan.json   # save only, do not send
#>
param(
  [string]$Dashboard = "http://localhost:8000",
  [string]$OutFile = ""
)
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

function Get-Iso($date) { if ($date) { try { return ([datetime]$date).ToUniversalTime().ToString("o") } catch { } }; return $null }

Write-Host "Scanning this PC (read-only)..." -ForegroundColor Cyan

# --- Windows version and updates
$os = Get-CimInstance Win32_OperatingSystem
$cv = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$hotfixes = @(Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 10 |
  ForEach-Object { [ordered]@{ id = $_.HotFixID; description = $_.Description; installed_on = (Get-Iso $_.InstalledOn) } })
$system = [ordered]@{
  computer      = $env:COMPUTERNAME
  os_name       = $os.Caption
  os_version    = $os.Version
  build         = [int]$os.BuildNumber
  ubr           = $cv.UBR
  display_version = $cv.DisplayVersion
  architecture  = $os.OSArchitecture
  last_boot     = (Get-Iso $os.LastBootUpTime)
  hotfixes      = $hotfixes
}
Write-Host ("  Windows: {0} (build {1}.{2})" -f $os.Caption, $os.BuildNumber, $cv.UBR)

# --- Installed programs (machine-wide 64/32-bit and current user)
$keys = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
          "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
          "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*")
$seen = @{}
$software = @(foreach ($k in $keys) {
  Get-ItemProperty $k | Where-Object { $_.DisplayName -and $_.SystemComponent -ne 1 -and -not $_.ParentKeyName } | ForEach-Object {
    $name = ($_.DisplayName -as [string]).Trim()
    $ver = ($_.DisplayVersion -as [string])
    $key = "$name|$ver"
    if (-not $seen.ContainsKey($key)) {
      $seen[$key] = $true
      [ordered]@{ name = $name; version = $ver; publisher = ($_.Publisher -as [string]); installed = ($_.InstallDate -as [string]) }
    }
  }
})
Write-Host ("  Installed programs: {0}" -f $software.Count)

# --- Microsoft Defender
$defender = [ordered]@{ available = $false }
$mp = Get-MpComputerStatus
if ($mp) {
  $defender = [ordered]@{
    available                 = $true
    antivirus_enabled         = [bool]$mp.AntivirusEnabled
    service_enabled           = [bool]$mp.AMServiceEnabled
    real_time_protection      = [bool]$mp.RealTimeProtectionEnabled
    behavior_monitor          = [bool]$mp.BehaviorMonitorEnabled
    tamper_protection         = [bool]$mp.IsTamperProtected
    signatures_updated        = (Get-Iso $mp.AntivirusSignatureLastUpdated)
    signature_version         = $mp.AntivirusSignatureVersion
    quick_scan_end            = (Get-Iso $mp.QuickScanEndTime)
    full_scan_end             = (Get-Iso $mp.FullScanEndTime)
    running_mode              = $mp.AMRunningMode
  }
  $threatNames = @{}
  foreach ($t in @(Get-MpThreat)) { $threatNames[[string]$t.ThreatID] = $t }
  $defender.detections = @(Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 50 | ForEach-Object {
    $t = $threatNames[[string]$_.ThreatID]
    [ordered]@{
      threat_id       = [string]$_.ThreatID
      name            = $(if ($t) { $t.ThreatName } else { "Threat $($_.ThreatID)" })
      severity_id     = $(if ($t) { [int]$t.SeverityID } else { 0 })
      category_id     = $(if ($t) { [int]$t.CategoryID } else { 0 })
      active          = $(if ($t) { [bool]$t.IsActive } else { $false })
      status_id       = [int]$_.ThreatStatusID
      action_success  = [bool]$_.ActionSuccess
      detected        = (Get-Iso $_.InitialDetectionTime)
      remediated      = (Get-Iso $_.RemediationTime)
      resources       = @($_.Resources | Select-Object -First 3)
      process         = $_.ProcessName
    }
  })
  Write-Host ("  Defender: real-time protection {0}, {1} detection(s) on record" -f $(if ($mp.RealTimeProtectionEnabled) { "ON" } else { "OFF" }), $defender.detections.Count)
} else {
  Write-Host "  Defender: status not available (another antivirus may be installed)"
}

# --- Firewall
$firewall = @(Get-NetFirewallProfile | ForEach-Object { [ordered]@{ profile = $_.Name; enabled = [bool]($_.Enabled -eq $true -or $_.Enabled -eq 1) } })

# --- Network: listening ports and established connections to public IPs
$procs = @{}
Get-Process | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
$listening = @(Get-NetTCPConnection -State Listen | Sort-Object LocalPort -Unique | ForEach-Object {
  [ordered]@{ address = $_.LocalAddress; port = [int]$_.LocalPort; process = $procs[[int]$_.OwningProcess] }
})
function Test-PublicIp([string]$ip) {
  if (-not $ip -or $ip -match '^(127\.|10\.|192\.168\.|169\.254\.|0\.|::1$|::$|fe80:|fc|fd)' -or $ip -match '^172\.(1[6-9]|2\d|3[01])\.') { return $false }
  return $true
}
$connections = @(Get-NetTCPConnection -State Established | Where-Object { Test-PublicIp $_.RemoteAddress } |
  Sort-Object RemoteAddress, RemotePort -Unique | Select-Object -First 300 | ForEach-Object {
  [ordered]@{ remote_ip = $_.RemoteAddress; remote_port = [int]$_.RemotePort; process = $procs[[int]$_.OwningProcess] }
})
Write-Host ("  Network: {0} listening port(s), {1} connection(s) to public IPs" -f $listening.Count, $connections.Count)

$scan = [ordered]@{
  scanner     = "scan-pc.ps1 v1"
  scanned_at  = (Get-Date).ToUniversalTime().ToString("o")
  system      = $system
  software    = $software
  defender    = $defender
  firewall    = $firewall
  listening   = $listening
  connections = $connections
}
$json = $scan | ConvertTo-Json -Depth 8 -Compress

if ($OutFile) {
  [System.IO.File]::WriteAllText((Join-Path (Get-Location) $OutFile), $json, (New-Object System.Text.UTF8Encoding($false)))
  Write-Host "Saved to $OutFile (not sent)." -ForegroundColor Green
  exit 0
}

Write-Host "Sending to $Dashboard and checking it against threat intelligence..." -ForegroundColor Cyan
try {
  $ErrorActionPreference = "Stop"
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
  $resp = Invoke-WebRequest -Uri "$Dashboard/api/pc/scans" -Method Post -ContentType "application/json; charset=utf-8" -Body $bytes -TimeoutSec 300 -UseBasicParsing
  # Windows PowerShell 5 would read the reply as Latin-1; decode it as UTF-8 so dashes and arrows print correctly.
  $r = [System.Text.Encoding]::UTF8.GetString($resp.RawContentStream.ToArray()) | ConvertFrom-Json
  Write-Host ""
  Write-Host ("Result: {0}  (risk score {1}/100)" -f $r.verdict, $r.risk_score) -ForegroundColor Yellow
  foreach ($f in @($r.findings | Select-Object -First 10)) { Write-Host ("  [{0}] {1}" -f $f.severity.ToUpper(), $f.title) }
  if (@($r.findings).Count -gt 10) { Write-Host ("  ... and {0} more" -f (@($r.findings).Count - 10)) }
  Write-Host ""
  Write-Host "Open $Dashboard/#pc for the full report, or ask the Threat Assistant: 'what threats are on my PC?'" -ForegroundColor Green
} catch {
  Write-Host "Could not reach the dashboard at $Dashboard. Is it running? ($($_.Exception.Message))" -ForegroundColor Red
  exit 1
}
