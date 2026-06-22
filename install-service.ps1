# ─────────────────────────────────────────────────────────────────────────────
# SecTool — install as a Windows service via NSSM.
# Run this ELEVATED (Administrator). It will:
#   1. Install NSSM (via winget) if it isn't already present.
#   2. Stop any temporary SecTool instance so port 5514 is free.
#   3. (Re)create the "SecTool" service -> node src/index.ts, auto-start on boot,
#      with logging and automatic restart on crash.
#   4. Start it and show the status.
# ─────────────────────────────────────────────────────────────────────────────
$ErrorActionPreference = "Stop"
$ServiceName = "SecTool"
$ProjectDir  = $PSScriptRoot

function Fail($msg) { Write-Host "ERROR: $msg" -ForegroundColor Red; Read-Host "Press Enter to close"; exit 1 }

# --- Must be elevated ---------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Fail "This script must be run as Administrator (right-click PowerShell -> Run as administrator)." }

# --- Locate node --------------------------------------------------------------
$node = (Get-Command node -ErrorAction SilentlyContinue).Source
if (-not $node) { $node = "C:\Program Files\nodejs\node.exe" }
if (-not (Test-Path $node)) { Fail "node.exe not found. Install Node.js or edit `$node in this script." }

$entry = Join-Path $ProjectDir "src\index.ts"
if (-not (Test-Path $entry)) { Fail "Could not find $entry. Run this script from the SecTool folder." }
Write-Host "node : $node"
Write-Host "entry: $entry"

# --- Ensure NSSM --------------------------------------------------------------
function Resolve-Nssm {
  $c = (Get-Command nssm -ErrorAction SilentlyContinue).Source
  if ($c) { return $c }
  $roots = @("$env:LOCALAPPDATA\Microsoft\WinGet\Packages", "$env:ProgramData\Microsoft\WinGet\Packages",
             "$env:LOCALAPPDATA\Microsoft\WinGet\Links")
  foreach ($r in $roots) {
    if (Test-Path $r) {
      $hit = Get-ChildItem $r -Recurse -Filter nssm.exe -ErrorAction SilentlyContinue |
             Where-Object { $_.FullName -match 'win64' } | Select-Object -First 1
      if (-not $hit) { $hit = Get-ChildItem $r -Recurse -Filter nssm.exe -ErrorAction SilentlyContinue | Select-Object -First 1 }
      if ($hit) { return $hit.FullName }
    }
  }
  return $null
}

$nssm = Resolve-Nssm
if (-not $nssm) {
  Write-Host "Installing NSSM via winget..." -ForegroundColor Cyan
  winget install --id NSSM.NSSM -e --source winget --accept-source-agreements --accept-package-agreements --disable-interactivity | Out-Host
  $nssm = Resolve-Nssm
}
if (-not $nssm) { Fail "NSSM install failed or nssm.exe not found. Install it manually from https://nssm.cc and re-run." }
Write-Host "nssm : $nssm"

# --- Stop any temporary instances holding the port ----------------------------
Write-Host "Stopping any running SecTool instances..." -ForegroundColor Cyan
Get-CimInstance Win32_Process -Filter "Name='node.exe'" -ErrorAction SilentlyContinue |
  Where-Object { $_.CommandLine -and $_.CommandLine -match 'SecTool|index\.ts' } |
  ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop; Write-Host "  stopped pid $($_.ProcessId)" } catch {} }

# --- Recreate the service (idempotent) ---------------------------------------
if (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
  Write-Host "Removing existing $ServiceName service..." -ForegroundColor Cyan
  & $nssm stop $ServiceName 2>$null | Out-Null
  & $nssm remove $ServiceName confirm | Out-Host
  Start-Sleep -Seconds 1
}

Write-Host "Creating $ServiceName service..." -ForegroundColor Cyan
& $nssm install $ServiceName $node $entry | Out-Host
& $nssm set $ServiceName AppDirectory $ProjectDir | Out-Null
& $nssm set $ServiceName DisplayName "SecTool UDM Sentinel" | Out-Null
& $nssm set $ServiceName Description "Ingests UDM Pro IDS/IPS syslog, summarizes via Claude, posts to Discord." | Out-Null
& $nssm set $ServiceName Start SERVICE_AUTO_START | Out-Null
& $nssm set $ServiceName AppStdout (Join-Path $ProjectDir "service.out.log") | Out-Null
& $nssm set $ServiceName AppStderr (Join-Path $ProjectDir "service.err.log") | Out-Null
& $nssm set $ServiceName AppRotateFiles 1 | Out-Null
& $nssm set $ServiceName AppRotateBytes 10485760 | Out-Null
& $nssm set $ServiceName AppExit Default Restart | Out-Null
& $nssm set $ServiceName AppRestartDelay 5000 | Out-Null

# --- Run as the user account so SSH-based Mongo polling works ------------------
# The watcher uses SSH key auth, which needs the user's key/known_hosts. Running
# as LocalSystem would not have access to them, so configure a user logon.
Write-Host ""
Write-Host "The service polls the UDM over SSH, which needs YOUR user's SSH key." -ForegroundColor Cyan
$default = "$env:USERDOMAIN\$env:USERNAME"
$acct = Read-Host "Run the service as which account? (Enter for $default)"
if (-not $acct) { $acct = $default }
$sec = Read-Host "Windows password for $acct (input hidden)" -AsSecureString
$bstr  = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
$plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
# nssm grants "Log on as a service" to the account automatically.
& $nssm set $ServiceName ObjectName $acct $plain | Out-Host
$plain = $null
Write-Host "Service will run as $acct." -ForegroundColor Green

Write-Host "Starting $ServiceName..." -ForegroundColor Cyan
& $nssm start $ServiceName | Out-Host
Start-Sleep -Seconds 3

$svc = Get-Service $ServiceName -ErrorAction SilentlyContinue
Write-Host ""
if ($svc -and $svc.Status -eq 'Running') {
  Write-Host "SUCCESS: $ServiceName is RUNNING and set to auto-start on boot." -ForegroundColor Green
  Write-Host "Logs: $ProjectDir\service.out.log  /  service.err.log"
} else {
  Write-Host "Service status: $($svc.Status). Check $ProjectDir\service.err.log for details." -ForegroundColor Yellow
}
Write-Host ""
Write-Host "Manage it later with:  nssm restart $ServiceName  |  nssm stop $ServiceName  |  Get-Service $ServiceName"
Read-Host "Press Enter to close"
