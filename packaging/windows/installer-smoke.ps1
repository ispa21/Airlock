<#
.SYNOPSIS
  Install Airlock silently for all users, check it works, then uninstall it.

.DESCRIPTION
  Used by the Windows packaging workflow on a fresh runner, and usable by
  hand on a clean test VM (elevated PowerShell). Checks:
    1. The installer finishes and places the app and the frozen engine.
    2. The all-users install added the two firewall rules for the engine.
    3. The installed engine passes the stdio smoke test (language model,
       OCR, PDF, verification), run from the repository's engine folder.
    4. Chrome and Edge find the engine as the extension's native-messaging
       host, and the engine answers the way the extension expects
       (packaging/bridge_smoke.py does what the browser does).
    5. The installed app starts and its host completes the engine handshake
       (the host checks the engine's SHA-256 first).
    6. Closing the app leaves no engine process behind.
    7. With -TauriDriver: the UI end-to-end test on the installed app
       (scripts/desktop_e2e.py through tauri-driver and the msedgedriver
       matching the WebView2 runtime): drop a file, scan, create and verify
       a copy, Copy Text for AI, check the clipboard and the log, kill the
       engine and recover, close the window with no process left.
    8. The silent uninstall removes the files, the firewall rules and the
       browser registrations.

.PARAMETER Installer
  Path to Airlock_<version>_x64-setup.exe.

.PARAMETER TauriDriver
  Path to tauri-driver.exe (cargo install tauri-driver). Without it the UI
  test is skipped.
#>
param(
  [Parameter(Mandatory = $true)][string]$Installer,
  [string]$TauriDriver
)

$ErrorActionPreference = "Stop"
$rule = "Airlock privacy engine (no network)"
$dir = Join-Path $env:ProgramFiles "Airlock"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$temp = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $env:TEMP }

function Step($text) { Write-Host "`n== $text" }

$hostKeys = @(
  "Software\Google\Chrome\NativeMessagingHosts\com.airlock.engine",
  "Software\Microsoft\Edge\NativeMessagingHosts\com.airlock.engine"
)

# The browsers read both registry views; the installer may write either.
function HostManifest($key) {
  foreach ($view in [Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32) {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
    $k = $base.OpenSubKey($key)
    if ($k) {
      $value = $k.GetValue("")
      $k.Close()
      if ($value) { return $value }
    }
  }
  return $null
}

Step "Install for all users (silent)"
$p = Start-Process -FilePath $Installer -ArgumentList "/S", "/ALLUSERS" -Wait -PassThru
if ($p.ExitCode -ne 0) { throw "installer exited with code $($p.ExitCode)" }
$engine = Join-Path $dir "engine\airlock-engine.exe"
$app = Get-ChildItem $dir -Filter *.exe | Where-Object { $_.Name -notmatch "uninstall" } | Select-Object -First 1
if (-not (Test-Path $engine) -or -not $app) {
  Get-ChildItem $dir -Depth 1 | Out-Host
  throw "app or engine missing after install"
}
$size = (Get-ChildItem $dir -Recurse -File | Measure-Object Length -Sum).Sum / 1MB
Write-Host ("installed {0} and the engine ({1:N0} MB)" -f $app.Name, $size)

Step "Firewall rules"
$rules = @(Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue)
if ($rules.Count -ne 2) { throw "expected 2 firewall rules, found $($rules.Count)" }
$rules | ForEach-Object { Write-Host "$($_.Direction) $($_.Action) $($_.Enabled)" }

Step "Installed engine smoke test"
Push-Location (Join-Path $repo "engine")
try {
  uv run python packaging/smoke.py $engine (Join-Path $temp "airlock-smoke")
  if ($LASTEXITCODE -ne 0) { throw "engine smoke test failed" }
} finally { Pop-Location }

Step "Browser extension host (Chrome and Edge)"
$manifest = Join-Path $dir "native-messaging-host.json"
foreach ($key in $hostKeys) {
  $value = HostManifest $key
  if ($value -ne $manifest) { throw "HKLM\$key is '$value', expected '$manifest'" }
}
if (-not (Test-Path $manifest)) { throw "the host manifest was not installed" }
Write-Host "registered for Chrome and Edge: $manifest"
Push-Location (Join-Path $repo "engine")
try {
  uv run python packaging/bridge_smoke.py $manifest
  if ($LASTEXITCODE -ne 0) { throw "bridge smoke test failed" }
} finally { Pop-Location }

Step "App starts and its host completes the engine handshake"
$log = Join-Path $env:LOCALAPPDATA "com.airlock.desktop\logs\airlock.log"
Remove-Item $log -ErrorAction SilentlyContinue
$proc = Start-Process -FilePath $app.FullName -PassThru
$ready = $false
for ($i = 0; $i -lt 60 -and -not $ready; $i++) {
  Start-Sleep -Seconds 2
  $ready = (Test-Path $log) -and (Select-String -Path $log -Pattern '"event":"engine_ready"' -Quiet)
}
if (-not $ready) {
  if (Test-Path $log) { Get-Content $log | Out-Host }
  throw "the app did not start the engine"
}
if (Select-String -Path $log -Pattern 'engine_integrity_failed' -Quiet) { throw "engine integrity check failed" }
Write-Host "host log: engine_ready"

Step "Closing the app leaves no engine behind"
Stop-Process -Id $proc.Id -Force
$left = $true
for ($i = 0; $i -lt 15 -and $left; $i++) {
  Start-Sleep -Seconds 1
  $left = [bool](Get-Process -Name "airlock-engine" -ErrorAction SilentlyContinue)
}
if ($left) { throw "airlock-engine is still running after the app closed" }

if ($TauriDriver) {
  Step "UI end to end through WebDriver (tauri-driver)"
  $edgeDriver = & (Join-Path $PSScriptRoot "edgedriver.ps1") -Destination (Join-Path $temp "msedgedriver")
  Push-Location (Join-Path $repo "engine")
  try {
    uv run python ../scripts/desktop_e2e.py --app $app.FullName --log $log `
      --driver $TauriDriver --native-driver $edgeDriver --work (Join-Path $temp "airlock-e2e")
    if ($LASTEXITCODE -ne 0) { throw "UI end-to-end test failed" }
  } finally { Pop-Location }
} else {
  Write-Host "`n(UI end-to-end test skipped: no -TauriDriver)"
}

Step "Uninstall (silent)"
$uninstaller = Join-Path $dir "uninstall.exe"
Start-Process -FilePath $uninstaller -ArgumentList "/S" -Wait
for ($i = 0; $i -lt 60 -and (Test-Path $engine); $i++) { Start-Sleep -Seconds 2 }
if (Test-Path $engine) { throw "the engine is still installed after uninstalling" }
$rules = @(Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue)
if ($rules.Count -ne 0) { throw "firewall rules left after uninstalling" }
foreach ($key in $hostKeys) {
  if (HostManifest $key) { throw "HKLM\$key left after uninstalling" }
}

Write-Host "`ninstaller smoke test passed"
