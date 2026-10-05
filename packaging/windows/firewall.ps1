<#
.SYNOPSIS
  Block all network traffic for the Airlock privacy engine (for administrators).

.DESCRIPTION
  The engine never needs the network; it already blocks itself in-process.
  This adds the same Windows Firewall rules the all-users installer creates,
  for per-user installs or deployment through Group Policy / Intune.
  Run in an elevated PowerShell.

.PARAMETER EnginePath
  Full path to airlock-engine.exe. By default the usual install locations are tried.

.PARAMETER Remove
  Remove the rules instead of adding them.
#>
param(
  [string]$EnginePath = "",
  [switch]$Remove
)

$ErrorActionPreference = "Stop"
$name = "Airlock privacy engine (no network)"

Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule
if ($Remove) {
  Write-Host "Removed the Airlock firewall rules."
  exit 0
}
if (-not $EnginePath) {
  $EnginePath = @(
    "$env:ProgramFiles\Airlock\engine\airlock-engine.exe",
    "$env:LOCALAPPDATA\Airlock\engine\airlock-engine.exe",
    "$env:LOCALAPPDATA\Programs\Airlock\engine\airlock-engine.exe"
  ) | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $EnginePath -or -not (Test-Path $EnginePath)) {
  throw "Engine not found at $EnginePath. Pass -EnginePath."
}
foreach ($direction in "Outbound", "Inbound") {
  New-NetFirewallRule -DisplayName $name -Direction $direction -Action Block `
    -Program $EnginePath -Profile Any | Out-Null
}
Write-Host "Blocked all network traffic for $EnginePath."
