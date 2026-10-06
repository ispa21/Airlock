<#
.SYNOPSIS
  Download the msedgedriver that matches the installed WebView2 runtime.

.DESCRIPTION
  tauri-driver drives the app through msedgedriver, which must have exactly
  the WebView2 runtime's version. Reads that version from EdgeUpdate's
  registry entry (or the runtime's folder), downloads the driver for it and
  prints the path to msedgedriver.exe. Used only to test; never shipped.

.PARAMETER Destination
  Folder for the driver.
#>
param([Parameter(Mandatory = $true)][string]$Destination)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function WebView2Version {
  $client = "Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
  foreach ($key in "HKLM:\SOFTWARE\WOW6432Node\$client", "HKLM:\SOFTWARE\$client", "HKCU:\Software\$client") {
    $pv = (Get-ItemProperty -Path $key -ErrorAction SilentlyContinue).pv
    if ($pv -and $pv -ne "0.0.0.0") { return $pv }
  }
  $folder = Join-Path ${env:ProgramFiles(x86)} "Microsoft\EdgeWebView\Application"
  $versions = Get-ChildItem $folder -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^\d+(\.\d+){3}$' -and (Test-Path (Join-Path $_.FullName "msedgewebview2.exe")) } |
    ForEach-Object { [version]$_.Name } | Sort-Object -Descending
  if ($versions) { return $versions[0].ToString() }
  throw "the WebView2 runtime is not installed"
}

$version = WebView2Version
$exe = Join-Path $Destination "msedgedriver.exe"
if (-not ((Test-Path $exe) -and ((& $exe --version) -match [regex]::Escape($version)))) {
  New-Item -ItemType Directory -Force -Path $Destination | Out-Null
  $zip = Join-Path $Destination "edgedriver_win64.zip"
  $downloaded = $false
  foreach ($site in "https://msedgedriver.microsoft.com", "https://msedgedriver.azureedge.net") {
    try {
      Invoke-WebRequest -Uri "$site/$version/edgedriver_win64.zip" -OutFile $zip -UseBasicParsing
      $downloaded = $true
      break
    } catch {
      Write-Host "msedgedriver $version not available from $site"
    }
  }
  if (-not $downloaded) { throw "no msedgedriver for WebView2 $version" }
  Expand-Archive -Path $zip -DestinationPath $Destination -Force
  Remove-Item $zip
}
$reported = & $exe --version
if ($reported -notmatch [regex]::Escape($version)) { throw "msedgedriver reports '$reported', expected $version" }
Write-Host "WebView2 $version; $reported"
$exe
