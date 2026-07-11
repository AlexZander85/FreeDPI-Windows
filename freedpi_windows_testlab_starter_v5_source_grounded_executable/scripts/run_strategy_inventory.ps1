<#
.SYNOPSIS
  Runs tools/strategy_inventory.py against a running FreeDPI-Windows instance
  (requires the 'qa' Cargo feature per docs/windows_test_control_contract.md).
  Falls back to static source scanning if the live endpoint isn't available yet.
#>
param(
    [string]$BaseUrl = "http://127.0.0.1:11337",
    [string]$ApiKey = $env:FREEDPI_API_KEY,
    [string]$RepoPath = "..\FreeDPI-Windows-master",
    [string]$OutDir = "testlab_results"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

if (-not $ApiKey) {
    Write-Warning "FREEDPI_API_KEY not set. Trying anyway (will fail auth if the API requires a key)."
}

Write-Host "Attempting live strategy inventory ..."
$liveExit = 0
try {
    python tools\strategy_inventory.py --base-url $BaseUrl --api-key $ApiKey `
        --out (Join-Path $OutDir "strategy_inventory")
    $liveExit = $LASTEXITCODE
} catch {
    $liveExit = 1
}

if ($liveExit -ne 0) {
    Write-Warning ("Live inventory failed or found fail-severity findings (exit $liveExit). " +
        "Falling back to static source scan for visibility (NOT a substitute - see known_limitations.md).")
    python tools\strategy_inventory.py --source-fallback --repo-path $RepoPath `
        --out (Join-Path $OutDir "strategy_inventory_static")
}

exit $liveExit
