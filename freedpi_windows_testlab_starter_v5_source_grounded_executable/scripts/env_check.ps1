<#
.SYNOPSIS
  Verifies the local Windows environment can run the FreeDPI-Windows test lab.

.DESCRIPTION
  Checks grounded in actual repo requirements (src/Cargo.toml, service/src/main.rs):
    - Windows 10/11
    - Administrator privileges (required for WinDivert driver + SCM operations)
    - Rust toolchain matching workspace edition 2021, MSVC target
    - Python 3.11+ for tools/*.py
    - WinDivert vendor files present (src/vendor/windivert/*)
    - Port 11337 (or configured API port) free before starting the service
#>

$ErrorActionPreference = "Continue"
$failures = @()

Write-Host "== FreeDPI-Windows test lab environment check ==" -ForegroundColor Cyan

# OS check
$os = Get-CimInstance Win32_OperatingSystem
Write-Host "OS: $($os.Caption) $($os.Version)"
if ($os.Caption -notmatch "Windows 10|Windows 11") {
    $failures += "Unsupported OS: $($os.Caption). This app targets Windows 10/11."
}

# Admin check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Administrator: $isAdmin"
if (-not $isAdmin) {
    $failures += "Not running as Administrator. WinDivert driver load and SCM install/uninstall will fail."
}

# Rust toolchain
$cargoVersion = & cargo --version 2>$null
if (-not $cargoVersion) {
    $failures += "cargo not found on PATH. Install Rust via rustup with the MSVC toolchain (stable)."
} else {
    Write-Host "Rust: $cargoVersion"
    $rustcTarget = & rustc -vV 2>$null | Select-String "host:"
    if ($rustcTarget -notmatch "msvc") {
        $failures += "Active rustc host is not MSVC ($rustcTarget). WinDivert static linking requires the MSVC toolchain, not GNU."
    }
}

# Python
$pyVersion = & python --version 2>$null
if (-not $pyVersion) {
    $failures += "python not found on PATH. Python 3.11+ required for tools/*.py."
} else {
    Write-Host "Python: $pyVersion"
    if ($pyVersion -match "Python (\d+)\.(\d+)") {
        $major = [int]$Matches[1]; $minor = [int]$Matches[2]
        if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 11)) {
            $failures += "Python $pyVersion found, but 3.11+ is required."
        }
    }
}

# WinDivert vendor files (path relative to repo root; set $env:FREEDPI_REPO_PATH if invoked elsewhere)
$repoPath = if ($env:FREEDPI_REPO_PATH) { $env:FREEDPI_REPO_PATH } else { "..\FreeDPI-Windows-master" }
$vendorDir = Join-Path $repoPath "src\vendor\windivert"
foreach ($f in @("WinDivert.dll", "WinDivert.lib", "WinDivert64.sys")) {
    $full = Join-Path $vendorDir $f
    if (Test-Path $full) {
        Write-Host "Found: $full"
    } else {
        $failures += "Missing vendored WinDivert file: $full (set `$env:FREEDPI_REPO_PATH if repo is elsewhere)"
    }
}

# Port availability (default 11337 per src/api/src/lib.rs doc comment)
$portInUse = Get-NetTCPConnection -LocalPort 11337 -ErrorAction SilentlyContinue
if ($portInUse) {
    Write-Host "NOTE: port 11337 already in use — may be a previous test run's service instance." -ForegroundColor Yellow
} else {
    Write-Host "Port 11337: free"
}

Write-Host ""
if ($failures.Count -eq 0) {
    Write-Host "Environment check PASSED." -ForegroundColor Green
    exit 0
} else {
    Write-Host "Environment check FAILED:" -ForegroundColor Red
    foreach ($f in $failures) { Write-Host "  - $f" -ForegroundColor Red }
    exit 1
}
