#Requires -RunAsAdministrator
# deploy.ps1 — Deployment script for FreeDPI Windows Service
# Install / Uninstall / Status

param(
    [ValidateSet("install", "uninstall", "status")]
    [string]$Command = "install",

    [string]$InstallDir = "$env:ProgramFiles\FreeDPI"
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
$ScriptDir = Split-Path -Parent $PSCommandPath
$ServiceExe = Join-Path $ScriptDir "freedpi-service.exe"
$WinDivertSys = Join-Path $ScriptDir "WinDivert64.sys"
# WinDivert.dll statically linked into freedpi-service.exe — no separate DLL needed.

# ---------------------------------------------------------------------------
function Write-Info   { Write-Host "[INFO] $args" -ForegroundColor Cyan }
function Write-Ok     { Write-Host "[OK]   $args" -ForegroundColor Green }
function Write-Error  { Write-Host "[ERR]  $args" -ForegroundColor Red }

# ---------------------------------------------------------------------------
# Prerequisites check
# ---------------------------------------------------------------------------
function Test-Artifacts {
    $missing = @()
    if (-not (Test-Path $ServiceExe))   { $missing += "freedpi-service.exe" }
    if (-not (Test-Path $WinDivertSys)) { $missing += "WinDivert64.sys" }
    if ($missing.Count -gt 0) {
        Write-Error "Missing artifacts in $ScriptDir : $($missing -join ', ')"
        Write-Info "Run 'cargo build --release -p freedpi-service' first, then copy artifacts."
        exit 1
    }
}

# ---------------------------------------------------------------------------
# Service helpers
# ---------------------------------------------------------------------------
function Get-ServiceStatus {
    try {
        $svc = Get-Service -Name "FreeDPI" -ErrorAction Stop
        return $svc.Status
    } catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
function Install-FreeDPI {
    Write-Info "Installing FreeDPI to $InstallDir"

    # 1. Create installation directory
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        Write-Ok "Created directory: $InstallDir"
    }

    # 2. Copy files
    Write-Info "Copying artifacts..."
    Copy-Item -Path $ServiceExe   -Destination $InstallDir -Force
    Copy-Item -Path $WinDivertSys -Destination $InstallDir -Force
    Write-Ok "Artifacts copied."
    Write-Info "Note: WinDivert.dll is statically linked into freedpi-service.exe."

    # 3. Create a sample config if not present
    $ConfigPath = Join-Path $InstallDir "config.toml"
    if (-not (Test-Path $ConfigPath)) {
        @"
# FreeDPI Configuration
# See documentation for all available options.

[windivert]
filter = "(ip or ipv6) && tcp.DstPort == 443"
queue_length = 4096

[api]
enabled = true
port = 8080
api_key = ""

[general]
log_level = "info"
conntrack_ttl = 30
"@ | Out-File -FilePath $ConfigPath -Encoding utf8
        Write-Ok "Default config created: $ConfigPath"
    }

    # 4. Register the Windows service with SCM
    $ServiceBin = Join-Path $InstallDir "freedpi-service.exe"
    Write-Info "Registering FreeDPI service with SCM..."
    & $ServiceBin --install 2>&1 | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to register service (exit code: $LASTEXITCODE). Run as Administrator."
        exit 1
    }
    Write-Ok "Service 'FreeDPI' registered (auto-start)."

    # 5. Start the service
    Write-Info "Starting FreeDPI service..."
    Start-Service -Name "FreeDPI" -ErrorAction Stop
    Write-Ok "Service started."

    # 6. Verify
    Start-Sleep -Seconds 2
    $status = Get-ServiceStatus
    if ($status -eq "Running") {
        Write-Ok "FreeDPI is RUNNING. Installation complete."
        Write-Info "API endpoint: http://127.0.0.1:8080"
        Write-Info ""
        Write-Info "Next steps:"
        Write-Info "  1. Edit config:    notepad '$ConfigPath'"
        Write-Info "  2. Restart:        Restart-Service -Name FreeDPI"
        Write-Info "  3. Check logs:     Get-Content '$InstallDir\freedpi.log' -Tail 50"
        Write-Info "  4. Uninstall:      .\deploy.ps1 uninstall"
    } else {
        Write-Error "Service status: $status. Check logs."
    }
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------
function Uninstall-FreeDPI {
    Write-Info "Uninstalling FreeDPI..."

    # 1. Stop service if running
    $status = Get-ServiceStatus
    if ($status -eq "Running") {
        Write-Info "Stopping FreeDPI service..."
        Stop-Service -Name "FreeDPI" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Write-Ok "Service stopped."
    }

    # 2. Unregister from SCM
    $ServiceBin = Join-Path $InstallDir "freedpi-service.exe"
    if (Test-Path $ServiceBin) {
        Write-Info "Unregistering FreeDPI service from SCM..."
        & $ServiceBin --uninstall 2>&1 | ForEach-Object { Write-Host $_ }
        Start-Sleep -Seconds 1
    }

    # 3. Remove files
    if (Test-Path $InstallDir) {
        Write-Info "Removing $InstallDir..."
        # Give SCM time to release file handles
        Start-Sleep -Seconds 2
        Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path $InstallDir) {
            Write-Error "Could not remove $InstallDir (files may be in use)."
        } else {
            Write-Ok "Installation directory removed."
        }
    }

    Write-Ok "FreeDPI uninstalled successfully."
}

# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------
function Show-Status {
    Write-Info "FreeDPI Deployment Status"
    Write-Info "=========================="
    Write-Info ""

    # Service status
    $status = Get-ServiceStatus
    if ($status -eq $null) {
        Write-Error "Service 'FreeDPI' is NOT installed."
    } else {
        Write-Host "Service:     FreeDPI" -ForegroundColor White
        Write-Host "Status:      $status" -ForegroundColor $(if ($status -eq "Running") { "Green" } else { "Yellow" })
        Write-Host "Start type:  Automatic" -ForegroundColor White
    }

    # Files
    if (Test-Path $InstallDir) {
        Write-Host "" -NoNewline
        Write-Host "Install dir: $InstallDir" -ForegroundColor White
        Get-ChildItem $InstallDir | Select-Object Name, Length | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_ -NoNewline }
    } else {
        Write-Error "Installation directory not found: $InstallDir"
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
function Main {
    if ($Command -eq "install") {
        Test-Artifacts
        Install-FreeDPI
    } elseif ($Command -eq "uninstall") {
        Uninstall-FreeDPI
    } elseif ($Command -eq "status") {
        Show-Status
    }
}

Main
