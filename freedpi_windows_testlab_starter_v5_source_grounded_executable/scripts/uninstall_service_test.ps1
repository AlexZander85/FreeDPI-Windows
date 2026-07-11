<#
.SYNOPSIS
  Stops and uninstalls the FreeDPI-Windows service, then verifies no orphaned
  process or driver/service state remains.

.DESCRIPTION
  Grounded in service/src/main.rs uninstall_service() -> OpenSCManagerW(...
  SC_MANAGER_CONNECT). This script verifies the cleanup claims the meta-prompt
  requires (no orphaned freedpi-service.exe, no orphaned WinDivert driver state)
  using OS-level checks, not the app's own self-report.
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$BinaryPath,
    [string]$ServiceName = $env:FREEDPI_SERVICE_NAME,
    [string]$ProcessName = "freedpi-service"
)

$ErrorActionPreference = "Continue"
$failures = @()

if (-not $ServiceName) {
    Write-Error "ServiceName not provided and FREEDPI_SERVICE_NAME not set."
    exit 1
}

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Host "Stopping service ..."
    Stop-Service -Name $ServiceName -Force
    Start-Sleep -Seconds 2
}

Write-Host "Uninstalling service via $BinaryPath --uninstall ..."
& $BinaryPath --uninstall
Start-Sleep -Seconds 2

# 1. Service must be gone from SCM
$svcAfter = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svcAfter) {
    $failures += "Service '$ServiceName' still present in SCM after --uninstall."
}

# 2. No orphaned process
$procs = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
if ($procs) {
    $failures += "Orphaned process(es) found: $($procs.Id -join ', ')"
}

# 3. No orphaned WinDivert driver/service entries
$windivertSvc = Get-Service -Name "WinDivert*" -ErrorAction SilentlyContinue
if ($windivertSvc) {
    foreach ($w in $windivertSvc) {
        Write-Host "Found WinDivert-related service: $($w.Name), Status: $($w.Status)"
        # Presence alone isn't necessarily a failure (WinDivert driver can be shared
        # across tools) but a RUNNING state after full uninstall with no other
        # WinDivert consumer active is suspicious - flag for manual confirmation.
        if ($w.Status -eq "Running") {
            $failures += "WinDivert-related service '$($w.Name)' still Running after uninstall - confirm no other consumer is active before treating as pass."
        }
    }
}

Write-Host ""
if ($failures.Count -eq 0) {
    Write-Host "uninstall_service_test PASSED - no orphaned process/service state." -ForegroundColor Green
    exit 0
} else {
    Write-Host "uninstall_service_test FAILED:" -ForegroundColor Red
    foreach ($f in $failures) { Write-Host "  - $f" -ForegroundColor Red }
    exit 1
}
