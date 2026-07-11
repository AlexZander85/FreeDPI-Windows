<#
.SYNOPSIS
  Installs the FreeDPI-Windows service via its real SCM registration path and
  verifies it via Get-Service, not via any HTTP self-report.

.DESCRIPTION
  Grounded in src/service/src/main.rs: the binary supports `--install` which calls
  install_service() -> OpenSCManagerW(...SC_MANAGER_CREATE_SERVICE) and registers
  under SERVICE_NAME. This script does NOT reimplement that logic — it drives the
  real binary and then asks Windows (SCM), not the process, whether it worked.

.PARAMETER BinaryPath
  Path to the built freedpi-service.exe (release or debug).
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$BinaryPath
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $BinaryPath)) {
    Write-Error "Binary not found at $BinaryPath. Build first (see build_debug.ps1 / build_release.ps1)."
    exit 1
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Must run elevated — SCM service creation requires Administrator."
    exit 1
}

Write-Host "Installing service from $BinaryPath ..."
& $BinaryPath --install
if ($LASTEXITCODE -ne 0) {
    Write-Error "install exited with code $LASTEXITCODE"
    exit 1
}

# Verify via SCM, independent of the binary's own stdout claim of success.
# Service name must match SERVICE_NAME const in service/src/main.rs — confirm exact
# string when implementing; placeholder below assumes it prints "installed successfully"
# and that Get-Service can find it by the same name used in install_service().
$serviceName = $env:FREEDPI_SERVICE_NAME
if (-not $serviceName) {
    Write-Warning ("FREEDPI_SERVICE_NAME env var not set - set it to the exact SERVICE_NAME " +
        "constant from service/src/main.rs before this check can verify via Get-Service. " +
        "Skipping SCM verification for now.")
    exit 2
}

$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Error "Service '$serviceName' not found in SCM after --install claimed success. This is a real bug, not a test artifact."
    exit 1
}

Write-Host "Service '$serviceName' registered in SCM. Status: $($svc.Status)" -ForegroundColor Green

Write-Host "Starting service ..."
Start-Service -Name $serviceName
Start-Sleep -Seconds 2
$svc.Refresh()
if ($svc.Status -ne "Running") {
    Write-Error "Service did not reach Running state (status: $($svc.Status)). Check Windows Event Log and service stdout/stderr logs."
    exit 1
}

Write-Host "Service running. install_service_test PASSED." -ForegroundColor Green
exit 0
