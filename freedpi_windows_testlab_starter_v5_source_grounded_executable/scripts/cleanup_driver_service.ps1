param([string]$ServiceName='FreeDPI')
$ErrorActionPreference='Continue'
Stop-Service $ServiceName -Force
sc.exe delete $ServiceName
Get-Process freedpi-service -ErrorAction SilentlyContinue | Stop-Process -Force
Write-Host 'Cleanup attempted. Verify WinDivert driver state manually if another WinDivert app is installed.'
