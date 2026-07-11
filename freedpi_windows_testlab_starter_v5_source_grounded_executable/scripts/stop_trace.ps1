param([string]$OutDir='.\runs\trace')
$ErrorActionPreference='Continue'
netsh trace stop
Write-Host "Trace stopped. Apply privacy_redact.py before sharing artifacts."
