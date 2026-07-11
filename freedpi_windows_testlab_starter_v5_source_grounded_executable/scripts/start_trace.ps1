param([string]$OutDir='.\runs\trace',[switch]$AllowRawCapture)
$ErrorActionPreference='Stop'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
if (-not $AllowRawCapture) { Write-Host 'Raw ETW/netsh trace disabled. Pass -AllowRawCapture to enable.'; exit 0 }
netsh trace start capture=yes report=no persistent=no tracefile="$OutDir\freedpi_trace.etl" maxsize=256
