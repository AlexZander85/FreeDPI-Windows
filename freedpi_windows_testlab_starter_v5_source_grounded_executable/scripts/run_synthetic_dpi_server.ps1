param(
  [string]$Mode = "CLEAN_ALLOW",
  [int]$TcpPort = 18443,
  [int]$HttpPort = 18080,
  [int]$DnsPort = 10053
)
$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
python "$Root\tools\synthetic_dpi_server.py" --mode $Mode --tcp-port $TcpPort --http-port $HttpPort --dns-port $DnsPort
