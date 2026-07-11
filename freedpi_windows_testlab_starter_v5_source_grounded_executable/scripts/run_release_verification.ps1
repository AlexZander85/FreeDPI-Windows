param(
  [string]$Config = "$env:ProgramFiles\FreeDPI\config.toml",
  [string]$Binary = "$env:ProgramFiles\FreeDPI\freedpi-service.exe",
  [string]$BaseUrl = "http://127.0.0.1:11337",
  [string]$ApiKey = $env:FREEDPI_API_KEY
)
$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
python "$Root\tools\release_verify.py" --config $Config --binary $Binary --base-url $BaseUrl --api-key $ApiKey
