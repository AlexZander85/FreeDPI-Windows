param(
  [string]$Scenario = "http-get",
  [string]$Url = "http://127.0.0.1:18080/",
  [string]$HostName = "127.0.0.1",
  [int]$Port = 18080,
  [string]$ResultsDir = "runs\\trafficgen"
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $ResultsDir | Out-Null
$tool = Join-Path $PSScriptRoot "..\\tools\\trafficgen_client.py"
if ($Scenario -eq "http-get") {
  python $tool http-get --url $Url --json-out (Join-Path $ResultsDir "trafficgen.json")
} elseif ($Scenario -eq "tcp-connect") {
  python $tool tcp-connect --host $HostName --port $Port --json-out (Join-Path $ResultsDir "trafficgen.json")
} elseif ($Scenario -eq "tls-handshake") {
  python $tool tls-handshake --host $HostName --port $Port --server-name $HostName --json-out (Join-Path $ResultsDir "trafficgen.json")
} elseif ($Scenario -eq "dns-udp") {
  python $tool dns-udp --server $HostName --port $Port --qname example.com --json-out (Join-Path $ResultsDir "trafficgen.json")
} elseif ($Scenario -eq "udp-quic-like") {
  python $tool udp-quic-like --host $HostName --port $Port --json-out (Join-Path $ResultsDir "trafficgen.json")
} else {
  throw "Unsupported scenario: $Scenario"
}
