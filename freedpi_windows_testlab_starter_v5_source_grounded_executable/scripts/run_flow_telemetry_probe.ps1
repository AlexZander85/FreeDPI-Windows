param([string]$Base="http://127.0.0.1:11337", [string]$ApiKey=$env:FREEDPI_API_KEY, [string]$Scenario="tcp-connect", [string]$Host="127.0.0.1", [int]$Port=80, [string]$Out="runs/flow_telemetry_probe.json")
python "$PSScriptRoot/../tools/flow_telemetry_probe.py" --base $Base --api-key $ApiKey --scenario $Scenario --host $Host --port $Port --json-out $Out
exit $LASTEXITCODE
