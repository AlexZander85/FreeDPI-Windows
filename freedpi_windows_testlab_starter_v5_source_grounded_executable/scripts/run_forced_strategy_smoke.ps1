param([string]$Base="http://127.0.0.1:11337", [string]$ApiKey=$env:FREEDPI_API_KEY, [string]$RepoRoot="..", [string]$OutDir="runs/forced_strategy_smoke", [int]$Limit=0)
python "$PSScriptRoot/../tools/forced_strategy_smoke.py" --base $Base --api-key $ApiKey --repo-root $RepoRoot --out-dir $OutDir --limit $Limit
exit $LASTEXITCODE
