param([string]$RepoRoot="..", [string]$Out="runs/probe_mapping_audit.json")
python "$PSScriptRoot/../tools/probe_mapping_audit.py" --repo-root $RepoRoot --out $Out
exit $LASTEXITCODE
