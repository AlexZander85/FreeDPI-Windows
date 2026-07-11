param([Parameter(Mandatory=$true)][string]$JsonFile, [string]$Out="runs/unsupported_reason_lint.json")
python "$PSScriptRoot/../tools/unsupported_reason_linter.py" $JsonFile --out $Out
exit $LASTEXITCODE
