param(
  [string]$RepoRoot='..',
  [string]$ResultsDir='.
uns
autotune',
  [string]$ExpectedClass='TLS_HANDSHAKE_TIMEOUT',
  [string]$OracleMode='TLS_HANDSHAKE_TIMEOUT',
  [string]$TargetUrl='http://127.0.0.1:18080/',
  [string]$ApiBase='http://127.0.0.1:11337',
  [int]$PollSeconds=30
)

# Observer-only AutoTune validation.
# This script must never call /qa/force_strategy. Forced strategies are allowed only in forced strategy smoke/deep tests.
python .\tools\windows_testlab_runner.py autotune-causal `
  --repo-root $RepoRoot `
  --results-dir $ResultsDir `
  --api-base $ApiBase `
  --oracle-mode $OracleMode `
  --expected-class $ExpectedClass `
  --target-url $TargetUrl `
  --poll-seconds $PollSeconds
