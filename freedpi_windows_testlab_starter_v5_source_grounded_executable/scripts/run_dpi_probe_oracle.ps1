param(
  [string]$RepoRoot='..',
  [string]$ResultsDir='.
uns\dpi_probe',
  [string]$ExpectedClass='TLS_HANDSHAKE_TIMEOUT',
  [string]$OracleMode='TLS_HANDSHAKE_TIMEOUT',
  [string]$TargetUrl='http://127.0.0.1:18080/',
  [string]$ApiBase='http://127.0.0.1:11337',
  [double]$ConfidenceMin=0.85,
  [int]$PollSeconds=2
)

# DPI Probe oracle verification. The runner creates/uses oracle conditions and asks the app to classify them.
# It must not inject the expected class into app state.
python .\tools\windows_testlab_runner.py dpi-probe-oracle `
  --repo-root $RepoRoot `
  --results-dir $ResultsDir `
  --api-base $ApiBase `
  --oracle-mode $OracleMode `
  --expected-class $ExpectedClass `
  --target-url $TargetUrl `
  --confidence-min $ConfidenceMin `
  --poll-seconds $PollSeconds
