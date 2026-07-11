param(
  [string]$RepoRoot='..',
  [string]$ResultsDir='.
uns\qa_contract',
  [string]$ApiBase='http://127.0.0.1:11337'
)

python .\tools\windows_testlab_runner.py qa-contract --repo-root $RepoRoot --results-dir $ResultsDir --api-base $ApiBase
