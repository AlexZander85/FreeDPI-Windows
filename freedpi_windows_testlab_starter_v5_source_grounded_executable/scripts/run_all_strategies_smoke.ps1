param([string]$RepoRoot='..',[string]$ResultsDir='.\runs\all_strategies')
python .\tools\windows_testlab_runner.py all-strategies-smoke --repo-root $RepoRoot --results-dir $ResultsDir
