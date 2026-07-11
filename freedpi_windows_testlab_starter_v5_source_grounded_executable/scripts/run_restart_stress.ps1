param([string]$RepoRoot='..',[string]$ResultsDir='.\runs\restart')
python .\tools\windows_testlab_runner.py restart-stress --repo-root $RepoRoot --results-dir $ResultsDir
