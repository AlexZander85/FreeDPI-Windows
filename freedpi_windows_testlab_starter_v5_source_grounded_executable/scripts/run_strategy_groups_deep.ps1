param([string]$RepoRoot='..',[string]$ResultsDir='.\runs\groups')
python .\tools\windows_testlab_runner.py strategy-groups-deep --repo-root $RepoRoot --results-dir $ResultsDir
