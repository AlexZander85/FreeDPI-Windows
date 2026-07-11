param([string]$RepoRoot='..',[string]$ResultsDir='.\runs\real_windows')
python .\tools\windows_testlab_runner.py real-windows-smoke --repo-root $RepoRoot --results-dir $ResultsDir
