param([string]$RepoRoot='..',[string]$ResultsDir='.\runs\replay')
python .\tools\windows_testlab_runner.py smoke --repo-root $RepoRoot --results-dir $ResultsDir
