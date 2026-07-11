param([string]$RepoRoot='..',[string]$ResultsDir='.\runs\provider')
python .\tools\windows_testlab_runner.py provider-auto --repo-root $RepoRoot --results-dir $ResultsDir
