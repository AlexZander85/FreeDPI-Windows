param([string]$RepoRoot='..')
$ErrorActionPreference='Stop'
Push-Location "$RepoRoot\src"
cargo test --workspace
Pop-Location
