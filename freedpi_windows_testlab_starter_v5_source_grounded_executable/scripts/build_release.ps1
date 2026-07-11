param([string]$RepoRoot='..')
$ErrorActionPreference='Stop'
Push-Location "$RepoRoot\src"
cargo build --workspace --release
Pop-Location
