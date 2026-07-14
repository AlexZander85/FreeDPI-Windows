param([string]$RepoRoot='..')
$ErrorActionPreference='Stop'
Push-Location "$RepoRoot\src"
cargo build --workspace --all-targets --features qa
Pop-Location
