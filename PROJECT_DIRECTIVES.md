# FreeDPI Windows — Project Directives (Rust)

## ⚠️ Mandatory After Every Change
```bash
cd src && cargo fmt && cargo clippy --workspace
```
**rustfmt + clippy ОБЯЗАТЕЛЬНЫ после любых изменений в .rs файлах.** Без этого коммит не принимается.

## Commands
- Build: `cargo build --release` (из `src/`)
- Test: `cargo test` (из `src/`)
- Lint: `cargo fmt -- --check && cargo clippy --workspace` (из `src/`)
- Run: `.\target\release\freedpi-service.exe` (требует admin)
- API: `curl -H "X-API-Key: <key>" http://127.0.0.1:11337/api/v1/status`
- Quick test: `cargo test -p freedpi-core --lib`

## Entry Points
- Workspace: `src/Cargo.toml` (3 members: core, api, service)
- Core library: `src/core/src/lib.rs`
- Service binary: `src/service/src/main.rs` — Windows Service + API
- API server: `src/api/src/lib.rs` — Axum HTTP API

## Production Engineering & Implementation Rules
1. **Evidence over eloquence**: Never assume documentation or comments represent the actual runtime. Always query call sites and verify current signatures, fields, enum variants, feature flags, and tests in the repository using grep/IDE tools.
2. **Enum Dispatching**: For `DesyncTechnique`, catch-all wildcards (e.g. `_ => passthrough()`) are forbidden in production dispatch. New variants must break compilation if dispatch/names/sources/effects are not updated.
3. **Direction Metadata**: Injection packet directions must be explicit. WinDivert address metadata must be modified according to the `InjectDirection` configuration. Real TCP RST or decoy injections must never accidentally inherit inbound direction and leak into the local TCP stack.
4. **Synchronization Invariants**: Before modifying or removing `Mutex`, `RwLock`, or `ArcSwap`, locate all usages. Ensure hot paths do not introduce global lock contention.
5. **Zero-Allocation Hot Path**: Avoid allocating buffers (`Vec`, `to_vec`, `String`, `format!`, clones of large structs) on the packet hot path. Use borrowed slices, `SmallVec`, and pool-acquired `BytesMut` elements.
6. **Protocol Validity (QUIC/TLS)**: Never inject pseudo-valid packets containing random bytes. QUIC Initial packets must satisfy length requirements (>=1200 bytes). If encryption fails, skip injection and increment metrics rather than injecting unencrypted fallbacks.
7. **TCP Reassembly Simulation**: Any technique that fragments, splits, or disorders TCP data must pass simulation tests. Real bytes necessary for server reassembly must be sent with normal TTL. Low TTL is reserved strictly for decoy/fake overlapping packets.

## Known Pitfalls
1. **WinDivert + VPN conflict** → check adapter binding, disable VPN
2. **Raw socket TCP на Windows** → use WinDivert for inbound
3. **Windows Defender blocking** → add exclusion for process directory
4. **WSASocket(SOCK_RAW) fails** → need admin elevation
5. **`windivert` crate** → uses `spawn_blocking`, tune `QUEUE_LENGTH`
6. **DashMap 7 vs 6** → use `dashmap 6` for stability
7. **Axum + Windows Service** → tokio runtime before axum::serve
8. **TLS Spoof SEQ conflict** → don't combine SeqOverlap + TLS Spoof
9. **SeqOverlap + WinDivert race** → inject via raw socket, not WinDivert
10. **`update_checksum_word` RFC 1624 fix** (2026-07-10) — была ошибка `~HC - ~m + ~m'` вместо `~(~HC + ~m + m')`. Исправлено. При подозрении на неверный checksum в TtlManipulation/других техниках сверять с прямым `ipv4_checksum`.
11. **AutoTune cold startup / zero observations fallback**: Checking success rate (`success_rate < failure_threshold`) on pre-allocated strategy metrics before any observations are recorded (where success rate is `0.0`) triggers a false positive proxy fallback. Always guard with `total_observations > 0`.

## Conventions
- Rust 2024 edition
- `cargo fmt` + `cargo clippy` **ОБЯЗАТЕЛЬНЫ** после каждого изменения
- `anyhow::Result` для fallible функций, `thiserror` для библиотечных ошибок
- Все публичные структуры — `Serialize`/`Deserialize`
- Packet processing — `bytes::Bytes` (zero-copy), не `Vec<u8>`
- Conntrack — `DashMap<ConnKey, ConntrackEntry>` (64 shards)
- Error handling: `tracing::error!` + метрики, не паника
- API handlers: async fn с `State<Arc<ApiState>>`
