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
- Workspace: `src/Cargo.toml` (5 членов: core, ffi-bridge, api, service, ui)
- Core library: `src/core/src/lib.rs`
- Service binary: `src/service/src/main.rs` — Windows Service + API
- API server: `src/api/src/lib.rs` — Axum HTTP API
- UI: `src/ui/src/main.rs` — System tray

## Invariants
- WinDivert + raw socket требуют admin elevation (UAC)
- Всего ~180 DPI-bypass техник
- HTTP API слушает ТОЛЬКО localhost (127.0.0.1:11337)
- Аутентификация API через `X-API-Key`
- Conntrack GC каждые 30 секунд
- DNS cache TTL = 300 секунд
- tokio — I/O (WinDivert recv, DNS, proxy, HTTP API)
- rayon — CPU-bound (desync, TLS, frag, checksum)

## Dependencies (ключевые)
- `windivert 0.7` — WinDivert binding
- `tokio 1.52` — async runtime
- `rayon 1.10` — parallel CPU
- `dashmap 6` — concurrent hash maps
- `moka 0.12` — concurrent cache
- `axum 0.8` — HTTP API server
- `crossbeam 0.8` — lock-free queues
- `getrandom 0.2` — CSPRNG for PRNG seed
- `pnet 0.35` — packet parsing
- `reqwest 0.12` — HTTP client (DoH, proxy)

## Architecture
```
src/
├── Cargo.toml               # workspace root
├── core/                    # core library
│   └── src/
│       ├── lib.rs
│       ├── packet_engine.rs # WinDivert + raw socket
│       ├── split_tunnel.rs  # blacklist/whitelist/auto
│       ├── classifier.rs    # packet classification
│       ├── conntrack.rs     # connection tracking (DashMap)
│       └── config.rs        # config loader
├── ffi-bridge/             # C → Rust FFI
├── api/                    # HTTP API server (Axum)
├── service/                # Windows Service binary
└── ui/                     # System tray binary
```

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

## Conventions
- Rust 2024 edition
- `cargo fmt` + `cargo clippy` **ОБЯЗАТЕЛЬНЫ** после каждого изменения
- `anyhow::Result` для fallible функций, `thiserror` для библиотечных ошибок
- Все публичные структуры — `Serialize`/`Deserialize`
- Packet processing — `bytes::Bytes` (zero-copy), не `Vec<u8>`
- Conntrack — `DashMap<ConnKey, ConntrackEntry>` (64 shards)
- Error handling: `tracing::error!` + метрики, не паника
- API handlers: async fn с `State<Arc<ApiState>>`
