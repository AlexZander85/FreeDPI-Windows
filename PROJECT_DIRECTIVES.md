# ByeByeDPI Windows — Project Directives (Rust)

## Commands
- Build: `cargo build --release` (из `src/`)
- Test: `cargo test` (из `src/`)
- Run: `.\target\release\byebyedpi-service.exe` (требует admin)
- API: `curl -H "X-API-Key: <key>" http://127.0.0.1:11337/api/v1/status`
- Quick test: `cargo test -p byebyedpi-core --lib`

## Entry Points
- Workspace: `src/Cargo.toml` (5 членов: core, ffi-bridge, api, service, ui)
- Core library: `src/core/src/lib.rs` — `Runtime::global()`
- Service binary: `src/service/src/main.rs` — Windows Service + API
- API server: `src/api/src/lib.rs` — Axum HTTP API для AI-агента
- UI: `src/ui/src/main.rs` — System tray

## Invariants
- WinDivert + raw socket требуют admin elevation (UAC)
- Всего ~165 DPI-bypass техник (45 Android + 130 новых из 21 проекта)
- HTTP API слушает ТОЛЬКО localhost (127.0.0.1:11337)
- Аутентификация API через `X-API-Key` (генерируется при первом запуске)
- Conntrack GC каждые 30 секунд
- DNS cache TTL = 300 секунд
- tokio — I/O (WinDivert recv, DNS, proxy, HTTP API)
- rayon — CPU-bound (desync, TLS, frag, checksum)
- FFI bridge → поэтапная Rust-миграция (фаза P8)

## Dependencies (ключевые)
- `windivert 0.7` — WinDivert binding
- `tokio 1.52` — async runtime
- `rayon 1.10` — parallel CPU (work-stealing)
- `dashmap 6` — concurrent hash maps (conntrack, blacklist)
- `moka 0.12` — concurrent cache (DNS, geo-route)
- `axum 0.8` — HTTP API server
- `windows 0.58` — WinAPI (raw sockets, service)
- `pnet 0.35` — packet parsing

## Архитектура директорий (src/)
```
src/
├── Cargo.toml               # workspace root
├── core/                    # core library (packet engine, conntrack, desync)
│   └── src/
│       ├── lib.rs           # Runtime, global init
│       ├── packet_engine.rs # WinDivert + raw socket
│       ├── split_tunnel.rs  # blacklist/whitelist/auto
│       ├── classifier.rs    # packet classification
│       ├── conntrack.rs     # connection tracking (DashMap)
│       └── config.rs        # config loader
├── ffi-bridge/             # C → Rust FFI (bye-dpi core)
├── api/                    # HTTP API server (Axum)
│   └── src/lib.rs
├── service/                # Windows Service binary
│   └── src/main.rs
└── ui/                     # System tray binary
    └── src/main.rs
```

## Known Pitfalls
1. **WinDivert + VPN conflict** → symptom: packets not intercepted → check adapter binding, disable VPN
2. **Raw socket TCP на Windows** → symptom: can send but can't receive TCP via raw → use WinDivert for inbound
3. **Windows Defender blocking** → symptom: .exe quarantined → add exclusion for process directory
4. **WSASocket(SOCK_RAW) fails** → symptom: WSAError 10013 → need admin elevation (UAC or SYSTEM)
5. **`windivert` crate async** → uses `spawn_blocking` internally, tune `QUEUE_LENGTH` for high throughput
6. **DashMap 7 vs 6** → note breaking changes, use `dashmap 6` for stability
7. **Axum + Windows Service** → tokio runtime must be created before axum::serve
8. **TLS Spoof SEQ conflict** → don't use SeqOverlap + TLS Spoof simultaneously on same connection
9. **SeqOverlap + WinDivert race** → inject overlap packets via raw socket, not WinDivert

## Conventions
- Rust 2021 edition, `cargo fmt` + `cargo clippy` обязательны
- `anyhow::Result` для fallible функций, `thiserror` для библиотечных ошибок
- Все публичные структуры — `Serialize`/`Deserialize`
- Packet processing — `bytes::Bytes` (zero-copy), не `Vec<u8>`
- Conntrack — `DashMap<ConnKey, ConntrackEntry>` (64 shards)
- Error handling: `tracing::error!` + метрики, не паника
- API handlers: async fn с `State<Arc<ApiState>>`
