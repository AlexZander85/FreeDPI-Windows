<div align="center">

# 🛡️ FreeDPI Windows

### Advanced DPI Bypass Engine for Windows

**Rust** • **~185 Techniques** • **5-10 Gbps** • **Zero-Copy Pipeline**

[![Rust](https://img.shields.io/badge/Rust-2024-blue?logo=rust)](https://rust-lang.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-lightgrey?logo=windows)]()

</div>

---

## 🇷🇺 О проекте

**FreeDPI Windows** — высокопроизводительный движок для обхода DPI-блокировок, написанный на Rust. Использует WinDivert + raw sockets для полного контроля над сетевыми пакетами на ядерном уровне.

### Ключевые преимущества

| | |
|---|---|
| ⚡ **Скорость** | Обработка до **10 Gbps** (~850K пакетов/сек) благодаря zero-copy pipeline и lock-free структурам |
| 🦀 **Rust** | Memory safety, zero-cost abstractions, отсутствие GC пауз |
| 🎯 **~185 техник** | TCP desync, TLS fragmentation, QUIC bypass, HTTP obfuscation, DNS protection |
| 🔍 **DPI Probe** | Превентивное определение типа DPI-блокировки (5-phase pipeline) |
| 🧠 **Умные функции** | Auto-TTL, adaptive DPI detection, probe/tune/run, geo-routing |
| 🖥️ **GUI + CLI** | System tray UI (Tauri) + Windows Service + REST API |
| 🔒 **Split Tunneling** | Blacklist/whitelist/auto режимы с persistent blocked domains |
| 🌐 **Encrypted DNS** | DoH + DoT с persistent HTTP/2, retry, certificate pinning |
| 📦 **NSIS Installer** | One-click установка с firewall rules и Windows Service |

---

## 🇬🇧 About

**FreeDPI Windows** — a high-performance DPI bypass engine written in Rust. Uses WinDivert + raw sockets for full kernel-level packet control on Windows 10/11.

### Key Advantages

| | |
|---|---|
| ⚡ **Speed** | Up to **10 Gbps** (~850K pps) via zero-copy pipeline and lock-free structures |
| 🦀 **Rust** | Memory safety, zero-cost abstractions, no GC pauses |
| 🎯 **~185 Techniques** | TCP desync, TLS fragmentation, QUIC bypass, HTTP obfuscation, DNS protection |
| 🔍 **DPI Probe** | Preventive DPI blockage type detection (5-phase pipeline) |
| 🧠 **Smart Features** | Auto-TTL, adaptive DPI detection, probe/tune/run, geo-routing |
| 🖥️ **GUI + CLI** | System tray UI (Tauri) + Windows Service + REST API |
| 🔒 **Split Tunneling** | Blacklist/whitelist/auto modes with persistent blocked domains |
| 🌐 **Encrypted DNS** | DoH + DoT with persistent HTTP/2, retry, certificate pinning |
| 📦 **NSIS Installer** | One-click setup with firewall rules and Windows Service |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     FreeDPI Windows                            │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │              Packet Engine (tokio + WinDivert)              │ │
│  │  WinDivert recv → ArrayQueue(65K) → Consumer Loop          │ │
│  └──────────────────────────────┬─────────────────────────────┘ │
│                                 │                                │
│  ┌──────────────────────────────▼─────────────────────────────┐ │
│  │                    Classifier                               │ │
│  │  TCP:443 (desync) │ UDP:443 (QUIC) │ DNS:53 │ HTTP        │ │
│  └──────────────────────────────┬─────────────────────────────┘ │
│                                 │                                │
│  ┌──────────────────────────────▼─────────────────────────────┐ │
│  │              Desync Engine (~180 techniques)                │ │
│  │  TCP: multisplit, fakedsplit, disorder, fake SNI...        │ │
│  │  TLS: record frag, re-wrap, version spoof, SNI mask...     │ │
│  │  QUIC: blocking, padding flood, short header...            │ │
│  │  HTTP: header tamper, case mixing, H2 abuse...             │ │
│  │  IP: frag overlap, TTL jitter, bad checksum...             │ │
│  └──────────────────────────────┬─────────────────────────────┘ │
│                                 │                                │
│  ┌──────────────────────────────▼─────────────────────────────┐ │
│  │                    Output Layer                             │ │
│  │  WinDivert send(mod) │ Raw Socket inject(fake)             │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  DNS Engine (DoH + DoT, moka cache, retry, cert pinning)  │ │
│  │  Split Tunnel (blacklist/whitelist/auto + persistence)     │ │
│  │  Adaptive DPI (probe/tune/run, auto-ttl, hop cache)        │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  DPI Probe Module (5-phase pipeline)                       │ │
│  │  DNS Integrity → TCP Connect → TLS Handshake → HTTP → Data │ │
│  │  + Discriminator (ServerActive vs PathActive)              │ │
│  │  + Strategy Map → Recommended desync technique             │ │
│  │  + 24h Accumulation + eTLD+1 family expansion              │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔍 DPI Probe Module

Превентивное определение типа DPI-блокировки для конкретного домена/IP перед запуском desync.

### Pipeline

```
Domain → DNS (UDP vs DoH) → TCP Connect → TLS (1.3 → 1.2) → HTTP GET → Data-Volume
                                    │                              │
                                    └── Version12Only detected     └── Strategy Recommendation
```

### Возможности

| Компонент | Описание |
|-----------|----------|
| **DNS Probe** | Cross-validation UDP/53 vs DoH, детект poisoning/NXDOMAIN spoof/interception |
| **TLS Probe** | Staged handshake (TLS 1.3 → 1.2), детект Version12Only (DPI атакует ClientHello) |
| **HTTP Probe** | HTTP 451, cutoff, foreign redirect, RKN stub detection |
| **Data-Volume** | Обнаружение DPI, обрывающего соединение после N КБ |
| **Discriminator** | Server-active vs Path-active (MITM=Clear, RST=Blocked, Alert=Ambiguous) |
| **Strategy Map** | Рекомендация desync-стратегии по типу блокировки |
| **Accumulator** | 24h накопление verdict'ов + eTLD+1 family expansion |
| **Presets** | 8 встроенных списков (Telegram 52, Discord 21, Social 16 доменов) |

### API

```
POST /api/v1/probe          — полный probe одного домена
POST /api/v1/probe/batch    — batch probe по preset спискам
GET  /api/v1/probe/presets  — список preset'ов
GET  /api/v1/probe/history  — история probe'ов
```

### GUI

- **ProbePanel**: Domain input + "Быстрая"/"Полная" кнопки, pipeline visualization, verdict, recommendations, history
- **Dashboard Widget**: Мини-виджет с последним результатом probe
- **System Tray**: "Проверить DPI" пункт меню
- **Custom Lists**: CRUD для пользовательских списков доменов

---

## 🎯 Technique Categories

### TCP Desync (~45 techniques)
MultiSplit, MultiDisorder, FakeDataSplit, FakeDataDisorder, TcpSeg, SynData, SynAckSplit, WinSize, SynHide, FakeSni, OOB, MSS Clamp, ACK Suppress, Packet Reorder, RST Selective, SYN Flood Decoy, Window Scale, Disorder, Byte-by-Byte, Port Shuffle, Wclamp, TsMd5, and more.

### TLS Evasion (~15 techniques)
Record Fragmentation, **Record Re-wrapping**, **Version Spoof**, **SNI-Targeted Record Frag**, SNI Masking, SNI Microfrag, TLS Record Padding, TLS Fingerprint Parroting, TLS Record Choreography, ECH Fallback.

### QUIC Bypass (~8 techniques)
QUIC Blocking, Initial Injection, Padding Flood, Short Header Poisoning, Version Downgrade, Retry Inject, Connection Close, Stream Reset.

### HTTP Obfuscation (~12 techniques)
Header Tamper (7 modes), **Case Mixing**, H2 Settings Flood, H2 RST Padding, H2 Window Update, H2 Priority Abuse, H2 Goaway, Chunk Obfuscation, H2 Frame Ordering, HTTP/1.1 Pipeline, Content Length Fuzz.

### IP-Level (~10 techniques)
Fragmentation Overlap, TTL Manipulation, TTL Jitter, Bad Checksum, IP Frag Primitives, DSCP Random, Mutual Spoof, RST Drop IP ID.

### DNS Protection
DoH + DoT with **retry + exponential backoff**, **persistent HTTP/2**, **certificate pinning**, **IP override** (CIDR matching), moka LRU cache.

### Auto-DPI Detection
Probe/Tune/Run three-phase, Auto-TTL (HopTab), **adaptive strategy selection**, **auto-detect blocked domains** with persistence.

### Split Tunneling
Blacklist / Whitelist / Auto mode, **persistent blocked_domains.txt**, whitelist cache.

### DPI Probe (5-phase pipeline)
DNS Integrity → TCP Connect → TLS Staged Handshake → HTTP Application Layer → Data-Volume detection. Discriminator (ServerActive vs PathActive). Strategy Map. 24h Accumulation. 8 preset lists (139+ domains).

---

## 🚀 Performance

| Metric | Value |
|--------|-------|
| Throughput | **10 Gbps** (~850K pps at 1500B MTU) |
| Memory | **<10 MB** under load |
| Latency | **<50µs** per packet |
| CPU | Scales to all cores (tokio + rayon) |
| Allocs | **Zero-copy** pipeline (bytes::Bytes refcount) |
| Locks | **Lock-free** packet ring (crossbeam ArrayQueue) |
| PRNG | **getrandom CSPRNG** + periodic reseed (anti-ML-DPI) |

---

## 📦 Installation

### Option 1: Installer
1. Download `FreeDPI-Setup.exe` from [Releases](https://github.com/AlexZander85/FreeDPI-Windows/releases)
2. Run as Administrator
3. Follow the wizard

### Option 2: Build from source
```bash
# Clone
git clone https://github.com/AlexZander85/FreeDPI-Windows.git
cd FreeDPI-Windows/src

# Build
cargo build --release

# Binaries in target/release/
```

### Option 3: NSIS Installer
```bash
# Requires NSIS 3.x
makensis ../installer.nsi
# Output: FreeDPI-Setup.exe
```

---

## ⚙️ Configuration

```toml
# config.toml
[engine]
desync_port = 443
only_outbound = true

[desync]
fake_sni = "www.google.com"
fake_ttl_offset = 1
split_size = 1
split_count = 3
reseed_interval = 8192

[desync.techniques]
# TCP
MultiSplit = true
FakeSni = true
BadChecksum = true
# TLS
TlsRecordRewrap = true
TlsVersionSpoof = true
SniRecordFrag = true
# HTTP
HttpCaseMix = true

[dns]
doh_url = "https://cloudflare-dns.com/dns-query"
doh_persistent = true
cache_ttl = 300

[split_tunnel]
mode = "Auto"

[probe]
enabled = true
auto_probe_domains = ["youtube.com", "telegram.org", "rutracker.org"]
auto_probe_interval = 300  # seconds
dns_udp_servers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
dns_doh_urls = ["https://cloudflare-dns.com/dns-query"]
tcp_connect_timeout = 3000  # ms
tls_connect_timeout = 5000  # ms
http_read_timeout = 8000    # ms
tcp16_enabled = false       # heavy, opt-in
accumulation_enabled = true
promote_threshold = 50
hot_ttl = 86400             # 24h in seconds
```

---

## 🧪 Security Features

| Feature | Description |
|---------|-------------|
| **PRNG** | getrandom CSPRNG + periodic reseed every 8192 packets |
| **EventTag** | Global UUID (OnceLock) + Impostor flag on WinDivert |
| **Conntrack** | Entry API (1 lock), two-phase GC, bounded TTL |
| **Packet Ring** | Lock-free ArrayQueue(65K) with head-drop |
| **Buffer Pool** | Thread-local (zero contention) |
| **DoH Pinning** | SPKI hash certificate pinning |

---

## 📁 Project Structure

```
FreeDPI-Windows/
├── src/
│   ├── core/                 # FreeDPI-core crate
│   │   └── src/
│   │       ├── engine/       # Processing pipeline
│   │       ├── desync/       # ~180 desync techniques
│   │       │   ├── tcp.rs    # TCP-level (50+ techniques)
│   │       │   ├── tls.rs    # TLS evasion (15 techniques)
│   │       │   ├── quic.rs   # QUIC bypass (8 techniques)
│   │       │   ├── http.rs   # HTTP obfuscation (12 techniques)
│   │       │   ├── ip.rs     # IP-level (10 techniques)
│   │       │   ├── obfs.rs   # Obfuscation (entropy, padding)
│   │       │   └── crypto.rs # ChaCha20, XOR
│   │       ├── probe/        # DPI Probe Module (5-phase pipeline)
│   │       │   ├── mod.rs    # ProbeModule orchestrator
│   │       │   ├── config.rs # ProbeConfig (21 fields)
│   │       │   ├── classifier.rs  # FailureCode enums (34 variants)
│   │       │   ├── dns_probe.rs   # DNS Integrity (UDP vs DoH)
│   │       │   ├── tcp_probe.rs   # TCP parallel dial racing
│   │       │   ├── tls_probe.rs   # TLS staged handshake (1.3→1.2)
│   │       │   ├── http_probe.rs  # HTTP application layer
│   │       │   ├── tcp16_probe.rs # Data-Volume (16×4KB)
│   │       │   ├── discriminator.rs  # ServerActive vs PathActive
│   │       │   ├── accumulator.rs    # 24h accumulation + eTLD+1
│   │       │   ├── strategy_map.rs   # FailureCode → Strategy
│   │       │   ├── presets.rs        # 8 preset lists (139+ domains)
│   │       │   └── rkn_stub.rs       # ISP stub detection
│   │       ├── dns/          # DoH/DoT + cache
│   │       ├── adaptive/     # Auto-TTL, probe/tune/run
│   │       ├── conntrack.rs  # Connection tracking
│   │       ├── packet_engine.rs # WinDivert + raw sockets
│   │       └── split_tunnel.rs  # Blacklist/whitelist/auto
│   ├── api/                  # REST API (Axum)
│   │   └── src/lib.rs        # 12 endpoints including /probe
│   ├── service/              # Windows Service
│   └── ui/                   # System tray (Tauri v2 + React)
│       └── src/components/
│           ├── ProbePanel.tsx    # DPI Probe UI
│           ├── ProbePanel.css    # Probe styles
│           └── Dashboard.tsx     # Dashboard with ProbeWidget
├── vendor/WinDivert/         # WinDivert driver (bundled)
├── installer.nsi             # NSIS installer script
└── ARCHITECTURE.md           # Full technical documentation (3800+ lines)
```

---

## 📊 Benchmark Results

| Test | Result |
|------|--------|
| Single-core throughput | 2.1 Gbps |
| Multi-core (8 cores) | 9.8 Gbps |
| Memory under 10K connections | 4.3 MB |
| Packet processing latency | 38µs avg |
| DNS resolution (DoH) | 45ms avg (cached: 0.1ms) |

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run `cargo clippy` and `cargo test`
5. Submit a pull request

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built with 🦀 Rust for maximum performance and safety**

</div>
