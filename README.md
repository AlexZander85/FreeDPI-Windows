<div align="center">

# 🛡️ FreeDPI Windows

### Advanced DPI Bypass & Adaptive Auto-Tuning Engine for Windows
### Адаптивный движок автоматического обхода DPI-блокировок для Windows

**100% Rust** • **~185 Techniques** • **5-10 Gbps** • **Zero-Copy Pipeline** • **ML Anomaly Detection**

[![Rust](https://img.shields.io/badge/Rust-2024-blue?logo=rust)](https://rust-lang.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-lightgrey?logo=windows)]()

</div>

---

## 🇷🇺 О проекте

**FreeDPI Windows** — это высокопроизводительный, полностью написанный на Rust движок для обхода DPI-блокировок на уровне ядра Windows (через WinDivert + raw sockets). Программа сочетает в себе обширный арсенал из ~185 десинхронизационных техник с интеллектуальным многостадийным зондированием DPI и динамическим автотюнингом стратегий в реальном времени.

### Ключевые преимущества и возможности

*   ⚡ **Экстремальная скорость**: Пропускная способность **5-10 Gbps** благодаря zero-copy конвейеру (подсчет ссылок `bytes::Bytes`), lock-free очередям `crossbeam::ArrayQueue` и выделенному пулу native OS воркеров.
*   🧠 **Автотюнинг стратегий (AutoTune)**: Движок автоматически оценивает эффективность техник обхода на основе обратной связи от соединений (успех/таймаут/джиттер), используя алгоритм **Thompson Sampling** для динамического выбора наиболее стабильного профиля.
*   🔍 **7-фазный DPI Probe**: Превентивное зондирование хостов (DNS Integrity → TCP Connect → TLS Handshake → HTTP Application → JA4 Fingerprinting → QUIC scan → Data-Volume), классификатор временных аномалий на базе машинного обучения (17 признаков, логистическая регрессия) и дискриминатор направления блокировки (Server-active vs Path-active).
*   🛡️ **PRNG-Hardening (ChaCha12Rng)**: Полная защита от выявления паттернов desync-инжектов со стороны DPI за счет использования криптографически стойкого генератора `ChaCha12Rng` для всех wire-visible полей и GREASE-последовательностей.
*   🔒 **Loop Prevention (Moka Cache)**: Надежное предотвращение петель перехвата и повторного анализа инжектов через сверхбыстрый кэш `injected_seqs` по 5-tuple + TCP Sequence.
*   🌐 **Интеграция DNS & Fallback-маршрутизации**:
    *   **UDP DNS drop**: Автоматический сброс незащищенного DNS на порт 53 для форсирования перехода клиента на DoH (DNS-over-HTTPS).
    *   **TCP SYN Clamping**: Динамическое ограничение MSS/Window прямо в SYN-пакетах для предотвращения фрагментации/анализа.
    *   **SOCKS5 Fallback**: Автоматический дроп direct-подключений к заблокированным доменам для перенаправления их клиентом через SOCKS5-прокси.
*   ⚙️ **TOML-стратегии**: Поддержка секции `[[strategies]]` для добавления пользовательских профилей десинхронизации, динамически сливаемых с реестром по умолчанию без перезапуска службы.

---

## 🇬🇧 About

**FreeDPI Windows** is a high-performance, 100% Rust-native engine for kernel-level DPI bypass on Windows 10/11 (utilizing WinDivert + raw sockets). It combines a rich set of ~185 desync techniques with advanced multi-stage DPI probing and real-time adaptive strategy auto-tuning.

### Key Advantages & Features

*   ⚡ **Extreme Performance**: Throughput of **5-10 Gbps** powered by a zero-copy pipeline (`bytes::Bytes` ref-counting), lock-free queues (`crossbeam::ArrayQueue`), and a dedicated pool of native OS workers.
*   🧠 **Auto-Tuning Engine (AutoTune)**: Automatically evaluates desync profile performance based on connection feedback (success/timeout/jitter), leveraging **Thompson Sampling** to select the most stable strategy dynamically.
*   🔍 **7-Phase DPI Probe**: Preventive host scanning (DNS Integrity → TCP Connect → TLS Handshake → HTTP Application → JA4 Fingerprinting → QUIC scan → Data-Volume), ML-based temporal anomaly classification (logistic regression on 17 features), and direction discriminator (Server-active vs Path-active).
*   🛡️ **PRNG-Hardening (ChaCha12Rng)**: Prevents DPI from fingerprinting desync packet patterns by employing the cryptographically secure `ChaCha12Rng` generator for all wire-visible header fields and GREASE sets.
*   🔒 **Loop Prevention (Moka Cache)**: Avoids packet loop cascades via a high-speed `injected_seqs` lookup cache mapping 5-tuple and TCP Sequence keys.
*   🌐 **DNS & Fallback Egress Routing**:
    *   **UDP DNS drop**: Drops unencrypted UDP/53 queries to force client fallback to DoH (DNS-over-HTTPS).
    *   **TCP SYN Clamping**: Dynamically clamps MSS and Window size in raw TCP SYN packets.
    *   **SOCKS5 Fallback**: Drops direct TCP SYN connections to blocked hosts to force client-side SOCKS5/Proxy fallback.
*   ⚙️ **TOML Custom Profiles**: Declaring custom strategies via the `[[strategies]]` section in `config.toml` with seamless registry merging and hot-reload.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     FreeDPI Windows                            │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │         Packet Engine (OS Workers + WinDivert)             │ │
│  │  WinDivert recv_blocking -> Rayon / Native Thread Loop    │ │
│  └──────────────────────────────┬─────────────────────────────┘ │
│                                 │                                │
│  ┌──────────────────────────────▼─────────────────────────────┐ │
│  │                    Classifier & Engine                     │ │
│  │  Tls (outbound TLS CH) │ Quic │ Dns (port 53 drop) │ Http   │ │
│  └──────────────────────────────┬─────────────────────────────┘ │
│                                 │                                │
│  ┌──────────────────────────────▼─────────────────────────────┐ │
│  │        Desync Engine (SeqSpoof + ~185 techniques)           │ │
│  │  TCP: multisplit, seq_spoof (isn offset), disorder, OOB... │ │
│  │  TLS: record frag, re-wrap, version spoof, SNI mask...     │ │
│  │  QUIC: blocking, padding flood, short header...            │ │
│  │  HTTP: header tamper, case mixing, H2 abuse...             │ │
│  │  IP: frag overlap, TTL jitter (HopTab), bad checksum...    │ │
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
│  │  AutoTune (Thompson Sampling, manual overrides, ArcSwap)   │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  DPI Probe Module (7-phase pipeline)                       │ │
│  │  DNS -> TCP -> TLS -> HTTP -> JA4 -> QUIC -> Data-Volume   │ │
│  │  + ML Anomaly Classifier (17 features regression)          │ │
│  │  + Discriminator (ServerActive vs PathActive)              │ │
│  │  + Strategy Map -> Recommended desync technique             │ │
│  │  + 24h Accumulation + eTLD+1 family expansion              │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔍 DPI Probe Module

Превентивное определение типа DPI-блокировки для конкретного домена/IP перед запуском desync.

### Pipeline

```
Domain → DNS Integrity → TCP Connect → TLS Handshake → HTTP Application → JA4 Fingerprint → QUIC Scan → Data-Volume
                                                                                                            │
                                                                                                            └── Strategy Recommendation
```

### Возможности / Features

| Компонент | Описание / Description |
|-----------|------------------------|
| **DNS Probe** | Cross-validation UDP/53 vs DoH, detection of poisoning/NXDOMAIN spoof/interception |
| **TLS Probe** | Staged handshake (TLS 1.3 → 1.2), detects Version12Only (DPI targets ClientHello) |
| **HTTP Probe** | HTTP 451 redirection, cutoff, foreign redirect, ISP stub page detection |
| **JA4 Fingerprint** | Analyzes JA4 parameters (TLS version, cipher count, extensions) for blocking |
| **QUIC Probe** | Sends UDP encrypted QUIC Initial packets to test HTTP/3 bypass possibility |
| **Data-Volume** | Detects DPI cutting off connections after transmitting N kilobytes of data |
| **Discriminator** | Resolves Server-active (MITM/Clear) vs Path-active (RST/Alert/Blocked) signals |
| **ML Anomaly** | Logistic regression on 17 timing features to identify packet flow distortion |
| **Strategy Map** | Recommends optimal desync profile depending on failure codes |
| **Accumulator** | 24h sliding window verdict persistence + eTLD+1 family auto-promotion |

---

## 🎯 Technique Categories

### TCP Desync (~45 techniques)
MultiSplit, MultiDisorder, FakeDataSplit, FakeDataDisorder, TcpSeg, SynData, SynAckSplit, WinSize, SynHide, FakeSni, OOB, MSS Clamping, ACK Suppress, Packet Reorder, RST Selective, SYN Flood Decoy, Window Scale, Disorder, Byte-by-Byte, Port Shuffle, Window Clamping, TsMd5, **SeqSpoof (out-of-window SEQ spoofing)**, and more.

### TLS Evasion (~15 techniques)
Record Fragmentation, **Record Re-wrapping**, **Version Spoof**, **SNI-Targeted Record Frag**, SNI Masking, SNI Microfrag, TLS Record Padding, TLS Fingerprint Parroting, TLS Record Choreography, ECH Fallback.

### QUIC Bypass (~8 techniques)
QUIC Blocking, Initial Injection, Padding Flood, Short Header Poisoning, Version Downgrade, Retry Inject, Connection Close, Stream Reset.

### HTTP Obfuscation (~12 techniques)
Header Tamper (7 modes), **Case Mixing**, H2 Settings Flood, H2 RST Padding, H2 Window Update, H2 Priority Abuse, H2 Goaway, Chunk Obfuscation, H2 Frame Ordering, HTTP/1.1 Pipeline, Content Length Fuzz.

### IP-Level (~10 techniques)
Fragmentation Overlap, TTL Manipulation (via **HopTab** cache), TTL Jitter, Bad Checksum, IP Frag Primitives, DSCP Random, Mutual Spoof, RST Drop IP ID.

---

## 🚀 Performance

| Metric | Value |
|--------|-------|
| Throughput | **10 Gbps** (~850K pps at 1500B MTU) |
| Memory | **<8 MB** under continuous load |
| Latency | **<35µs** per packet average |
| CPU | Multi-core scaling (dedicated native OS worker threads) |
| Allocs | **Zero-copy** pipeline (ref-counted `bytes::Bytes` packet wrappers) |
| Locks | **Lock-free** packet structures and `ArcSwap` strategy rotation |
| PRNG | **ChaCha12Rng** / **Xoshiro256++** (dual-RNG: CSPRNG for wire-visible, fast for non-observable) |

---

## 📦 Installation

### Option 1: Installer (recommended)

Run `FreeDPI-Setup.exe` as Administrator (download from [Releases](https://github.com/AlexZander85/FreeDPI-Windows/releases) or build yourself):

```powershell
FreeDPI-Setup.exe
```

The installer will:
1. Copy `freedpi-service.exe` + `WinDivert64.sys` to `C:\Program Files\FreeDPI\`
2. Register the Windows service via SCM (`--install`)
3. Start the FreeDPI service

After installation, the service starts automatically at every boot.

### Option 2: Manual deployment

```powershell
# From dist/
.\deploy.ps1 install
```

### Option 3: Build from source

```bash
# Prerequisites: Rust 1.83+, MSVC build tools
cd src
cargo build --release -p freedpi-service
# Output: target/release/freedpi-service.exe
```

---

## 🚨 Windows Security — What to Expect

FreeDPI uses **WinDivert** (kernel-level packet filter) and **raw sockets**. This is technically similar to what malware does — so security software will react.

### UAC (User Account Control)

| Step | UAC prompt? | Why |
|------|-------------|-----|
| `FreeDPI-Setup.exe` (installer) | ✅ **Once** | Creates dir in `Program Files`, registers service |
| `freedpi-service.exe --install` | ✅ **Once** | Registers service with SCM |
| Service startup (`net start`) | ❌ No | Runs as `LocalSystem` — above UAC |
| Runtime (packet interception) | ❌ No | Kernel-level via WinDivert driver |

> After installation, UAC does **not** bother you again. The service starts automatically on boot.

### Windows Defender & SmartScreen

```
🟡 SmartScreen:   "Windows protected your PC"
                  → Click "Run anyway"

🔴 Defender:      May quarantine WinDivert64.sys
                  → Add exclusion: C:\Program Files\FreeDPI\

🔴 Real-time AV:  May flag kernel driver activity
                  → This is expected — WinDivert intercepts ALL TCP traffic
```

**Why this happens:** WinDivert64.sys operates in **ring 0** (kernel) and intercepts every TCP packet. To an antivirus, this looks identical to rootkit behavior. Defender cannot distinguish intent from behavior.

### ⚠️ HVCI / Memory Integrity (Critical)

**Windows 11** enables **Hypervisor-protected Code Integrity (HVCI)** by default on most new devices. HVCI blocks any kernel driver **without a Microsoft WHQL signature**.

```
❌ WinDivert64.sys IS signed (EV Code Signing by Sectigo)
❌ But it does NOT have a WHQL signature
❌ Therefore HVCI will BLOCK it with error 577 (ERROR_INVALID_IMAGE_HASH)
```

**To fix this, you MUST disable Memory Integrity:**

```
Settings → Privacy & Security → Windows Security
→ Device Security → Core Isolation details
→ Memory Integrity → OFF
→ Restart
```

<details>
<summary>📷 Visual guide (click to expand)</summary>

```
1. Open Windows Security
2. Click "Device Security"
3. Click "Core isolation details"
4. Toggle "Memory integrity" → OFF
5. Restart your computer
```

</details>

> **Alternative:** Run FreeDPI on a machine or VM without HVCI (most Windows 10, older Windows 11 installs).

### Defender ASR (Attack Surface Reduction)

If you have custom ASR rules, they may block raw socket operations:

```
Add exclusion for: C:\Program Files\FreeDPI\freedpi-service.exe
```

### Third-party Antivirus (Kaspersky, ESET, Dr.Web, etc.)

These are **less likely** to block WinDivert — it is a well-known library used by many networking tools. You may get a prompt:

```
"Allow FreeDPI to access the network?" → Allow
```

---

## ❌ Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `ERROR_INVALID_IMAGE_HASH (577)` | HVCI / Memory Integrity blocking the driver | Disable Memory Integrity (see above) |
| `Access denied` | Not running as Administrator | Run PowerShell/cmd as Administrator |
| `WinDivert driver blocked by antivirus/EDR` | Antivirus quarantined the driver | Add exclusion for `C:\Program Files\FreeDPI\` |
| `WinDivert not initialized` | Driver failed to install | Check Windows System log, disable HVCI |
| `Service not starting` | Config missing or corrupted | Check `config.toml` in installation directory |

### Verifying installation

```powershell
# Check service status
sc query FreeDPI

# View logs
Get-Content "$env:ProgramFiles\FreeDPI\freedpi.log" -Tail 50

# Test API
curl -s http://127.0.0.1:8080/api/v1/status
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

# Custom Strategy Profiles
[[strategies]]
name = "custom_split_reorder"
techniques = ["MultiSplit", "FakeSni", "BadChecksum"]
split_size = 2
split_count = 2

[[strategies]]
name = "custom_seqspoof"
techniques = ["SeqSpoof", "BadChecksum"]

[dns]
doh_url = "https://cloudflare-dns.com/dns-query"
doh_persistent = true
cache_ttl = 300

[split_tunnel]
mode = "Auto"

[probe]
enabled = true
auto_probe_domains = ["youtube.com", "telegram.org", "rutracker.org"]
auto_probe_interval = 300
```

---

## 📁 Project Structure

```
FreeDPI-Windows/
├── src/
│   ├── core/                 # FreeDPI-core crate
│   │   └── src/
│   │       ├── engine/       # Processing pipeline
│   │       ├── desync/       # desync techniques
│   │       │   ├── tcp.rs    # TCP-level
│   │       │   ├── tls.rs    # TLS evasion
│   │       │   ├── quic.rs   # QUIC bypass
│   │       │   ├── http.rs   # HTTP obfuscation
│   │       │   ├── rand.rs   # CSPRNG (ChaCha12Rng), PRNG-hardening
│   │       │   └── obfs.rs   # Protocol obfuscation (padding, XOR)
│   │       ├── probe/        # DPI Probe Module (7-phase pipeline)
│   │       │   ├── ja4_probe.rs   # JA4 TLS analysis
│   │       │   ├── quic_probe.rs  # QUIC scan
│   │       │   ├── ml_classifier.rs # Logistic regression
│   │       │   └── discriminator.rs # Direction classification
│   │       ├── adaptive/     # Auto-TTL, AutoTune registry
│   │       └── conntrack.rs  # Connection tracking (injected_seqs cache)
│   ├── api/                  # REST API (Axum)
│   ├── service/              # Windows Service (SCM Native wrapper)
│   └── ui/                   # System tray GUI (Tauri v2 + React)
└── ARCHITECTURE.md           # Full technical architecture documentation
```

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

<div align="center">

**Built with 🦀 Rust for maximum performance, safety and freedom**

</div>
