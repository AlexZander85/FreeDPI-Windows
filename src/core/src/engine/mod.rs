//! Processing Pipeline — центральный оркестратор, объединяющий все модули.
//!
//! ## Архитектура
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │                    ProcessingPipeline                    │
//! │                                                          │
//! │  ┌──────────┐   ┌──────────┐   ┌──────────────────┐     │
//! │  │ WinDivert │──▶│ Packet   │──▶│ Outbound TLS?    │     │
//! │  │ recv      │   │ Classify │   │ → FakeIP lookup  │     │
//! │  └──────────┘   └──────────┘   │ → GeoRouter      │     │
//! │                                │ → EgressChain     │     │
//! │                                │ → Desync Strategy │     │
//! │                                └────────┬─────────┘     │
//! │                                         ▼               │
//! │  ┌──────────┐   ┌──────────┐   ┌──────────────────┐     │
//! │  │ Stats    │◀──│ WinDivert│◀──│ Forward / Modify  │     │
//! │  │ Update   │   │ send     │   │ Inject (raw sock) │     │
//! │  └──────────┘   │ inject   │   └──────────────────┘     │
//! │                 └──────────┘                             │
//! └──────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Packet Flow (outbound TLS)
//! 1. WinDivert recv → `is_injected_packet()` → skip если наш
//! 2. `Classifier::classify()` → Classification::Tls
//! 3. `FakeIpManager::lookup(dst_ip)` → domain (reverse DNS)
//! 4. `GeoRouter::resolve(domain, dst_ip)` → RouteDecision
//! 5. `HopTab::observe(packet.ttl)` → учим расстояние до сервера
//! 6. `seq_spoof::build_seq_spoof_packet()` → fake CH
//! 7. `event_tag::tag_injected_packet()` → метка для WinDivert
//! 8. `inject_raw(fake_packet)` → raw socket (обходит WinDivert)
//! 9. `send_blocking(original_packet)` → WinDivert (пропускаем оригинал)
//!
//! ## Источник
//! Адаптировано из [zapret](https://github.com/bol-van/zapret),
//! [byedpi](https://github.com/hufrea/byedpi),
//! [sni-spoofing-rust](https://github.com/HirbodBehnam/sni-spoofing-rust).

use crate::adaptive::hop_tab::HopTab;
use crate::classifier::{ClassifiedPacket, Classification, Classifier};
use crate::conntrack::Conntrack;
use crate::desync::{DesyncConfig, DesyncTechnique};
use crate::desync::group::DesyncGroup;
use crate::dns::fakeip::FakeIpManager;
use crate::infra::event_tag;
use crate::packet_engine::PacketEngine;
use crate::routing::geo::GeoRouter;
use pnet_packet::ipv4::Ipv4Packet;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, warn};
use windivert::prelude::{NetworkLayer, WinDivertAddress};

/// Размер буфера для WinDivert recv.
const PACKET_BUFFER_SIZE: usize = 65535;

/// Решение о том, что делать с пакетом.
#[derive(Debug)]
pub enum PacketDecision {
    /// Пропустить без изменений (forward через WinDivert)
    Forward,
    /// Модифицировать и отправить через WinDivert
    Modify(bytes::Bytes),
    /// Инжектировать дополнительный пакет + forward оригинал
    Desync {
        /// Пакеты для инъекции
        inject: Vec<bytes::Bytes>,
        /// Протокол инжектируемых пакетов
        inject_protocol: InjectProtocol,
    },
    /// Дропнуть пакет
    Drop,
}

/// Протокол для инъекции пакетов.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InjectProtocol {
    /// TCP — инъекция через WinDivert (reinject)
    Tcp,
    /// UDP — инъекция через raw socket
    Udp,
}

/// Статистика обработки пакетов.
#[derive(Debug)]
pub struct ProcessingStats {
    /// Всего получено пакетов (считаны из WinDivert)
    pub total_received: AtomicU64,
    /// Пропущено injected пакетов (наши собственные)
    pub injected_skipped: AtomicU64,
    /// Классифицировано как TLS outbound
    pub tls_outbound: AtomicU64,
    /// Fake CH инъекций через raw socket
    pub fake_ch_injected: AtomicU64,
    /// Пакетов отправлено через WinDivert
    pub forwarded: AtomicU64,
    /// Пакетов дропнуто
    pub dropped: AtomicU64,
    /// Ошибок обработки
    pub errors: AtomicU64,
}

impl ProcessingStats {
    fn new() -> Self {
        Self {
            total_received: AtomicU64::new(0),
            injected_skipped: AtomicU64::new(0),
            tls_outbound: AtomicU64::new(0),
            fake_ch_injected: AtomicU64::new(0),
            forwarded: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }

    /// Снэпшот статистики (не-atomic копия для чтения).
    pub fn snapshot(&self) -> ProcessingStatsSnapshot {
        ProcessingStatsSnapshot {
            total_received: self.total_received.load(Ordering::Relaxed),
            injected_skipped: self.injected_skipped.load(Ordering::Relaxed),
            tls_outbound: self.tls_outbound.load(Ordering::Relaxed),
            fake_ch_injected: self.fake_ch_injected.load(Ordering::Relaxed),
            forwarded: self.forwarded.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }
}

/// Снэпшот статистики (для чтения).
#[derive(Debug, Clone, Default)]
pub struct ProcessingStatsSnapshot {
    pub total_received: u64,
    pub injected_skipped: u64,
    pub tls_outbound: u64,
    pub fake_ch_injected: u64,
    pub forwarded: u64,
    pub dropped: u64,
    pub errors: u64,
}

/// Конфигурация Processing Pipeline.
#[derive(Debug, Clone)]
pub struct ProcessingConfig {
    /// Разрешить SEQ Spoofing (fake CH)
    pub seq_spoof_enabled: bool,
    /// Fake SNI для SEQ Spoofing
    pub fake_sni: String,
    /// Разрешить HopTab auto-TTL
    pub hop_tab_enabled: bool,
    /// Разрешить EventTag loop prevention
    pub event_tag_enabled: bool,
    /// Разрешить Geo-Routing
    pub geo_routing_enabled: bool,
    /// Порт для DPI desync (обычно 443)
    pub desync_port: u16,
    /// Только outbound пакеты
    pub only_outbound: bool,
    /// Период вывода статистики (0 = отключено)
    pub stats_print_interval: Duration,
    /// Конфигурация desync техник
    pub desync: DesyncConfig,
    /// Техники для применения (пусто = default set)
    pub techniques: Vec<DesyncTechnique>,
}

impl Default for ProcessingConfig {
    fn default() -> Self {
        Self {
            seq_spoof_enabled: true,
            fake_sni: "www.google.com".to_string(),
            hop_tab_enabled: true,
            event_tag_enabled: true,
            geo_routing_enabled: true,
            desync_port: 443,
            only_outbound: true,
            stats_print_interval: Duration::from_secs(60),
            desync: DesyncConfig::default(),
            techniques: Vec::new(),
        }
    }
}

/// Processing Pipeline — центральный оркестратор пакетной обработки.
///
/// Объединяет:
/// - `PacketEngine` — WinDivert + raw socket I/O
/// - `Classifier` — классификация пакетов
/// - `FakeIpManager` — reverse DNS lookup
/// - `GeoRouter` — региональная маршрутизация
/// - `HopTab` — auto-TTL кэш для fake пакетов
/// - EventTag — loop prevention
/// - SEQ Spoofing — fake CH инъекция
///
/// ## Потокобезопасность
/// Все внутренние компоненты — `Send + Sync`.
/// `ProcessingPipeline` можно разделять между потоками через `Arc`.
///
/// ## Пример
/// ```rust
/// use byebyedpi_core::engine::ProcessingPipeline;
/// use byebyedpi_core::engine::ProcessingConfig;
/// use std::sync::Arc;
///
/// // Pipeline requires admin rights for WinDivert.
/// // In tests, use api-only mode:
/// let pipeline = ProcessingPipeline::new_api_only(ProcessingConfig::default());
/// assert!(!pipeline.has_divert());
/// ```
pub struct ProcessingPipeline {
    packet_engine: Arc<PacketEngine>,
    fake_ip: Arc<FakeIpManager>,
    geo_router: Arc<GeoRouter>,
    hop_tab: Arc<HopTab>,
    conntrack: Arc<Conntrack>,
    desync_group: Arc<DesyncGroup>,
    config: ProcessingConfig,
    stats: Arc<ProcessingStats>,
    /// SEQ numbers injected fake пакетов (для skip retransmits)
    injected_seqs: dashmap::DashSet<u32>,
}

impl ProcessingPipeline {
    /// Создаёт новый ProcessingPipeline с WinDivert + всеми компонентами.
    ///
    /// # Требования
    /// - Admin права для WinDivert + raw socket
    /// - WinDivert DLL в PATH
    pub fn new(
        filter: &str,
        config: ProcessingConfig,
        geo_router: Arc<GeoRouter>,
        fake_ip: Arc<FakeIpManager>,
        hop_tab: Arc<HopTab>,
    ) -> Result<Self, anyhow::Error> {
        let packet_engine = Arc::new(PacketEngine::new(filter)?);
        let conntrack = Arc::new(Conntrack::new(Duration::from_secs(120)));
        let desync_group = Arc::new(Self::build_desync_group(&config));

        Ok(Self {
            packet_engine,
            fake_ip,
            geo_router,
            hop_tab,
            conntrack,
            desync_group,
            config,
            stats: Arc::new(ProcessingStats::new()),
            injected_seqs: dashmap::DashSet::new(),
        })
    }

    /// Создаёт pipeline без WinDivert (API-only / тестовый режим).
    pub fn new_api_only(config: ProcessingConfig) -> Self {
        let packet_engine = Arc::new(PacketEngine::new_api_only());
        let desync_group = Arc::new(Self::build_desync_group(&config));

        Self {
            packet_engine,
            fake_ip: Arc::new(FakeIpManager::new(1000)),
            geo_router: Arc::new(GeoRouter::new_default()),
            hop_tab: Arc::new(HopTab::new()),
            conntrack: Arc::new(Conntrack::new(Duration::from_secs(120))),
            desync_group,
            config,
            stats: Arc::new(ProcessingStats::new()),
            injected_seqs: dashmap::DashSet::new(),
        }
    }

    /// Строит DesyncGroup из конфигурации.
    fn build_desync_group(config: &ProcessingConfig) -> DesyncGroup {
        let mut group = DesyncGroup::new(config.desync.clone());
        if config.techniques.is_empty() {
            // Default: FakeSni + MultiSplit + BadChecksum
            group.add(crate::desync::DesyncTechnique::FakeSni);
            group.add(crate::desync::DesyncTechnique::MultiSplit);
            group.add(crate::desync::DesyncTechnique::BadChecksum);
        } else {
            for t in &config.techniques {
                group.add(*t);
            }
        }
        group
    }

    /// Запускает основной цикл обработки пакетов.
    ///
    /// Завершается при получении `shutdown` сигнала или разрыве WinDivert.
    pub async fn run(&self, shutdown: tokio::sync::broadcast::Receiver<()>) {
        debug!("ProcessingPipeline started");

        let (tx, mut rx) = tokio::sync::mpsc::channel::<CapturedPacket>(1024);

        // WinDivert recv loop
        let engine = self.packet_engine.clone();
        let stats = self.stats.clone();
        let mut shutdown_rx = shutdown.resubscribe();
        let handle = tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; PACKET_BUFFER_SIZE];
            loop {
                if shutdown_rx.try_recv().is_ok() {
                    debug!("WinDivert recv: shutdown signal received");
                    break;
                }
                match engine.recv_blocking(&mut buf) {
                    Ok((data, addr)) => {
                        stats.total_received.fetch_add(1, Ordering::Relaxed);
                        if tx.blocking_send(CapturedPacket { data, addr }).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        error!("WinDivert recv error: {}", e);
                        break;
                    }
                }
            }
        });

        // Packet processing loop
        while let Some(captured) = rx.recv().await {
            if self.config.event_tag_enabled && event_tag::is_injected_packet(&captured.data) {
                self.stats.injected_skipped.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            match self.process_one(&captured).await {
                Ok(PacketDecision::Forward) => {
                    self.forward_packet(&captured).await;
                }
                Ok(PacketDecision::Modify(modified)) => {
                    if let Err(e) = self.packet_engine.send_blocking(&modified, &captured.addr) {
                        error!("Failed to send modified packet: {}", e);
                        self.stats.errors.fetch_add(1, Ordering::Relaxed);
                    }
                    self.stats.forwarded.fetch_add(1, Ordering::Relaxed);
                }
                Ok(PacketDecision::Desync { inject, inject_protocol }) => {
                    for inject_pkt in &inject {
                        match inject_protocol {
                            InjectProtocol::Tcp => {
                                // TCP: reinject через WinDivert (raw socket НЕ работает для TCP)
                                let mut tagged = inject_pkt.to_vec();
                                if self.config.event_tag_enabled {
                                    event_tag::tag_injected_packet(&mut tagged);
                                }
                                if let Err(e) = self.packet_engine.inject_via_divert(&tagged, &captured.addr) {
                                    warn!("Failed to inject TCP desync packet via WinDivert: {}", e);
                                }
                            }
                            InjectProtocol::Udp => {
                                // UDP: raw socket работает (не проходит через WinDivert filter)
                                if let Err(e) = self.packet_engine.inject_raw_udp(inject_pkt) {
                                    warn!("Failed to inject UDP desync packet via raw socket: {}", e);
                                }
                            }
                        }
                        self.stats.fake_ch_injected.fetch_add(1, Ordering::Relaxed);
                    }
                    self.forward_packet(&captured).await;
                }
                Ok(PacketDecision::Drop) => {
                    self.packet_engine.drop_packet();
                    self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    debug!("Packet processing error (forwarding as fallback): {}", e);
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                    self.forward_packet(&captured).await;
                }
            }
        }

        let _ = handle.await;
        debug!("ProcessingPipeline stopped");
    }

    /// Отправляет пакет через WinDivert (forward).
    async fn forward_packet(&self, captured: &CapturedPacket) {
        if let Err(e) = self.packet_engine.send_blocking(&captured.data, &captured.addr) {
            error!("Failed to forward packet: {}", e);
            self.stats.errors.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.forwarded.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Обрабатывает один пакет: классификация → маршрутизация → desync.
    async fn process_one(&self, captured: &CapturedPacket) -> Result<PacketDecision, anyhow::Error> {
        let classification = Classifier::classify(&captured.data);

        match classification {
            Classification::Tls(cp) if cp.dst_port == self.config.desync_port => {
                if self.config.only_outbound && !is_outbound(&cp.src_ip) {
                    return Ok(PacketDecision::Forward);
                }
                self.process_outbound_tls(&cp, &captured.data, &captured.addr).await
            }
            Classification::Quic(cp) => {
                // QUIC: применяем QUIC desync техники
                if self.config.only_outbound && !is_outbound(&cp.src_ip) {
                    return Ok(PacketDecision::Forward);
                }
                self.process_quic(&cp, &captured.data).await
            }
            Classification::Dns(_) => {
                // DNS: пропускаем (DNS engine обрабатывает отдельно)
                Ok(PacketDecision::Forward)
            }
            Classification::Http(cp) => {
                // HTTP: применяем HTTP desync техники
                if self.config.only_outbound && !is_outbound(&cp.src_ip) {
                    return Ok(PacketDecision::Forward);
                }
                self.process_http(&cp, &captured.data).await
            }
            _ => Ok(PacketDecision::Forward),
        }
    }

    /// Обрабатывает outbound QUIC пакет.
    async fn process_quic(
        &self,
        _cp: &ClassifiedPacket,
        original_packet: &[u8],
    ) -> Result<PacketDecision, anyhow::Error> {
        let result = self.apply_desync_async(original_packet).await;
        if result.inject.is_empty() && result.modified.is_none() && !result.drop {
            return Ok(PacketDecision::Forward);
        }
        if result.drop {
            return Ok(PacketDecision::Drop);
        }
        if let Some(modified) = result.modified {
            return Ok(PacketDecision::Modify(modified));
        }
        Ok(PacketDecision::Desync {
            inject: result.inject,
            inject_protocol: InjectProtocol::Udp,
        })
    }

    /// Обрабатывает outbound HTTP пакет.
    async fn process_http(
        &self,
        _cp: &ClassifiedPacket,
        original_packet: &[u8],
    ) -> Result<PacketDecision, anyhow::Error> {
        let result = self.apply_desync_async(original_packet).await;
        if result.inject.is_empty() && result.modified.is_none() && !result.drop {
            return Ok(PacketDecision::Forward);
        }
        if result.drop {
            return Ok(PacketDecision::Drop);
        }
        if let Some(modified) = result.modified {
            return Ok(PacketDecision::Modify(modified));
        }
        Ok(PacketDecision::Desync {
            inject: result.inject,
            inject_protocol: InjectProtocol::Tcp,
        })
    }

    /// Обрабатывает outbound TLS пакет: DNS → GeoRouter → Desync.
    async fn process_outbound_tls(
        &self,
        cp: &ClassifiedPacket,
        original_packet: &[u8],
        captured_addr: &windivert::prelude::WinDivertAddress<windivert::prelude::NetworkLayer>,
    ) -> Result<PacketDecision, anyhow::Error> {
        self.stats.tls_outbound.fetch_add(1, Ordering::Relaxed);

        // 0. Skip retransmits injected пакетов (FIX-5: Fake CH race prevention)
        {
            if let Some(ip) = crate::desync::parse_ip_header(original_packet) {
                let tcp_data = &original_packet[ip.header_len..];
                if let Some(tcp) = pnet_packet::tcp::TcpPacket::new(tcp_data) {
                    if self.injected_seqs.contains(&tcp.get_sequence()) {
                        return Ok(PacketDecision::Forward);
                    }
                }
            }
        }

        // 1. Reverse DNS lookup через FakeIP
        let domain = self.fake_ip.lookup(&cp.dst_ip);

        // 2. Geo-Routing
        if self.config.geo_routing_enabled {
            let decision = self.geo_router.resolve(
                domain.as_deref().unwrap_or("unknown"),
                Some(std::net::IpAddr::V4(cp.dst_ip)),
            );

            // Excluded — не применяем desync
            if decision.excluded {
                debug!("Excluded by GeoRouter: {}", domain.as_deref().unwrap_or("?"));
                return Ok(PacketDecision::Forward);
            }
        }

        // 3. HopTab observation (учим TTL)
        if self.config.hop_tab_enabled {
            let ip_packet = Ipv4Packet::new(original_packet)
                .ok_or_else(|| anyhow::anyhow!("Failed to parse IP for HopTab"))?;
            self.hop_tab.observe(
                HopTab::ip_to_u32(&cp.dst_ip),
                ip_packet.get_ttl(),
            );
        }

        // 4. Conntrack — записываем соединение
        {
            use crate::conntrack::{ConnKey, ConntrackEntry, ConnState};
            use std::time::Instant;

            let key = ConnKey::new(cp.src_ip, cp.dst_ip, cp.src_port, cp.dst_port);
            let entry = ConntrackEntry {
                client_isn: 0,
                server_isn: 0,
                client_seq: 0,
                server_seq: 0,
                client_ack: 0,
                server_ack: 0,
                rtt_us: 0,
                state: ConnState::Established,
                desync_applied: false,
                strategy_id: 0,
                last_activity: Instant::now(),
                dup_ack_count: 0,
                rng: Some(crate::desync::rand::PerConnRng::new(cp.dst_ip.to_bits() as u64)),
            };
            self.conntrack.upsert(key, entry);
        }

        // 5. DesyncGroup — применяет все настроенные техники
        let result = self.apply_desync_async(original_packet).await;

        // 5.1. Запоминаем SEQ инжектированных пакетов (для skip retransmits)
        if !result.inject.is_empty() {
            if let Some(ip) = crate::desync::parse_ip_header(original_packet) {
                let tcp_data = &original_packet[ip.header_len..];
                if let Some(tcp) = pnet_packet::tcp::TcpPacket::new(tcp_data) {
                    self.injected_seqs.insert(tcp.get_sequence());
                }
            }
        }

        if result.inject.is_empty() && result.modified.is_none() && !result.drop {
            // Ни одна техника не модифицировала пакет — forward как есть
            return Ok(PacketDecision::Forward);
        }

        if result.drop {
            return Ok(PacketDecision::Drop);
        }

        if let Some(modified) = result.modified {
            // Техника модифицировала оригинальный пакет
            // + возможны inject'ы
            if result.inject.is_empty() {
                return Ok(PacketDecision::Modify(modified));
            }
            // Modified + inject: сначала inject через WinDivert, потом modify
            for inject_pkt in &result.inject {
                self.inject_tcp_packet(inject_pkt, captured_addr)?;
            }
            return Ok(PacketDecision::Modify(modified));
        }

        // Только inject'ы (без модификации оригинала)
        Ok(PacketDecision::Desync {
            inject: result.inject,
            inject_protocol: InjectProtocol::Tcp,
        })
    }

    /// Инжектирует TCP пакет через WinDivert с EventTag.
    fn inject_tcp_packet(&self, packet: &[u8], addr: &windivert::prelude::WinDivertAddress<windivert::prelude::NetworkLayer>) -> Result<(), anyhow::Error> {
        let mut tagged = packet.to_vec();
        if self.config.event_tag_enabled {
            event_tag::tag_injected_packet(&mut tagged);
        }
        self.packet_engine.inject_via_divert(&tagged, addr)
            .map_err(|e| anyhow::anyhow!("WinDivert inject failed: {}", e))?;
        self.stats.fake_ch_injected.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    // ---- Accessors ----

    /// Проверяет, инициализирован ли WinDivert.
    pub fn has_divert(&self) -> bool {
        self.packet_engine.has_divert()
    }

    /// Применяет DesyncGroup к пакету async (через spawn_blocking).
    ///
    /// Предотвращает Tokio Reactor Starvation:
    /// - Лёгкие операции (TTL, window) — выполняются in-place
    /// - Тяжёлые (ChaCha20, fragmentation) — offload на rayon через spawn_blocking
    async fn apply_desync_async(&self, packet: &[u8]) -> crate::desync::DesyncResult {
        let packet = bytes::Bytes::copy_from_slice(packet);
        let group = self.desync_group.clone();

        tokio::task::spawn_blocking(move || {
            group.apply(&packet)
        })
        .await
        .unwrap_or_else(|e| {
            tracing::error!("DesyncGroup spawn_blocking failed: {}", e);
            crate::desync::DesyncResult::passthrough()
        })
    }

    /// Возвращает ссылку на статистику.
    pub fn stats(&self) -> &ProcessingStats {
        &self.stats
    }

    /// Возвращает Arc<ProcessingStats>.
    pub fn stats_arc(&self) -> Arc<ProcessingStats> {
        self.stats.clone()
    }

    /// Возвращает ссылку на PacketEngine.
    pub fn packet_engine(&self) -> &PacketEngine {
        &self.packet_engine
    }

    /// Возвращает конфигурацию.
    pub fn config(&self) -> &ProcessingConfig {
        &self.config
    }
}

/// Пакет, захваченный WinDivert.
struct CapturedPacket {
    data: Vec<u8>,
    addr: WinDivertAddress<NetworkLayer>,
}

/// Определяет, является ли src_ip "локальным" (outbound).
///
/// Проверяет common private ranges: 127.0.0.0/8, 10.0.0.0/8,
/// 172.16.0.0/12, 192.168.0.0/16.
fn is_outbound(src_ip: &Ipv4Addr) -> bool {
    let octets = src_ip.octets();
    match octets[0] {
        127 => true,                                        // loopback
        10 => true,                                         // 10.0.0.0/8
        172 if octets[1] >= 16 && octets[1] <= 31 => true, // 172.16.0.0/12
        192 if octets[1] == 168 => true,                    // 192.168.0.0/16
        _ => false,
    }
}

impl Default for ProcessingPipeline {
    fn default() -> Self {
        Self::new_api_only(ProcessingConfig::default())
    }
}
