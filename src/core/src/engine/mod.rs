//! Processing Pipeline — центральный оркестратор, объединяющий все модули.
//!
//! ## Packet Flow (outbound TLS)
//! 1. WinDivert recv → `is_injected_packet()` → skip если наш
//! 2. `Classifier::classify()` → Classification::Tls
//! 3. `FakeIpManager::lookup(dst_ip)` → domain (reverse DNS)
//! 4. `GeoRouter::resolve(domain, dst_ip)` → RouteDecision
//! 5. `HopTab::observe(packet.ttl)` → учим расстояние до сервера
//! 6. Conntrack — записываем/обновляем соединение
//! 7. DesyncGroup → fake CH / split / bad checksum
//! 8. Inject fake пакет, forward оригинал

use crate::adaptive::auto_tune::{AutoTune, TuneParams};
use crate::adaptive::hop_tab::HopTab;
use crate::classifier::{Classification, ClassifiedPacket, Classifier};
use crate::conntrack::Conntrack;
use crate::desync::group::DesyncGroup;
use crate::desync::{DesyncConfig, DesyncTechnique};
use crate::dns::fakeip::FakeIpManager;
use crate::packet_engine::{PacketBufferPool, PacketEngine, PaddedCounter};
use crate::routing::geo::GeoRouter;
use pnet_packet::ipv4::Ipv4Packet;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use tracing::{debug, error, warn};
use windivert::prelude::{NetworkLayer, WinDivertAddress};

#[derive(Debug)]
pub enum PacketDecision {
    Forward,
    Modify(bytes::Bytes),
    Desync {
        inject: smallvec::SmallVec<[bytes::Bytes; 4]>,
        modified: Option<bytes::Bytes>,
        inject_protocol: InjectProtocol,
        inter_delay_us: u32,
    },
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InjectProtocol {
    Tcp,
    Udp,
}

#[derive(Debug)]
pub struct ProcessingStats {
    pub total_received: PaddedCounter,
    pub injected_skipped: PaddedCounter,
    pub tls_outbound: PaddedCounter,
    pub fake_ch_injected: PaddedCounter,
    pub forwarded: PaddedCounter,
    pub dropped: PaddedCounter,
    pub errors: PaddedCounter,
}

impl ProcessingStats {
    fn new() -> Self {
        Self {
            total_received: PaddedCounter::new(0),
            injected_skipped: PaddedCounter::new(0),
            tls_outbound: PaddedCounter::new(0),
            fake_ch_injected: PaddedCounter::new(0),
            forwarded: PaddedCounter::new(0),
            dropped: PaddedCounter::new(0),
            errors: PaddedCounter::new(0),
        }
    }

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

#[derive(Debug, Clone)]
pub struct ProcessingConfig {
    pub seq_spoof_enabled: bool,
    pub fake_sni: std::sync::Arc<str>,
    pub hop_tab_enabled: bool,
    pub geo_routing_enabled: bool,
    pub desync_port: u16,
    pub only_outbound: bool,
    pub stats_print_interval: Duration,
    pub desync: DesyncConfig,
    pub techniques: Vec<DesyncTechnique>,
}

impl Default for ProcessingConfig {
    fn default() -> Self {
        Self {
            seq_spoof_enabled: true,
            fake_sni: std::sync::Arc::from("www.google.com"),
            hop_tab_enabled: true,
            geo_routing_enabled: true,
            desync_port: 443,
            only_outbound: true,
            stats_print_interval: Duration::from_secs(60),
            desync: DesyncConfig::default(),
            techniques: Vec::new(),
        }
    }
}

/// Ключ для отслеживания injected SEQ — 5-tuple (src_ip, dst_ip, src_port, dst_port, seq).
type SeqKey = (u64, u64, u16, u16, u32);

pub struct ProcessingPipeline {
    packet_engine: Arc<PacketEngine>,
    fake_ip: Arc<FakeIpManager>,
    geo_router: Arc<GeoRouter>,
    hop_tab: Arc<HopTab>,
    conntrack: Arc<Conntrack>,
    desync_group: Arc<DesyncGroup>,
    config: ProcessingConfig,
    stats: Arc<ProcessingStats>,
    injected_seqs: moka::sync::Cache<SeqKey, ()>,
    auto_tune: std::sync::Mutex<AutoTune>,
    /// Buffer pool для zero-alloc steady-state.
    /// Один пул на все workers (ArrayQueue — lock-free MPMC, безопасно для concurrent access).
    buf_pool: Arc<PacketBufferPool>,
    /// Флаг наличия non-empty session ticket от сервера.
    /// Устанавливается после успешного TLS handshake, когда сервер
    /// прислал session ticket. Используется для 0-RTT resumption
    /// при генерации fake ClientHello (SeqSpoof).
    #[allow(dead_code)]
    has_non_empty_session_ticket: bool,
}

/// Проверяет, содержит ли TLS ClientHello non-empty session_ticket extension.
///
/// Это сигнал TLS 1.3 session resumption (RFC 8446 §4.6.1):
/// - Empty session_ticket = просто signalling support (есть в каждом CH)
/// - Non-empty session_ticket = реальный тикет от предыдущей сессии = resumption
///
/// # Arguments
/// * `payload` — полный TLS record (ContentType + Version + Length + Handshake + CH)
fn has_non_empty_session_ticket(payload: &[u8]) -> bool {
    // TLS Record: ContentType(1) + Version(2) + Length(2)
    if payload.len() < 5 || payload[0] != 0x16 {
        return false;
    }
    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if 5 + record_len > payload.len() {
        return false;
    }

    // Handshake: Type(1) + Length(3) + Body
    let handshake = &payload[5..];
    if handshake.len() < 4 || handshake[0] != 0x01 {
        // 0x01 = ClientHello
        return false;
    }
    let ch_body = &handshake[4..];

    // ClientHello: ProtocolVersion(2) + Random(32) + SessionID(1 + len)
    if ch_body.len() < 35 {
        return false;
    }
    let session_id_len = ch_body[34] as usize;
    let mut pos = 35 + session_id_len;

    // Cipher Suites: length(2) + suites
    if pos + 2 > ch_body.len() {
        return false;
    }
    let cs_len = u16::from_be_bytes([ch_body[pos], ch_body[pos + 1]]) as usize;
    pos += 2 + cs_len;

    // Compression Methods: length(1) + methods
    if pos >= ch_body.len() {
        return false;
    }
    let comp_len = ch_body[pos] as usize;
    pos += 1 + comp_len;

    // Extensions: total_length(2) + extensions
    if pos + 2 > ch_body.len() {
        return false;
    }
    let ext_total = u16::from_be_bytes([ch_body[pos], ch_body[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + ext_total;
    while pos + 4 <= ext_end && pos + 4 <= ch_body.len() {
        let ext_type = u16::from_be_bytes([ch_body[pos], ch_body[pos + 1]]);
        let ext_len = u16::from_be_bytes([ch_body[pos + 2], ch_body[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0023 {
            // session_ticket extension (RFC 5077 / RFC 8446 §4.6.1)
            // Non-empty = resumption (real ticket from previous session)
            return ext_len > 0;
        }
        pos += ext_len;
    }

    false
}

impl ProcessingPipeline {
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

        // Buffer pool: capacity = workers * 4 (глубина на worker)
        // Каждый буфер 2048 байт → pool = 4 * 4 * 2048 = ~32 KB
        let buf_pool = Arc::new(PacketBufferPool::new(64));

        Ok(Self {
            packet_engine,
            fake_ip,
            geo_router,
            hop_tab,
            conntrack,
            desync_group,
            config,
            stats: Arc::new(ProcessingStats::new()),
            injected_seqs: moka::sync::Cache::builder()
                .max_capacity(100_000)
                .time_to_live(Duration::from_secs(30))
                .build(),
            auto_tune: std::sync::Mutex::new(AutoTune::new()),
            buf_pool,
            has_non_empty_session_ticket: false,
        })
    }

    pub fn new_api_only(config: ProcessingConfig) -> Self {
        let packet_engine = Arc::new(PacketEngine::new_api_only());
        let desync_group = Arc::new(Self::build_desync_group(&config));

        let buf_pool = Arc::new(PacketBufferPool::new(64));

        Self {
            packet_engine,
            fake_ip: Arc::new(FakeIpManager::new(1000)),
            geo_router: Arc::new(GeoRouter::new_default()),
            hop_tab: Arc::new(HopTab::new()),
            conntrack: Arc::new(Conntrack::new(Duration::from_secs(120))),
            desync_group,
            config,
            stats: Arc::new(ProcessingStats::new()),
            injected_seqs: moka::sync::Cache::builder()
                .max_capacity(100_000)
                .time_to_live(Duration::from_secs(30))
                .build(),
            auto_tune: std::sync::Mutex::new(AutoTune::new()),
            buf_pool,
            has_non_empty_session_ticket: false,
        }
    }

    fn build_desync_group(config: &ProcessingConfig) -> DesyncGroup {
        let mut group = DesyncGroup::new(config.desync.clone());
        if config.techniques.is_empty() {
            group.add(DesyncTechnique::FakeSni);
            group.add(DesyncTechnique::BadChecksum);
        } else {
            for t in &config.techniques {
                group.add(*t);
            }
        }
        // Валидация при построении — падаем рано с понятной ошибкой
        if let Err(e) = group.validate() {
            tracing::error!("DesyncGroup validation failed: {}", e);
            // Fallback на safe default: только FakeSni + BadChecksum
            let mut safe_group = DesyncGroup::new(config.desync.clone());
            safe_group.add(DesyncTechnique::FakeSni);
            safe_group.add(DesyncTechnique::BadChecksum);
            return safe_group;
        }
        group
    }

    pub async fn run(self: Arc<Self>, shutdown: tokio::sync::broadcast::Receiver<()>) {
        debug!("ProcessingPipeline started");

        let n_workers = num_cpus::get().max(2);
        const QUEUE_SIZE: usize = 1024;

        // Per-worker lock-free queues for rendezvous-free handoff
        let queues: Vec<Arc<crossbeam::queue::ArrayQueue<CapturedPacket>>> = (0..n_workers)
            .map(|_| Arc::new(crossbeam::queue::ArrayQueue::new(QUEUE_SIZE)))
            .collect();

        let shutdown_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));

        // ── Producer: reads from WinDivert, distributes by packet hash ──
        {
            let engine = self.packet_engine.clone();
            let stats = self.stats.clone();
            let queues = queues.clone();
            let shutdown_flag = shutdown_flag.clone();
            let mut shutdown_rx = shutdown.resubscribe();

            let pool = self.buf_pool.clone();
            tokio::task::spawn_blocking(move || {
                loop {
                    if shutdown_rx.try_recv().is_ok() {
                        debug!("WinDivert recv: shutdown signal received");
                        shutdown_flag.store(true, Ordering::Release);
                        break;
                    }
                    match engine.recv_blocking(&pool) {
                        Ok((data, addr)) => {
                            stats.total_received.fetch_add(1, Ordering::Relaxed);
                            let pkt = CapturedPacket { data, addr };

                            // Route by 4-tuple hash — все пакеты одного TCP-соединения → один воркер
                            let idx = route_to_worker(&pkt.data, n_workers);

                            // Non-blocking push with spin-retry
                            while queues[idx].push(pkt.clone()).is_err() {
                                std::hint::spin_loop();
                            }
                        }
                        Err(e) => {
                            // На ошибку recv не делаем break — WinDivert handle мог
                            // смениться через update_filter. Producer переживёт смену.
                            // Если ошибка повторяется — retry с экспоненциальной задержкой.
                            error!("WinDivert recv error: {}", e);
                            std::thread::sleep(Duration::from_millis(10));
                        }
                    }
                }
            });
        }

        // ── Workers: N std::threads calling sync methods directly ──
        // All pipeline fields are behind Arc — clone per worker.
        let mut worker_handles = Vec::with_capacity(n_workers);
        for queue in queues.into_iter() {
            let shutdown_flag = shutdown_flag.clone();
            let self_clone = self.clone();

            let handle = std::thread::spawn(move || {
                let mut empty_spins: u32 = 0;

                loop {
                    if shutdown_flag.load(Ordering::Acquire) {
                        break;
                    }

                    match queue.pop() {
                        Some(captured) => {
                            empty_spins = 0;
                            match self_clone.process_one_sync(&captured) {
                                Ok(decision) => {
                                    self_clone.execute_decision_sync(decision, &captured)
                                }
                                Err(e) => {
                                    debug!("Packet processing error (forwarding fallback): {}", e);
                                    self_clone.stats.errors.fetch_add(1, Ordering::Relaxed);
                                    self_clone.forward_packet_sync(&captured);
                                }
                            }
                            // Возвращаем буфер захваченного пакета в пул.
                            // Все send/inject уже сделали release на своих клонах;
                            // captured.data — последний владелец исходного буфера.
                            self_clone.buf_pool.release_bytes(captured.data);
                        }
                        None => {
                            empty_spins += 1;
                            if empty_spins < 100 {
                                std::hint::spin_loop();
                            } else {
                                std::thread::sleep(Duration::from_micros(100));
                                empty_spins = 0;
                            }
                        }
                    }
                }
            });

            worker_handles.push(handle);
        }

        // Wait for all workers to finish
        for handle in worker_handles {
            let _ = handle.join();
        }
        debug!("ProcessingPipeline stopped");
    }

    // ──────────────────────────────────────────────
    // Sync processing methods (worker threads)
    // ──────────────────────────────────────────────

    /// Sync version: apply desync directly (no spawn_cpu).
    /// Применяет desync техники с опцией is_resumption для 0-RTT defense.
    /// Использует `is_resumption` только если передан явно (Some).
    /// `None` означает "неизвестно" — техники обрабатывают как false.
    fn apply_desync_sync(
        &self,
        packet: bytes::Bytes,
        dscp_value: Option<u8>,
        tune_params: Option<TuneParams>,
        is_resumption: Option<bool>,
        conn_rng_fork: Option<crate::desync::rand::PerConnRng>,
    ) -> crate::desync::DesyncResult {
        let override_params: Option<crate::desync::group::ConfigOverride> =
            tune_params.map(Into::into);
        self.desync_group.apply_with_rng(
            &packet,
            dscp_value,
            override_params,
            is_resumption,
            conn_rng_fork,
        )
    }

    /// Sync version: send packet via WinDivert (no spawn_blocking).
    /// После отправки возвращает буфер в пул через release_bytes.
    fn send_packet_sync(&self, packet: bytes::Bytes, addr: &WinDivertAddress<NetworkLayer>) {
        let result = self.packet_engine.send_blocking(&packet, addr);
        match result {
            Ok(_) => {
                self.stats.forwarded.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                error!("Failed to send packet: {}", e);
                self.stats.errors.fetch_add(1, Ordering::Relaxed);
            }
        }
        // Возвращаем буфер в пул независимо от результата send
        self.buf_pool.release_bytes(packet);
    }

    /// Sync version: forward original (same as send_packet_sync).
    fn forward_packet_sync(&self, captured: &CapturedPacket) {
        self.send_packet_sync(captured.data.clone(), &captured.addr);
    }

    /// Sync version: inject TCP fake via raw socket (no spawn_blocking).
    /// После инжекта возвращает буфер в пул.
    fn inject_tcp_packet_sync(&self, packet: bytes::Bytes, addr: &WinDivertAddress<NetworkLayer>) {
        let result = self.packet_engine.inject_via_divert(&packet, addr);
        match result {
            Ok(_) => {
                self.stats.fake_ch_injected.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                warn!("Failed to inject TCP desync packet: {}", e);
            }
        }
        // Возвращаем буфер в пул независимо от результата
        self.buf_pool.release_bytes(packet);
    }

    /// Sync version: process_one (calls sync sub-methods directly).
    fn process_one_sync(&self, captured: &CapturedPacket) -> Result<PacketDecision, anyhow::Error> {
        let classification = Classifier::classify(&captured.data);

        match classification {
            Classification::Tls(cp) if cp.dst_port == self.config.desync_port => {
                if self.config.only_outbound && !is_outbound_cached(cp.src_ip) {
                    return Ok(PacketDecision::Forward);
                }
                // Quick pre-filter
                let conn_key = crate::conntrack::ConnKey::new(
                    cp.src_ip,
                    cp.dst_ip,
                    cp.src_port,
                    cp.dst_port,
                    cp.protocol,
                );
                let desync_applied = self
                    .conntrack
                    .get(&conn_key)
                    .map(|e| e.desync_applied)
                    .unwrap_or(false);
                if !Classifier::is_desync_target(&captured.data, desync_applied) {
                    return Ok(PacketDecision::Forward);
                }
                self.process_outbound_tls_sync(captured, &cp)
            }
            Classification::Quic(cp) => {
                if self.config.only_outbound && !is_outbound_cached(cp.src_ip) {
                    return Ok(PacketDecision::Forward);
                }
                self.process_quic_sync(captured, &cp)
            }
            Classification::Dns(_) => Ok(PacketDecision::Forward),
            Classification::Http(cp) => {
                if self.config.only_outbound && !is_outbound_cached(cp.src_ip) {
                    return Ok(PacketDecision::Forward);
                }
                self.process_http_sync(captured)
            }
            _ => Ok(PacketDecision::Forward),
        }
    }

    fn process_outbound_tls_sync(
        &self,
        captured: &CapturedPacket,
        cp: &ClassifiedPacket,
    ) -> Result<PacketDecision, anyhow::Error> {
        self.stats.tls_outbound.fetch_add(1, Ordering::Relaxed);

        let original_packet = &captured.data;

        // 0. Skip retransmits
        {
            if let Some(ip) = crate::desync::parse_ip_header(original_packet) {
                let tcp_data = &original_packet[ip.header_len()..];
                if let Some(tcp) = pnet_packet::tcp::TcpPacket::new(tcp_data) {
                    let key = (
                        ip_to_u64(cp.src_ip),
                        ip_to_u64(cp.dst_ip),
                        cp.src_port,
                        cp.dst_port,
                        tcp.get_sequence(),
                    );
                    if self.injected_seqs.contains_key(&key) {
                        return Ok(PacketDecision::Forward);
                    }
                }
            }
        }

        // 1. Reverse DNS lookup
        let domain = self.fake_ip.lookup(&cp.dst_ip);

        // 2. Geo-Routing
        if self.config.geo_routing_enabled {
            let decision = self
                .geo_router
                .resolve(domain.as_deref().unwrap_or("unknown"), Some(cp.dst_ip));
            if decision.excluded {
                return Ok(PacketDecision::Forward);
            }
        }

        // 3. HopTab observation
        if self.config.hop_tab_enabled {
            if let Some(ip_packet) = Ipv4Packet::new(original_packet) {
                self.hop_tab
                    .observe(HopTab::ip_to_u32(&cp.dst_ip), ip_packet.get_ttl());
            }
        }

        // 4. Conntrack
        let conn_key = crate::conntrack::ConnKey::new(
            cp.src_ip,
            cp.dst_ip,
            cp.src_port,
            cp.dst_port,
            cp.protocol,
        );
        {
            use crate::conntrack::{ConnState, ConntrackEntry};

            if self.conntrack.get(&conn_key).is_none() {
                let conn_id = ip_to_u64(cp.src_ip)
                    ^ (ip_to_u64(cp.dst_ip) << 32)
                    ^ ((cp.src_port as u64) << 48)
                    ^ (cp.dst_port as u64);
                let entry = ConntrackEntry {
                    client_isn: 0,
                    server_isn: 0,
                    client_seq: 0,
                    server_seq: 0,
                    client_ack: 0,
                    server_ack: 0,
                    rtt_us: 0,
                    state: ConnState::SynSent,
                    desync_applied: false,
                    dscp_spoof: crate::desync::rand::random_range(0, 48) as u8,
                    strategy_id: 0,
                    last_activity: Instant::now(),
                    dup_ack_count: 0,
                    rng: Some(crate::desync::rand::PerConnRng::new(conn_id)),
                    quic_pn: 0,
                    quic_dcid: vec![],
                    is_resumption: false,
                };
                self.conntrack.insert(conn_key, entry);
            } else {
                if let Some(mut entry) = self.conntrack.get_mut(&conn_key) {
                    entry.last_activity = Instant::now();
                }
            }
        }

        // 4.5. T43: Определяем is_resumption по ClientHello и сохраняем в conntrack
        let is_resumption = {
            let payload = &captured.data;
            has_non_empty_session_ticket(payload)
        };
        if let Some(mut entry) = self.conntrack.get_mut(&conn_key) {
            entry.is_resumption = is_resumption;
        }

        // 5. DesyncGroup — sync directly; fork RNG from conntrack if available
        let packet = captured.data.clone();
        let (dscp_value, conn_rng_fork) = if let Some(mut entry) = self.conntrack.get_mut(&conn_key)
        {
            let rng_fork = entry.rng.as_mut().map(|r| r.fork());
            (Some(entry.dscp_spoof), rng_fork)
        } else {
            (None, None)
        };
        let tune_start = Instant::now();
        let result = self.apply_desync_sync(
            packet,
            dscp_value,
            Some(self.get_tuned_config("outbound_tls")),
            Some(is_resumption),
            conn_rng_fork,
        );

        // 5.0. AutoTune
        {
            let latency_us = tune_start.elapsed().as_micros() as u64;
            let success = !result.inject.is_empty() || result.modified.is_some();
            let mut tune = self.auto_tune.lock().unwrap();
            tune.record("outbound_tls", success, latency_us);
            if tune.should_escalate("outbound_tls") {
                warn!(
                    "AutoTune: outbound_tls strategy degrading (latency={}us)",
                    latency_us
                );
            }
        }

        // 5.1. Запоминаем SEQ
        if !result.inject.is_empty() {
            if let Some(ip) = crate::desync::parse_ip_header(original_packet) {
                let tcp_data = &original_packet[ip.header_len()..];
                if let Some(tcp) = pnet_packet::tcp::TcpPacket::new(tcp_data) {
                    let key = (
                        ip_to_u64(cp.src_ip),
                        ip_to_u64(cp.dst_ip),
                        cp.src_port,
                        cp.dst_port,
                        tcp.get_sequence(),
                    );
                    self.injected_seqs.insert(key, ());
                }
            }
        }

        if result.inject.is_empty() && result.modified.is_none() && !result.drop {
            return Ok(PacketDecision::Forward);
        }
        if result.drop {
            return Ok(PacketDecision::Drop);
        }

        let inter_delay = result.inter_delay_us;

        if let Some(modified) = result.modified {
            if result.inject.is_empty() {
                return Ok(PacketDecision::Modify(modified));
            }
            return Ok(PacketDecision::Desync {
                inject: result.inject,
                modified: Some(modified),
                inject_protocol: InjectProtocol::Tcp,
                inter_delay_us: inter_delay,
            });
        }

        Ok(PacketDecision::Desync {
            inject: result.inject,
            modified: result.modified,
            inject_protocol: InjectProtocol::Tcp,
            inter_delay_us: inter_delay,
        })
    }

    fn process_quic_sync(
        &self,
        captured: &CapturedPacket,
        cp: &crate::classifier::ClassifiedPacket,
    ) -> Result<PacketDecision, anyhow::Error> {
        let packet = captured.data.clone();

        // Conntrack: извлекаем QUIC PN/DCID для PN gap detection
        {
            use crate::conntrack::{ConnState, ConntrackEntry};
            use crate::desync::quic::extract_quic_pn_and_dcid;

            if self.conntrack.get(&cp.conn_key).is_none() {
                let conn_id = ip_to_u64(cp.src_ip)
                    ^ (ip_to_u64(cp.dst_ip) << 32)
                    ^ ((cp.src_port as u64) << 48)
                    ^ (cp.dst_port as u64);
                let (quic_pn, quic_dcid) = extract_quic_pn_and_dcid(&packet).unwrap_or((0, vec![]));
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
                    dscp_spoof: crate::desync::rand::random_range(0, 48) as u8,
                    strategy_id: 0,
                    last_activity: std::time::Instant::now(),
                    dup_ack_count: 0,
                    rng: Some(crate::desync::rand::PerConnRng::new(conn_id)),
                    quic_pn,
                    quic_dcid,
                    is_resumption: false,
                };
                self.conntrack.insert(cp.conn_key, entry);
            } else {
                if let Some(mut entry) = self.conntrack.get_mut(&cp.conn_key) {
                    entry.last_activity = std::time::Instant::now();
                    // Обновляем PN, даже если не смогли распарсить (оставляем старый)
                    if let Some((pn, _)) = extract_quic_pn_and_dcid(&packet) {
                        entry.quic_pn = pn;
                    }
                }
            }
        }

        // T43: QUIC не использует is_resumption — передаём None
        let result = self.apply_desync_sync(packet, None, None, None, None);
        if result.inject.is_empty() && result.modified.is_none() && !result.drop {
            return Ok(PacketDecision::Forward);
        }
        if result.drop {
            return Ok(PacketDecision::Drop);
        }
        let inter_delay = result.inter_delay_us;
        if let Some(modified) = result.modified {
            if result.inject.is_empty() {
                return Ok(PacketDecision::Modify(modified));
            }
            return Ok(PacketDecision::Desync {
                inject: result.inject,
                modified: Some(modified),
                inject_protocol: InjectProtocol::Udp,
                inter_delay_us: inter_delay,
            });
        }
        Ok(PacketDecision::Desync {
            inject: result.inject,
            modified: None,
            inject_protocol: InjectProtocol::Udp,
            inter_delay_us: inter_delay,
        })
    }

    fn process_http_sync(
        &self,
        captured: &CapturedPacket,
    ) -> Result<PacketDecision, anyhow::Error> {
        let packet = captured.data.clone();
        // T43: HTTP не использует is_resumption — передаём None
        let result = self.apply_desync_sync(packet, None, None, None, None);
        if result.inject.is_empty() && result.modified.is_none() && !result.drop {
            return Ok(PacketDecision::Forward);
        }
        if result.drop {
            return Ok(PacketDecision::Drop);
        }
        let inter_delay = result.inter_delay_us;
        if let Some(modified) = result.modified {
            if result.inject.is_empty() {
                return Ok(PacketDecision::Modify(modified));
            }
            return Ok(PacketDecision::Desync {
                inject: result.inject,
                modified: Some(modified),
                inject_protocol: InjectProtocol::Tcp,
                inter_delay_us: inter_delay,
            });
        }
        Ok(PacketDecision::Desync {
            inject: result.inject,
            modified: None,
            inject_protocol: InjectProtocol::Tcp,
            inter_delay_us: inter_delay,
        })
    }

    /// Execute a PacketDecision synchronously from a worker thread.
    fn execute_decision_sync(&self, decision: PacketDecision, captured: &CapturedPacket) {
        match decision {
            PacketDecision::Forward => {
                self.forward_packet_sync(captured);
            }
            PacketDecision::Modify(modified) => {
                self.send_packet_sync(modified, &captured.addr);
                self.stats.forwarded.fetch_add(1, Ordering::Relaxed);
            }
            PacketDecision::Desync {
                mut inject,
                modified,
                inject_protocol,
                inter_delay_us,
            } => {
                for (i, inject_pkt) in inject.iter().enumerate() {
                    if i > 0 && inter_delay_us > 0 {
                        std::thread::sleep(Duration::from_micros(inter_delay_us as u64));
                    }
                    match inject_protocol {
                        InjectProtocol::Tcp => {
                            self.inject_tcp_packet_sync(inject_pkt.clone(), &captured.addr);
                        }
                        InjectProtocol::Udp => {
                            let pkt_clone = inject_pkt.clone();
                            if let Err(e) = self.packet_engine.inject_raw_udp(&pkt_clone) {
                                warn!("Failed to inject UDP desync packet: {}", e);
                            }
                            self.buf_pool.release_bytes(pkt_clone);
                        }
                    }
                    self.stats.fake_ch_injected.fetch_add(1, Ordering::Relaxed);
                }
                // Возвращаем оставшиеся inject-буферы в пул (они не были consumed,
                // потому что inject_pkt.clone() только увеличивал refcount).
                for pkt in inject.drain(..) {
                    self.buf_pool.release_bytes(pkt);
                }
                // Timing jitter
                let delay_us = self.config.desync.inject_delay_us;
                if delay_us > 0 {
                    let jitter = crate::desync::rand::random_range(0, delay_us as u32);
                    std::thread::sleep(Duration::from_micros(jitter as u64));
                }
                // Send modified original or forward original
                // (send_packet_sync / forward_packet_sync уже делают release внутри)
                if let Some(modified) = modified {
                    self.send_packet_sync(modified, &captured.addr);
                } else {
                    self.forward_packet_sync(captured);
                }
            }
            PacketDecision::Drop => {
                self.packet_engine.drop_packet();
                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn has_divert(&self) -> bool {
        self.packet_engine.has_divert()
    }

    /// Получает рекомендованные AutoTune параметры для стратегии.
    pub fn get_tuned_config(&self, strategy_name: &str) -> TuneParams {
        self.auto_tune.lock().unwrap().recommend(strategy_name)
    }

    pub fn stats(&self) -> &ProcessingStats {
        &self.stats
    }
    pub fn stats_arc(&self) -> Arc<ProcessingStats> {
        self.stats.clone()
    }
    pub fn packet_engine(&self) -> &PacketEngine {
        &self.packet_engine
    }
    pub fn config(&self) -> &ProcessingConfig {
        &self.config
    }
}

#[derive(Clone)]
struct CapturedPacket {
    data: bytes::Bytes,
    addr: WinDivertAddress<NetworkLayer>,
}

/// Route packet to a worker by hashing the TCP 4-tuple (src_ip, dst_ip, src_port, dst_port).
/// Все пакеты одного соединения → один воркер (in-order desync).
fn route_to_worker(packet: &[u8], n_workers: usize) -> usize {
    if let Some(ip) = crate::desync::parse_ip_header(packet) {
        if ip.protocol() == pnet_packet::ip::IpNextHeaderProtocols::Tcp {
            let tcp_data = &packet[ip.header_len()..];
            if let Some(tcp) = pnet_packet::tcp::TcpPacket::new(tcp_data) {
                let mut h = 0u64;
                h = h
                    .wrapping_mul(0x9E3779B97F4A7C15)
                    .wrapping_add(ip_to_u64(ip.src()));
                h = h
                    .wrapping_mul(0x9E3779B97F4A7C15)
                    .wrapping_add(ip_to_u64(ip.dst()));
                h = h
                    .wrapping_mul(0x9E3779B97F4A7C15)
                    .wrapping_add(tcp.get_source() as u64);
                h = h
                    .wrapping_mul(0x9E3779B97F4A7C15)
                    .wrapping_add(tcp.get_destination() as u64);
                return (h as usize) % n_workers;
            }
        }
    }
    0
}

/// Cached list of local IP addresses, populated once at startup.
static LOCAL_IPS: OnceLock<Arc<Vec<IpAddr>>> = OnceLock::new();

/// Populates `LOCAL_IPS` once. Safe to call multiple times — only the first call takes effect.
pub fn refresh_local_ips() {
    LOCAL_IPS.get_or_init(|| {
        let mut ips = Vec::new();
        if let Ok(ifaces) = local_ip_address::list_afinet_netifas() {
            for (_, ip) in ifaces {
                ips.push(ip);
            }
        }
        Arc::new(ips)
    });
}

/// Convert an IP address to a u64 for hashing/conn_id purposes.
/// For IPv4: zero-extend the 32-bit value.
/// For IPv6: XOR-fold upper and lower 64 bits.
fn ip_to_u64(ip: IpAddr) -> u64 {
    match ip {
        IpAddr::V4(v4) => v4.to_bits() as u64,
        IpAddr::V6(v6) => {
            let bits = v6.to_bits();
            let upper = (bits >> 64) as u64;
            let lower = bits as u64;
            upper ^ lower
        }
    }
}

/// Fast cached check: does `src_ip` belong to a local interface or private range?
pub fn is_outbound_cached(src_ip: IpAddr) -> bool {
    if let Some(ips) = LOCAL_IPS.get() {
        if ips.contains(&src_ip) {
            return true;
        }
    }
    match src_ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            match octets[0] {
                127 => true,
                10 => true,
                172 if octets[1] >= 16 && octets[1] <= 31 => true,
                192 if octets[1] == 168 => true,
                100 if octets[1] >= 64 && octets[1] <= 127 => true,
                _ => false,
            }
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // ULA
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // Link-Local
        }
    }
}

impl Default for ProcessingPipeline {
    fn default() -> Self {
        Self::new_api_only(ProcessingConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Строит minimally-valid TLS ClientHello с session_ticket extension заданной длины.
    ///
    /// # Arguments
    /// * `ticket_len` — длина данных session_ticket (0 = empty ticket, >0 = non-empty)
    fn build_test_ch_with_session_ticket(ticket_len: usize) -> Vec<u8> {
        let mut ch = Vec::with_capacity(300);

        // TLS Record header
        ch.push(0x16); // ContentType: Handshake
        ch.extend_from_slice(&[0x03, 0x01]); // Version
        ch.extend_from_slice(&[0x00, 0x00]); // placeholder length

        // Handshake header
        ch.push(0x01); // ClientHello
        ch.extend_from_slice(&[0x00, 0x00, 0x00]); // placeholder length

        // ClientHello body
        ch.extend_from_slice(&[0x03, 0x03]); // ProtocolVersion: TLS 1.2
        ch.extend_from_slice(&[0u8; 32]); // Random
        ch.push(0); // session_id length (empty)

        // Cipher Suites: TLS_AES_128_GCM_SHA256
        ch.extend_from_slice(&[0x00, 0x02]); // length
        ch.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256

        // Compression Methods: null
        ch.push(1);
        ch.push(0x00);

        // Extensions
        let ext_data_len = 4 + ticket_len; // type(2) + len(2) + data(N)
        let ext_total_len = ext_data_len;
        ch.extend_from_slice(&(ext_total_len as u16).to_be_bytes());

        // session_ticket extension (0x0023)
        ch.extend_from_slice(&0x0023u16.to_be_bytes());
        ch.extend_from_slice(&(ticket_len as u16).to_be_bytes());
        if ticket_len > 0 {
            ch.extend_from_slice(&vec![0xABu8; ticket_len]);
        }

        // Update TLS record length
        let record_len = (ch.len() - 5) as u16;
        ch[3..5].copy_from_slice(&record_len.to_be_bytes());

        // Update handshake length
        let hs_len = (ch.len() - 5 - 4) as u32;
        ch[6..9].copy_from_slice(&hs_len.to_be_bytes()[1..4]); // 3 bytes

        ch
    }

    #[test]
    fn test_has_non_empty_session_ticket_empty() {
        let ch = build_test_ch_with_session_ticket(0);
        assert!(!has_non_empty_session_ticket(&ch));
    }

    #[test]
    fn test_has_non_empty_session_ticket_non_empty() {
        let ch = build_test_ch_with_session_ticket(4);
        assert!(has_non_empty_session_ticket(&ch));
    }

    #[test]
    fn test_has_non_empty_session_ticket_not_tls() {
        let ch = build_test_ch_with_session_ticket(4);
        // ContentType != 0x16
        let mut bad = ch.clone();
        bad[0] = 0x17;
        assert!(!has_non_empty_session_ticket(&bad));
    }

    #[test]
    fn test_has_non_empty_session_ticket_not_clienthello() {
        let ch = build_test_ch_with_session_ticket(4);
        // Handshake type != 0x01
        let mut bad = ch.clone();
        bad[5] = 0x02;
        assert!(!has_non_empty_session_ticket(&bad));
    }

    #[test]
    fn test_has_non_empty_session_ticket_truncated() {
        assert!(!has_non_empty_session_ticket(&[
            0x16, 0x03, 0x01, 0x00, 0x05
        ]));
    }

    #[test]
    fn test_has_non_empty_session_ticket_empty_payload() {
        assert!(!has_non_empty_session_ticket(&[]));
    }

    #[test]
    fn test_has_non_empty_session_ticket_with_real_ch() {
        // Используем реальный CH генератор с resumption
        use crate::adaptive::ch_gen;
        let ch = ch_gen::build_client_hello_template_with_resumption("example.com");
        assert!(has_non_empty_session_ticket(&ch));
    }

    #[test]
    fn test_has_non_empty_session_ticket_with_normal_ch() {
        // Обычный CH (без resumption) — session_ticket пустой
        use crate::adaptive::ch_gen;
        let mut rng = crate::desync::rand::PerConnRng::new(42);
        let ch = ch_gen::build_client_hello("example.com", &mut rng);
        // В нормальном CH session_ticket extension есть (ext type 0x0023),
        // но он пустой (data length = 0)
        assert!(!has_non_empty_session_ticket(&ch));
    }
}
