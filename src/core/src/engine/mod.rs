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
use crate::adaptive::strategy::StrategyCategory;
use crate::adaptive::strategy_profile::{StrategyProfile, StrategyProfileRegistry};
use crate::classifier::{Classification, ClassifiedPacket, Classifier};
use crate::conntrack::Conntrack;
use crate::desync::group::DesyncGroup;
use crate::desync::{DesyncConfig, DesyncTechnique};
use crate::dns::fakeip::FakeIpManager;
use crate::packet_engine::{PacketBufferPool, PacketEngine, PaddedCounter};
use crate::routing::geo::GeoRouter;
use arc_swap::ArcSwap;
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
    pub strategies: Vec<crate::config::StrategyProfileConfig>,
    pub proxy_config: crate::config::ProxyConfig,
    pub dns_config: crate::config::DnsConfig,
    pub adaptive_router_config: crate::routing::adaptive_router::AdaptiveRouterConfig,
    pub zero_config: crate::config::ZeroConfigConfig,
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
            strategies: Vec::new(),
            proxy_config: crate::config::ProxyConfig::default(),
            dns_config: crate::config::DnsConfig::default(),
            adaptive_router_config: crate::routing::adaptive_router::AdaptiveRouterConfig::default(
            ),
            zero_config: crate::config::ZeroConfigConfig::default(),
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
    profile_registry: Arc<StrategyProfileRegistry>,
    active_profile_tls: ArcSwap<String>,
    active_profile_quic: ArcSwap<String>,
    active_profile_http: ArcSwap<String>,
    config: ProcessingConfig,
    stats: Arc<ProcessingStats>,
    injected_seqs: moka::sync::Cache<SeqKey, ()>,
    auto_tune: std::sync::Mutex<AutoTune>,
    /// Buffer pool для zero-alloc steady-state.
    /// Один пул на все workers (ArrayQueue — lock-free MPMC, безопасно для concurrent access).
    buf_pool: Arc<PacketBufferPool>,
    redirect_table: Arc<crate::desync::redirect_table::RedirectTable>,
    socks_redirector: Arc<crate::proxy::redirector::SocksRedirector>,
    dns_proxy: Arc<crate::dns::dns_proxy::DnsProxyEngine>,
    #[allow(dead_code)]
    zero_config: Arc<crate::proxy::zero_config::ZeroConfigEngine>,
    adaptive_router: Arc<crate::routing::adaptive_router::AdaptiveRouter>,
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
        let profile_registry = Arc::new(StrategyProfileRegistry::from_config(
            &config.desync,
            &config.strategies,
            &config.techniques,
        ));
        let active_profile_tls = ArcSwap::from_pointee(
            profile_registry
                .get_default_for_category(StrategyCategory::Tls)
                .expect("outbound_tls must be registered")
                .name
                .clone(),
        );
        let active_profile_quic = ArcSwap::from_pointee(
            profile_registry
                .get_default_for_category(StrategyCategory::Quic)
                .expect("outbound_quic must be registered")
                .name
                .clone(),
        );
        let active_profile_http = ArcSwap::from_pointee(
            profile_registry
                .get_default_for_category(StrategyCategory::Http)
                .expect("outbound_http must be registered")
                .name
                .clone(),
        );

        // Buffer pool: capacity = workers * 4 (глубина на worker)
        // Каждый буфер 2048 байт → pool = 4 * 4 * 2048 = ~32 KB
        let buf_pool = Arc::new(PacketBufferPool::new(64));

        let mut auto_tune = AutoTune::new();
        for strategy_cfg in &config.strategies {
            if strategy_cfg.enabled == Some(true) {
                auto_tune.set_override(
                    &strategy_cfg.name,
                    crate::adaptive::auto_tune::TuneParams {
                        split_size: strategy_cfg.split_size,
                        split_count: strategy_cfg.split_count,
                        fake_ttl_offset: strategy_cfg.fake_ttl_offset,
                        max_seg_size: strategy_cfg.max_seg_size,
                    },
                );
                tracing::info!(
                    "Pre-activated custom profile '{}' from config",
                    strategy_cfg.name
                );
            }
        }

        let redirect_table = Arc::new(crate::desync::redirect_table::RedirectTable::new());

        // T63: Initialize and start ZeroConfigEngine background task
        let zero_config = Arc::new(crate::proxy::zero_config::ZeroConfigEngine::new(
            config.zero_config.clone(),
        ));
        let zero_config_clone = zero_config.clone();
        tokio::spawn(async move {
            if let Err(e) = zero_config_clone.initialize().await {
                tracing::error!("Failed to initialize Zero-Config bypass engine: {e}");
            }
        });

        // T63: Initialize Whitelist Detector if auto_detect is enabled
        if config.zero_config.auto_detect {
            let canary_path = std::path::Path::new(&config.zero_config.canary_domains_path);
            if !canary_path.exists() {
                let default_content = "# Whitelist Detector Canary Domains\n\
                                       gosuslugi.ru,positive\n\
                                       vk.com,positive\n\
                                       sberbank.ru,positive\n\
                                       example.com,negative\n\
                                       iana.org,negative\n\
                                       rfc-editor.org,negative\n";
                let _ = std::fs::write(canary_path, default_content);
            }

            match crate::detector::canary_list::load_canary_list(canary_path) {
                Ok(canaries) => {
                    let detector = Arc::new(crate::detector::detector::WhitelistDetector::new(
                        canaries,
                        zero_config.clone(),
                        config.zero_config.detection_interval_secs,
                    ));
                    detector.start_loop();
                }
                Err(e) => {
                    tracing::error!("Failed to load canary domains for Whitelist Detector: {e:#}");
                }
            }
        }

        // Запуск SOCKS5-редиректора в бэкграунде
        let proxy_pool = Arc::new(crate::proxy::types::OperaProxyPool::new(vec![
            "185.167.238.201:1080".parse().unwrap(),
            "185.167.238.202:1080".parse().unwrap(),
            "185.167.238.203:1080".parse().unwrap(),
            "185.167.238.204:1080".parse().unwrap(),
            "185.167.238.205:1080".parse().unwrap(),
        ]));
        let redirector = Arc::new(crate::proxy::redirector::SocksRedirector::new(
            redirect_table.clone(),
            proxy_pool.clone(),
            config.proxy_config.custom_proxy.clone(),
            zero_config.clone(),
        ));
        let redirector_clone = redirector.clone();
        tokio::spawn(async move {
            if let Err(e) = redirector_clone.bind_and_run().await {
                tracing::error!("Failed to start SocksRedirector: {}", e);
            }
        });

        let dns_config_doh_url = config.dns_config.doh_url.clone();
        let dns_proxy = Arc::new(crate::dns::dns_proxy::DnsProxyEngine::new(
            crate::dns::dns_proxy::DnsProxyConfig {
                enabled: true,
                adblock_enabled: false,
                doh_servers: vec![dns_config_doh_url],
                system_dns_servers: vec!["8.8.8.8".to_string()],
                censored_domains: Vec::new(),
                adblock_domains: vec![
                    "doubleclick.net".into(),
                    "googlesyndication.com".into(),
                    "googleadservices.com".into(),
                    "google-analytics.com".into(),
                ],
                ttl: config.dns_config.cache_ttl as u32,
            },
            fake_ip.clone(),
            geo_router.clone(),
            zero_config.clone(),
        ));

        let adaptive_router = Arc::new(crate::routing::adaptive_router::AdaptiveRouter::new(
            config.adaptive_router_config.clone(),
        ));

        Ok(Self {
            packet_engine,
            fake_ip,
            geo_router,
            hop_tab,
            conntrack,
            profile_registry,
            active_profile_tls,
            active_profile_quic,
            active_profile_http,
            config,
            stats: Arc::new(ProcessingStats::new()),
            injected_seqs: moka::sync::Cache::builder()
                .max_capacity(100_000)
                .time_to_live(Duration::from_secs(30))
                .build(),
            auto_tune: std::sync::Mutex::new(auto_tune),
            buf_pool,
            redirect_table,
            socks_redirector: redirector,
            dns_proxy,
            zero_config,
            adaptive_router,
            has_non_empty_session_ticket: false,
        })
    }

    pub fn new_api_only(config: ProcessingConfig) -> Self {
        let packet_engine = Arc::new(PacketEngine::new_api_only());
        let profile_registry = Arc::new(StrategyProfileRegistry::from_config(
            &config.desync,
            &config.strategies,
            &config.techniques,
        ));
        let active_profile_tls = ArcSwap::from_pointee(
            profile_registry
                .get_default_for_category(StrategyCategory::Tls)
                .expect("outbound_tls must be registered")
                .name
                .clone(),
        );
        let active_profile_quic = ArcSwap::from_pointee(
            profile_registry
                .get_default_for_category(StrategyCategory::Quic)
                .expect("outbound_quic must be registered")
                .name
                .clone(),
        );
        let active_profile_http = ArcSwap::from_pointee(
            profile_registry
                .get_default_for_category(StrategyCategory::Http)
                .expect("outbound_http must be registered")
                .name
                .clone(),
        );

        let buf_pool = Arc::new(PacketBufferPool::new(64));

        let mut auto_tune = AutoTune::new();
        for strategy_cfg in &config.strategies {
            if strategy_cfg.enabled == Some(true) {
                auto_tune.set_override(
                    &strategy_cfg.name,
                    crate::adaptive::auto_tune::TuneParams {
                        split_size: strategy_cfg.split_size,
                        split_count: strategy_cfg.split_count,
                        fake_ttl_offset: strategy_cfg.fake_ttl_offset,
                        max_seg_size: strategy_cfg.max_seg_size,
                    },
                );
                tracing::info!(
                    "Pre-activated custom profile '{}' from config",
                    strategy_cfg.name
                );
            }
        }

        let redirect_table = Arc::new(crate::desync::redirect_table::RedirectTable::new());

        // T63: Initialize ZeroConfigEngine for api-only (disabled or default configuration)
        let zero_config = Arc::new(crate::proxy::zero_config::ZeroConfigEngine::new(
            config.zero_config.clone(),
        ));

        let proxy_pool = Arc::new(crate::proxy::types::OperaProxyPool::new(vec![
            "185.167.238.201:1080".parse().unwrap(),
        ]));
        let redirector = Arc::new(crate::proxy::redirector::SocksRedirector::new(
            redirect_table.clone(),
            proxy_pool.clone(),
            config.proxy_config.custom_proxy.clone(),
            zero_config.clone(),
        ));

        let fake_ip = Arc::new(FakeIpManager::new(1000));
        let geo_router = Arc::new(GeoRouter::new_default());
        let dns_config_doh_url = config.dns_config.doh_url.clone();
        let dns_proxy = Arc::new(crate::dns::dns_proxy::DnsProxyEngine::new(
            crate::dns::dns_proxy::DnsProxyConfig {
                enabled: true,
                adblock_enabled: false,
                doh_servers: vec![dns_config_doh_url],
                system_dns_servers: vec!["8.8.8.8".to_string()],
                censored_domains: Vec::new(),
                adblock_domains: vec![
                    "doubleclick.net".into(),
                    "googlesyndication.com".into(),
                    "googleadservices.com".into(),
                    "google-analytics.com".into(),
                ],
                ttl: config.dns_config.cache_ttl as u32,
            },
            fake_ip.clone(),
            geo_router.clone(),
            zero_config.clone(),
        ));

        let adaptive_router = Arc::new(crate::routing::adaptive_router::AdaptiveRouter::new(
            config.adaptive_router_config.clone(),
        ));

        Self {
            packet_engine,
            fake_ip,
            geo_router,
            hop_tab: Arc::new(HopTab::new()),
            conntrack: Arc::new(Conntrack::new(Duration::from_secs(120))),
            profile_registry,
            active_profile_tls,
            active_profile_quic,
            active_profile_http,
            config,
            stats: Arc::new(ProcessingStats::new()),
            injected_seqs: moka::sync::Cache::builder()
                .max_capacity(100_000)
                .time_to_live(Duration::from_secs(30))
                .build(),
            auto_tune: std::sync::Mutex::new(auto_tune),
            buf_pool,
            redirect_table,
            socks_redirector: redirector,
            dns_proxy,
            zero_config,
            adaptive_router,
            has_non_empty_session_ticket: false,
        }
    }

    pub fn socks_redirector(&self) -> &Arc<crate::proxy::redirector::SocksRedirector> {
        &self.socks_redirector
    }

    pub fn profile_registry(&self) -> &Arc<StrategyProfileRegistry> {
        &self.profile_registry
    }

    pub fn geo_router(&self) -> &Arc<GeoRouter> {
        &self.geo_router
    }

    fn resolve_active_profile(&self, category: StrategyCategory) -> &StrategyProfile {
        let active_name = match category {
            StrategyCategory::Tls => self.active_profile_tls.load(),
            StrategyCategory::Quic => self.active_profile_quic.load(),
            StrategyCategory::Http => self.active_profile_http.load(),
            other => unreachable!(
                "resolve_active_profile вызван для категории {:?} без hot-path переключения",
                other
            ),
        };
        self.profile_registry
            .get(active_name.as_str())
            .unwrap_or_else(|| {
                self.profile_registry
                    .get("outbound_tls")
                    .expect("outbound_tls всегда зарегистрирован")
            })
    }

    pub fn apply_strategy_tune(&self, strategy_id: u32, params: TuneParams) {
        let Some(profile) = self.profile_registry.get_by_id(strategy_id) else {
            warn!(
                "apply_strategy_tune: неизвестный strategy_id={}",
                strategy_id
            );
            return;
        };
        match profile.category {
            StrategyCategory::Tls => self
                .active_profile_tls
                .store(Arc::new(profile.name.clone())),
            StrategyCategory::Quic => self
                .active_profile_quic
                .store(Arc::new(profile.name.clone())),
            StrategyCategory::Http => self
                .active_profile_http
                .store(Arc::new(profile.name.clone())),
            _ => {
                tracing::info!(
                    "apply_strategy_tune: id={} (профиль='{}', категория={:?}) — только числовой override",
                    strategy_id, profile.name, profile.category
                );
            }
        }
        self.auto_tune
            .lock()
            .unwrap()
            .set_override(&profile.name, params);
        tracing::info!(
            "apply_strategy_tune: id={} → активный профиль для {:?} = '{}'",
            strategy_id,
            profile.category,
            profile.name
        );
    }

    pub fn clear_strategy_tune(&self, strategy_id: u32) {
        let Some(profile) = self.profile_registry.get_by_id(strategy_id) else {
            warn!(
                "clear_strategy_tune: неизвестный strategy_id={}",
                strategy_id
            );
            return;
        };
        if let Some(default_profile) = self
            .profile_registry
            .get_default_for_category(profile.category)
        {
            match profile.category {
                StrategyCategory::Tls => self
                    .active_profile_tls
                    .store(Arc::new(default_profile.name.clone())),
                StrategyCategory::Quic => self
                    .active_profile_quic
                    .store(Arc::new(default_profile.name.clone())),
                StrategyCategory::Http => self
                    .active_profile_http
                    .store(Arc::new(default_profile.name.clone())),
                _ => {}
            }
        }
        self.auto_tune.lock().unwrap().clear_override(&profile.name);
        tracing::info!(
            "clear_strategy_tune: id={} — сброшен к default профилю категории",
            strategy_id
        );
    }

    pub async fn run(self: Arc<Self>, shutdown: tokio::sync::broadcast::Receiver<()>) {
        debug!("ProcessingPipeline started (T62 batch mode)");

        let n_workers = num_cpus::get().clamp(2, 16);
        let shutdown_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut worker_handles = Vec::with_capacity(n_workers);

        for id in 0..n_workers {
            let engine = self.packet_engine.clone();
            let pipeline = self.clone();
            let pool = self.buf_pool.clone();
            let shutdown_flag = shutdown_flag.clone();
            let mut shutdown_rx = shutdown.resubscribe();

            let handle = std::thread::Builder::new()
                .name(format!("fp-worker-{}", id))
                .spawn(move || loop {
                    if shutdown_rx.try_recv().is_ok() || shutdown_flag.load(Ordering::Acquire) {
                        shutdown_flag.store(true, Ordering::Release);
                        break;
                    }
                    Self::worker_loop(
                        id,
                        engine.clone(),
                        pipeline.clone(),
                        pool.clone(),
                        shutdown_flag.clone(),
                    );
                })
                .expect("spawn worker");
            worker_handles.push(handle);
        }

        // Wait for shutdown
        let mut shutdown_rx = shutdown.resubscribe();
        let _ = shutdown_rx.recv().await;
        shutdown_flag.store(true, Ordering::Release);
        for handle in worker_handles {
            let _ = handle.join();
        }

        debug!("ProcessingPipeline stopped");
    }

    /// T62: Worker loop с batch recv + batch send.
    fn worker_loop(
        id: usize,
        engine: Arc<PacketEngine>,
        pipeline: Arc<Self>,
        pool: Arc<PacketBufferPool>,
        shutdown: Arc<std::sync::atomic::AtomicBool>,
    ) {
        let mut empty_spins: u32 = 0;

        let mut forward_batch: Vec<(bytes::Bytes, WinDivertAddress<NetworkLayer>)> =
            Vec::with_capacity(64);
        let mut inject_batch: Vec<(bytes::Bytes, WinDivertAddress<NetworkLayer>)> =
            Vec::with_capacity(64);

        loop {
            if shutdown.load(Ordering::Acquire) {
                break;
            }

            // 1. Batch recv — до 64 пакетов за 1 syscall
            let packets = match engine.recv_batch(&pool) {
                Ok(pkts) => {
                    if pkts.is_empty() {
                        empty_spins += 1;
                        if empty_spins < 100 {
                            std::hint::spin_loop();
                        } else {
                            std::thread::sleep(std::time::Duration::from_micros(100));
                            empty_spins = 0;
                        }
                        continue;
                    }
                    empty_spins = 0;
                    pkts
                }
                Err(e) => {
                    if !engine.has_divert() {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        continue;
                    }
                    tracing::error!("recv_batch error: {}", e);
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
            };

            pipeline
                .stats
                .total_received
                .fetch_add(packets.len() as u64, Ordering::Relaxed);

            // 2. Очищаем batch buffers
            forward_batch.clear();
            inject_batch.clear();

            // 3. Обрабатываем каждый пакет
            for (data, addr) in packets {
                let captured = CapturedPacket {
                    data: data.clone(),
                    addr: addr.clone(),
                };

                match pipeline.process_one_sync(&captured) {
                    Ok(decision) => {
                        match decision {
                            PacketDecision::Forward => {
                                // Накапливаем для batch send (оригинальный буфер освободится в конце)
                                forward_batch.push((data, addr));
                            }
                            PacketDecision::Modify(modified) => {
                                // Исходный буфер больше не нужен — возвращаем в пул
                                pool.release_bytes(data);
                                forward_batch.push((modified, addr));
                            }
                            PacketDecision::Desync {
                                inject,
                                modified,
                                inject_protocol,
                                inter_delay_us,
                            } => {
                                match inject_protocol {
                                    InjectProtocol::Tcp => {
                                        for (i, inject_pkt) in inject.iter().enumerate() {
                                            if i > 0 && inter_delay_us > 0 {
                                                if !inject_batch.is_empty() {
                                                    let _ = engine
                                                        .inject_batch_via_divert(&inject_batch);
                                                    for (d, _) in &inject_batch {
                                                        pool.release_bytes(d.clone());
                                                    }
                                                    inject_batch.clear();
                                                }
                                                std::thread::sleep(
                                                    std::time::Duration::from_micros(
                                                        inter_delay_us as u64,
                                                    ),
                                                );
                                            }
                                            inject_batch.push((inject_pkt.clone(), addr.clone()));
                                        }
                                    }
                                    InjectProtocol::Udp => {
                                        for (i, inject_pkt) in inject.iter().enumerate() {
                                            if i > 0 && inter_delay_us > 0 {
                                                std::thread::sleep(
                                                    std::time::Duration::from_micros(
                                                        inter_delay_us as u64,
                                                    ),
                                                );
                                            }
                                            if let Err(e) = engine.inject_raw_udp(inject_pkt) {
                                                tracing::warn!(
                                                    "Failed to inject UDP desync packet: {}",
                                                    e
                                                );
                                            }
                                            pool.release_bytes(inject_pkt.clone());
                                            pipeline
                                                .stats
                                                .fake_ch_injected
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                }

                                // Обработка оригинального/модифицированного пакета
                                if let Some(m) = modified {
                                    forward_batch.push((m, addr));
                                    pool.release_bytes(data);
                                } else {
                                    // Если модификации нет, то оригинальный пакет пробрасывается дальше
                                    forward_batch.push((data, addr));
                                }
                            }
                            PacketDecision::Drop => {
                                pool.release_bytes(data);
                                pipeline.stats.dropped.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Packet processing error: {}", e);
                        forward_batch.push((data, addr));
                        pipeline.stats.errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }

            // 4. Batch send — все forward/modify пакеты за 1 syscall
            if !forward_batch.is_empty() {
                let sent = engine.send_batch(&forward_batch);
                if let Ok(n) = sent {
                    pipeline
                        .stats
                        .forwarded
                        .fetch_add(n as u64, Ordering::Relaxed);
                }
                // Возвращаем буферы в пул
                for (data, _) in &forward_batch {
                    pool.release_bytes(data.clone());
                }
            }

            // 5. Batch inject — все impostor пакеты за 1 syscall
            if !inject_batch.is_empty() {
                let sent = engine.inject_batch_via_divert(&inject_batch);
                if let Ok(n) = sent {
                    pipeline
                        .stats
                        .fake_ch_injected
                        .fetch_add(n as u64, Ordering::Relaxed);
                }
                // Возвращаем буферы в пул
                for (data, _) in &inject_batch {
                    pool.release_bytes(data.clone());
                }
            }
        }

        tracing::debug!("Worker {} stopped", id);
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
        group: &DesyncGroup,
        packet: bytes::Bytes,
        dscp_value: Option<u8>,
        tune_params: Option<TuneParams>,
        is_resumption: Option<bool>,
        conn_rng_fork: Option<crate::desync::rand::PerConnRng>,
    ) -> crate::desync::DesyncResult {
        let override_params: Option<crate::desync::group::ConfigOverride> =
            tune_params.map(Into::into);
        let mut group_clone = group.clone();
        group_clone.set_context(self.hop_tab.clone(), self.conntrack.clone());
        group_clone.apply_with_rng(
            &packet,
            dscp_value,
            override_params,
            is_resumption,
            conn_rng_fork,
        )
    }

    /// Sync version: send packet via WinDivert (no spawn_blocking).
    /// После отправки возвращает буфер в пул через release_bytes.
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    fn forward_packet_sync(&self, captured: &CapturedPacket) {
        self.send_packet_sync(captured.data.clone(), &captured.addr);
    }

    /// Sync version: inject TCP fake via raw socket (no spawn_blocking).
    /// После инжекта возвращает буфер в пул.
    #[allow(dead_code)]
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
        self.process_one_sync_dispatch(captured)
    }

    pub(crate) fn process_one_sync_dispatch(
        &self,
        captured: &CapturedPacket,
    ) -> Result<PacketDecision, anyhow::Error> {
        let classification = Classifier::classify(&captured.data);

        // 1. DNS (UDP:53) check
        if let Classification::Dns(ref cp) = classification {
            if cp.dst_port == 53 && cp.protocol == 17 {
                let rt = crate::Runtime::global();
                if let Some(resp_data) =
                    rt.block_on(self.dns_proxy.handle_dns_query(&captured.data))
                {
                    let mut addr = captured.addr.clone();
                    addr.set_outbound(false); // Reinject as inbound response
                    let _ = self.packet_engine.inject_via_divert(&resp_data, &addr);
                    self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                    return Ok(PacketDecision::Drop); // Drop original query
                }
            }
        }

        // 2. Return path from SocksRedirector (loopback, src_port == 17650)
        if let Classification::Other(ref cp) = classification {
            if cp.src_port == 17650 {
                if let Some(entry) = self.redirect_table.get(cp.dst_port) {
                    tracing::debug!(
                        "SocksRedirector return path: rewriting src 127.0.0.1:17650 -> {}:{}",
                        entry.orig_dst_ip,
                        entry.orig_dst_port
                    );
                    let modified = crate::proxy::rewrite::rewrite_src_addr(
                        &captured.data,
                        entry.orig_dst_ip,
                        entry.orig_dst_port,
                    )?;
                    return Ok(PacketDecision::Modify(modified.into()));
                }
            }
        }

        // 3. Fake IP traffic (destination is 10.x.x.x)
        if let Classification::Other(ref cp) = classification {
            if cp.protocol == 6 {
                if let IpAddr::V4(v4) = cp.dst_ip {
                    if crate::dns::fakeip::FakeIpManager::is_fake_ip(&v4) {
                        return self.process_fake_ip_traffic(captured, cp);
                    }
                }
            }
        }
        if let Classification::Tls(ref cp) | Classification::Http(ref cp) = classification {
            if cp.protocol == 6 {
                if let IpAddr::V4(v4) = cp.dst_ip {
                    if crate::dns::fakeip::FakeIpManager::is_fake_ip(&v4) {
                        return self.process_fake_ip_traffic(captured, cp);
                    }
                }
            }
        }

        // 4. Opera IP protection (apply desync when connecting to Opera proxies)
        if let Classification::Other(ref cp) = classification {
            if cp.protocol == 6 {
                let is_syn = if let Some(ip) = crate::desync::parse_ip_header(&captured.data) {
                    let tcp_data = &captured.data[ip.header_len()..];
                    if let Some(tcp) = crate::desync::parse_tcp_packet(tcp_data) {
                        (tcp.flags & 0x02) != 0 && (tcp.flags & 0x10) == 0
                    } else {
                        false
                    }
                } else {
                    false
                };
                if is_syn && self.socks_redirector.proxy_pool.is_known_ip(&cp.dst_ip) {
                    return self.process_generic_tcp(captured, cp);
                }
            }
        }

        // 5. Adaptive Routing decision
        if let Classification::Tls(ref cp)
        | Classification::Http(ref cp)
        | Classification::Quic(ref cp)
        | Classification::Other(ref cp) = classification
        {
            if cp.protocol == 6 || cp.protocol == 17 {
                if self.config.only_outbound && !is_outbound_cached(cp.src_ip) {
                    return Ok(PacketDecision::Forward);
                }

                let domain = self.fake_ip.lookup(&cp.dst_ip);
                let is_blocked = if let Some(ref d) = domain {
                    let route = self.geo_router.resolve(d, Some(cp.dst_ip));
                    route.needs_desync()
                } else {
                    let route = self.geo_router.resolve("unknown", Some(cp.dst_ip));
                    route.needs_desync()
                };
                let is_geo_blocked = if let Some(ref d) = domain {
                    let region = self.geo_router.classify(d, Some(cp.dst_ip));
                    matches!(
                        region,
                        crate::routing::GeoRegion::Europe | crate::routing::GeoRegion::UnitedStates
                    )
                } else {
                    let region = self.geo_router.classify("unknown", Some(cp.dst_ip));
                    matches!(
                        region,
                        crate::routing::GeoRegion::Europe | crate::routing::GeoRegion::UnitedStates
                    )
                };
                let has_sni_or_host = matches!(
                    &classification,
                    Classification::Tls(_) | Classification::Http(_)
                );

                let decision = self.adaptive_router.decide(
                    domain.as_deref(),
                    is_blocked,
                    is_geo_blocked,
                    has_sni_or_host,
                    cp.protocol,
                    &self.auto_tune.lock().unwrap(),
                    "outbound_tls",
                );

                match decision {
                    crate::routing::adaptive_router::RoutingDecision::Direct => {
                        return Ok(PacketDecision::Forward);
                    }
                    crate::routing::adaptive_router::RoutingDecision::Drop => {
                        self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                        return Ok(PacketDecision::Drop);
                    }
                    crate::routing::adaptive_router::RoutingDecision::Proxy => {
                        if cp.protocol == 17 {
                            // Drop UDP/QUIC to force TCP fallback
                            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                            return Ok(PacketDecision::Drop);
                        }
                        tracing::debug!(
                            "AdaptiveRouter decided Proxy fallback for connection to {}:{}",
                            cp.dst_ip,
                            cp.dst_port
                        );
                        self.redirect_table.insert(
                            cp.src_port,
                            crate::desync::redirect_table::RedirectEntry {
                                orig_dst_ip: cp.dst_ip,
                                orig_dst_port: cp.dst_port,
                                domain,
                                created_at: std::time::Instant::now(),
                            },
                        );
                        let localhost = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
                        let modified = crate::proxy::rewrite::rewrite_dst_addr(
                            &captured.data,
                            localhost,
                            17650,
                        )?;
                        self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                        return Ok(PacketDecision::Modify(modified.into()));
                    }
                    crate::routing::adaptive_router::RoutingDecision::Desync => {
                        // Continue to standard desync handling below
                    }
                }
            }
        }

        // Fallback: run standard classification (TLS, HTTP, QUIC, generic TCP desync)
        match classification {
            Classification::Tls(cp) if cp.dst_port == self.config.desync_port => {
                if self.config.only_outbound && !is_outbound_cached(cp.src_ip) {
                    return Ok(PacketDecision::Forward);
                }
                let conn_key = crate::conntrack::ConnKey::new(
                    cp.src_ip,
                    cp.dst_ip,
                    cp.src_port,
                    cp.dst_port,
                    cp.protocol,
                );

                let mut should_desync = false;
                if Classifier::is_client_hello(&captured.data[cp.payload_offset..])
                    && captured.data.len() - cp.payload_offset >= 50
                {
                    should_desync = self.conntrack.check_and_apply_desync(conn_key, || {
                        ip_to_u64(cp.src_ip)
                            ^ (ip_to_u64(cp.dst_ip) << 32)
                            ^ ((cp.src_port as u64) << 48)
                            ^ (cp.dst_port as u64)
                    });
                }

                if !should_desync {
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
            Classification::Dns(cp) => self.process_dns(captured, &cp),
            Classification::Http(cp) => {
                if self.config.only_outbound && !is_outbound_cached(cp.src_ip) {
                    return Ok(PacketDecision::Forward);
                }
                self.process_http_sync(captured, &cp)
            }
            Classification::Other(cp) => {
                if self.config.only_outbound && !is_outbound_cached(cp.src_ip) {
                    return Ok(PacketDecision::Forward);
                }
                self.process_generic_tcp(captured, &cp)
            }
            _ => Ok(PacketDecision::Forward),
        }
    }

    pub(crate) fn process_fake_ip_traffic(
        &self,
        captured: &CapturedPacket,
        cp: &ClassifiedPacket,
    ) -> Result<PacketDecision, anyhow::Error> {
        let domain = match self.fake_ip.lookup(&cp.dst_ip) {
            Some(d) => d,
            None => return Ok(PacketDecision::Forward),
        };

        let is_syn = if let Some(ip) = crate::desync::parse_ip_header(&captured.data) {
            let tcp_data = &captured.data[ip.header_len()..];
            if let Some(tcp) = crate::desync::parse_tcp_packet(tcp_data) {
                (tcp.flags & 0x02) != 0 && (tcp.flags & 0x10) == 0
            } else {
                false
            }
        } else {
            false
        };

        if is_syn {
            // Fail-open check
            if self.socks_redirector.proxy_pool.select_best().is_none()
                && !self.socks_redirector.custom_proxy.read().unwrap().enabled
            {
                tracing::warn!(
                    "FakeIP: no healthy proxies, falling back to direct connection for {}",
                    domain
                );
                return Ok(PacketDecision::Forward);
            }

            tracing::debug!("FakeIP redirecting SYN for {} -> 127.0.0.1:17650", domain);
            self.redirect_table.insert(
                cp.src_port,
                crate::desync::redirect_table::RedirectEntry {
                    orig_dst_ip: cp.dst_ip,
                    orig_dst_port: cp.dst_port,
                    domain: Some(domain),
                    created_at: std::time::Instant::now(),
                },
            );

            let localhost = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
            let modified =
                crate::proxy::rewrite::rewrite_dst_addr(&captured.data, localhost, 17650)?;
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return Ok(PacketDecision::Modify(modified.into()));
        }

        if cp.protocol == 17 {
            tracing::debug!(
                "FakeIP dropping QUIC payload to force TCP fallback for {}",
                domain
            );
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return Ok(PacketDecision::Drop);
        }

        Ok(PacketDecision::Forward)
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

        // T55: резолвим активный профиль для TLS — то, что реально может переключить
        // tune_strategy (не только числа поверх фиксированного FakeSni+BadChecksum).
        let profile = self.resolve_active_profile(StrategyCategory::Tls);

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
        let auto_tune_override = self.auto_tune.lock().unwrap().recommend(&profile.name);
        let mut tune_params = profile.merged_params(&auto_tune_override);
        if self.config.hop_tab_enabled && tune_params.fake_ttl_offset.is_none() {
            tune_params.fake_ttl_offset = self.hop_tab.fake_ttl_for_ip(&cp.dst_ip);
        }
        let result = self.apply_desync_sync(
            &profile.desync_group,
            packet,
            dscp_value,
            Some(tune_params),
            Some(is_resumption),
            conn_rng_fork,
        );

        // 5.0. AutoTune — записываем под именем АКТИВНОГО профиля, не хардкод "outbound_tls"
        {
            let latency_us = tune_start.elapsed().as_micros() as u64;
            let success = !result.inject.is_empty() || result.modified.is_some();
            let mut tune = self.auto_tune.lock().unwrap();
            tune.record(&profile.name, success, latency_us);
            if tune.should_escalate(&profile.name) {
                warn!(
                    "AutoTune: '{}' strategy degrading (latency={}us)",
                    profile.name, latency_us
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

        // T55: резолвим активный профиль для QUIC.
        let profile = self.resolve_active_profile(StrategyCategory::Quic);

        // T43: QUIC не использует is_resumption — передаём None
        let tune_start = Instant::now();
        let auto_tune_override = self.auto_tune.lock().unwrap().recommend(&profile.name);
        let mut tune_params = profile.merged_params(&auto_tune_override);
        if self.config.hop_tab_enabled && tune_params.fake_ttl_offset.is_none() {
            tune_params.fake_ttl_offset = self.hop_tab.fake_ttl_for_ip(&cp.dst_ip);
        }
        let result = self.apply_desync_sync(
            &profile.desync_group,
            packet,
            None,
            Some(tune_params),
            None,
            None,
        );

        {
            let latency_us = tune_start.elapsed().as_micros() as u64;
            let success = !result.inject.is_empty() || result.modified.is_some();
            let mut tune = self.auto_tune.lock().unwrap();
            tune.record(&profile.name, success, latency_us);
            if tune.should_escalate(&profile.name) {
                warn!(
                    "AutoTune: '{}' strategy degrading (latency={}us)",
                    profile.name, latency_us
                );
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
        cp: &crate::classifier::ClassifiedPacket,
    ) -> Result<PacketDecision, anyhow::Error> {
        let packet = captured.data.clone();
        // T55: резолвим активный профиль для HTTP.
        let profile = self.resolve_active_profile(StrategyCategory::Http);

        // T43: HTTP не использует is_resumption — передаём None
        let tune_start = Instant::now();
        let auto_tune_override = self.auto_tune.lock().unwrap().recommend(&profile.name);
        let mut tune_params = profile.merged_params(&auto_tune_override);
        if self.config.hop_tab_enabled && tune_params.fake_ttl_offset.is_none() {
            tune_params.fake_ttl_offset = self.hop_tab.fake_ttl_for_ip(&cp.dst_ip);
        }
        let result = self.apply_desync_sync(
            &profile.desync_group,
            packet,
            None,
            Some(tune_params),
            None,
            None,
        );

        {
            let latency_us = tune_start.elapsed().as_micros() as u64;
            let success = !result.inject.is_empty() || result.modified.is_some();
            let mut tune = self.auto_tune.lock().unwrap();
            tune.record(&profile.name, success, latency_us);
            if tune.should_escalate(&profile.name) {
                warn!(
                    "AutoTune: '{}' strategy degrading (latency={}us)",
                    profile.name, latency_us
                );
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
            modified: None,
            inject_protocol: InjectProtocol::Tcp,
            inter_delay_us: inter_delay,
        })
    }

    /// T57: Обработка DNS пакетов.
    ///
    /// Если активирован профиль "dns_doh":
    /// - Перехватываем UDP DNS запросы (dst_port == 53, protocol == 17 (UDP))
    /// - Дропаем UDP DNS — заставляем клиента fallback на DoH
    ///
    /// NOTE: TCP DNS запросы (TCP:53) намеренно не обрабатываются здесь.
    /// Обход блокировок для TCP DNS ложится на стандартные правила TCP маршрутизации (SOCKS5/UserProxy).
    fn process_dns(
        &self,
        captured: &CapturedPacket,
        cp: &ClassifiedPacket,
    ) -> Result<PacketDecision, anyhow::Error> {
        let dns_profile_active =
            self.profile_registry.get("dns_doh").is_some() && self.is_profile_activated("dns_doh");

        if dns_profile_active && cp.dst_port == 53 && cp.protocol == 17 {
            tracing::debug!(
                "DNS: dropping UDP DNS query to {}:{} (dns_doh profile active)",
                cp.dst_ip,
                cp.dst_port
            );
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return Ok(PacketDecision::Drop);
        }

        Ok(PacketDecision::Forward)
    }

    /// T57: Обработка generic TCP (non-443, non-80).
    ///
    /// Проверяет на data-volume cutoff patterns.
    /// Если активирован профиль "tcp_mss_clamp" — применяет MSS clamp к SYN пакетам.
    /// Если активирован профиль "tcp_window_clamp" — применяет window clamp.
    fn process_generic_tcp(
        &self,
        captured: &CapturedPacket,
        cp: &ClassifiedPacket,
    ) -> Result<PacketDecision, anyhow::Error> {
        // T57.5: Сначала проверяем SOCKS5 fallback — применяется к ЛЮБОМУ TCP трафику
        let socks5_decision = self.process_socks5_redirect(captured, cp)?;
        if !matches!(socks5_decision, PacketDecision::Forward) {
            return Ok(socks5_decision);
        }

        // Проверяем — это TCP SYN? (MSS clamp и window clamp работают на SYN)
        let is_syn = if let Some(ip) = crate::desync::parse_ip_header(&captured.data) {
            let tcp_data = &captured.data[ip.header_len()..];
            if let Some(tcp) = crate::desync::parse_tcp_packet(tcp_data) {
                (tcp.flags & 0x02) != 0 // SYN = 0x02
            } else {
                false
            }
        } else {
            false
        };

        if !is_syn {
            return Ok(PacketDecision::Forward);
        }

        // T57: Проверяем активированные профили (window clamp приоритетнее, так как включает в себя и MSS)
        let mss_clamp_active = self.is_profile_activated("tcp_mss_clamp");
        let window_clamp_active = self.is_profile_activated("tcp_window_clamp");

        if window_clamp_active {
            // Применяем window clamp + MSS clamp
            let profile = self.profile_registry.get("tcp_window_clamp");
            if let Some(profile) = profile {
                let tune_start = Instant::now();
                let auto_tune_override =
                    self.auto_tune.lock().unwrap().recommend("tcp_window_clamp");
                let tune_params = profile.merged_params(&auto_tune_override);

                let result = self.apply_desync_sync(
                    &profile.desync_group,
                    captured.data.clone(),
                    None,
                    Some(tune_params),
                    None,
                    None,
                );

                let latency_us = tune_start.elapsed().as_micros() as u64;
                let success = !result.inject.is_empty() || result.modified.is_some();
                self.auto_tune
                    .lock()
                    .unwrap()
                    .record("tcp_window_clamp", success, latency_us);

                if result.drop {
                    return Ok(PacketDecision::Drop);
                }
                if let Some(modified) = result.modified {
                    if result.inject.is_empty() {
                        return Ok(PacketDecision::Modify(modified));
                    }
                    return Ok(PacketDecision::Desync {
                        inject: result.inject,
                        modified: Some(modified),
                        inject_protocol: InjectProtocol::Tcp,
                        inter_delay_us: result.inter_delay_us,
                    });
                }
                if !result.inject.is_empty() {
                    return Ok(PacketDecision::Desync {
                        inject: result.inject,
                        modified: None,
                        inject_protocol: InjectProtocol::Tcp,
                        inter_delay_us: result.inter_delay_us,
                    });
                }
            }
        } else if mss_clamp_active {
            // Применяем MSS clamp + PktReorder
            let profile = self.profile_registry.get("tcp_mss_clamp");
            if let Some(profile) = profile {
                let tune_start = Instant::now();
                let auto_tune_override = self.auto_tune.lock().unwrap().recommend("tcp_mss_clamp");
                let tune_params = profile.merged_params(&auto_tune_override);

                let result = self.apply_desync_sync(
                    &profile.desync_group,
                    captured.data.clone(),
                    None,
                    Some(tune_params),
                    None,
                    None,
                );

                let latency_us = tune_start.elapsed().as_micros() as u64;
                let success = !result.inject.is_empty() || result.modified.is_some();
                self.auto_tune
                    .lock()
                    .unwrap()
                    .record("tcp_mss_clamp", success, latency_us);

                if result.drop {
                    return Ok(PacketDecision::Drop);
                }
                if let Some(modified) = result.modified {
                    if result.inject.is_empty() {
                        return Ok(PacketDecision::Modify(modified));
                    }
                    return Ok(PacketDecision::Desync {
                        inject: result.inject,
                        modified: Some(modified),
                        inject_protocol: InjectProtocol::Tcp,
                        inter_delay_us: result.inter_delay_us,
                    });
                }
                if !result.inject.is_empty() {
                    return Ok(PacketDecision::Desync {
                        inject: result.inject,
                        modified: None,
                        inject_protocol: InjectProtocol::Tcp,
                        inter_delay_us: result.inter_delay_us,
                    });
                }
            }
        }

        Ok(PacketDecision::Forward)
    }

    /// T57: Проверяет — активирован ли профиль (через probe recommendation или manual override).
    fn is_profile_activated(&self, profile_name: &str) -> bool {
        self.auto_tune
            .lock()
            .unwrap()
            .is_strategy_active(profile_name)
    }

    /// T57: Проверяет — нужно ли перенаправить пакет через SOCKS5 proxy.
    ///
    /// Если профиль "socks5_fallback" активирован и целевой домен/IP направляется через SOCKS5
    /// (определяется через GeoRouter), пакет дропается (клиент должен использовать proxy).
    pub(crate) fn process_socks5_redirect(
        &self,
        captured: &CapturedPacket,
        cp: &ClassifiedPacket,
    ) -> Result<PacketDecision, anyhow::Error> {
        let socks5_active = self.is_profile_activated("socks5_fallback");

        if !socks5_active {
            return Ok(PacketDecision::Forward);
        }

        // Fail-open check: if no healthy proxies, return Forward!
        let has_custom = self.socks_redirector.custom_proxy.read().unwrap().enabled;
        let has_opera = self.socks_redirector.proxy_pool.select_best().is_some();
        if !has_custom && !has_opera {
            return Ok(PacketDecision::Forward);
        }

        // Проверяем — домен/IP направляется через SOCKS5/UserProxy/OperaVpn?
        let domain = self.fake_ip.lookup(&cp.dst_ip);
        let decision = self
            .geo_router
            .resolve(domain.as_deref().unwrap_or("unknown"), Some(cp.dst_ip));

        let should_tunnel = decision.egress_chain.iter().any(|hop| {
            matches!(
                hop.egress,
                crate::routing::Egress::Socks5 { .. }
                    | crate::routing::Egress::UserProxy
                    | crate::routing::Egress::OperaVpn
            )
        });

        if should_tunnel {
            tracing::debug!(
                "SOCKS5 Redirect: redirecting connection to {}:{} (domain={:?}) to local SocksRedirector",
                cp.dst_ip, cp.dst_port, domain
            );

            // Записываем оригинальный адрес перед перенаправлением
            self.redirect_table.insert(
                cp.src_port,
                crate::desync::redirect_table::RedirectEntry {
                    orig_dst_ip: cp.dst_ip,
                    orig_dst_port: cp.dst_port,
                    domain,
                    created_at: std::time::Instant::now(),
                },
            );

            // Переписываем dst в самом пакете на Localhost:REDIRECTOR_PORT
            let localhost = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
            let modified = crate::proxy::rewrite::rewrite_dst_addr(
                &captured.data,
                localhost,
                17650, // REDIRECTOR_PORT
            )?;

            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return Ok(PacketDecision::Modify(modified.into()));
        }

        Ok(PacketDecision::Forward)
    }

    /// Execute a PacketDecision synchronously from a worker thread.
    #[allow(dead_code)]
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
                // T60: Register RST for Circuit Breaker
                for inject_pkt in inject.iter() {
                    if let Some(ip) = crate::desync::parse_ip_header(inject_pkt) {
                        let tcp_data = &inject_pkt[ip.header_len()..];
                        if let Some(tcp) = crate::desync::parse_tcp_packet(tcp_data) {
                            if (tcp.flags & 0x04) != 0 {
                                // RST flag
                                self.adaptive_router.record_rst();
                            }
                        }
                    }
                }

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
pub(crate) struct CapturedPacket {
    data: bytes::Bytes,
    addr: WinDivertAddress<NetworkLayer>,
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

impl CapturedPacket {
    #[cfg(test)]
    fn for_test(data: Vec<u8>) -> Self {
        Self {
            data: bytes::Bytes::from(data),
            addr: unsafe { std::mem::zeroed() },
        }
    }
}

#[cfg(test)]
mod concurrency_tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    fn build_synthetic_client_hello() -> Vec<u8> {
        let mut pkt = Vec::new();
        // IPv4 Header (20 bytes)
        pkt.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x00, // Version, IHL, Total Length
            0x00, 0x00, 0x00, 0x00, // Id, Flags, Frag Offset
            0x40, 0x06, 0x00, 0x00, // TTL(64), Protocol(6), Checksum
            127, 0, 0, 1, // Src IP (127.0.0.1)
            127, 0, 0, 1, // Dst IP (127.0.0.1)
        ]);
        // TCP Header (20 bytes)
        pkt.extend_from_slice(&[
            0x30, 0x39, // Src Port (12345)
            0x01, 0xBB, // Dst Port (443)
            0x00, 0x00, 0x00, 0x01, // Seq
            0x00, 0x00, 0x00, 0x00, // Ack
            0x50, 0x18, 0xFF, 0xFF, // Data offset (5 * 4 = 20), Flags (PSH | ACK)
            0x00, 0x00, 0x00, 0x00, // Checksum, Urgent
        ]);
        // TLS ClientHello (min 6 bytes for classification)
        pkt.extend_from_slice(&[
            0x16, 0x03, 0x01, // Record layer: Handshake, TLS 1.0
            0x00, 0x36, // Record length
            0x01, // ClientHello
        ]);
        // Rest of the ClientHello payload
        pkt.extend_from_slice(&[0; 50]);

        // Fix IPv4 total length: 20 + 20 + 5 + 51 = 96
        let total_len = pkt.len() as u16;
        pkt[2..4].copy_from_slice(&total_len.to_be_bytes());

        pkt
    }

    /// Два потока конкурентно видят один и тот же ClientHello (одинаковый conn_key
    /// и одинаковый TLS record) — is_desync_target должен вернуть false во втором
    /// проходе независимо от того, какой поток обработал пакет первым.
    #[test]
    fn concurrent_desync_gate_applies_once() {
        let pipeline = Arc::new(ProcessingPipeline::new_api_only(ProcessingConfig::default()));
        let packet = build_synthetic_client_hello();

        let p1 = pipeline.clone();
        let p2 = pipeline.clone();
        let pkt1 = packet.clone();
        let pkt2 = packet.clone();

        let t1 = thread::spawn(move || p1.process_one_sync(&CapturedPacket::for_test(pkt1)));
        let t2 = thread::spawn(move || p2.process_one_sync(&CapturedPacket::for_test(pkt2)));

        let r1 = t1.join().unwrap();
        let r2 = t2.join().unwrap();

        // Ровно один из двух результатов — реальный десинк (Inject/Modify),
        // второй — Forward (гейт desync_applied сработал).
        let decisions: Vec<_> = [r1, r2].into_iter().filter_map(Result::ok).collect();
        let desync_count = decisions
            .iter()
            .filter(|d| !matches!(d, PacketDecision::Forward))
            .count();
        assert_eq!(
            desync_count, 1,
            "десинк должен примениться ровно один раз из двух конкурентных проходов"
        );
    }

    #[test]
    fn test_routing_only_enabled() {
        let mut config = ProcessingConfig::default();
        config.strategies = vec![crate::config::StrategyProfileConfig {
            name: "socks5_fallback".into(),
            protocol: "tcp".into(),
            techniques: vec![],
            split_size: None,
            split_count: None,
            fake_ttl_offset: None,
            max_seg_size: None,
            default: None,
            enabled: Some(true),
        }];
        let pipeline = ProcessingPipeline::new_api_only(config);
        assert!(pipeline.is_profile_activated("socks5_fallback"));
    }
}
