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

use crossbeam::channel::{RecvTimeoutError, TrySendError};
use tracing::{debug, error, warn};
use windivert::prelude::{NetworkLayer, WinDivertAddress};

pub mod awg_async;
pub mod delayed_inject;
pub mod dns_async;
pub(crate) mod flow_affinity;

#[derive(Debug)]
pub enum PacketDecision {
    Forward,
    Modify(bytes::Bytes),
    Desync {
        inject: smallvec::SmallVec<[bytes::Bytes; 4]>,
        modified: Option<bytes::Bytes>,
        inject_protocol: InjectProtocol,
        inter_delay_us: u32,
        /// P0-10: Направление инъекции (PreserveOriginal, ForceOutbound, ForceInbound).
        inject_direction: crate::desync::InjectDirection,
        drop_original: bool,
    },
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InjectProtocol {
    Tcp,
    Udp,
}

enum TxAction {
    Forward(bytes::Bytes, WinDivertAddress<NetworkLayer>),
    Inject(bytes::Bytes, WinDivertAddress<NetworkLayer>),
}

use serde::{Deserialize, Serialize};
use std::sync::atomic::AtomicU64;

#[derive(Debug)]
pub struct FixedLatencyHist {
    buckets: [AtomicU64; 16],
}

impl FixedLatencyHist {
    pub fn new() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl Default for FixedLatencyHist {
    fn default() -> Self {
        Self::new()
    }
}

impl FixedLatencyHist {
    pub fn observe_us(&self, v: u64) {
        let idx = match v {
            0..=9 => 0,
            10..=24 => 1,
            25..=49 => 2,
            50..=99 => 3,
            100..=249 => 4,
            250..=499 => 5,
            500..=999 => 6,
            1_000..=2_499 => 7,
            2_500..=4_999 => 8,
            5_000..=9_999 => 9,
            10_000..=24_999 => 10,
            25_000..=49_999 => 11,
            50_000..=99_999 => 12,
            100_000..=249_999 => 13,
            250_000..=999_999 => 14,
            _ => 15,
        };
        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
    }

    pub fn estimate_percentiles(&self) -> (u64, u64, u64) {
        let counts: Vec<u64> = self
            .buckets
            .iter()
            .map(|b| b.load(Ordering::Relaxed))
            .collect();
        let total: u64 = counts.iter().sum();
        if total == 0 {
            return (0, 0, 0);
        }

        let midpoints = [
            5, 17, 37, 75, 175, 375, 750, 1750, 3750, 7500, 17500, 37500, 75000, 175000, 625000,
            1500000,
        ];

        let find_pct = |pct: f64| -> u64 {
            let target = (total as f64 * pct) as u64;
            let mut acc = 0u64;
            for (i, &count) in counts.iter().enumerate() {
                acc += count;
                if acc >= target {
                    return midpoints[i];
                }
            }
            midpoints[15]
        };

        (find_pct(0.50), find_pct(0.95), find_pct(0.99))
    }
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

    // P4-02 Classification stats
    pub capture_tls_ch: PaddedCounter,
    pub capture_quic_initial: PaddedCounter,
    pub capture_dns: PaddedCounter,
    pub capture_other: PaddedCounter,

    // Shard queue stats
    pub shard_queue_full: PaddedCounter,

    // Latency histogram
    pub desync_application_latency_us: FixedLatencyHist,

    // Proxy rewrite stats
    pub rewrite_inplace_success: PaddedCounter,
    pub rewrite_copy_fallback: PaddedCounter,
    pub rewrite_errors: PaddedCounter,

    // P5-01 Capture Governor stats
    pub capture_mode: std::sync::atomic::AtomicU8,
    pub capture_filter_update_failures_total: PaddedCounter,
    pub capture_rx_pps: std::sync::atomic::AtomicU64,
    pub capture_drop_ratio_ppm: std::sync::atomic::AtomicU64,
    pub capture_other_udp443_pps: std::sync::atomic::AtomicU64,
    pub capture_max_worker_queue_depth: std::sync::atomic::AtomicUsize,

    // P5-02 Invariant Guard stats
    pub invariant_too_short: PaddedCounter,
    pub invariant_unsupported_ip_version: PaddedCounter,
    pub invariant_ipv4_header_too_short: PaddedCounter,
    pub invariant_ipv4_total_length_mismatch: PaddedCounter,
    pub invariant_ipv4_bad_header_checksum: PaddedCounter,
    pub invariant_ipv6_payload_length_mismatch: PaddedCounter,
    pub invariant_tcp_header_too_short: PaddedCounter,
    pub invariant_udp_header_too_short: PaddedCounter,
    pub invariant_udp_length_mismatch: PaddedCounter,
    pub invariant_quic_initial_too_small: PaddedCounter,

    // References for dynamic stats
    pub buf_pool: std::sync::OnceLock<Arc<PacketBufferPool>>,
    pub shard_txs: std::sync::OnceLock<Arc<Vec<crossbeam::channel::Sender<CapturedPacket>>>>,
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

            capture_tls_ch: PaddedCounter::new(0),
            capture_quic_initial: PaddedCounter::new(0),
            capture_dns: PaddedCounter::new(0),
            capture_other: PaddedCounter::new(0),

            shard_queue_full: PaddedCounter::new(0),

            desync_application_latency_us: FixedLatencyHist::new(),

            rewrite_inplace_success: PaddedCounter::new(0),
            rewrite_copy_fallback: PaddedCounter::new(0),
            rewrite_errors: PaddedCounter::new(0),

            capture_mode: std::sync::atomic::AtomicU8::new(0), // Default Strict (0)
            capture_filter_update_failures_total: PaddedCounter::new(0),
            capture_rx_pps: std::sync::atomic::AtomicU64::new(0),
            capture_drop_ratio_ppm: std::sync::atomic::AtomicU64::new(0),
            capture_other_udp443_pps: std::sync::atomic::AtomicU64::new(0),
            capture_max_worker_queue_depth: std::sync::atomic::AtomicUsize::new(0),

            invariant_too_short: PaddedCounter::new(0),
            invariant_unsupported_ip_version: PaddedCounter::new(0),
            invariant_ipv4_header_too_short: PaddedCounter::new(0),
            invariant_ipv4_total_length_mismatch: PaddedCounter::new(0),
            invariant_ipv4_bad_header_checksum: PaddedCounter::new(0),
            invariant_ipv6_payload_length_mismatch: PaddedCounter::new(0),
            invariant_tcp_header_too_short: PaddedCounter::new(0),
            invariant_udp_header_too_short: PaddedCounter::new(0),
            invariant_udp_length_mismatch: PaddedCounter::new(0),
            invariant_quic_initial_too_small: PaddedCounter::new(0),

            buf_pool: std::sync::OnceLock::new(),
            shard_txs: std::sync::OnceLock::new(),
        }
    }

    pub fn snapshot(&self) -> ProcessingStatsSnapshot {
        let (pool_acq, pool_miss, pool_rel_ok, pool_rel_fail, pool_cap) =
            if let Some(pool) = self.buf_pool.get() {
                (
                    pool.pool_acquire_total(),
                    pool.pool_acquire_miss_total(),
                    pool.pool_release_success_total(),
                    pool.pool_release_refcount_failed_total(),
                    pool.pool_capacity(),
                )
            } else {
                (0, 0, 0, 0, 0)
            };

        let q_depth = if let Some(txs) = self.shard_txs.get() {
            txs.iter().map(|tx| tx.len()).sum()
        } else {
            0
        };

        let (p50, p95, p99) = self.desync_application_latency_us.estimate_percentiles();

        ProcessingStatsSnapshot {
            total_received: self.total_received.load(Ordering::Relaxed),
            injected_skipped: self.injected_skipped.load(Ordering::Relaxed),
            tls_outbound: self.tls_outbound.load(Ordering::Relaxed),
            fake_ch_injected: self.fake_ch_injected.load(Ordering::Relaxed),
            forwarded: self.forwarded.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),

            capture_tls_ch: self.capture_tls_ch.load(Ordering::Relaxed),
            capture_quic_initial: self.capture_quic_initial.load(Ordering::Relaxed),
            capture_dns: self.capture_dns.load(Ordering::Relaxed),
            capture_other: self.capture_other.load(Ordering::Relaxed),

            shard_queue_full: self.shard_queue_full.load(Ordering::Relaxed),
            shard_queue_depth_current: q_depth,

            pool_acquire_total: pool_acq,
            pool_acquire_miss: pool_miss,
            pool_release_success: pool_rel_ok,
            pool_release_refcount_failed: pool_rel_fail,
            pool_capacity: pool_cap,

            desync_application_latency_us_p50: p50,
            desync_application_latency_us_p95: p95,
            desync_application_latency_us_p99: p99,

            capture_mode: self.capture_mode.load(Ordering::Relaxed),
            capture_filter_update_failures_total: self
                .capture_filter_update_failures_total
                .load(Ordering::Relaxed),
            capture_rx_pps: self.capture_rx_pps.load(Ordering::Relaxed),
            capture_drop_ratio_ppm: self.capture_drop_ratio_ppm.load(Ordering::Relaxed),
            capture_other_udp443_pps: self.capture_other_udp443_pps.load(Ordering::Relaxed),
            capture_max_worker_queue_depth: self
                .capture_max_worker_queue_depth
                .load(Ordering::Relaxed),

            invariant_too_short: self.invariant_too_short.load(Ordering::Relaxed),
            invariant_unsupported_ip_version: self
                .invariant_unsupported_ip_version
                .load(Ordering::Relaxed),
            invariant_ipv4_header_too_short: self
                .invariant_ipv4_header_too_short
                .load(Ordering::Relaxed),
            invariant_ipv4_total_length_mismatch: self
                .invariant_ipv4_total_length_mismatch
                .load(Ordering::Relaxed),
            invariant_ipv4_bad_header_checksum: self
                .invariant_ipv4_bad_header_checksum
                .load(Ordering::Relaxed),
            invariant_ipv6_payload_length_mismatch: self
                .invariant_ipv6_payload_length_mismatch
                .load(Ordering::Relaxed),
            invariant_tcp_header_too_short: self
                .invariant_tcp_header_too_short
                .load(Ordering::Relaxed),
            invariant_udp_header_too_short: self
                .invariant_udp_header_too_short
                .load(Ordering::Relaxed),
            invariant_udp_length_mismatch: self
                .invariant_udp_length_mismatch
                .load(Ordering::Relaxed),
            invariant_quic_initial_too_small: self
                .invariant_quic_initial_too_small
                .load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessingStatsSnapshot {
    pub total_received: u64,
    pub injected_skipped: u64,
    pub tls_outbound: u64,
    pub fake_ch_injected: u64,
    pub forwarded: u64,
    pub dropped: u64,
    pub errors: u64,

    pub capture_tls_ch: u64,
    pub capture_quic_initial: u64,
    pub capture_dns: u64,
    pub capture_other: u64,

    pub shard_queue_full: u64,
    pub shard_queue_depth_current: usize,

    pub pool_acquire_total: u64,
    pub pool_acquire_miss: u64,
    pub pool_release_success: u64,
    pub pool_release_refcount_failed: u64,
    pub pool_capacity: usize,

    pub desync_application_latency_us_p50: u64,
    pub desync_application_latency_us_p95: u64,
    pub desync_application_latency_us_p99: u64,

    pub capture_mode: u8,
    pub capture_filter_update_failures_total: u64,
    pub capture_rx_pps: u64,
    pub capture_drop_ratio_ppm: u64,
    pub capture_other_udp443_pps: u64,
    pub capture_max_worker_queue_depth: usize,

    pub invariant_too_short: u64,
    pub invariant_unsupported_ip_version: u64,
    pub invariant_ipv4_header_too_short: u64,
    pub invariant_ipv4_total_length_mismatch: u64,
    pub invariant_ipv4_bad_header_checksum: u64,
    pub invariant_ipv6_payload_length_mismatch: u64,
    pub invariant_tcp_header_too_short: u64,
    pub invariant_udp_header_too_short: u64,
    pub invariant_udp_length_mismatch: u64,
    pub invariant_quic_initial_too_small: u64,
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
    pub awg: crate::config::AwgConfig,
    pub network_tuning: crate::config::NetworkTuningConfig,
    pub capture_budget: crate::capture_budget::CaptureBudgetConfig,
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
            awg: crate::config::AwgConfig::default(),
            network_tuning: crate::config::NetworkTuningConfig::default(),
            capture_budget: crate::capture_budget::CaptureBudgetConfig::default(),
        }
    }
}

/// Ключ для отслеживания injected SEQ — 5-tuple (src_ip, dst_ip, src_port, dst_port, seq).
/// P0-09: key = (conn_id, tcp_sequence). conn_id — SipHash от FlowKey.
type SeqKey = (u64, u32);

pub struct ProcessingPipeline {
    packet_engine: Arc<PacketEngine>,
    fake_ip: Arc<FakeIpManager>,
    geo_router: Arc<GeoRouter>,
    hop_tab: Arc<HopTab>,
    conntrack: Arc<Conntrack>,
    profile_registry: Arc<StrategyProfileRegistry>,
    active_profile_tls: std::sync::atomic::AtomicU32,
    active_profile_quic: std::sync::atomic::AtomicU32,
    active_profile_http: std::sync::atomic::AtomicU32,
    config: ProcessingConfig,
    stats: Arc<ProcessingStats>,
    /// P1-16: DashMap with atomic entry API — check-and-mark без TOCTOU race.
    /// Значение = Instant::now() при вставке, используется periodic sweep для eviction.
    injected_seqs: Arc<dashmap::DashMap<SeqKey, Instant>>,
    auto_tune: AutoTune,
    /// Buffer pool для zero-alloc steady-state.
    /// Один пул на все workers (ArrayQueue — lock-free MPMC, безопасно для concurrent access).
    buf_pool: Arc<PacketBufferPool>,
    redirect_table: Arc<crate::desync::redirect_table::RedirectTable>,
    socks_redirector: Arc<crate::proxy::redirector::SocksRedirector>,
    #[allow(dead_code)]
    dns_proxy: Arc<crate::dns::dns_proxy::DnsProxyEngine>,
    #[allow(dead_code)]
    zero_config: Arc<crate::proxy::zero_config::ZeroConfigEngine>,
    adaptive_router: Arc<crate::routing::adaptive_router::AdaptiveRouter>,
    awg_tunnel: Arc<ArcSwap<Option<Arc<crate::proxy::awg_tunnel::AwgTunnel>>>>,
    delayed_inject: Arc<delayed_inject::DelayedInject>,
    dns_async: Arc<dns_async::DnsAsyncBridge>,
    awg_async: Arc<ArcSwap<Option<Arc<awg_async::AwgAsyncWriter>>>>,
    split_tunnel: Option<Arc<crate::split_tunnel::SplitTunnel>>,
    fallback_chain: Arc<std::sync::Mutex<crate::adaptive::fallback::FallbackChain>>,
    target_escalator: Arc<std::sync::Mutex<crate::adaptive::target_escalate::TargetEscalation>>,
    tls_reassembler: Arc<crate::tls_reassembly::TlsReassembler>,
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
        split_tunnel: Option<Arc<crate::split_tunnel::SplitTunnel>>,
    ) -> Result<Self, anyhow::Error> {
        let packet_engine = Arc::new(PacketEngine::new_with_tuning(
            filter,
            &config.network_tuning,
        )?);
        let conntrack = Arc::new(Conntrack::new(Duration::from_secs(120)));
        let profile_registry = Arc::new(StrategyProfileRegistry::from_config(
            &config.desync,
            &config.strategies,
            &config.techniques,
        ));
        let default_tls = profile_registry
            .get_default_for_category(StrategyCategory::Tls)
            .expect("outbound_tls must be registered");
        let active_profile_tls = std::sync::atomic::AtomicU32::new(default_tls.id.0);

        let default_quic = profile_registry
            .get_default_for_category(StrategyCategory::Quic)
            .expect("outbound_quic must be registered");
        let active_profile_quic = std::sync::atomic::AtomicU32::new(default_quic.id.0);

        let default_http = profile_registry
            .get_default_for_category(StrategyCategory::Http)
            .expect("outbound_http must be registered");
        let active_profile_http = std::sync::atomic::AtomicU32::new(default_http.id.0);

        // Dynamically size the buffer pool
        let worker_count = num_cpus::get().clamp(2, 16);
        let pool_cap = crate::packet_engine::packet_pool_capacity(worker_count, 64);
        let buf_pool = Arc::new(PacketBufferPool::new(pool_cap));

        let auto_tune = AutoTune::new_with_registry(&profile_registry);
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
        fake_ip.register_active_checkers(conntrack.clone(), redirect_table.clone());
        let redirect_table_clone = redirect_table.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                let swept = redirect_table_clone.sweep_stale(std::time::Duration::from_secs(300));
                if swept > 0 {
                    tracing::debug!("P2-07: swept {} stale redirect_table entries", swept);
                }
            }
        });

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

        let mut fallback = crate::adaptive::fallback::FallbackChain::new();
        for t in &config.techniques {
            fallback.add(*t);
        }
        let fallback_chain = Arc::new(std::sync::Mutex::new(fallback));

        let target_escalator = Arc::new(std::sync::Mutex::new(
            crate::adaptive::target_escalate::TargetEscalation::new(
                config.adaptive_router_config.circuit_breaker_rst_threshold as usize,
                config.adaptive_router_config.circuit_breaker_window_secs,
                config.adaptive_router_config.circuit_breaker_timeout_secs,
            ),
        ));

        let awg_tunnel_state = Arc::new(ArcSwap::from_pointee(None));
        let awg_async_writer = Arc::new(ArcSwap::from_pointee(None));
        if config.awg.enabled {
            let awg_config = config.awg.clone();
            let engine_clone = packet_engine.clone();
            let state_clone = awg_tunnel_state.clone();
            let async_clone = awg_async_writer.clone();
            tokio::spawn(async move {
                tracing::info!("AWG: Starting userspace AmneziaWG tunnel...");
                match crate::proxy::awg_tunnel::AwgTunnel::start(awg_config, engine_clone).await {
                    Ok(tunnel) => {
                        tracing::info!("AWG: Userspace AmneziaWG tunnel started successfully!");
                        let tunnel_arc = Arc::new(tunnel);
                        state_clone.store(Arc::new(Some(tunnel_arc.clone())));
                        let writer = awg_async::AwgAsyncWriter::start(tunnel_arc, 10000);
                        async_clone.store(Arc::new(Some(writer)));
                    }
                    Err(e) => {
                        tracing::error!("AWG: Failed to start userspace AmneziaWG tunnel: {e:#}");
                    }
                }
            });
        }

        let tls_reassembler = Arc::new(crate::tls_reassembly::TlsReassembler::new());
        let tls_reassembler_clone = tls_reassembler.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                interval.tick().await;
                tls_reassembler_clone.gc();
            }
        });

        let delayed_inject =
            delayed_inject::DelayedInject::start(packet_engine.clone(), buf_pool.clone(), 10000);
        let dns_async =
            dns_async::DnsAsyncBridge::start(packet_engine.clone(), dns_proxy.clone(), 10000);

        let stats = Arc::new(ProcessingStats::new());
        let _ = stats.buf_pool.set(buf_pool.clone());

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
            stats,
            injected_seqs: Arc::new(dashmap::DashMap::with_capacity(100_000)),
            auto_tune,
            buf_pool,
            redirect_table,
            socks_redirector: redirector,
            dns_proxy,
            zero_config,
            adaptive_router,
            awg_tunnel: awg_tunnel_state,
            delayed_inject,
            dns_async,
            awg_async: awg_async_writer,
            split_tunnel,
            fallback_chain,
            target_escalator,
            tls_reassembler,
        })
    }

    pub fn new_api_only(config: ProcessingConfig) -> Self {
        let packet_engine = Arc::new(PacketEngine::new_api_only());
        let profile_registry = Arc::new(StrategyProfileRegistry::from_config(
            &config.desync,
            &config.strategies,
            &config.techniques,
        ));
        let default_tls = profile_registry
            .get_default_for_category(StrategyCategory::Tls)
            .expect("outbound_tls must be registered");
        let active_profile_tls = std::sync::atomic::AtomicU32::new(default_tls.id.0);

        let default_quic = profile_registry
            .get_default_for_category(StrategyCategory::Quic)
            .expect("outbound_quic must be registered");
        let active_profile_quic = std::sync::atomic::AtomicU32::new(default_quic.id.0);

        let default_http = profile_registry
            .get_default_for_category(StrategyCategory::Http)
            .expect("outbound_http must be registered");
        let active_profile_http = std::sync::atomic::AtomicU32::new(default_http.id.0);

        // Dynamically size the buffer pool in API-only mode as well
        let worker_count = num_cpus::get().clamp(2, 16);
        let pool_cap = crate::packet_engine::packet_pool_capacity(worker_count, 64);
        let buf_pool = Arc::new(PacketBufferPool::new(pool_cap));

        let auto_tune = AutoTune::new_with_registry(&profile_registry);
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

        let delayed_inject =
            delayed_inject::DelayedInject::start(packet_engine.clone(), buf_pool.clone(), 10);
        let dns_async =
            dns_async::DnsAsyncBridge::start(packet_engine.clone(), dns_proxy.clone(), 10);

        let tls_reassembler = Arc::new(crate::tls_reassembly::TlsReassembler::new());

        let stats = Arc::new(ProcessingStats::new());
        let _ = stats.buf_pool.set(buf_pool.clone());

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
            stats,
            injected_seqs: Arc::new(dashmap::DashMap::with_capacity(100_000)),
            auto_tune,
            buf_pool,
            redirect_table,
            socks_redirector: redirector,
            dns_proxy,
            zero_config,
            adaptive_router,
            awg_tunnel: Arc::new(ArcSwap::from_pointee(None)),
            delayed_inject,
            dns_async,
            awg_async: Arc::new(ArcSwap::from_pointee(None)),
            split_tunnel: None,
            fallback_chain: Arc::new(std::sync::Mutex::new(
                crate::adaptive::fallback::FallbackChain::new(),
            )),
            target_escalator: Arc::new(std::sync::Mutex::new(
                crate::adaptive::target_escalate::TargetEscalation::new(10, 30, 30),
            )),
            tls_reassembler,
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
        let active_id = match category {
            StrategyCategory::Tls => self.active_profile_tls.load(Ordering::Relaxed),
            StrategyCategory::Quic => self.active_profile_quic.load(Ordering::Relaxed),
            StrategyCategory::Http => self.active_profile_http.load(Ordering::Relaxed),
            other => unreachable!(
                "resolve_active_profile вызван для категории {:?} без hot-path переключения",
                other
            ),
        };
        self.profile_registry
            .get_by_profile_id(crate::adaptive::strategy_profile::ProfileId(active_id))
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
                .store(profile.id.0, Ordering::Relaxed),
            StrategyCategory::Quic => self
                .active_profile_quic
                .store(profile.id.0, Ordering::Relaxed),
            StrategyCategory::Http => self
                .active_profile_http
                .store(profile.id.0, Ordering::Relaxed),
            _ => {
                tracing::info!(
                    "apply_strategy_tune: id={} (профиль='{}', категория={:?}) — только числовой override",
                    strategy_id, profile.name, profile.category
                );
            }
        }
        self.auto_tune.set_override(&profile.name, params);
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
                    .store(default_profile.id.0, Ordering::Relaxed),
                StrategyCategory::Quic => self
                    .active_profile_quic
                    .store(default_profile.id.0, Ordering::Relaxed),
                StrategyCategory::Http => self
                    .active_profile_http
                    .store(default_profile.id.0, Ordering::Relaxed),
                _ => {}
            }
        }
        self.auto_tune.clear_override(&profile.name);
        tracing::info!(
            "clear_strategy_tune: id={} — сброшен к default профилю категории",
            strategy_id
        );
    }

    pub async fn run(self: Arc<Self>, shutdown: tokio::sync::broadcast::Receiver<()>) {
        debug!("ProcessingPipeline started (P1-00 flow-affinity mode)");

        // P5-01: Capture Budget Governor background loop
        {
            let pipeline = self.clone();
            let mut shutdown_rx = shutdown.resubscribe();
            let mut governor = crate::capture_budget::CaptureBudgetGovernor::new(
                pipeline.config.capture_budget.clone(),
            );

            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            let total_received = pipeline.stats.total_received.load(Ordering::Relaxed);
                            let total_dropped = pipeline.stats.dropped.load(Ordering::Relaxed);
                            let total_other = pipeline.stats.capture_other.load(Ordering::Relaxed);

                            let q_depth = if let Some(txs) = pipeline.stats.shard_txs.get() {
                                txs.iter().map(|tx| tx.len()).max().unwrap_or(0)
                            } else {
                                0
                            };

                            let (next_mode, pressure) = governor.observe_window(
                                total_received,
                                total_dropped,
                                total_other,
                                std::time::Duration::from_secs(1),
                                q_depth,
                            );

                            // Store pressure in stats
                            pipeline.stats.capture_rx_pps.store(pressure.rx_pps, Ordering::Relaxed);
                            pipeline.stats.capture_drop_ratio_ppm.store(pressure.drop_ratio_ppm, Ordering::Relaxed);
                            pipeline.stats.capture_other_udp443_pps.store(pressure.other_udp443_pps, Ordering::Relaxed);
                            pipeline.stats.capture_max_worker_queue_depth.store(pressure.max_worker_queue_depth, Ordering::Relaxed);

                            if let Some(mode) = next_mode {
                                let mode_val = match mode {
                                    crate::capture_budget::CaptureMode::Strict => 0,
                                    crate::capture_budget::CaptureMode::Balanced => 1,
                                    crate::capture_budget::CaptureMode::SafeFallback => 2,
                                };
                                pipeline.stats.capture_mode.store(mode_val, Ordering::Relaxed);

                                let enable_dns = true;
                                let enable_quic = pipeline.config.techniques.iter().any(|t| {
                                    let name = format!("{:?}", t);
                                    name.starts_with("Quic") || name == "DoppelgangerGrease" || name == "UdpCoalescing"
                                });

                                let new_filter = crate::capture_budget::build_filter(mode, enable_dns, enable_quic);
                                tracing::info!(
                                    "Capture Budget Governor changed mode to {:?}. Rotating filter to: {}",
                                    mode,
                                    new_filter
                                );

                                if let Err(e) = pipeline.packet_engine.update_filter(&new_filter) {
                                    tracing::error!("Capture Budget Governor failed to rotate filter: {}", e);
                                    pipeline.stats.capture_filter_update_failures_total.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                        _ = shutdown_rx.recv() => {
                            break;
                        }
                    }
                }
            });
        }

        let n_shards = num_cpus::get().clamp(2, 16);
        let shutdown_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut handles = Vec::with_capacity(n_shards + 2);

        // Create per-shard bounded queues — depth 8192 prevents head-of-line blocking
        let (shard_txs, shard_rxs): (Vec<_>, Vec<_>) = (0..n_shards)
            .map(|_| crossbeam::channel::bounded::<CapturedPacket>(8192))
            .unzip();
        let shard_txs = Arc::new(shard_txs);
        let _ = self.stats.shard_txs.set(shard_txs.clone());

        // 1. Capture thread: exclusively reads WinDivert, classifies flow, dispatches to shard
        {
            let engine = self.packet_engine.clone();
            let pool = self.buf_pool.clone();
            let shutdown = shutdown_flag.clone();
            let txs = shard_txs.clone();
            let stats = self.stats.clone();
            handles.push(
                std::thread::Builder::new()
                    .name("fp-capture".into())
                    .spawn(move || {
                        Self::capture_loop(engine, pool, shutdown, txs, stats);
                    })
                    .expect("spawn capture thread"),
            );
        }

        // 2. Shard workers: process packets from their assigned queue, send/inject
        for (id, rx) in shard_rxs.into_iter().enumerate() {
            let engine = self.packet_engine.clone();
            let pipeline = self.clone();
            let pool = self.buf_pool.clone();
            let shutdown = shutdown_flag.clone();
            handles.push(
                std::thread::Builder::new()
                    .name(format!("fp-shard-{}", id))
                    .spawn(move || {
                        Self::shard_worker_loop(id, rx, engine, pipeline, pool, shutdown);
                    })
                    .expect("spawn shard worker"),
            );
        }

        // 3. (P1-16) Periodic sweep: evict stale injected_seqs entries
        {
            let seqs = self.injected_seqs.clone();
            let shutdown = shutdown_flag.clone();
            handles.push(
                std::thread::Builder::new()
                    .name("fp-seq-evict".into())
                    .spawn(move || {
                        let evict_after = Duration::from_secs(30);
                        loop {
                            if shutdown.load(Ordering::Acquire) {
                                break;
                            }
                            std::thread::sleep(Duration::from_secs(5));
                            let cutoff = Instant::now() - evict_after;
                            seqs.retain(|_k, v| *v > cutoff);
                        }
                        tracing::debug!("Seq evict thread stopped");
                    })
                    .expect("spawn seq evict thread"),
            );
        }

        // Wait for shutdown signal
        let mut shutdown_rx = shutdown.resubscribe();
        let _ = shutdown_rx.recv().await;
        shutdown_flag.store(true, Ordering::Release);
        for handle in handles {
            let _ = handle.join();
        }

        debug!("ProcessingPipeline stopped");
    }

    /// P1-00: Capture loop — exclusively reads WinDivert, classifies flow,
    /// dispatches each packet to the correct shard queue.
    ///
    /// Fail-open: if a shard queue is full, the packet is forwarded directly
    /// (no backpressure on the capture thread).
    fn capture_loop(
        engine: Arc<PacketEngine>,
        pool: Arc<PacketBufferPool>,
        shutdown: Arc<std::sync::atomic::AtomicBool>,
        shard_txs: Arc<Vec<crossbeam::channel::Sender<CapturedPacket>>>,
        stats: Arc<ProcessingStats>,
    ) {
        let mut empty_spins: u32 = 0;
        let mut recv_buf = Vec::with_capacity(64);

        while !shutdown.load(Ordering::Acquire) {
            let n = match engine.recv_batch_into(&pool, &mut recv_buf) {
                Ok(n_pkts) => {
                    if n_pkts == 0 {
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
                    n_pkts
                }
                Err(e) => {
                    if !engine.has_divert() {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        continue;
                    }
                    tracing::error!("capture_loop recv_batch error: {}", e);
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
            };

            stats.total_received.fetch_add(n as u64, Ordering::Relaxed);

            for (data, addr) in recv_buf.drain(..) {
                // Perform classification for stats
                match crate::classifier::Classifier::classify(&data) {
                    crate::classifier::Classification::Tls(ref cp) => {
                        if let Some(payload) = data.get(cp.payload_offset..) {
                            if crate::classifier::Classifier::is_client_hello(payload) {
                                stats.capture_tls_ch.fetch_add(1, Ordering::Relaxed);
                            } else {
                                stats.capture_other.fetch_add(1, Ordering::Relaxed);
                            }
                        } else {
                            stats.capture_other.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    crate::classifier::Classification::Quic(ref cp) => {
                        if let Some(payload) = data.get(cp.payload_offset..) {
                            if is_quic_initial_check(payload) {
                                stats.capture_quic_initial.fetch_add(1, Ordering::Relaxed);
                            } else {
                                stats.capture_other.fetch_add(1, Ordering::Relaxed);
                            }
                        } else {
                            stats.capture_other.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    crate::classifier::Classification::Dns(_) => {
                        stats.capture_dns.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {
                        stats.capture_other.fetch_add(1, Ordering::Relaxed);
                    }
                }

                // Classify flow for shard routing
                let key = flow_affinity::classify_flow_key(&data);
                let shard = flow_affinity::shard_for_flow(key, &data, shard_txs.len());
                let pkt = CapturedPacket { data, addr };
                match shard_txs[shard].try_send(pkt) {
                    Ok(()) => {}
                    Err(TrySendError::Full(pkt)) => {
                        stats.shard_queue_full.fetch_add(1, Ordering::Relaxed);
                        // Fail-open: forward directly, never block capture
                        let _ = engine.send_batch(&[(pkt.data.clone(), pkt.addr)]);
                        pool.release_bytes(pkt.data);
                    }
                    Err(TrySendError::Disconnected(_)) => return,
                }
            }
        }
    }

    /// P1-00: Shard worker loop — receives packets from its assigned queue,
    /// processes them (classify, desync), and sends/injects in batches.
    fn shard_worker_loop(
        id: usize,
        rx: crossbeam::channel::Receiver<CapturedPacket>,
        engine: Arc<PacketEngine>,
        pipeline: Arc<Self>,
        pool: Arc<PacketBufferPool>,
        shutdown: Arc<std::sync::atomic::AtomicBool>,
    ) {
        let mut tx_queue: Vec<TxAction> = Vec::with_capacity(128);

        loop {
            if shutdown.load(Ordering::Acquire) {
                break;
            }

            // 1. Wait for first packet with timeout (poll shutdown)
            let first = match rx.recv_timeout(std::time::Duration::from_millis(10)) {
                Ok(pkt) => pkt,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => break,
            };

            // 2. Prepare batches
            tx_queue.clear();

            // 3. Process first packet
            Self::shard_process_one(
                first,
                &mut tx_queue,
                &engine,
                &pipeline,
                &pool,
            );

            // 4. Drain remaining available packets (batch processing)
            while tx_queue.len() < 64 {
                match rx.try_recv() {
                    Ok(pkt) => Self::shard_process_one(
                        pkt,
                        &mut tx_queue,
                        &engine,
                        &pipeline,
                        &pool,
                    ),
                    Err(_) => break,
                }
            }

            // 5. Send tx_queue actions while preserving wire order and batching adjacent ones
            if !tx_queue.is_empty() {
                let mut i = 0;
                while i < tx_queue.len() {
                    match &tx_queue[i] {
                        TxAction::Forward(_, _) => {
                            let mut batch = Vec::new();
                            while i < tx_queue.len() {
                                if let TxAction::Forward(ref data, ref addr) = tx_queue[i] {
                                    batch.push((data.clone(), addr.clone()));
                                    i += 1;
                                } else {
                                    break;
                                }
                            }
                            if let Ok(n) = engine.send_batch(&batch) {
                                pipeline.stats.forwarded.fetch_add(n as u64, Ordering::Relaxed);
                            }
                            for (data, _) in batch {
                                pool.release_bytes(data);
                            }
                        }
                        TxAction::Inject(_, _) => {
                            let mut batch = Vec::new();
                            while i < tx_queue.len() {
                                if let TxAction::Inject(ref data, ref addr) = tx_queue[i] {
                                    batch.push((data.clone(), addr.clone()));
                                    i += 1;
                                } else {
                                    break;
                                }
                            }
                            if let Ok(n) = engine.inject_batch_via_divert(&batch) {
                                pipeline.stats.fake_ch_injected.fetch_add(n as u64, Ordering::Relaxed);
                            }
                            for (data, _) in batch {
                                pool.release_bytes(data);
                            }
                        }
                    }
                }
                tx_queue.clear();
            }
        }

        tracing::debug!("Shard worker {} stopped", id);
    }

    /// P0-10: Apply the configured inject direction to the WinDivertAddress.
    fn apply_inject_direction(
        original: &WinDivertAddress<NetworkLayer>,
        direction: crate::desync::InjectDirection,
    ) -> WinDivertAddress<NetworkLayer> {
        let mut addr = original.clone();
        match direction {
            crate::desync::InjectDirection::ForceOutbound => addr.set_outbound(true),
            crate::desync::InjectDirection::ForceInbound => addr.set_outbound(false),
            crate::desync::InjectDirection::PreserveOriginal => {}
            crate::desync::InjectDirection::DerivedFromPacketTuple => {
                addr.set_outbound(true);
            }
        }
        addr
    }

    /// P1-00: Process a single packet in the shard worker context.
    /// Inline helper to avoid duplicating the match arms.
    fn shard_process_one(
        captured: CapturedPacket,
        tx_queue: &mut Vec<TxAction>,
        engine: &PacketEngine,
        pipeline: &Self,
        pool: &PacketBufferPool,
    ) {
        let decision = pipeline.process_one_sync(&captured);
        let CapturedPacket { data, addr } = captured;

        match decision {
            Ok(decision) => match decision {
                PacketDecision::Forward => {
                    tx_queue.push(TxAction::Forward(data, addr));
                }
                PacketDecision::Modify(modified) => {
                    pool.release_bytes(data);
                    if pipeline.validate_packet_and_log(&modified) {
                        tx_queue.push(TxAction::Forward(modified, addr));
                    }
                }
                PacketDecision::Desync {
                    inject,
                    modified,
                    inject_protocol,
                    inter_delay_us,
                    inject_direction,
                    drop_original,
                } => {
                    let inject_addr = Self::apply_inject_direction(&addr, inject_direction);

                    // 1. First inject decoy/fake segments (with appropriate delay)
                    match inject_protocol {
                        InjectProtocol::Tcp => {
                            for (i, inject_pkt) in inject.into_iter().enumerate() {
                                if !pipeline.validate_packet_and_log(&inject_pkt) {
                                    pool.release_bytes(inject_pkt);
                                    continue;
                                }
                                if i > 0 && inter_delay_us > 0 {
                                    if !pipeline.delayed_inject.try_schedule(
                                        inter_delay_us * i as u32,
                                        inject_pkt.clone(),
                                        inject_addr.clone(),
                                    ) {
                                        tx_queue.push(TxAction::Inject(inject_pkt, inject_addr.clone()));
                                    }
                                } else {
                                    tx_queue.push(TxAction::Inject(inject_pkt, inject_addr.clone()));
                                }
                            }
                        }
                        InjectProtocol::Udp => {
                            for (i, inject_pkt) in inject.into_iter().enumerate() {
                                if !pipeline.validate_packet_and_log(&inject_pkt) {
                                    pool.release_bytes(inject_pkt);
                                    continue;
                                }
                                if i > 0 && inter_delay_us > 0 {
                                    if !pipeline.delayed_inject.try_schedule(
                                        inter_delay_us * i as u32,
                                        inject_pkt.clone(),
                                        inject_addr.clone(),
                                    ) {
                                        if let Err(e) = engine.inject_raw_udp(&inject_pkt) {
                                            tracing::warn!("Failed to inject UDP desync packet: {}", e);
                                        }
                                        pool.release_bytes(inject_pkt);
                                    }
                                } else {
                                    if let Err(e) = engine.inject_raw_udp(&inject_pkt) {
                                        tracing::warn!("Failed to inject UDP desync packet: {}", e);
                                    }
                                    pool.release_bytes(inject_pkt);
                                }
                                pipeline
                                    .stats
                                    .fake_ch_injected
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }

                    // 2. Then send modified or original packet (if drop_original is false)
                    if let Some(m) = modified {
                        if pipeline.validate_packet_and_log(&m) {
                            tx_queue.push(TxAction::Forward(m, addr));
                        }
                        pool.release_bytes(data);
                    } else if !drop_original {
                        tx_queue.push(TxAction::Forward(data, addr));
                    } else {
                        pool.release_bytes(data);
                    }
                }
                PacketDecision::Drop => {
                    pool.release_bytes(data);
                    pipeline.stats.dropped.fetch_add(1, Ordering::Relaxed);
                }
            },
            Err(e) => {
                tracing::debug!("Packet processing error: {}", e);
                tx_queue.push(TxAction::Forward(data, addr));
                pipeline.stats.errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn validate_packet_and_log(&self, pkt: &[u8]) -> bool {
        match crate::packet_invariants::validate_before_send(
            pkt,
            crate::packet_invariants::ValidationMode::Fast,
        ) {
            Ok(()) => true,
            Err(reason) => {
                tracing::warn!(
                    ?reason,
                    len = pkt.len(),
                    "dropping malformed generated/modified packet before wire"
                );
                self.stats.dropped.fetch_add(1, Ordering::Relaxed);

                // Increment specific invariant metric
                match reason {
                    crate::packet_invariants::PacketInvalidReason::TooShort => {
                        self.stats
                            .invariant_too_short
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    crate::packet_invariants::PacketInvalidReason::UnsupportedIpVersion(_) => {
                        self.stats
                            .invariant_unsupported_ip_version
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    crate::packet_invariants::PacketInvalidReason::Ipv4HeaderTooShort => {
                        self.stats
                            .invariant_ipv4_header_too_short
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    crate::packet_invariants::PacketInvalidReason::Ipv4TotalLengthMismatch => {
                        self.stats
                            .invariant_ipv4_total_length_mismatch
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    crate::packet_invariants::PacketInvalidReason::Ipv4BadHeaderChecksum => {
                        self.stats
                            .invariant_ipv4_bad_header_checksum
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    crate::packet_invariants::PacketInvalidReason::Ipv6PayloadLengthMismatch => {
                        self.stats
                            .invariant_ipv6_payload_length_mismatch
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    crate::packet_invariants::PacketInvalidReason::TcpHeaderTooShort => {
                        self.stats
                            .invariant_tcp_header_too_short
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    crate::packet_invariants::PacketInvalidReason::UdpHeaderTooShort => {
                        self.stats
                            .invariant_udp_header_too_short
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    crate::packet_invariants::PacketInvalidReason::UdpLengthMismatch => {
                        self.stats
                            .invariant_udp_length_mismatch
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    crate::packet_invariants::PacketInvalidReason::QuicInitialTooSmall => {
                        self.stats
                            .invariant_quic_initial_too_small
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
                false
            }
        }
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
        client_hello_shape: Option<crate::desync::tls::ClientHelloShape>,
    ) -> crate::desync::DesyncResult {
        let start = Instant::now();
        let override_params: Option<crate::desync::group::ConfigOverride> =
            tune_params.map(Into::into);
        let res = group.apply_with_runtime_context(
            &packet,
            dscp_value,
            override_params,
            is_resumption,
            conn_rng_fork,
            Some(&self.hop_tab),
            Some(&self.conntrack),
            client_hello_shape,
        );
        let elapsed = start.elapsed().as_micros() as u64;
        self.stats.desync_application_latency_us.observe_us(elapsed);
        res
    }

    /// Sync version: process_one (calls sync sub-methods directly).
    fn process_one_sync(&self, captured: &CapturedPacket) -> Result<PacketDecision, anyhow::Error> {
        self.process_one_sync_dispatch(captured)
    }

    /// P0-07: Наблюдает сетевые исходы для соединений, к которым применялся desync.
    /// Вызывается для каждого TCP-пакета. Если conntrack знает `applied_strategy`,
    /// то RST → record_outcome(fail), SYN-ACK → record_outcome(success).
    fn observe_connection_outcome(&self, packet: &[u8], cp: &ClassifiedPacket) {
        if cp.protocol != 6 {
            return; // только TCP
        }
        let ip = match crate::desync::parse_ip_header(packet) {
            Some(h) => h,
            None => return,
        };
        let tcp_data = &packet[ip.header_len()..];
        let tcp = match crate::desync::parse_tcp_packet(tcp_data) {
            Some(t) => t,
            None => return,
        };

        let flags = tcp.flags;
        let is_rst = (flags & 0x04) != 0;
        let is_syn = (flags & 0x02) != 0;
        let is_ack = (flags & 0x10) != 0;

        // P2-04: CircuitBreaker & ThroughputTracker integration
        let is_inbound = !is_outbound_cached(cp.src_ip);
        if is_inbound {
            let rev_key = crate::conntrack::ConnKey::new(
                cp.dst_ip,
                cp.src_ip,
                cp.dst_port,
                cp.src_port,
                cp.protocol,
            );
            if let Some(entry) = self.conntrack.get(&rev_key) {
                if let Some(ref route_key) = entry.route_key {
                    if is_rst {
                        self.adaptive_router.record_rst();
                        debug!(
                            "P2-04: recorded inbound RST (CircuitBreaker) for domain {}",
                            route_key
                        );
                    } else if (is_syn && is_ack) || cp.payload_len > 0 {
                        self.adaptive_router.record_success();
                        if cp.payload_len > 0 {
                            self.adaptive_router
                                .record_bytes(route_key, cp.payload_len as u64);
                            debug!(
                                "P2-04: recorded inbound success & {} bytes for domain {}",
                                cp.payload_len, route_key
                            );
                        }
                    }
                }
            }
        }

        // Если conntrack не знает `applied_strategy` — не наш случай
        let applied_strategy = match self.conntrack.get(&cp.conn_key) {
            Some(e) => e.applied_strategy.clone(),
            None => return,
        };
        let strategy_name = match applied_strategy {
            Some(ref name) => name.clone(),
            None => return,
        };

        if is_rst {
            // RST = fail (соединение было сброшено)
            self.auto_tune.record_outcome(&strategy_name, false, 0);
            debug!("P0-07: outcome=Fail(RST) strategy={}", strategy_name);

            // P2-05: FallbackChain & TargetEscalation recording failure
            self.fallback_chain.lock().unwrap().record_failure();

            let target_key = format!("{}:{}", cp.dst_ip, cp.dst_port);
            self.target_escalator
                .lock()
                .unwrap()
                .record_rst(&target_key);

            // Advance fallback chain
            if let Some(entry) = self.fallback_chain.lock().unwrap().current() {
                if let Some(profile) = self.profile_registry.find_by_technique(entry.technique) {
                    let mut params = crate::adaptive::auto_tune::TuneParams {
                        split_size: None,
                        split_count: None,
                        fake_ttl_offset: None,
                        max_seg_size: None,
                    };
                    if self
                        .target_escalator
                        .lock()
                        .unwrap()
                        .should_escalate(&target_key)
                    {
                        params.fake_ttl_offset = Some(2); // increase aggressiveness
                    }
                    self.apply_strategy_tune(profile.strategy_id, params);
                    tracing::info!(
                        "P2-05: Fallback advanced to strategy '{}' (technique: {:?}) for {}",
                        profile.name,
                        entry.technique,
                        target_key
                    );
                }
            }
        } else if is_syn && is_ack {
            // SYN-ACK = success (сервер ответил, соединение устанавливается)
            self.auto_tune.record_outcome(&strategy_name, true, 0);
            debug!("P0-07: outcome=Success(SYN-ACK) strategy={}", strategy_name);

            // P2-05: FallbackChain record success
            self.fallback_chain.lock().unwrap().record_success(0);
        }
    }

    pub(crate) fn process_one_sync_dispatch(
        &self,
        captured: &CapturedPacket,
    ) -> Result<PacketDecision, anyhow::Error> {
        let classification = Classifier::classify(&captured.data);

        // P0-07: Наблюдаем исходы для TCP-соединений с применённым desync
        if let Classification::Tls(ref cp) = classification {
            self.observe_connection_outcome(&captured.data, cp);
        } else if let Classification::Http(ref cp) = classification {
            self.observe_connection_outcome(&captured.data, cp);
        } else if let Classification::Other(ref cp) = classification {
            self.observe_connection_outcome(&captured.data, cp);
        }

        let cp_opt = match &classification {
            Classification::Tls(cp) => Some(cp),
            Classification::Quic(cp) => Some(cp),
            Classification::Dns(cp) => Some(cp),
            Classification::Http(cp) => Some(cp),
            Classification::Other(cp) => Some(cp),
            Classification::Unknown => None,
        };

        if let Some(ref st) = self.split_tunnel {
            if let Some(cp) = cp_opt {
                if cp.dst_port != 53 && cp.src_port != 17650 {
                    if st.should_bypass_ip(&cp.dst_ip) {
                        return Ok(PacketDecision::Forward);
                    }
                    if let Some(domain) = self.fake_ip.lookup(&cp.dst_ip) {
                        if st.should_bypass_domain(&domain) {
                            return Ok(PacketDecision::Forward);
                        }
                    }
                }
            }
        }

        // 1. DNS (UDP:53) check
        if let Classification::Dns(ref cp) = classification {
            if cp.dst_port == 53 && cp.protocol == 17 {
                let mut addr = captured.addr.clone();
                addr.set_outbound(false); // Reinject as inbound response

                // P1-05: DNS async queue offload bridge
                if self
                    .dns_async
                    .try_offload(captured.data.clone(), addr.clone())
                {
                    self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                    return Ok(PacketDecision::Drop); // Drop original query
                } else {
                    // Queue full: fail-open (forward original query directly to network)
                    tracing::warn!("DNS async queue full, fail-open: forwarding original DNS query");
                    return Ok(PacketDecision::Forward);
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
                    let modified = crate::proxy::rewrite::rewrite_src_addr_cow(
                        captured.data.clone(),
                        entry.orig_dst_ip,
                        entry.orig_dst_port,
                        &self.stats,
                    )?;
                    return Ok(PacketDecision::Modify(modified));
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
                    &self.auto_tune,
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
                            let awg_guard = self.awg_tunnel.load();
                            if let Some(ref awg) = **awg_guard {
                                let awg_async_guard = self.awg_async.load();
                                if let Some(ref writer) = **awg_async_guard {
                                    debug!(
                                        "AdaptiveRouter decided Proxy: routing UDP/QUIC packet to {}:{} via Userspace AmneziaWG (async offload)",
                                        cp.dst_ip, cp.dst_port
                                    );
                                    if writer.try_send(captured.data.clone()) {
                                        self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                                        return Ok(PacketDecision::Drop);
                                    } else {
                                        let awg_clone = Arc::clone(awg);
                                        let data_copy = captured.data.clone();
                                        crate::Runtime::global().io.spawn(async move {
                                            if let Err(e) = awg_clone.send_ip_packet(data_copy).await {
                                                error!("AWG: failed to send packet (spawn fallback): {e:#}");
                                            }
                                        });
                                        self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                                        return Ok(PacketDecision::Drop);
                                    }
                                } else {
                                    debug!(
                                        "AdaptiveRouter decided Proxy: routing UDP/QUIC packet to {}:{} via Userspace AmneziaWG (legacy spawn)",
                                        cp.dst_ip, cp.dst_port
                                    );
                                    let awg_clone = Arc::clone(awg);
                                    let data_copy = captured.data.clone();
                                    crate::Runtime::global().io.spawn(async move {
                                        if let Err(e) = awg_clone.send_ip_packet(data_copy).await {
                                            error!("AWG: failed to send packet: {e:#}");
                                        }
                                    });
                                    self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                                    return Ok(PacketDecision::Drop);
                                }
                            }

                            // Drop UDP/QUIC to force TCP fallback if AWG is not enabled/active
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
                        let modified = crate::proxy::rewrite::rewrite_dst_addr_cow(
                            captured.data.clone(),
                            localhost,
                            17650,
                            &self.stats,
                        )?;
                        self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                        return Ok(PacketDecision::Modify(modified));
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

                let payload = match captured.data.get(cp.payload_offset..) {
                    Some(p) => p,
                    None => return Ok(PacketDecision::Forward),
                };
                let should_desync = if Classifier::is_client_hello(payload) && payload.len() >= 50 {
                    self.conntrack.check_and_apply_desync(conn_key, || {
                        let fk = crate::conntrack::FlowKey::new_bidirectional(
                            cp.src_ip,
                            cp.dst_ip,
                            cp.src_port,
                            cp.dst_port,
                            cp.protocol,
                        );
                        crate::conntrack::compute_conn_id(&fk)
                    })
                } else {
                    match self.tls_reassembler.observe(conn_key, payload).0 {
                        crate::tls_reassembly::ReassemblyState::Complete => {
                            self.conntrack.check_and_apply_desync(conn_key, || {
                                let fk = crate::conntrack::FlowKey::new_bidirectional(
                                    cp.src_ip,
                                    cp.dst_ip,
                                    cp.src_port,
                                    cp.dst_port,
                                    cp.protocol,
                                );
                                crate::conntrack::compute_conn_id(&fk)
                            })
                        }
                        crate::tls_reassembly::ReassemblyState::NeedMore => {
                            return Ok(PacketDecision::Forward)
                        }
                        crate::tls_reassembly::ReassemblyState::NotTls => {
                            return Ok(PacketDecision::Forward)
                        }
                        crate::tls_reassembly::ReassemblyState::TooLarge => {
                            return Ok(PacketDecision::Forward)
                        }
                    }
                };

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
            let modified = crate::proxy::rewrite::rewrite_dst_addr_cow(
                captured.data.clone(),
                localhost,
                17650,
                &self.stats,
            )?;
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return Ok(PacketDecision::Modify(modified));
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

        // 0. Skip retransmits — P1-16: atomic check-and-mark
        {
            if let Some(ip) = crate::desync::parse_ip_header(original_packet) {
                let tcp_data = &original_packet[ip.header_len()..];
                if let Some(tcp) = pnet_packet::tcp::TcpPacket::new(tcp_data) {
                    let fk = crate::conntrack::FlowKey::new_bidirectional(
                        cp.src_ip,
                        cp.dst_ip,
                        cp.src_port,
                        cp.dst_port,
                        cp.protocol,
                    );
                    let conn_id = crate::conntrack::compute_conn_id(&fk);
                    let key = (conn_id, tcp.get_sequence());
                    // P1-16: DashMap entry API — атомарный check-and-mark.
                    // Только первый поток, вставивший key, проходит дальше.
                    // Если desync не сработает (no inject), запись останется
                    // в таблице и будет очищена periodic sweep — это лучше,
                    // чем TOCTOU double injection.
                    use dashmap::mapref::entry::Entry;
                    match self.injected_seqs.entry(key) {
                        Entry::Occupied(_) => return Ok(PacketDecision::Forward),
                        Entry::Vacant(entry) => {
                            entry.insert(Instant::now());
                        }
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
        let mut is_syn = false;
        let mut tcp_seq = 0;
        if let Some(ip) = crate::desync::parse_ip_header(original_packet) {
            let tcp_data = &original_packet[ip.header_len()..];
            if let Some(tcp) = pnet_packet::tcp::TcpPacket::new(tcp_data) {
                is_syn = (tcp.get_flags() & pnet_packet::tcp::TcpFlags::SYN) != 0;
                tcp_seq = tcp.get_sequence();
            }
        }
        {
            use crate::conntrack::{ConnState, ConntrackEntry};

            if self.conntrack.get(&conn_key).is_none() {
                let fk = crate::conntrack::FlowKey::new_bidirectional(
                    cp.src_ip,
                    cp.dst_ip,
                    cp.src_port,
                    cp.dst_port,
                    cp.protocol,
                );
                let conn_id = crate::conntrack::compute_conn_id(&fk);
                let entry = ConntrackEntry {
                    client_isn: if is_syn { tcp_seq } else { 0 },
                    server_isn: 0,
                    client_seq: if is_syn { tcp_seq } else { 0 },
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
                    applied_strategy: None,
                    route_key: domain.clone(),
                    quic_dropped_initials: 0,
                };
                self.conntrack.insert(conn_key, entry);
            } else {
                if let Some(mut entry) = self.conntrack.get_mut(&conn_key) {
                    entry.last_activity = Instant::now();
                    if is_syn && entry.client_isn == 0 {
                        entry.client_isn = tcp_seq;
                        entry.client_seq = tcp_seq;
                    }
                    if entry.route_key.is_none() {
                        entry.route_key = domain.clone();
                    }
                }
            }
        }

        // 4.5. T43: Определяем is_resumption по ClientHello и сохраняем в conntrack
        let tls_payload = if cp.payload_offset < captured.data.len() {
            Some(&captured.data[cp.payload_offset..])
        } else {
            None
        };
        let is_resumption = if let Some(payload) = tls_payload {
            has_non_empty_session_ticket(payload)
        } else {
            false
        };
        let ch_shape = if let Some(payload) = tls_payload {
            crate::desync::tls::parse_client_hello_shape(payload)
        } else {
            None
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
        let auto_tune_override = self.auto_tune.recommend_by_id(profile.id);
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
            ch_shape,
        );

        // P0-07: сохраняем имя стратегии в conntrack для record_outcome
        if !result.inject.is_empty() || result.modified.is_some() {
            if let Some(mut entry) = self.conntrack.get_mut(&conn_key) {
                if entry.applied_strategy.is_none() {
                    entry.applied_strategy = Some(profile.name.clone());
                }
            }
        }

        // 5.0. AutoTune — P0-07: только record_application (локальная генерация, не исход)
        {
            let latency_us = tune_start.elapsed().as_micros() as u64;
            self.auto_tune.record_application_by_id(profile.id);
            if self.auto_tune.should_escalate(&profile.name) {
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
                    let fk = crate::conntrack::FlowKey::new_bidirectional(
                        cp.src_ip,
                        cp.dst_ip,
                        cp.src_port,
                        cp.dst_port,
                        cp.protocol,
                    );
                    let conn_id = crate::conntrack::compute_conn_id(&fk);
                    let key = (conn_id, tcp.get_sequence());
                    // P1-16: ключ уже вставлен на check-этапе (step 0).
                    // Этот or_insert — no-op (защита на случай рефакторинга).
                    self.injected_seqs.entry(key).or_insert(Instant::now());
                }
            }
        }

        if result.inject.is_empty() && result.modified.is_none() {
            if result.drop {
                return Ok(PacketDecision::Drop);
            } else {
                return Ok(PacketDecision::Forward);
            }
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
                inject_direction: result.inject_direction,
                drop_original: result.drop,
            });
        }

        Ok(PacketDecision::Desync {
            inject: result.inject,
            modified: None,
            inject_protocol: InjectProtocol::Tcp,
            inter_delay_us: inter_delay,
            inject_direction: result.inject_direction,
            drop_original: result.drop,
        })
    }

    fn process_quic_sync(
        &self,
        captured: &CapturedPacket,
        cp: &crate::classifier::ClassifiedPacket,
    ) -> Result<PacketDecision, anyhow::Error> {
        let packet = captured.data.clone();

        // Conntrack: извлекаем QUIC DCID для conntrack
        {
            use crate::conntrack::{ConnState, ConntrackEntry};
            use crate::desync::quic::extract_quic_dcid_from_long_header;

            if self.conntrack.get(&cp.conn_key).is_none() {
                let fk = crate::conntrack::FlowKey::new_bidirectional(
                    cp.src_ip,
                    cp.dst_ip,
                    cp.src_port,
                    cp.dst_port,
                    cp.protocol,
                );
                let conn_id = crate::conntrack::compute_conn_id(&fk);
                let quic_dcid = if cp.payload_offset < packet.len() {
                    extract_quic_dcid_from_long_header(&packet[cp.payload_offset..]).unwrap_or_default()
                } else {
                    vec![]
                };
                let quic_pn = 0; // P3-02/P3-06: QUIC PN parsing is quarantined
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
                    applied_strategy: None,
                    route_key: self.fake_ip.lookup(&cp.dst_ip),
                    quic_dropped_initials: 0,
                };
                self.conntrack.insert(cp.conn_key, entry);
            } else {
                if let Some(mut entry) = self.conntrack.get_mut(&cp.conn_key) {
                    entry.last_activity = std::time::Instant::now();
                    // QUIC PN parsing is quarantined (P3-02/P3-06)
                    if entry.route_key.is_none() {
                        entry.route_key = self.fake_ip.lookup(&cp.dst_ip);
                    }
                }
            }
        }

        // T55: резолвим активный профиль для QUIC.
        let profile = self.resolve_active_profile(StrategyCategory::Quic);

        // T43: QUIC не использует is_resumption — передаём None
        let tune_start = Instant::now();
        let auto_tune_override = self.auto_tune.recommend_by_id(profile.id);
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
            None,
        );

        {
            let latency_us = tune_start.elapsed().as_micros() as u64;
            self.auto_tune.record_application_by_id(profile.id);
            if self.auto_tune.should_escalate(&profile.name) {
                warn!(
                    "AutoTune: '{}' strategy degrading (latency={}us)",
                    profile.name, latency_us
                );
            }
        }
        if result.inject.is_empty() && result.modified.is_none() {
            if result.drop {
                return Ok(PacketDecision::Drop);
            } else {
                return Ok(PacketDecision::Forward);
            }
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
                inject_direction: result.inject_direction,
                drop_original: result.drop,
            });
        }
        Ok(PacketDecision::Desync {
            inject: result.inject,
            modified: None,
            inject_protocol: InjectProtocol::Udp,
            inter_delay_us: inter_delay,
            inject_direction: result.inject_direction,
            drop_original: result.drop,
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
        let auto_tune_override = self.auto_tune.recommend_by_id(profile.id);
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
            None,
        );

        {
            let latency_us = tune_start.elapsed().as_micros() as u64;
            self.auto_tune.record_application_by_id(profile.id);
            if self.auto_tune.should_escalate(&profile.name) {
                warn!(
                    "AutoTune: '{}' strategy degrading (latency={}us)",
                    profile.name, latency_us
                );
            }
        }
        if result.inject.is_empty() && result.modified.is_none() {
            if result.drop {
                return Ok(PacketDecision::Drop);
            } else {
                return Ok(PacketDecision::Forward);
            }
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
                inject_direction: result.inject_direction,
                drop_original: result.drop,
            });
        }
        Ok(PacketDecision::Desync {
            inject: result.inject,
            modified: None,
            inject_protocol: InjectProtocol::Tcp,
            inter_delay_us: inter_delay,
            inject_direction: result.inject_direction,
            drop_original: result.drop,
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
                let auto_tune_override = self.auto_tune.recommend_by_id(profile.id);
                let tune_params = profile.merged_params(&auto_tune_override);

                let result = self.apply_desync_sync(
                    &profile.desync_group,
                    captured.data.clone(),
                    None,
                    Some(tune_params),
                    None,
                    None,
                    None,
                );

                let latency_us = tune_start.elapsed().as_micros() as u64;
                self.auto_tune.record_application_by_id(profile.id);

                if result.inject.is_empty() && result.modified.is_none() {
                    if result.drop {
                        return Ok(PacketDecision::Drop);
                    }
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
                        inject_direction: result.inject_direction,
                        drop_original: result.drop,
                    });
                }
                if !result.inject.is_empty() {
                    return Ok(PacketDecision::Desync {
                        inject: result.inject,
                        modified: None,
                        inject_protocol: InjectProtocol::Tcp,
                        inter_delay_us: result.inter_delay_us,
                        inject_direction: result.inject_direction,
                        drop_original: result.drop,
                    });
                }
            }
        } else if mss_clamp_active {
            // Применяем MSS clamp + PktReorder
            let profile = self.profile_registry.get("tcp_mss_clamp");
            if let Some(profile) = profile {
                let tune_start = Instant::now();
                let auto_tune_override = self.auto_tune.recommend_by_id(profile.id);
                let tune_params = profile.merged_params(&auto_tune_override);

                let result = self.apply_desync_sync(
                    &profile.desync_group,
                    captured.data.clone(),
                    None,
                    Some(tune_params),
                    None,
                    None,
                    None,
                );

                let latency_us = tune_start.elapsed().as_micros() as u64;
                self.auto_tune.record_application_by_id(profile.id);

                if result.inject.is_empty() && result.modified.is_none() {
                    if result.drop {
                        return Ok(PacketDecision::Drop);
                    }
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
                        inject_direction: result.inject_direction,
                        drop_original: result.drop,
                    });
                }
                if !result.inject.is_empty() {
                    return Ok(PacketDecision::Desync {
                        inject: result.inject,
                        modified: None,
                        inject_protocol: InjectProtocol::Tcp,
                        inter_delay_us: result.inter_delay_us,
                        inject_direction: result.inject_direction,
                        drop_original: result.drop,
                    });
                }
            }
        }

        Ok(PacketDecision::Forward)
    }

    /// T57: Проверяет — активирован ли профиль (через probe recommendation или manual override).
    fn is_profile_activated(&self, profile_name: &str) -> bool {
        self.auto_tune.is_strategy_active(profile_name)
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
            let modified = crate::proxy::rewrite::rewrite_dst_addr_cow(
                captured.data.clone(),
                localhost,
                17650, // REDIRECTOR_PORT
                &self.stats,
            )?;

            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return Ok(PacketDecision::Modify(modified));
        }

        Ok(PacketDecision::Forward)
    }



    pub fn has_divert(&self) -> bool {
        self.packet_engine.has_divert()
    }

    /// Получает рекомендованные AutoTune параметры для стратегии.
    pub fn get_tuned_config(&self, strategy_name: &str) -> TuneParams {
        self.auto_tune.recommend(strategy_name)
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
pub struct CapturedPacket {
    pub data: bytes::Bytes,
    pub addr: WinDivertAddress<NetworkLayer>,
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

fn is_quic_initial_check(payload: &[u8]) -> bool {
    payload.len() >= 5
        && (payload[0] & 0x80) != 0
        && (payload[0] & 0x40) != 0
        && (payload[0] & 0x30) == 0x00
        && payload[1..5] != [0, 0, 0, 0]
}

impl Default for ProcessingPipeline {
    fn default() -> Self {
        Self::new_api_only(ProcessingConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn awg_state_is_shared_not_unwrapped() {
        let state =
            std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(None::<std::sync::Arc<()>>));
        let cloned = state.clone();
        assert_eq!(std::sync::Arc::strong_count(&state), 2);
        drop(cloned);
        assert_eq!(std::sync::Arc::strong_count(&state), 1);
    }

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
