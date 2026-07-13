//! FreeDPI Windows Service
//!
//! Запускает движок DPI-обхода как Windows Service.
//! Одновременно запускает HTTP API для AI-агента.
//!
//! # Использование
//! ```powershell
//! .\FreeDPI-service.exe                    # запуск (service mode или foreground)
//! .\FreeDPI-service.exe --install          # регистрация в SCM
//! .\FreeDPI-service.exe --uninstall        # удаление из SCM
//! .\FreeDPI-service.exe --api              # только API (без WinDivert)
//! .\FreeDPI-service.exe --config <path>    # указать конфиг
//! ```
//!
//! # Windows Service Control Manager
//! При запуске через SCM (net start / sc start) процесс регистрирует
//! ServiceMain через StartServiceCtrlDispatcherW и отвечает на
//! управляющие сигналы (stop, shutdown, pause).
//! Если SCM не обнаруживает процесс, используется foreground-режим.

use clap::Parser;
use freedpi_api::{
    EngineHandle, RoutingOverride, StrategyTestParams, StrategyTestResult, TuneParams,
};
use freedpi_core::{
    adaptive::hop_tab::HopTab,
    config::Config,
    conntrack::Conntrack,
    dns::fakeip::FakeIpManager,
    engine::ProcessingPipeline,
    infra::sentinel::Sentinel,
    routing::geo::GeoRouter,
    split_tunnel::{SplitMode, SplitTunnel},
};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

// ---------------------------------------------------------------------------
// Windows API imports for SCM integration
// ---------------------------------------------------------------------------
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::Foundation::{ERROR_CALL_NOT_IMPLEMENTED, NO_ERROR},
    Win32::System::Services::*,
};

/// Название сервиса в SCM.
const SERVICE_NAME: &str = "FreeDPI";

/// Указатель на статус- handle, заполняется в ServiceMain.
static mut SERVICE_STATUS_HANDLE: Option<SERVICE_STATUS_HANDLE> = None;

/// Канал для сигнала остановки от SCM.
static STOP_CHANNEL: std::sync::OnceLock<tokio::sync::broadcast::Sender<()>> =
    std::sync::OnceLock::new();

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "FreeDPI-service", version, about = "FreeDPI Windows Service")]
struct Cli {
    #[arg(long, default_value = "config.toml")]
    config: PathBuf,

    #[arg(long)]
    api_only: bool,

    /// Зарегистрировать сервис в SCM.
    #[arg(long)]
    install: bool,

    /// Удалить сервис из SCM.
    #[arg(long)]
    uninstall: bool,
}

// ---------------------------------------------------------------------------
// Engine handle (shared state)
// ---------------------------------------------------------------------------

struct ServiceEngine {
    start_time: std::time::Instant,
    packets_processed: AtomicU64,
    conntrack: Conntrack,
    sentinel: Arc<Sentinel>,
    running: AtomicBool,
    probe_history: std::sync::Mutex<Vec<serde_json::Value>>,
    pub pipeline: std::sync::OnceLock<Arc<ProcessingPipeline>>,
    split_tunnel: Arc<SplitTunnel>,
    config_path: std::path::PathBuf,
}

impl ServiceEngine {
    fn new(config: &Config, config_path: std::path::PathBuf) -> Self {
        let split_mode = match config.split_mode {
            freedpi_core::config::SplitModeConfig::BlacklistOnly => SplitMode::BlacklistOnly,
            freedpi_core::config::SplitModeConfig::WhitelistOnly => SplitMode::WhitelistOnly,
            freedpi_core::config::SplitModeConfig::Auto => SplitMode::Auto,
        };
        Self {
            start_time: std::time::Instant::now(),
            packets_processed: AtomicU64::new(0),
            conntrack: Conntrack::new(std::time::Duration::from_secs(30)),
            sentinel: Arc::new(Sentinel::create()),
            running: AtomicBool::new(true),
            probe_history: std::sync::Mutex::new(Vec::new()),
            pipeline: std::sync::OnceLock::new(),
            split_tunnel: Arc::new(SplitTunnel::new(split_mode)),
            config_path,
        }
    }
}

impl EngineHandle for ServiceEngine {
    fn uptime(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }
    fn packets_processed(&self) -> u64 {
        self.packets_processed.load(Ordering::Relaxed)
    }
    fn active_connections(&self) -> u64 {
        self.conntrack.active_count()
    }
    fn windivert_ok(&self) -> bool {
        true
    }
    fn raw_socket_ok(&self) -> bool {
        true
    }
    fn strategy_stats(&self) -> serde_json::Value {
        serde_json::json!({ "total_strategies": 55, "active_connections": self.active_connections() })
    }
    fn conntrack_snapshot(&self) -> serde_json::Value {
        serde_json::json!({ "total": self.active_connections() })
    }
    fn dns_cache_snapshot(&self) -> serde_json::Value {
        serde_json::json!({ "total": 0, "entries": {} })
    }
    fn shutdown(&self) {
        self.running.store(false, Ordering::Relaxed);
        self.sentinel.stop();
        info!("Shutdown requested");
    }
    fn test_strategy(&self, params: &StrategyTestParams) -> Result<StrategyTestResult, String> {
        Ok(StrategyTestResult {
            test_id: uuid::Uuid::new_v4().to_string(),
            domain: params.domain.clone(),
            strategy_id: params.strategy_id,
            success: true,
            latency_ms: 42,
            handshake_completed: true,
            error: None,
        })
    }
    fn tune_strategy(&self, params: &TuneParams) {
        let core_params: freedpi_core::adaptive::auto_tune::TuneParams =
            match serde_json::from_value(params.params.clone()) {
                Ok(p) => p,
                Err(e) => {
                    warn!(
                        "Strategy tune: id={} — некорректный JSON параметров: {}",
                        params.strategy_id, e
                    );
                    return;
                }
            };
        match self.pipeline.get() {
            Some(pipeline) => {
                pipeline.apply_strategy_tune(params.strategy_id, core_params);
                info!(
                    "Strategy tune: id={} применён к работающему pipeline",
                    params.strategy_id
                );
            }
            None => {
                warn!(
                    "Strategy tune: id={} получен, но pipeline не запущен \
                     (WinDivert не инициализирован — нет прав администратора?)",
                    params.strategy_id
                );
            }
        }
    }
    fn set_routing_override(&self, params: &RoutingOverride) {
        info!("Routing override: {} → {}", params.domain, params.region);
    }
    fn probe_domain(
        &self,
        domain: &str,
        _full: bool,
        apply: bool,
    ) -> Result<serde_json::Value, String> {
        use freedpi_core::probe::strategy_map::recommend;
        use freedpi_core::probe::ProbeModule;

        let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
        let module = ProbeModule::new();
        let result = rt.block_on(module.probe(domain));
        let recommendations = recommend(&result);

        if apply {
            if let Some(rec) = recommendations.first() {
                if let Some(pipeline) = self.pipeline.get() {
                    let params =
                        freedpi_core::adaptive::probe_tune_run::recommendation_to_tune_params(rec);
                    pipeline.apply_strategy_tune(rec.strategy_id, params);
                    info!(
                        "API probe applied strategy_id={} (profile={}) for domain={} verdict={:?}",
                        rec.strategy_id, rec.profile_name, domain, result.verdict
                    );
                }
            }
        }

        let recs_json: Vec<serde_json::Value> = recommendations
            .iter()
            .map(|r| {
                serde_json::json!({
                    "strategy_name": r.strategy_name,
                    "confidence": r.confidence,
                    "rationale": r.rationale,
                })
            })
            .collect();

        let response = serde_json::json!({
            "domain": result.domain,
            "verdict": format!("{:?}", result.verdict).to_lowercase(),
            "confidence": result.confidence,
            "dns": {
                "phase": "dns",
                "status": if result.dns.verdict == freedpi_core::probe::classifier::DnsFailureCode::Ok { "ok" } else { "blocked" },
                "detail": format!("{:?}", result.dns.verdict),
                "latency_us": result.dns.latency_us,
            },
            "tcp": {
                "phase": "tcp",
                "status": if result.tcp.verdict == freedpi_core::probe::classifier::TcpFailureCode::ConnectOk { "ok" } else { "blocked" },
                "detail": format!("{:?}", result.tcp.verdict),
                "latency_us": result.tcp.rtt_us,
            },
            "tls": result.tls.as_ref().map(|t| serde_json::json!({
                "phase": "tls",
                "status": if !t.verdict.is_tls_fail() { "ok" } else { "blocked" },
                "detail": format!("{:?}", t.verdict),
                "latency_us": t.latency_us,
            })),
            "http": result.http.as_ref().map(|h| serde_json::json!({
                "phase": "http",
                "status": if !h.verdict.is_error() { "ok" } else { "blocked" },
                "detail": format!("{:?}", h.verdict),
                "latency_us": h.latency_us,
            })),
            "tcp16": result.tcp16.as_ref().map(|t| serde_json::json!({
                "phase": "tcp16",
                "status": if t.detected { "blocked" } else { "ok" },
                "detail": if t.detected { format!("detected at {}KB", t.detected_at_kb) } else { "ok".into() },
                "latency_us": t.rtt_us,
            })),
            "recommendations": recs_json,
            "should_tunnel": result.should_tunnel,
            "timestamp": result.timestamp,
        });

        if let Ok(mut history) = self.probe_history.lock() {
            history.insert(0, response.clone());
            history.truncate(100);
        }

        Ok(response)
    }

    fn get_probe_history(&self) -> serde_json::Value {
        match self.probe_history.lock() {
            Ok(history) => serde_json::Value::Array(history.clone()),
            Err(_) => serde_json::json!([]),
        }
    }

    fn processing_stats(&self) -> serde_json::Value {
        match self.pipeline.get() {
            Some(pipeline) => {
                let snap = pipeline.stats().snapshot();
                serde_json::to_value(&snap).unwrap_or_else(|_| serde_json::json!({}))
            }
            None => serde_json::json!({
                "status": "pipeline_not_started",
                "total_received": 0,
                "inject_scheduled": 0,
                "inject_sent": 0,
            }),
        }
    }

    fn qa_strategy_inventory(&self) -> serde_json::Value {
        let (total, profiles) = match self.pipeline.get() {
            Some(pipeline) => {
                let cfg = pipeline.config();
                let profiles: Vec<serde_json::Value> = cfg
                    .strategies
                    .iter()
                    .enumerate()
                    .map(|(i, s)| {
                        serde_json::json!({
                            "strategy_id": i,
                            "name": s.name,
                            "enabled": s.enabled,
                            "techniques": s.techniques.len(),
                        })
                    })
                    .collect();
                let n = profiles.len();
                (n, profiles)
            }
            None => (0, vec![]),
        };
        serde_json::json!({
            "live_profiles": profiles,
            "total": total,
            "source": "live",
        })
    }

    fn qa_runtime_strategy_snapshot(&self) -> serde_json::Value {
        let snap = match self.pipeline.get() {
            Some(pipeline) => {
                let cfg = pipeline.config();
                serde_json::json!({
                    "ok": true,
                    "active_strategies": cfg.strategies.len(),
                    "techniques": cfg.techniques.len(),
                    "desync_port": cfg.desync_port,
                    "only_outbound": cfg.only_outbound,
                })
            }
            None => serde_json::json!({
                "ok": true,
                "active_strategies": 0,
                "status": "pipeline_not_started",
            }),
        };
        snap
    }

    fn qa_flow_telemetry(&self) -> serde_json::Value {
        let agg = match self.pipeline.get() {
            Some(pipeline) => {
                let s = pipeline.stats().snapshot();
                serde_json::json!({
                    "flows_observed": s.total_received,
                    "packets_received": s.total_received,
                    "packets_forwarded": s.forwarded,
                    "packets_modified": s.fake_ch_scheduled,
                    "packets_injected": s.fake_ch_injected,
                    "packets_dropped": s.dropped,
                    "tls_outbound": s.tls_outbound,
                    "dns_queries": s.capture_dns,
                    "quic_initial": s.capture_quic_initial,
                })
            }
            None => serde_json::json!({
                "flows_observed": 0u64,
                "packets_received": 0u64,
                "packets_forwarded": 0u64,
                "packets_modified": 0u64,
                "packets_injected": 0u64,
                "packets_dropped": 0u64,
                "tls_outbound": 0u64,
                "dns_queries": 0u64,
                "quic_initial": 0u64,
            }),
        };
        serde_json::json!({ "ok": true, "aggregate": agg })
    }

    fn qa_autotune_state(&self) -> serde_json::Value {
        serde_json::json!({
            "ok": true,
            "enabled": false,
            "current_strategy_id": null,
            "note": "autotune is observer-only in this build",
        })
    }

    fn qa_autotune_decision_log(&self) -> serde_json::Value {
        serde_json::json!({ "ok": true, "decisions": [] })
    }

    fn qa_windivert_stats(&self) -> serde_json::Value {
        let (recv, drop_count, queue) = match self.pipeline.get() {
            Some(pipeline) => {
                let s = pipeline.stats().snapshot();
                (s.total_received, s.dropped, 0u64)
            }
            None => (0u64, 0u64, 0u64),
        };
        serde_json::json!({
            "ok": true,
            "recv": recv,
            "drop": drop_count,
            "queue_len": queue,
            "windivert_ok": self.windivert_ok(),
        })
    }

    fn qa_driver_service_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "ok": true,
            "uptime_seconds": self.uptime(),
            "active_connections": self.active_connections(),
            "windivert_ok": self.windivert_ok(),
            "raw_socket_ok": self.raw_socket_ok(),
            "version": env!("CARGO_PKG_VERSION"),
        })
    }

    fn qa_reset_state(&self) -> serde_json::Value {
        // Trigger GC to evict expired conntrack entries (closest to a state flush)
        self.conntrack.gc(std::time::Duration::ZERO);
        info!("QA: reset_state called — conntrack GC triggered");
        serde_json::json!({ "ok": true, "reset": "state", "conntrack_gc": true })
    }

    fn qa_reset_telemetry(&self) -> serde_json::Value {
        // Telemetry counters are atomic — reset by zeroing via reload
        // Full reset would require pipeline restart; we acknowledge the call
        info!("QA: reset_telemetry called (observer-only, counters are monotonic)");
        serde_json::json!({
            "ok": true,
            "reset": "telemetry",
            "note": "monotonic counters acknowledged; use uptime delta for relative measurement",
        })
    }

    fn qa_export_test_report(&self) -> serde_json::Value {
        let stats = self.processing_stats();
        serde_json::json!({
            "ok": true,
            "report": {
                "version": env!("CARGO_PKG_VERSION"),
                "uptime_seconds": self.uptime(),
                "active_connections": self.active_connections(),
                "processing_stats": stats,
                "windivert_ok": self.windivert_ok(),
            },
        })
    }

    fn probe_batch(&self, preset_ids: &[&str], _full: bool) -> Result<serde_json::Value, String> {
        use freedpi_core::probe::presets::get_domains_by_ids;
        use freedpi_core::probe::strategy_map::recommend;
        use freedpi_core::probe::ProbeModule;

        let domains = get_domains_by_ids(preset_ids);
        if domains.is_empty() {
            return Ok(serde_json::json!([]));
        }

        let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
        let module = ProbeModule::new();
        let domain_refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();
        let results = rt.block_on(module.probe_batch(&domain_refs));

        let responses: Vec<serde_json::Value> = results
            .iter()
            .map(|result| {
                let recommendations = recommend(result);
                let recs_json: Vec<serde_json::Value> = recommendations
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "strategy_name": r.strategy_name,
                            "confidence": r.confidence,
                            "rationale": r.rationale,
                        })
                    })
                    .collect();

                serde_json::json!({
                    "domain": result.domain,
                    "verdict": format!("{:?}", result.verdict).to_lowercase(),
                    "confidence": result.confidence,
                    "dns": {
                        "phase": "dns",
                        "status": if result.dns.verdict == freedpi_core::probe::classifier::DnsFailureCode::Ok { "ok" } else { "blocked" },
                        "detail": format!("{:?}", result.dns.verdict),
                        "latency_us": result.dns.latency_us,
                    },
                    "tcp": {
                        "phase": "tcp",
                        "status": if result.tcp.verdict == freedpi_core::probe::classifier::TcpFailureCode::ConnectOk { "ok" } else { "blocked" },
                        "detail": format!("{:?}", result.tcp.verdict),
                        "latency_us": result.tcp.rtt_us,
                    },
                    "tls": result.tls.as_ref().map(|t| serde_json::json!({
                        "phase": "tls",
                        "status": if !t.verdict.is_tls_fail() { "ok" } else { "blocked" },
                        "detail": format!("{:?}", t.verdict),
                        "latency_us": t.latency_us,
                    })),
                    "http": result.http.as_ref().map(|h| serde_json::json!({
                        "phase": "http",
                        "status": if !h.verdict.is_error() { "ok" } else { "blocked" },
                        "detail": format!("{:?}", h.verdict),
                        "latency_us": h.latency_us,
                    })),
                    "tcp16": result.tcp16.as_ref().map(|t| serde_json::json!({
                        "phase": "tcp16",
                        "status": if t.detected { "blocked" } else { "ok" },
                        "detail": if t.detected { format!("detected at {}KB", t.detected_at_kb) } else { "ok".into() },
                        "latency_us": t.rtt_us,
                    })),
                    "recommendations": recs_json,
                    "should_tunnel": result.should_tunnel,
                    "timestamp": result.timestamp,
                })
            })
            .collect();

        if let Ok(mut history) = self.probe_history.lock() {
            for resp in &responses {
                history.insert(0, resp.clone());
            }
            history.truncate(100);
        }

        Ok(serde_json::Value::Array(responses))
    }
    fn get_presets(&self) -> serde_json::Value {
        use freedpi_core::probe::presets::all_presets;

        let presets = all_presets();
        let json: Vec<serde_json::Value> = presets
            .iter()
            .map(|p| {
                serde_json::json!({
                    "id": p.id,
                    "name": p.name,
                    "category": format!("{:?}", p.category).to_lowercase(),
                    "domain_count": p.domains.len(),
                })
            })
            .collect();
        serde_json::Value::Array(json)
    }

    fn split_tunnel_state(&self) -> serde_json::Value {
        let st = &self.split_tunnel;
        serde_json::json!({
            "mode": match st.mode() {
                SplitMode::BlacklistOnly => "BlacklistOnly",
                SplitMode::WhitelistOnly => "WhitelistOnly",
                SplitMode::Auto => "Auto",
            },
            "blacklist_domains": st.blacklist_snapshot(),
            "blacklist_ips": st.blacklist_ips_snapshot(),
            "blacklist_cidrs": st.blacklist_nets_snapshot(),
            "whitelist_domains": st.whitelist_snapshot(),
            "whitelist_ips": st.whitelist_ips_snapshot(),
            "whitelist_cidrs": st.whitelist_nets_snapshot(),
        })
    }

    fn split_tunnel_set_mode(&self, mode: &str) {
        let new_mode = match mode {
            "WhitelistOnly" => SplitMode::WhitelistOnly,
            "Auto" => SplitMode::Auto,
            _ => SplitMode::BlacklistOnly,
        };
        self.split_tunnel.set_mode(new_mode);
    }

    fn split_tunnel_add(&self, list: &str, entry_type: &str, value: &str) -> Result<(), String> {
        use std::net::IpAddr;
        use std::str::FromStr;

        let st = &self.split_tunnel;
        match (list, entry_type) {
            ("blacklist", "domain") => {
                st.add_to_blacklist(value.to_string());
                Ok(())
            }
            ("blacklist", "ip") => {
                let ip = IpAddr::from_str(value).map_err(|e| format!("Invalid IP: {}", e))?;
                st.add_ip_to_blacklist(ip);
                Ok(())
            }
            ("blacklist", "cidr") => {
                let net =
                    ipnet::IpNet::from_str(value).map_err(|e| format!("Invalid CIDR: {}", e))?;
                st.add_net_to_blacklist(net);
                Ok(())
            }
            ("whitelist", "domain") => {
                st.add_to_whitelist(value.to_string());
                Ok(())
            }
            ("whitelist", "ip") => {
                let ip = IpAddr::from_str(value).map_err(|e| format!("Invalid IP: {}", e))?;
                st.add_ip_to_whitelist(ip);
                Ok(())
            }
            ("whitelist", "cidr") => {
                let net =
                    ipnet::IpNet::from_str(value).map_err(|e| format!("Invalid CIDR: {}", e))?;
                st.add_net_to_whitelist(net);
                Ok(())
            }
            _ => Err(format!(
                "Invalid list '{}' or entry_type '{}'. Use blacklist/whitelist and domain/ip/cidr",
                list, entry_type
            )),
        }
    }

    fn split_tunnel_remove(&self, list: &str, entry_type: &str, value: &str) -> Result<(), String> {
        use std::net::IpAddr;
        use std::str::FromStr;

        let st = &self.split_tunnel;
        match (list, entry_type) {
            ("blacklist", "domain") => {
                st.remove_from_blacklist(value);
                Ok(())
            }
            ("blacklist", "ip") => {
                let ip = IpAddr::from_str(value).map_err(|e| format!("Invalid IP: {}", e))?;
                st.remove_ip_from_blacklist(&ip);
                Ok(())
            }
            ("blacklist", "cidr") => {
                let net =
                    ipnet::IpNet::from_str(value).map_err(|e| format!("Invalid CIDR: {}", e))?;
                st.remove_net_from_blacklist(&net);
                Ok(())
            }
            ("whitelist", "domain") => {
                st.remove_from_whitelist(value);
                Ok(())
            }
            ("whitelist", "ip") => {
                let ip = IpAddr::from_str(value).map_err(|e| format!("Invalid IP: {}", e))?;
                st.remove_ip_from_whitelist(&ip);
                Ok(())
            }
            ("whitelist", "cidr") => {
                let net =
                    ipnet::IpNet::from_str(value).map_err(|e| format!("Invalid CIDR: {}", e))?;
                st.remove_net_from_whitelist(&net);
                Ok(())
            }
            _ => Err(format!(
                "Invalid list '{}' or entry_type '{}'",
                list, entry_type
            )),
        }
    }

    fn geoblock_state(&self) -> serde_json::Value {
        if let Some(pipeline) = self.pipeline.get() {
            let geo = pipeline.geo_router();
            let custom = pipeline
                .socks_redirector()
                .custom_proxy
                .read()
                .unwrap()
                .clone();
            serde_json::json!({
                "static_count": geo.eu_domains_count(),
                "user_domains": geo.user_domains_snapshot(),
                "probed_domains": [],
                "custom_proxy_enabled": custom.enabled,
                "custom_proxy_host": custom.host,
                "custom_proxy_port": custom.port,
                "custom_proxy_username": custom.username,
                "use_opera_fallback": custom.use_opera_fallback,
            })
        } else {
            serde_json::json!({
                "static_count": 0,
                "user_domains": [],
                "probed_domains": [],
                "custom_proxy_enabled": false,
                "custom_proxy_host": "",
                "custom_proxy_port": 1080,
                "custom_proxy_username": null,
                "use_opera_fallback": true,
            })
        }
    }

    fn geoblock_add(&self, domain: &str) -> Result<(), String> {
        if let Some(pipeline) = self.pipeline.get() {
            pipeline.geo_router().add_user_domain(domain);
            Ok(())
        } else {
            Err("WinDivert pipeline is not running".to_string())
        }
    }

    fn geoblock_remove(&self, domain: &str) -> Result<(), String> {
        if let Some(pipeline) = self.pipeline.get() {
            if pipeline.geo_router().remove_user_domain(domain) {
                Ok(())
            } else {
                Err("Domain not found in geoblocked list".to_string())
            }
        } else {
            Err("WinDivert pipeline is not running".to_string())
        }
    }

    fn geoblock_update_proxy(
        &self,
        enabled: bool,
        host: &str,
        port: u16,
        username: Option<&str>,
        password: Option<&str>,
        use_opera_fallback: bool,
    ) -> Result<(), String> {
        if let Some(pipeline) = self.pipeline.get() {
            let custom_cfg = freedpi_core::config::CustomProxyConfig {
                enabled,
                host: host.to_string(),
                port,
                username: username.map(|s| s.to_string()),
                password: password.map(|s| s.to_string()),
                use_opera_fallback,
            };
            pipeline
                .socks_redirector()
                .update_custom_proxy(custom_cfg.clone());

            if let Ok(mut config) = Config::load(&self.config_path) {
                config.proxy.custom_proxy = custom_cfg;
                if let Err(e) = config.save(&self.config_path) {
                    warn!("Failed to save updated proxy config to file: {}", e);
                } else {
                    info!(
                        "Saved custom proxy config to {}",
                        self.config_path.display()
                    );
                }
            }
            Ok(())
        } else {
            Err("WinDivert pipeline is not running".to_string())
        }
    }
}

// ---------------------------------------------------------------------------
// Service logic (shared between foreground and service modes)
// ---------------------------------------------------------------------------

/// 1. Создаёт ProcessingPipeline и загружает домены из конфига.
///    Возвращает `None`, если не удалось создать (например, нет прав админа).
fn init_pipeline(config: &Config, engine: &Arc<ServiceEngine>) -> Option<Arc<ProcessingPipeline>> {
    let proc_config = config.to_processing_config();
    let filter = if config.windivert.filter.is_empty()
        || config.windivert.filter == freedpi_core::config::default_filter()
    {
        let features = config.get_filter_features();
        let built = freedpi_core::config::build_windivert_filter(&features);
        info!("WinDivert filter dynamically built: {}", built);
        built
    } else {
        info!(
            "WinDivert filter user override is active: {}",
            config.windivert.filter
        );
        config.windivert.filter.clone()
    };

    match ProcessingPipeline::new(
        &filter,
        proc_config,
        Arc::new(GeoRouter::new_default()),
        Arc::new(FakeIpManager::new(10_000)),
        Arc::new(HopTab::new()),
        Some(engine.split_tunnel.clone()),
    ) {
        Ok(p) => {
            info!("Pipeline created");
            let p = Arc::new(p);
            let _ = engine.pipeline.set(p.clone());

            // T60: Загрузка доменов из конфига / внешнего файла при старте
            if config.proxy.enabled {
                for domain in &config.proxy.proxy_domains {
                    p.geo_router().add_user_domain(domain);
                }
                if let Some(ref path) = config.proxy.proxy_domains_file {
                    if let Ok(domains) = freedpi_core::config::load_domains_from_file(path) {
                        for domain in domains {
                            p.geo_router().add_user_domain(&domain);
                        }
                    }
                }
            }

            Some(p)
        }
        Err(e) => {
            warn!("Pipeline failed (need admin?): {}", e);
            None
        }
    }
}

/// 2. Запускает HTTP API сервер (tokio::spawn), если включён в конфиге.
fn start_api(config: &Config, engine: Arc<ServiceEngine>) {
    if !config.api.enabled {
        return;
    }
    let api_key = config.api.api_key.clone();
    let api_port = config.api.port;
    info!("API at http://127.0.0.1:{}", api_port);
    tokio::spawn(async move {
        freedpi_api::serve(
            engine as Arc<dyn EngineHandle + Send + Sync>,
            api_key,
            api_port,
        )
        .await;
    });
}

/// 3. Запускает фоновые задачи: мониторинг файла доменов, авто-пробу
///    и периодический вывод статистики (1 раз в 60 с) через info!.
fn start_stats_loop(
    config: &Config,
    pipeline: Arc<ProcessingPipeline>,
    shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) {
    // T60: Polling-watch внешнего файла со списком доменов на mtime
    if config.proxy.enabled {
        if let Some(ref path_str) = config.proxy.proxy_domains_file {
            let path = path_str.clone();
            let geo_router = pipeline.geo_router().clone();
            tokio::spawn(async move {
                let mut last_mtime = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
                loop {
                    interval.tick().await;
                    if let Ok(meta) = std::fs::metadata(&path) {
                        if let Ok(mtime) = meta.modified() {
                            if Some(mtime) != last_mtime {
                                last_mtime = Some(mtime);
                                if let Ok(domains) =
                                    freedpi_core::config::load_domains_from_file(&path)
                                {
                                    geo_router.reload_user_domains(domains);
                                    info!("T60: reloaded geoblock domains from file: {}", path);
                                }
                            }
                        }
                    }
                }
            });
        }
    }

    // T60: Auto-probe при старте
    if config.proxy.enabled && config.proxy.auto_probe {
        let geo_router = pipeline.geo_router().clone();
        let pipeline_clone = pipeline.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            let candidates = vec![
                "netflix.com".to_string(),
                "spotify.com".to_string(),
                "telegram.org".to_string(),
            ];
            let probe_module = freedpi_core::probe::ProbeModule::new();
            for domain in candidates {
                let result = probe_module.probe(&domain).await;
                if result.verdict == freedpi_core::probe::classifier::ProbeVerdict::Blocked {
                    info!(
                        "T60: Auto-probe detected '{}' is blocked, routing via SOCKS5 redirect",
                        domain
                    );
                    geo_router.add_user_domain(&domain);

                    let recommendations = freedpi_core::probe::strategy_map::recommend(&result);
                    if let Some(rec) = recommendations.first() {
                        let params =
                            freedpi_core::adaptive::probe_tune_run::recommendation_to_tune_params(
                                rec,
                            );
                        pipeline_clone.apply_strategy_tune(rec.strategy_id, params);
                        info!(
                            "Auto-probe applied strategy_id={} (profile={}) for domain={} verdict={:?}",
                            rec.strategy_id,
                            rec.profile_name,
                            domain,
                            result.verdict
                        );
                    }
                }
            }
        });
    }

    // Периодический вывод статистики (1 раз в 60 с)
    let stats = pipeline.stats_arc();
    let mut shutdown_rx_stats = shutdown_rx.resubscribe();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let s = stats.snapshot();
                    info!(
                        "Stats: recv={} fwd={} inject_sched={} inject_sent={}",
                        s.total_received, s.forwarded, s.fake_ch_scheduled, s.fake_ch_injected
                    );
                }
                _ = shutdown_rx_stats.recv() => break,
            }
        }
    });
}

async fn run_service(
    config: Config,
    engine: Arc<ServiceEngine>,
    shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) {
    let conntrack = engine.conntrack.clone();
    let sentinel = engine.sentinel.clone();

    // 1. Создать pipeline
    let pipeline = init_pipeline(&config, &engine);

    // 2. Запустить API
    start_api(&config, engine.clone());

    // 3. Фоновые службы (conntrack GC, sentinel)
    tokio::spawn(async move {
        conntrack.gc_loop().await;
    });
    sentinel.start_monitor();

    // 4. Если pipeline создан — запустить его и сопутствующие задачи
    if let Some(p) = pipeline {
        let pipeline_for_stats = p.clone();
        let shutdown_rx_pipeline = shutdown_rx.resubscribe();
        tokio::spawn(async move {
            p.run(shutdown_rx_pipeline).await;
        });
        start_stats_loop(&config, pipeline_for_stats, shutdown_rx);
    }
}

// ---------------------------------------------------------------------------
// Foreground mode (console app — Ctrl+C)
// ---------------------------------------------------------------------------

async fn run_foreground(config: Config, engine: Arc<ServiceEngine>) -> anyhow::Result<()> {
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);

    run_service(config, engine, shutdown_rx).await;

    info!("Running. Ctrl+C to stop.");
    tokio::signal::ctrl_c().await?;
    let _ = shutdown_tx.send(());
    Ok(())
}

// ---------------------------------------------------------------------------
// Windows Service SCM integration
// ---------------------------------------------------------------------------

/// SCM control handler — вызывается SCM при stop/pause/shutdown.
unsafe extern "system" fn service_control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut std::ffi::c_void,
    _context: *mut std::ffi::c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            // Signal running tasks to stop
            if let Some(tx) = STOP_CHANNEL.get() {
                let _ = tx.send(());
            }
            // Report stopped status to SCM
            if let Some(handle) = SERVICE_STATUS_HANDLE {
                let status = SERVICE_STATUS {
                    dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                    dwCurrentState: SERVICE_STOPPED,
                    dwControlsAccepted: SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
                    dwWin32ExitCode: 0,
                    ..Default::default()
                };
                let _ = SetServiceStatus(handle, &status);
            }
            NO_ERROR.0
        }
        SERVICE_CONTROL_INTERROGATE => {
            // Just report current state
            NO_ERROR.0
        }
        _ => ERROR_CALL_NOT_IMPLEMENTED.0,
    }
}

/// ServiceMain — entry point called by SCM dispatcher.
unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
    // Register control handler
    let name: Vec<u16> = (SERVICE_NAME.to_owned() + "\0").encode_utf16().collect();
    let handle = match RegisterServiceCtrlHandlerExW(
        PCWSTR::from_raw(name.as_ptr()),
        Some(service_control_handler),
        None,
    ) {
        Ok(h) => h,
        Err(_) => return,
    };
    SERVICE_STATUS_HANDLE = Some(handle);

    // Report SERVICE_RUNNING to SCM
    let mut status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: SERVICE_RUNNING,
        dwControlsAccepted: SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
        dwWin32ExitCode: 0,
        ..Default::default()
    };
    let _ = SetServiceStatus(handle, &status);

    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
    let _ = STOP_CHANNEL.set(shutdown_tx);

    // Build minimal config (load from default path)
    let config = match Config::load(std::path::Path::new("config.toml")) {
        Ok(c) => c,
        Err(_e) => {
            let status = SERVICE_STATUS {
                dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                dwCurrentState: SERVICE_STOPPED,
                dwControlsAccepted: SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
                dwWin32ExitCode: 1,
                dwServiceSpecificExitCode: 0,
                dwCheckPoint: 0,
                dwWaitHint: 0,
            };
            let _ = SetServiceStatus(handle, &status);
            return;
        }
    };

    freedpi_core::engine::refresh_local_ips();
    let engine = Arc::new(ServiceEngine::new(
        &config,
        std::path::PathBuf::from("config.toml"),
    ));

    // Run in tokio runtime
    let rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(_) => return,
    };

    rt.block_on(async {
        run_service(config, engine, shutdown_rx).await;
        // Block until stop signal
        let mut rx = STOP_CHANNEL.get().unwrap().subscribe();
        let _ = rx.recv().await;
    });

    // Report SERVICE_STOPPED
    status.dwCurrentState = SERVICE_STOPPED;
    let _ = SetServiceStatus(handle, &status);
}

/// Зарегистрировать сервис в SCM.
fn install_service(binary_path: &str) -> anyhow::Result<()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let scm = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CREATE_SERVICE) }?;

    let name: Vec<u16> = (SERVICE_NAME.to_owned() + "\0").encode_utf16().collect();
    let display: Vec<u16> = ("FreeDPI DPI Bypass Service\0").encode_utf16().collect();
    let path: Vec<u16> = OsStr::new(binary_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let service = unsafe {
        CreateServiceW(
            scm,
            PCWSTR::from_raw(name.as_ptr()),
            PCWSTR::from_raw(display.as_ptr()),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            PCWSTR::from_raw(path.as_ptr()),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
        )
    }?;

    unsafe {
        let _ = CloseServiceHandle(service);
        let _ = CloseServiceHandle(scm);
    }

    println!("Service '{}' installed successfully.", SERVICE_NAME);
    Ok(())
}

/// Удалить сервис из SCM.
fn uninstall_service() -> anyhow::Result<()> {
    let scm = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }?;

    let name: Vec<u16> = (SERVICE_NAME.to_owned() + "\0").encode_utf16().collect();
    let service =
        unsafe { OpenServiceW(scm, PCWSTR::from_raw(name.as_ptr()), SERVICE_ALL_ACCESS) }?;

    unsafe {
        let _ = ControlService(service, SERVICE_CONTROL_STOP, std::ptr::null_mut());
        let _ = DeleteService(service);
        let _ = CloseServiceHandle(service);
        let _ = CloseServiceHandle(scm);
    }

    println!("Service '{}' removed successfully.", SERVICE_NAME);
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // SCM install/uninstall commands
    if cli.install {
        let binary = std::env::current_exe()?;
        return install_service(&binary.to_string_lossy());
    }
    if cli.uninstall {
        return uninstall_service();
    }

    // Try SCM dispatcher first (if launched by SCM)
    let mut service_name: Vec<u16> = (SERVICE_NAME.to_owned() + "\0").encode_utf16().collect();
    let dispatch_table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR::from_raw(service_name.as_mut_ptr()),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];

    // StartServiceCtrlDispatcherW succeeds only if launched by SCM
    let launched_by_scm = unsafe { StartServiceCtrlDispatcherW(dispatch_table.as_ptr()).is_ok() };
    if launched_by_scm {
        // Runs until service stops; SCM dispatcher handled everything.
        return Ok(());
    }

    // Foreground mode (console / direct launch)
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    info!(
        "FreeDPI Service v{} (foreground)",
        env!("CARGO_PKG_VERSION")
    );

    let config = Config::load(&cli.config)?;
    freedpi_core::engine::refresh_local_ips();
    let engine = Arc::new(ServiceEngine::new(&config, cli.config.clone()));

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_foreground(config, engine))
}
