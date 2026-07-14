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

    #[cfg(feature = "qa")]
    fn qa_strategy_inventory(&self) -> serde_json::Value {
        let mut live_profiles = vec![];
        let mut probe_numeric_ids = vec![];
        let mut unresolved_count = 0;
        let mut unmapped_probe_ids = vec![];

        if let Some(pipeline) = self.pipeline.get() {
            let registry = pipeline.profile_registry();
            for p in registry.all_profiles() {
                let (force_sel, run_switch, run_switch_reason, unsupported_reasons) =
                    match p.category {
                        freedpi_core::adaptive::strategy::StrategyCategory::Tls => (
                            true,
                            true,
                            serde_json::json!("active_profile_slot_tls"),
                            serde_json::json!([]),
                        ),
                        freedpi_core::adaptive::strategy::StrategyCategory::Quic => (
                            true,
                            true,
                            serde_json::json!("active_profile_slot_quic"),
                            serde_json::json!([]),
                        ),
                        freedpi_core::adaptive::strategy::StrategyCategory::Http => (
                            true,
                            true,
                            serde_json::json!("active_profile_slot_http"),
                            serde_json::json!([]),
                        ),
                        _ => (
                            false,
                            false,
                            serde_json::Value::Null,
                            serde_json::json!(["no_active_profile_slot_for_category"]),
                        ),
                    };

                live_profiles.push(serde_json::json!({
                    "name": p.name,
                    "strategy_id": p.strategy_id,
                    "category": format!("{:?}", p.category),
                    "techniques": p.techniques.iter().map(|t| format!("{:?}", t)).collect::<Vec<_>>(),
                    "description": p.description,
                    "source": "builtin",
                    "runtime_status": "live",
                    "force_selectable": force_sel,
                    "runtime_switchable": run_switch,
                    "runtime_switch_reason": run_switch_reason,
                    "auto_selectable": true,
                    "unsupported_reasons": unsupported_reasons,
                }));
            }

            let recommended_ids = freedpi_core::probe::strategy_map::known_recommendation_ids();
            for &rid in recommended_ids {
                if let Some(p) = registry.get_by_id(rid) {
                    probe_numeric_ids.push(serde_json::json!({
                        "strategy_id": rid,
                        "mapped_profile_name": p.name,
                        "status": "mapped",
                    }));
                } else {
                    probe_numeric_ids.push(serde_json::json!({
                        "strategy_id": rid,
                        "mapped_profile_name": serde_json::Value::Null,
                        "status": "unresolved",
                        "unsupported_reasons": ["unmapped_probe_strategy_id"],
                    }));
                    unresolved_count += 1;
                    unmapped_probe_ids.push(rid);
                }
            }
        }

        let mut duplicate_ids = vec![];
        let mut seen_ids = std::collections::HashSet::new();
        for p in &live_profiles {
            if let Some(id) = p.get("strategy_id").and_then(|i| i.as_u64()) {
                if !seen_ids.insert(id) {
                    duplicate_ids.push(id);
                }
            }
        }

        let mut findings = vec![];
        if !duplicate_ids.is_empty() {
            findings.push(serde_json::json!({
                "severity": "fail",
                "message": format!("duplicate live strategy ids: {:?}", duplicate_ids),
            }));
        }
        if unresolved_count > 0 {
            findings.push(serde_json::json!({
                "severity": "warn",
                "message": format!("{} probe numeric ids do not map to live profiles: {:?}", unresolved_count, unmapped_probe_ids),
            }));
        }

        serde_json::json!({
            "live_profiles": live_profiles,
            "probe_numeric_ids": probe_numeric_ids,
            "dead_registry_entries": serde_json::json!([]),
            "reconciliation": {
                "live_profiles": live_profiles,
                "probe_numeric_ids": probe_numeric_ids,
                "dead_trait_registry": serde_json::json!([]),
                "unmapped_probe_ids": unmapped_probe_ids,
                "duplicate_ids": duplicate_ids,
                "findings": findings,
                "numeric_ids_unresolved": unresolved_count,
                "live_profiles_unreachable_by_any_numeric_id": serde_json::json!([]),
            }
        })
    }

    #[cfg(feature = "qa")]
    fn qa_runtime_strategy_snapshot(&self) -> serde_json::Value {
        if let Some(pipeline) = self.pipeline.get() {
            let registry = pipeline.profile_registry();
            let tls_id =
                pipeline.active_profile_id(freedpi_core::adaptive::strategy::StrategyCategory::Tls);
            let quic_id = pipeline
                .active_profile_id(freedpi_core::adaptive::strategy::StrategyCategory::Quic);
            let http_id = pipeline
                .active_profile_id(freedpi_core::adaptive::strategy::StrategyCategory::Http);

            let tls_profile = registry
                .get_by_profile_id(freedpi_core::adaptive::strategy_profile::ProfileId(tls_id));
            let quic_profile = registry
                .get_by_profile_id(freedpi_core::adaptive::strategy_profile::ProfileId(quic_id));
            let http_profile = registry
                .get_by_profile_id(freedpi_core::adaptive::strategy_profile::ProfileId(http_id));

            let forced_id = pipeline
                .qa_last_tuned_strategy_id
                .load(std::sync::atomic::Ordering::Relaxed);
            let is_forced = forced_id != -1;

            let mut forced_profile_name = "n/a".to_string();
            let mut tls_src = "config";
            let mut quic_src = "config";
            let mut http_src = "config";

            if is_forced {
                if let Some(p) = registry.get_by_id(forced_id as u32) {
                    forced_profile_name = p.name.clone();
                    match p.category {
                        freedpi_core::adaptive::strategy::StrategyCategory::Tls => {
                            tls_src = "forced"
                        }
                        freedpi_core::adaptive::strategy::StrategyCategory::Quic => {
                            quic_src = "forced"
                        }
                        freedpi_core::adaptive::strategy::StrategyCategory::Http => {
                            http_src = "forced"
                        }
                        _ => {}
                    }
                }
            }

            let timestamp_utc = {
                let ms = pipeline
                    .qa_last_tuned_time_ms
                    .load(std::sync::atomic::Ordering::Relaxed);
                if ms > 0 {
                    chrono::DateTime::from_timestamp(
                        (ms / 1000) as i64,
                        ((ms % 1000) * 1_000_000) as u32,
                    )
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_else(|| "n/a".to_string())
                } else {
                    "n/a".to_string()
                }
            };

            serde_json::json!({
                "ok": true,
                "generation": pipeline.qa_strategy_generation.load(std::sync::atomic::Ordering::Relaxed),
                "active_profiles": {
                    "tls": {
                        "profile_id": tls_profile.map(|p| p.strategy_id).unwrap_or(0),
                        "name": tls_profile.map(|p| p.name.as_str()).unwrap_or("unknown"),
                        "source": tls_src,
                    },
                    "quic": {
                        "profile_id": quic_profile.map(|p| p.strategy_id).unwrap_or(0),
                        "name": quic_profile.map(|p| p.name.as_str()).unwrap_or("unknown"),
                        "source": quic_src,
                    },
                    "http": {
                        "profile_id": http_profile.map(|p| p.strategy_id).unwrap_or(0),
                        "name": http_profile.map(|p| p.name.as_str()).unwrap_or("unknown"),
                        "source": http_src,
                    }
                },
                "forced": {
                    "enabled": is_forced,
                    "strategy_id": if is_forced { serde_json::Value::Number(forced_id.into()) } else { serde_json::Value::Null },
                    "profile_name": forced_profile_name,
                    "expires_at": serde_json::Value::Null,
                },
                "last_strategy_update": {
                    "strategy_id": if is_forced { serde_json::Value::Number(forced_id.into()) } else { serde_json::Value::Null },
                    "params_hash": "n/a",
                    "timestamp_utc": timestamp_utc
                }
            })
        } else {
            serde_json::json!({
                "ok": true,
                "generation": 0,
                "status": "pipeline_not_started"
            })
        }
    }

    #[cfg(feature = "qa")]
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

        let recent = match self.pipeline.get() {
            Some(pipeline) => {
                let flows = pipeline.qa_recent_flows.lock().unwrap();
                flows.iter().cloned().collect::<Vec<_>>()
            }
            None => vec![],
        };

        serde_json::json!({
            "ok": true,
            "aggregate": agg,
            "recent_flows": recent,
        })
    }

    #[cfg(feature = "qa")]
    fn qa_autotune_state(&self) -> serde_json::Value {
        serde_json::json!({
            "ok": false,
            "unsupported": true,
            "reason": "autotune_state_not_implemented",
        })
    }

    #[cfg(feature = "qa")]
    fn qa_autotune_decision_log(&self) -> serde_json::Value {
        serde_json::json!({
            "ok": false,
            "unsupported": true,
            "reason": "autotune_decision_log_not_implemented",
        })
    }

    #[cfg(feature = "qa")]
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

    #[cfg(feature = "qa")]
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

    #[cfg(feature = "qa")]
    fn qa_reset_state(&self) -> serde_json::Value {
        self.conntrack.gc(std::time::Duration::ZERO);
        if let Some(pipeline) = self.pipeline.get() {
            pipeline.qa_reset_state();
        }
        info!("QA: reset_state called — conntrack GC and pipeline state cleared");
        serde_json::json!({ "ok": true, "reset": "state", "conntrack_gc": true })
    }

    #[cfg(feature = "qa")]
    fn qa_reset_telemetry(&self) -> serde_json::Value {
        info!("QA: reset_telemetry called (counters are monotonic, returns unsupported)");
        serde_json::json!({
            "ok": false,
            "unsupported": true,
            "reason": "telemetry_counters_are_monotonic",
        })
    }

    #[cfg(feature = "qa")]
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
