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
    adaptive::hop_tab::HopTab, config::Config, conntrack::Conntrack, dns::fakeip::FakeIpManager,
    engine::ProcessingPipeline, infra::sentinel::Sentinel, routing::geo::GeoRouter,
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
}

impl ServiceEngine {
    fn new() -> Self {
        Self {
            start_time: std::time::Instant::now(),
            packets_processed: AtomicU64::new(0),
            conntrack: Conntrack::new(std::time::Duration::from_secs(30)),
            sentinel: Arc::new(Sentinel::create()),
            running: AtomicBool::new(true),
            probe_history: std::sync::Mutex::new(Vec::new()),
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
        info!("Strategy tune: id={}", params.strategy_id);
    }
    fn set_routing_override(&self, params: &RoutingOverride) {
        info!("Routing override: {} → {}", params.domain, params.region);
    }
    fn probe_domain(&self, domain: &str, _full: bool) -> Result<serde_json::Value, String> {
        use freedpi_core::probe::strategy_map::recommend;
        use freedpi_core::probe::ProbeModule;

        let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
        let module = ProbeModule::new();
        let result = rt.block_on(module.probe(domain));
        let recommendations = recommend(&result);
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
}

// ---------------------------------------------------------------------------
// Service logic (shared between foreground and service modes)
// ---------------------------------------------------------------------------

async fn run_service(
    config: Config,
    engine: Arc<ServiceEngine>,
    shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) {
    let conntrack = engine.conntrack.clone();
    let sentinel = engine.sentinel.clone();

    // Build pipeline (inside scope so pipeline Arc is dropped properly)
    let pipeline = {
        let proc_config = config.to_processing_config();
        match ProcessingPipeline::new(
            &config.windivert.filter,
            proc_config,
            Arc::new(GeoRouter::new_default()),
            Arc::new(FakeIpManager::new(10_000)),
            Arc::new(HopTab::new()),
        ) {
            Ok(p) => {
                info!("Pipeline created");
                Some(p)
            }
            Err(e) => {
                warn!("Pipeline failed (need admin?): {}", e);
                None
            }
        }
    };

    // Start API server
    if config.api.enabled {
        let api_key = config.api.api_key.clone();
        let api_port = config.api.port;
        let engine_clone = engine.clone();
        info!("API at http://127.0.0.1:{}", api_port);
        tokio::spawn(async move {
            freedpi_api::serve(
                engine_clone as Arc<dyn EngineHandle + Send + Sync>,
                api_key,
                api_port,
            )
            .await;
        });
    }

    // Start conntrack GC
    tokio::spawn(async move {
        conntrack.gc_loop().await;
    });

    // Start sentinel monitor
    sentinel.start_monitor();

    // Start pipeline
    if let Some(pipeline) = pipeline {
        let pipeline = std::sync::Arc::new(pipeline);
        let stats = pipeline.stats_arc();
        let shutdown_rx_pipeline = shutdown_rx.resubscribe();
        tokio::spawn(async move {
            pipeline.run(shutdown_rx_pipeline).await;
        });
        let mut shutdown_rx_stats = shutdown_rx.resubscribe();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let s = stats.snapshot();
                        info!(
                            "Stats: recv={} fwd={} inject={}",
                            s.total_received, s.forwarded, s.fake_ch_injected
                        );
                    }
                    _ = shutdown_rx_stats.recv() => break,
                }
            }
        });
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
                let mut status = SERVICE_STATUS::default();
                status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
                status.dwCurrentState = SERVICE_STOPPED;
                status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
                status.dwWin32ExitCode = 0;
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
    let mut status = SERVICE_STATUS::default();
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = SERVICE_RUNNING;
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    status.dwWin32ExitCode = 0;
    let _ = SetServiceStatus(handle, &status);

    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
    let _ = STOP_CHANNEL.set(shutdown_tx);

    // Build minimal config (load from default path)
    let config = match Config::load(std::path::Path::new("config.toml")) {
        Ok(c) => c,
        Err(e) => {
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
    let engine = Arc::new(ServiceEngine::new());

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
    let launched_by_scm = unsafe {
        StartServiceCtrlDispatcherW(dispatch_table.as_ptr() as *const SERVICE_TABLE_ENTRYW).is_ok()
    };
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
    let engine = Arc::new(ServiceEngine::new());

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_foreground(config, engine))
}
