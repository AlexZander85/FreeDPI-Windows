//! Adaptive Multi-Path Routing — умный выбор между desync, proxy и direct.
//!
//! ## Маршруты
//! - **Direct**: пропустить без модификации (РФ домены, незашифрованный трафик)
//! - **Desync**: применить desync техники (FakeSni, MultiSplit, etc.)
//! - **Proxy**: направить через SOCKS5 proxy (Opera)
//! - **Drop**: заблокировать (реклама, QUIC к Fake IP)

use crate::adaptive::auto_tune::AutoTune;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Решение маршрутизации для пакета.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingDecision {
    /// Пропустить без модификации (РФ домены, незашифрованный трафик)
    Direct,
    /// Применить desync техники (FakeSni, MultiSplit, etc.)
    Desync,
    /// Направить через SOCKS5 proxy (Opera)
    Proxy,
    /// Заблокировать (реклама, QUIC к Fake IP)
    Drop,
}

/// Конфигурация Adaptive Router.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveRouterConfig {
    /// T60.1: Если desync success_rate ниже этого порога → switch to proxy.
    pub desync_failure_threshold: f64,
    /// T60.3: Если throughput ниже этого значения (bytes/sec) → switch to proxy.
    pub throttling_threshold_bps: u64,
    /// T60.4: Circuit Breaker — если RST count за окно > этого значения → OPEN.
    pub circuit_breaker_rst_threshold: u32,
    /// T60.4: Circuit Breaker — размер окна (секунды).
    pub circuit_breaker_window_secs: u64,
    /// T60.4: Circuit Breaker — timeout перед HALF-OPEN (секунды).
    pub circuit_breaker_timeout_secs: u64,
    /// T60.2: Протоколы без SNI/Host → автоматически через proxy если домен заблокирован.
    pub proxy_non_sni_blocked: bool,
    /// T60.3: Измерять throughput и переключаться на proxy при throttling.
    pub throughput_aware_routing: bool,
}

impl Default for AdaptiveRouterConfig {
    fn default() -> Self {
        Self {
            desync_failure_threshold: 0.30,
            throttling_threshold_bps: 500_000, // 500 KB/s = 4 Mbps
            circuit_breaker_rst_threshold: 50,
            circuit_breaker_window_secs: 60,
            circuit_breaker_timeout_secs: 300, // 5 минут
            proxy_non_sni_blocked: true,
            throughput_aware_routing: true,
        }
    }
}

/// T60.4: Circuit Breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitBreakerState {
    /// Desync работает нормально.
    Closed,
    /// Слишком много RST — desync отключён, всё через proxy.
    Open,
    /// Timeout прошёл — пробуем desync на одном соединении.
    HalfOpen,
}

/// T60: Adaptive Multi-Path Routing Engine.
pub struct AdaptiveRouter {
    config: AdaptiveRouterConfig,
    /// Circuit Breaker state.
    circuit_breaker: Arc<CircuitBreaker>,
    /// Throughput tracker — domain → (bytes_transferred, timestamp).
    throughput_tracker: Arc<ThroughputTracker>,
}

/// T60.4: Circuit Breaker — защита от массовых RST.
pub struct CircuitBreaker {
    state: AtomicU8, // 0=Closed, 1=Open, 2=HalfOpen
    /// RST count в текущем окне.
    rst_count: AtomicU32,
    /// Когда окно началось.
    window_start: std::sync::Mutex<Instant>,
    /// Когда circuit breaker открылся (для timeout).
    opened_at: std::sync::Mutex<Option<Instant>>,
}

impl CircuitBreaker {
    pub fn new() -> Self {
        Self {
            state: AtomicU8::new(0), // Closed
            rst_count: AtomicU32::new(0),
            window_start: std::sync::Mutex::new(Instant::now()),
            opened_at: std::sync::Mutex::new(None),
        }
    }

    pub fn get_state(&self) -> CircuitBreakerState {
        match self.state.load(Ordering::Relaxed) {
            0 => CircuitBreakerState::Closed,
            1 => CircuitBreakerState::Open,
            2 => CircuitBreakerState::HalfOpen,
            _ => CircuitBreakerState::Closed,
        }
    }

    /// Регистрирует RST пакет.
    pub fn record_rst(&self, threshold: u32, window_secs: u64, timeout_secs: u64) {
        self.rst_count.fetch_add(1, Ordering::Relaxed);

        let mut window = self.window_start.lock().unwrap();
        let now = Instant::now();

        // Проверяем — нужно ли сбросить окно
        if now.duration_since(*window) > Duration::from_secs(window_secs) {
            *window = now;
            self.rst_count.store(1, Ordering::Relaxed);
            return;
        }

        let count = self.rst_count.load(Ordering::Relaxed);

        // Если RST count > threshold → OPEN
        if count >= threshold && self.get_state() == CircuitBreakerState::Closed {
            self.state.store(1, Ordering::Relaxed); // Open
            *self.opened_at.lock().unwrap() = Some(now);
            warn!(
                "CircuitBreaker: OPEN — {} RSTs in {}s window (threshold={})",
                count, window_secs, threshold
            );
        }

        // Если OPEN и timeout прошёл → HALF-OPEN
        if self.get_state() == CircuitBreakerState::Open {
            let opened = self.opened_at.lock().unwrap();
            if let Some(opened_time) = *opened {
                if now.duration_since(opened_time) > Duration::from_secs(timeout_secs) {
                    self.state.store(2, Ordering::Relaxed); // HalfOpen
                    info!(
                        "CircuitBreaker: HALF-OPEN — testing desync after {}s timeout",
                        timeout_secs
                    );
                }
            }
        }
    }

    /// Регистрирует успешное соединение (для HALF-OPEN → CLOSED).
    pub fn record_success(&self) {
        if self.get_state() == CircuitBreakerState::HalfOpen {
            self.state.store(0, Ordering::Relaxed); // Closed
            self.rst_count.store(0, Ordering::Relaxed);
            info!("CircuitBreaker: CLOSED — desync working again");
        }
    }

    /// Сбрасывает circuit breaker (для тестов или manual override).
    pub fn reset(&self) {
        self.state.store(0, Ordering::Relaxed);
        self.rst_count.store(0, Ordering::Relaxed);
        *self.window_start.lock().unwrap() = Instant::now();
        *self.opened_at.lock().unwrap() = None;
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

/// T60.3: Throughput tracker — измеряет скорость соединения.
pub struct ThroughputTracker {
    /// domain → (bytes_transferred, window_start)
    trackers: dashmap::DashMap<String, ThroughputEntry>,
}

#[derive(Debug, Clone)]
struct ThroughputEntry {
    bytes: u64,
    window_start: Instant,
    /// Rolling average bytes/sec.
    avg_bps: u64,
}

impl ThroughputTracker {
    pub fn new() -> Self {
        Self {
            trackers: dashmap::DashMap::new(),
        }
    }

    /// Регистрирует переданные байты для домена.
    pub fn record_bytes(&self, domain: &str, bytes: u64) {
        let mut entry =
            self.trackers
                .entry(domain.to_string())
                .or_insert_with(|| ThroughputEntry {
                    bytes: 0,
                    window_start: Instant::now(),
                    avg_bps: 0,
                });

        entry.bytes += bytes;

        let elapsed = entry.window_start.elapsed().as_secs_f64();
        if elapsed > 1.0 {
            // Обновляем rolling average
            let current_bps = (entry.bytes as f64 / elapsed) as u64;
            // Exponential moving average: 80% old, 20% new
            entry.avg_bps = ((entry.avg_bps as f64 * 0.8) + (current_bps as f64 * 0.2)) as u64;
            entry.bytes = 0;
            entry.window_start = Instant::now();

            debug!(
                "Throughput '{}': {} bps (avg: {} bps)",
                domain, current_bps, entry.avg_bps
            );
        }
    }

    /// Возвращает текущий throughput для домена (bytes/sec).
    pub fn get_throughput(&self, domain: &str) -> u64 {
        self.trackers.get(domain).map(|e| e.avg_bps).unwrap_or(0)
    }

    /// Очищает устаревшие записи.
    pub fn cleanup(&self) {
        let now = Instant::now();
        self.trackers
            .retain(|_, entry| now.duration_since(entry.window_start) < Duration::from_secs(300));
    }
}

impl Default for ThroughputTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl AdaptiveRouter {
    pub fn new(config: AdaptiveRouterConfig) -> Self {
        Self {
            config,
            circuit_breaker: Arc::new(CircuitBreaker::new()),
            throughput_tracker: Arc::new(ThroughputTracker::new()),
        }
    }

    /// T60: Принимает решение о маршрутизации для пакета.
    pub fn decide(
        &self,
        domain: Option<&str>,
        is_blocked: bool,
        is_geo_blocked: bool,
        has_sni_or_host: bool,
        _protocol: u8,
        auto_tune: &AutoTune,
        profile_name: &str,
    ) -> RoutingDecision {
        // 1. Геоблокировка → всегда Proxy (Fake IP → SOCKS5)
        if is_geo_blocked {
            return RoutingDecision::Proxy;
        }

        // 2. Не заблокирован → Direct
        if !is_blocked {
            return RoutingDecision::Direct;
        }

        // 3. Заблокирован (RKN) — проверяем условия для Proxy fallback

        // 3a. Circuit Breaker OPEN → Proxy для всех заблокированных
        let cb_state = self.circuit_breaker.get_state();
        if cb_state == CircuitBreakerState::Open {
            debug!("Routing: CircuitBreaker OPEN → Proxy for all blocked");
            return RoutingDecision::Proxy;
        }

        // 3b. Нет SNI/Host → desync неприменим → Proxy
        if self.config.proxy_non_sni_blocked && !has_sni_or_host {
            debug!("Routing: no SNI/Host + blocked → Proxy (desync inapplicable)");
            return RoutingDecision::Proxy;
        }

        // 3c. Desync success_rate < threshold → Proxy fallback
        let metrics = auto_tune.get_metrics(profile_name);
        if let Some(m) = metrics {
            let success_rate = m.success_rate();
            if success_rate < self.config.desync_failure_threshold {
                debug!(
                    "Routing: desync success_rate={:.0}% < {:.0}% → Proxy fallback",
                    success_rate * 100.0,
                    self.config.desync_failure_threshold * 100.0
                );
                return RoutingDecision::Proxy;
            }
        }

        // 3d. Throughput < threshold → Proxy (throttling bypass)
        if self.config.throughput_aware_routing {
            if let Some(domain) = domain {
                let throughput = self.throughput_tracker.get_throughput(domain);
                if throughput > 0 && throughput < self.config.throttling_threshold_bps {
                    debug!(
                        "Routing: throughput={} bps < {} bps → Proxy (throttling bypass)",
                        throughput, self.config.throttling_threshold_bps
                    );
                    return RoutingDecision::Proxy;
                }
            }
        }

        // 3e. Circuit Breaker HALF-OPEN → пробуем desync
        if cb_state == CircuitBreakerState::HalfOpen {
            debug!("Routing: CircuitBreaker HALF-OPEN → testing Desync");
            return RoutingDecision::Desync;
        }

        // 4. Default: Desync
        RoutingDecision::Desync
    }

    /// T60.4: Регистрирует RST пакет (для Circuit Breaker).
    pub fn record_rst(&self) {
        self.circuit_breaker.record_rst(
            self.config.circuit_breaker_rst_threshold,
            self.config.circuit_breaker_window_secs,
            self.config.circuit_breaker_timeout_secs,
        );
    }

    /// T60.4: Регистрирует успешное соединение (Circuit Breaker HALF-OPEN → CLOSED).
    pub fn record_success(&self) {
        self.circuit_breaker.record_success();
    }

    /// T60.3: Регистрирует переданные байты (для throughput tracking).
    pub fn record_bytes(&self, domain: &str, bytes: u64) {
        self.throughput_tracker.record_bytes(domain, bytes);
    }

    /// Очищает устаревшие throughput записи.
    pub fn cleanup(&self) {
        self.throughput_tracker.cleanup();
    }

    pub fn circuit_breaker_state(&self) -> CircuitBreakerState {
        self.circuit_breaker.get_state()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_routing_geo_blocked_always_proxy() {
        let router = AdaptiveRouter::new(AdaptiveRouterConfig::default());
        let auto_tune = AutoTune::new();

        let decision = router.decide(
            Some("netflix.com"),
            false, // not RKN-blocked
            true,  // geo-blocked
            true,  // has SNI
            6,     // TCP
            &auto_tune,
            "outbound_tls",
        );
        assert_eq!(decision, RoutingDecision::Proxy);
    }

    #[test]
    fn test_routing_not_blocked_direct() {
        let router = AdaptiveRouter::new(AdaptiveRouterConfig::default());
        let auto_tune = AutoTune::new();

        let decision = router.decide(
            Some("vk.com"),
            false, // not blocked
            false, // not geo-blocked
            true,  // has SNI
            6,
            &auto_tune,
            "outbound_tls",
        );
        assert_eq!(decision, RoutingDecision::Direct);
    }

    #[test]
    fn test_routing_blocked_with_sni_desync() {
        let router = AdaptiveRouter::new(AdaptiveRouterConfig::default());
        let auto_tune = AutoTune::new();

        let decision = router.decide(
            Some("instagram.com"),
            true,  // blocked
            false, // not geo-blocked
            true,  // has SNI
            6,
            &auto_tune,
            "outbound_tls",
        );
        assert_eq!(decision, RoutingDecision::Desync);
    }

    #[test]
    fn test_routing_blocked_no_sni_proxy() {
        let router = AdaptiveRouter::new(AdaptiveRouterConfig::default());
        let auto_tune = AutoTune::new();

        let decision = router.decide(
            Some("ssh.blocked.com"),
            true,  // blocked
            false, // not geo-blocked
            false, // NO SNI (SSH)
            6,
            &auto_tune,
            "outbound_tls",
        );
        assert_eq!(decision, RoutingDecision::Proxy);
    }

    #[test]
    fn test_circuit_breaker_open() {
        let router = AdaptiveRouter::new(AdaptiveRouterConfig {
            circuit_breaker_rst_threshold: 5,
            circuit_breaker_window_secs: 60,
            ..Default::default()
        });
        let auto_tune = AutoTune::new();

        // Trigger 5 RSTs
        for _ in 0..5 {
            router.record_rst();
        }

        // Now all blocked traffic should go through Proxy
        let decision = router.decide(
            Some("blocked.com"),
            true,
            false,
            true, // has SNI
            6,
            &auto_tune,
            "outbound_tls",
        );
        assert_eq!(decision, RoutingDecision::Proxy);
        assert_eq!(router.circuit_breaker_state(), CircuitBreakerState::Open);
    }

    #[test]
    fn test_circuit_breaker_closed_after_success() {
        let router = AdaptiveRouter::new(AdaptiveRouterConfig {
            circuit_breaker_rst_threshold: 5,
            circuit_breaker_window_secs: 60,
            circuit_breaker_timeout_secs: 0, // immediate timeout
            ..Default::default()
        });

        // Open the breaker
        for _ in 0..5 {
            router.record_rst();
        }
        assert_eq!(router.circuit_breaker_state(), CircuitBreakerState::Open);

        // Wait for timeout → HalfOpen
        std::thread::sleep(Duration::from_millis(10));
        router.record_rst(); // trigger timeout check

        // Record success → Closed
        router.record_success();
        assert_eq!(router.circuit_breaker_state(), CircuitBreakerState::Closed);
    }

    #[test]
    fn test_throughput_tracking() {
        let tracker = ThroughputTracker::new();

        // Record some bytes
        tracker.record_bytes("youtube.com", 1_000_000);

        // Wait for window to pass
        std::thread::sleep(Duration::from_millis(1100));

        // Record more to trigger average calculation
        tracker.record_bytes("youtube.com", 500_000);

        let throughput = tracker.get_throughput("youtube.com");
        assert!(
            throughput > 0,
            "Throughput should be > 0, got {}",
            throughput
        );
    }
}
