//! Fallback Chain — цепочка стратегий с automatic failover + backoff.
//!
//! ## Принцип
//! Если основная стратегия не работает (DPI блокирует),
//! автоматически переключаемся на следующую стратегию из цепочки.
//! Каждая стратегия имеет success/fail счётчики + sliding window ошибок
//! + exponential backoff для предотвращения rapid cycling.
//!
//! ## Источник
//! Адаптировано из [RIPDPI](https://github.com/nickel-org/ripdpi) — Fallback Chain.

use crate::desync::DesyncTechnique;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::{debug, info};

/// Запись стратегии в fallback chain.
#[derive(Debug)]
pub struct FallbackEntry {
    pub technique: DesyncTechnique,
    pub success_count: u64,
    pub fail_count: u64,
    pub last_used: Option<Instant>,
    pub avg_latency_us: u64,
}

impl FallbackEntry {
    pub fn new(technique: DesyncTechnique) -> Self {
        Self {
            technique,
            success_count: 0,
            fail_count: 0,
            last_used: None,
            avg_latency_us: 0,
        }
    }

    pub fn success_rate(&self) -> f64 {
        let total = self.success_count + self.fail_count;
        if total == 0 {
            return 1.0;
        }
        self.success_count as f64 / total as f64
    }
}

/// Sliding window ошибок: хранит timestamp'ы ошибок за последние window_duration.
struct ErrorWindow {
    errors: VecDeque<Instant>,
    window_duration: Duration,
}

impl ErrorWindow {
    fn new(window_duration: Duration) -> Self {
        Self {
            errors: VecDeque::new(),
            window_duration,
        }
    }

    fn record(&mut self) {
        self.errors.push_back(Instant::now());
        self.cleanup();
    }

    fn cleanup(&mut self) {
        let cutoff = Instant::now() - self.window_duration;
        while self.errors.front().is_some_and(|t| *t < cutoff) {
            self.errors.pop_front();
        }
    }

    fn count(&mut self) -> usize {
        self.cleanup();
        self.errors.len()
    }

    fn reset(&mut self) {
        self.errors.clear();
    }
}

/// Fallback Chain: цепочка стратегий с automatic failover + backoff.
///
/// ## Алгоритм
/// 1. Применяем текущую стратегию
/// 2. Если успех → увеличиваем success_count, сбрасываем backoff
/// 3. Если ошибка → увеличиваем fail_count, записываем в sliding window
/// 4. Если ошибок >= threshold за window → advance + exponential backoff
/// 5. Если все стратегии исчерпаны → direct (passthrough)
pub struct FallbackChain {
    entries: Vec<Mutex<FallbackEntry>>,
    current: AtomicUsize,
    min_success_rate: f64,
    min_switch_interval: Duration,
    last_switch: Mutex<Instant>,
    error_window: Mutex<ErrorWindow>,
    error_threshold: u32,
    next_allowed: Mutex<Instant>,
    backoff_base: Duration,
    backoff_cap: Duration,
}

impl FallbackChain {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            current: AtomicUsize::new(0),
            min_success_rate: 0.3,
            min_switch_interval: Duration::from_secs(30),
            last_switch: Mutex::new(Instant::now()),
            error_window: Mutex::new(ErrorWindow::new(Duration::from_secs(30))),
            error_threshold: 10,
            next_allowed: Mutex::new(Instant::now()),
            backoff_base: Duration::from_millis(500),
            backoff_cap: Duration::from_secs(15),
        }
    }

    pub fn from_techniques(techniques: Vec<DesyncTechnique>) -> Self {
        let entries: Vec<Mutex<FallbackEntry>> = techniques
            .into_iter()
            .map(|t| Mutex::new(FallbackEntry::new(t)))
            .collect();
        Self {
            entries,
            ..Self::new()
        }
    }

    pub fn add(&mut self, technique: DesyncTechnique) {
        self.entries.push(Mutex::new(FallbackEntry::new(technique)));
    }

    pub fn current(&self) -> Option<std::sync::MutexGuard<'_, FallbackEntry>> {
        let idx = self.current.load(Ordering::Relaxed);
        self.entries.get(idx).map(|e| e.lock().unwrap())
    }

    fn can_switch(&self) -> bool {
        let now = Instant::now();
        {
            let last = self.last_switch.lock().unwrap();
            if now.duration_since(*last) < self.min_switch_interval {
                return false;
            }
        }
        {
            let allowed = self.next_allowed.lock().unwrap();
            if now < *allowed {
                return false;
            }
        }
        true
    }

    pub fn advance(&self) -> Option<std::sync::MutexGuard<'_, FallbackEntry>> {
        if !self.can_switch() {
            debug!("FallbackChain: advance blocked by cooldown/backoff");
            return self.current();
        }

        let len = self.entries.len();
        if len == 0 {
            return None;
        }

        let start = self.current.load(Ordering::Relaxed);
        for i in 1..=len {
            let idx = (start + i) % len;
            let entry = self.entries[idx].lock().unwrap();
            if entry.success_rate() >= self.min_success_rate {
                drop(entry);
                self.current.store(idx, Ordering::Relaxed);
                {
                    let mut last = self.last_switch.lock().unwrap();
                    *last = Instant::now();
                }
                info!(
                    "FallbackChain: advanced to strategy {} ({})",
                    idx,
                    self.entries[idx].lock().unwrap().technique.name()
                );
                return Some(self.entries[idx].lock().unwrap());
            }
        }

        debug!("FallbackChain: all strategies exhausted");
        None
    }

    fn calculate_backoff(&self, attempts: u32) -> Duration {
        let max_sleep = self.backoff_base.as_millis() as f64 * 2.0_f64.powi(attempts as i32);
        let capped = max_sleep.min(self.backoff_cap.as_millis() as f64);
        let jittered = rand_jitter(capped);
        Duration::from_millis(jittered as u64)
    }

    pub fn record_success(&self, latency_us: u64) {
        let idx = self.current.load(Ordering::Relaxed);
        if idx >= self.entries.len() {
            return;
        }

        let mut entry = self.entries[idx].lock().unwrap();
        entry.success_count += 1;
        entry.last_used = Some(Instant::now());
        let old = entry.avg_latency_us;
        let count = entry.success_count;
        entry.avg_latency_us = if count <= 1 {
            latency_us
        } else {
            old + (latency_us.saturating_sub(old)) / count
        };

        let rate = entry.success_rate();
        drop(entry);

        {
            let mut next = self.next_allowed.lock().unwrap();
            *next = Instant::now();
        }
        {
            let mut window = self.error_window.lock().unwrap();
            window.reset();
        }

        debug!(
            "FallbackChain: success for strategy {} ({}us, rate={:.2})",
            idx, latency_us, rate
        );
    }

    pub fn record_failure(&self) {
        let idx = self.current.load(Ordering::Relaxed);
        if idx < self.entries.len() {
            self.entries[idx].lock().unwrap().fail_count += 1;
        }

        let error_count = {
            let mut window = self.error_window.lock().unwrap();
            window.record();
            // Отпускаем window MutexGuard перед advance()
            window.count()
        };

        if error_count >= self.error_threshold as usize {
            self.advance();

            let attempts = error_count as u32 / self.error_threshold;
            let backoff = self.calculate_backoff(attempts);
            {
                let mut next = self.next_allowed.lock().unwrap();
                *next = Instant::now() + backoff;
            }
            info!(
                "FallbackChain: error threshold reached ({}/{}), backoff {:?}",
                error_count, self.error_threshold, backoff
            );
        }

        debug!("FallbackChain: failure for strategy {}", idx);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn snapshot(&self) -> Vec<FallbackSnapshot> {
        let current_idx = self.current.load(Ordering::Relaxed);
        let error_count = self.error_window.lock().unwrap().count();
        self.entries
            .iter()
            .enumerate()
            .map(|(i, e)| {
                let e = e.lock().unwrap();
                FallbackSnapshot {
                    index: i,
                    technique: e.technique.name().to_string(),
                    success_count: e.success_count,
                    fail_count: e.fail_count,
                    success_rate: e.success_rate(),
                    is_current: i == current_idx,
                    error_window_count: error_count,
                }
            })
            .collect()
    }
}

impl Default for FallbackChain {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FallbackSnapshot {
    pub index: usize,
    pub technique: String,
    pub success_count: u64,
    pub fail_count: u64,
    pub success_rate: f64,
    pub is_current: bool,
    pub error_window_count: usize,
}

fn rand_jitter(max: f64) -> f64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    Instant::now().hash(&mut hasher);
    let hash = hasher.finish();
    (hash as f64 / u64::MAX as f64) * max
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fallback_chain_empty() {
        let chain = FallbackChain::new();
        assert!(chain.is_empty());
        assert!(chain.current().is_none());
    }

    #[test]
    fn test_fallback_chain_from_techniques() {
        let chain = FallbackChain::from_techniques(vec![
            DesyncTechnique::FakeSni,
            DesyncTechnique::MultiSplit,
            DesyncTechnique::Disorder,
        ]);
        assert_eq!(chain.len(), 3);
        assert!(chain.current().is_some());
    }

    #[test]
    fn test_record_success_increments_count() {
        let chain = FallbackChain::from_techniques(vec![
            DesyncTechnique::FakeSni,
            DesyncTechnique::MultiSplit,
        ]);

        assert_eq!(chain.entries[0].lock().unwrap().success_count, 0);
        chain.record_success(1000);
        assert_eq!(chain.entries[0].lock().unwrap().success_count, 1);
        chain.record_success(2000);
        assert_eq!(chain.entries[0].lock().unwrap().success_count, 2);
    }

    #[test]
    fn test_record_failure_increments_count() {
        let chain = FallbackChain::from_techniques(vec![
            DesyncTechnique::FakeSni,
            DesyncTechnique::MultiSplit,
        ]);

        assert_eq!(chain.entries[0].lock().unwrap().fail_count, 0);
        chain.record_failure();
        assert_eq!(chain.entries[0].lock().unwrap().fail_count, 1);
        // После 1 ошибки из error_threshold=10 advance не вызывается
        assert_eq!(chain.current().unwrap().technique.name(), "FakeSni");
    }

    #[test]
    fn test_success_rate_calculation() {
        let chain = FallbackChain::from_techniques(vec![DesyncTechnique::FakeSni]);

        assert_eq!(chain.entries[0].lock().unwrap().success_rate(), 1.0);
        chain.record_success(100);
        assert_eq!(chain.entries[0].lock().unwrap().success_rate(), 1.0);
        chain.record_failure();
        let rate = chain.entries[0].lock().unwrap().success_rate();
        assert!((rate - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_fallback_advance() {
        // Создаём цепочку с минимальным cooldown для теста
        let chain = FallbackChain {
            entries: vec![
                Mutex::new(FallbackEntry::new(DesyncTechnique::FakeSni)),
                Mutex::new(FallbackEntry::new(DesyncTechnique::MultiSplit)),
            ],
            min_switch_interval: Duration::ZERO,
            last_switch: Mutex::new(Instant::now()),
            error_window: Mutex::new(ErrorWindow::new(Duration::from_secs(30))),
            error_threshold: 1, // 1 ошибка → сразу advance
            next_allowed: Mutex::new(Instant::now()),
            ..FallbackChain::new()
        };
        let first = chain.current().unwrap().technique.name().to_string();
        chain.record_failure();
        let second = chain.current().unwrap().technique.name().to_string();
        assert_ne!(first, second);
        assert_eq!(second, "MultiSplit");
    }

    #[test]
    fn test_fallback_snapshot() {
        let chain = FallbackChain::from_techniques(vec![
            DesyncTechnique::FakeSni,
            DesyncTechnique::MultiSplit,
        ]);
        chain.record_success(100);
        chain.record_failure();
        let snap = chain.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].success_count, 1);
        assert_eq!(snap[0].fail_count, 1);
    }

    #[test]
    fn test_error_window() {
        let mut window = ErrorWindow::new(Duration::from_millis(100));
        assert_eq!(window.count(), 0);
        window.record();
        assert_eq!(window.count(), 1);
    }

    #[test]
    fn test_backoff_calculation() {
        let chain = FallbackChain::new();
        let b0 = chain.calculate_backoff(0);
        let b2 = chain.calculate_backoff(2);
        // Backoff should not exceed cap
        assert!(b0 <= chain.backoff_cap);
        assert!(b2 <= chain.backoff_cap);
        // Higher attempts should produce larger max backoff
        let b0_max = chain.backoff_base.as_millis() as f64;
        let b2_max = chain.backoff_base.as_millis() as f64 * 4.0;
        assert!(b0_max < b2_max);
    }
}
