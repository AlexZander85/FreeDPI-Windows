//! Auto-Tune — автоматическая подстройка параметров стратегий.
//!
//! ## Принцип
//! На основе результатов применения стратегий (success/fail, latency)
//! автоматически подстраиваем параметры: split_size, ttl_offset,
//! split_count, inject_delay.
//!
//! ## Источник
//! Адаптировано из [autodpi](https://github.com/brannondorsey/autodpi) — Auto-tune.

use std::sync::atomic::{AtomicU64, Ordering};
use tracing::debug;

/// Параметры для auto-tune.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct TuneParams {
    pub split_size: Option<usize>,
    pub split_count: Option<usize>,
    pub fake_ttl_offset: Option<u8>,
    pub max_seg_size: Option<usize>,
}

/// Fixed number of strategies supported.
const MAX_STRATEGIES: usize = 16;

/// Strategy metrics stored as atomics for lock-free access.
pub struct StrategyMetrics {
    pub success_count: AtomicU64,
    pub fail_count: AtomicU64,
    pub total_latency_us: AtomicU64,
}

impl Default for StrategyMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl StrategyMetrics {
    pub const fn new() -> Self {
        Self {
            success_count: AtomicU64::new(0),
            fail_count: AtomicU64::new(0),
            total_latency_us: AtomicU64::new(0),
        }
    }

    pub fn success_rate(&self) -> f64 {
        let s = self.success_count.load(Ordering::Relaxed);
        let f = self.fail_count.load(Ordering::Relaxed);
        let total = s + f;
        if total == 0 {
            return 1.0;
        }
        s as f64 / total as f64
    }

    pub fn avg_latency_us(&self) -> u64 {
        let s = self.success_count.load(Ordering::Relaxed);
        if s == 0 {
            return 0;
        }
        self.total_latency_us.load(Ordering::Relaxed) / s
    }
}

/// Auto-Tune engine with lock-free atomics and Thompson sampling.
pub struct AutoTune {
    /// Fixed array of strategy metrics — no heap allocation.
    metrics: [StrategyMetrics; MAX_STRATEGIES],
    /// Strategy name → index mapping.
    strategy_indices: std::collections::HashMap<String, usize>,
    /// Tune threshold.
    tune_threshold: f64,
    /// Manual overrides.
    pub manual_overrides: std::collections::HashMap<String, TuneParams>,
}

impl AutoTune {
    pub fn new() -> Self {
        Self {
            metrics: [const { StrategyMetrics::new() }; MAX_STRATEGIES],
            strategy_indices: std::collections::HashMap::new(),
            tune_threshold: 0.5,
            manual_overrides: std::collections::HashMap::new(),
        }
    }

    pub fn set_override(&mut self, strategy_name: &str, params: TuneParams) {
        self.manual_overrides
            .insert(strategy_name.to_string(), params);
    }

    pub fn clear_override(&mut self, strategy_name: &str) {
        self.manual_overrides.remove(strategy_name);
    }

    fn get_or_create_index(&mut self, strategy_name: &str) -> usize {
        if let Some(&idx) = self.strategy_indices.get(strategy_name) {
            return idx;
        }
        let idx = self.strategy_indices.len();
        if idx >= MAX_STRATEGIES {
            // Hash to existing slot on overflow
            return strategy_name.len() % MAX_STRATEGIES;
        }
        self.strategy_indices.insert(strategy_name.to_string(), idx);
        idx
    }

    /// Records a real connection outcome (success/failure with latency).
    pub fn record(&mut self, strategy_name: &str, success: bool, latency_us: u64) {
        let idx = self.get_or_create_index(strategy_name);
        let m = &self.metrics[idx];

        if success {
            m.success_count.fetch_add(1, Ordering::Relaxed);
            m.total_latency_us.fetch_add(latency_us, Ordering::Relaxed);
        } else {
            m.fail_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Thompson sampling: sample from Beta posterior and return strategy with highest sample.
    ///
    /// Beta(a, b) approximated via Gamma(a, 1) / (Gamma(a, 1) + Gamma(b, 1)).
    /// Gamma shape approximated using Marsaglia's method.
    pub fn thompson_sample(&self) -> Option<String> {
        if self.strategy_indices.is_empty() {
            return None;
        }

        let mut best_name = None;
        let mut best_sample = 0.0_f64;

        for (name, &idx) in &self.strategy_indices {
            let s = self.metrics[idx].success_count.load(Ordering::Relaxed) as f64 + 1.0;
            let f = self.metrics[idx].fail_count.load(Ordering::Relaxed) as f64 + 1.0;

            // Sample from Gamma(shape, 1) using Marsaglia's method
            let ga = Self::sample_gamma(s);
            let gb = Self::sample_gamma(f);
            let sample = ga / (ga + gb);

            if sample > best_sample {
                best_sample = sample;
                best_name = Some(name.clone());
            }
        }

        best_name
    }

    /// Approximate Gamma(shape, 1) sample via Marsaglia & Tsang's method.
    fn sample_gamma(shape: f64) -> f64 {
        if shape < 1.0 {
            // For shape < 1, use the relation: Gamma(a) = Gamma(a+1) * U^(1/a)
            let u: f64 = rand_f64();
            return Self::sample_gamma(shape + 1.0) * u.powf(1.0 / shape);
        }

        let d = shape - 1.0 / 3.0;
        let c = 1.0 / (9.0 * d).sqrt();

        loop {
            let mut x;
            let mut v;
            loop {
                x = Self::sample_normal();
                v = 1.0 + c * x;
                if v > 0.0 {
                    break;
                }
            }
            v = v * v * v;
            let u: f64 = rand_f64();

            if u < 1.0 - 0.0331 * (x * x) * (x * x) {
                return d * v;
            }
            if u.ln() < 0.5 * x * x + d * (1.0 - v + v.ln()) {
                return d * v;
            }
        }
    }

    /// Approximate standard normal via Box-Muller.
    fn sample_normal() -> f64 {
        let u1: f64 = rand_f64().max(1e-10);
        let u2: f64 = rand_f64();
        (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
    }

    /// Gets metrics snapshot for a strategy.
    pub fn get_metrics(&self, strategy_name: &str) -> Option<StrategySnapshot> {
        let idx = self.strategy_indices.get(strategy_name)?;
        let m = &self.metrics[*idx];
        Some(StrategySnapshot {
            success_count: m.success_count.load(Ordering::Relaxed),
            fail_count: m.fail_count.load(Ordering::Relaxed),
            avg_latency_us: m.avg_latency_us(),
        })
    }

    /// All metrics as snapshots.
    pub fn all_metrics(&self) -> std::collections::HashMap<String, StrategySnapshot> {
        self.strategy_indices
            .iter()
            .map(|(name, &idx)| {
                let m = &self.metrics[idx];
                (
                    name.clone(),
                    StrategySnapshot {
                        success_count: m.success_count.load(Ordering::Relaxed),
                        fail_count: m.fail_count.load(Ordering::Relaxed),
                        avg_latency_us: m.avg_latency_us(),
                    },
                )
            })
            .collect()
    }

    /// Проверяет, нужно ли сменить стратегию.
    pub fn should_escalate(&self, strategy_name: &str) -> bool {
        let idx = match self.strategy_indices.get(strategy_name) {
            Some(&idx) => idx,
            None => return false,
        };
        let m = &self.metrics[idx];
        let f = m.fail_count.load(Ordering::Relaxed);
        m.success_rate() < 0.2 && f >= 5
    }

    /// T57: Проверяет наличие manual override для стратегии.
    pub fn has_manual_override(&self, strategy_name: &str) -> bool {
        self.manual_overrides.contains_key(strategy_name)
    }

    /// T57: Проверяет, активна ли стратегия (через manual override или success_count > 0).
    pub fn is_strategy_active(&self, strategy_name: &str) -> bool {
        if self.has_manual_override(strategy_name) {
            return true;
        }
        if let Some(&idx) = self.strategy_indices.get(strategy_name) {
            return self.metrics[idx].success_count.load(Ordering::Relaxed) > 0;
        }
        false
    }

    /// Gets recommended params for a strategy.
    pub fn recommend(&self, strategy_name: &str) -> TuneParams {
        if let Some(overridden) = self.manual_overrides.get(strategy_name) {
            return overridden.clone();
        }
        let idx = match self.strategy_indices.get(strategy_name) {
            Some(&idx) => idx,
            None => return TuneParams::default(),
        };
        let m = &self.metrics[idx];
        let mut params = TuneParams::default();

        if m.success_rate() < self.tune_threshold {
            params.split_size = Some(1);
            params.split_count = Some(5);
            params.fake_ttl_offset = Some(2);
            debug!(
                "AutoTune: {} low success ({:.1}%) → aggressive split",
                strategy_name,
                m.success_rate() * 100.0
            );
        } else if m.avg_latency_us() > 50_000 {
            params.split_count = Some(2);
            params.fake_ttl_offset = Some(1);
            debug!(
                "AutoTune: {} high latency ({}us) → simplified",
                strategy_name,
                m.avg_latency_us()
            );
        } else if m.success_rate() > 0.8 {
            params.split_size = Some(1);
            params.split_count = Some(2);
            debug!(
                "AutoTune: {} good ({:.1}%) → minimal",
                strategy_name,
                m.success_rate() * 100.0
            );
        }

        params
    }

    /// Reset all metrics.
    pub fn reset(&mut self) {
        for m in &self.metrics {
            m.success_count.store(0, Ordering::Relaxed);
            m.fail_count.store(0, Ordering::Relaxed);
            m.total_latency_us.store(0, Ordering::Relaxed);
        }
        self.strategy_indices.clear();
    }
}

/// Snapshot of strategy metrics (for read-only access).
#[derive(Debug, Clone)]
pub struct StrategySnapshot {
    pub success_count: u64,
    pub fail_count: u64,
    pub avg_latency_us: u64,
}

impl StrategySnapshot {
    pub fn success_rate(&self) -> f64 {
        let total = self.success_count + self.fail_count;
        if total == 0 {
            0.0
        } else {
            self.success_count as f64 / total as f64
        }
    }
}

impl Default for AutoTune {
    fn default() -> Self {
        Self::new()
    }
}

/// Pseudo-random f64 in (0, 1) using the project's thread-local ChaCha8Rng.
/// Used for Thompson Sampling noise — CSPRNG is overkill here, but we reuse
/// the existing infrastructure rather than adding another dependency.
///
/// The loop guarantees the open interval (0, 1) — Marsaglia's gamma
/// approximation calls `u.ln()` which would panic on exact 0.0.
fn rand_f64() -> f64 {
    loop {
        let v = crate::desync::rand::random_f64();
        if v > 0.0 && v < 1.0 {
            return v;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_tune_record() {
        let mut tune = AutoTune::new();
        tune.record("FakeSni", true, 1000);
        tune.record("FakeSni", true, 1500);
        tune.record("FakeSni", false, 0);

        let m = tune.get_metrics("FakeSni").unwrap();
        assert_eq!(m.success_count, 2);
        assert_eq!(m.fail_count, 1);
        assert!((m.success_rate() - 0.667).abs() < 0.01);
    }

    #[test]
    fn test_auto_tune_recommend_low_success() {
        let mut tune = AutoTune::new();
        for _ in 0..3 {
            tune.record("Test", false, 0);
        }
        let params = tune.recommend("Test");
        assert_eq!(params.split_size, Some(1));
        assert_eq!(params.split_count, Some(5));
    }

    #[test]
    fn test_auto_tune_should_escalate() {
        let mut tune = AutoTune::new();
        for _ in 0..6 {
            tune.record("Test", false, 0);
        }
        assert!(tune.should_escalate("Test"));
    }

    #[test]
    fn test_auto_tune_no_escalate_good() {
        let mut tune = AutoTune::new();
        for _ in 0..10 {
            tune.record("Test", true, 500);
        }
        assert!(!tune.should_escalate("Test"));
    }

    #[test]
    fn test_thompson_sample_returns_something() {
        let mut tune = AutoTune::new();
        tune.record("A", true, 100);
        tune.record("A", true, 100);
        tune.record("B", false, 0);
        let sampled = tune.thompson_sample();
        assert!(sampled.is_some());
    }

    #[test]
    fn test_is_strategy_active_and_manual_override() {
        let mut tune = AutoTune::new();
        // inactive by default
        assert!(!tune.is_strategy_active("Test"));
        assert!(!tune.has_manual_override("Test"));

        // active after manual override
        tune.manual_overrides
            .insert("Test".to_string(), TuneParams::default());
        assert!(tune.has_manual_override("Test"));
        assert!(tune.is_strategy_active("Test"));

        // active after success
        let mut tune2 = AutoTune::new();
        tune2.record("Test", true, 100);
        assert!(!tune2.has_manual_override("Test"));
        assert!(tune2.is_strategy_active("Test"));
    }
}
