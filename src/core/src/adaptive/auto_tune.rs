//! Auto-Tune — автоматическая подстройка параметров стратегий.
//!
//! ## Принцип
//! На основе результатов применения стратегий (success/fail, latency)
//! автоматически подстраиваем параметры: split_size, ttl_offset,
//! split_count, inject_delay.
//!
//! ## Источник
//! Адаптировано из [autodpi](https://github.com/brannondorsey/autodpi) — Auto-tune.

use arc_swap::ArcSwap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::debug;

/// Параметры для auto-tune.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct TuneParams {
    pub split_size: Option<usize>,
    pub split_count: Option<usize>,
    pub fake_ttl_offset: Option<u8>,
    pub max_seg_size: Option<usize>,
}

/// Strategy metrics stored as atomics for lock-free access.
pub struct StrategyMetrics {
    /// P0-07: Успехи/неудачи по сетевым исходам (RST, ESTABLISHED, TIMEOUT).
    /// Только эти счётчики влияют на Thompson sampling.
    pub success_count: AtomicU64,
    pub fail_count: AtomicU64,
    /// P0-07: Локальные применения desync (не влияют на Thompson).
    pub application_count: AtomicU64,
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
            application_count: AtomicU64::new(0),
            total_latency_us: AtomicU64::new(0),
        }
    }

    /// P0-07: success_rate теперь считает только outcome-счётчики.
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
    metrics_by_profile: Box<[StrategyMetrics]>,
    name_to_id: std::collections::HashMap<String, crate::adaptive::strategy_profile::ProfileId>,
    overrides: arc_swap::ArcSwap<Vec<Option<TuneParams>>>,
    tune_threshold: f64,
    // Dynamic slots fallback for unregistered names (only used in tests)
    dynamic_names: std::sync::Mutex<std::collections::HashMap<String, usize>>,
    dynamic_start_idx: usize,
}

impl AutoTune {
    pub fn new() -> Self {
        let registry = crate::adaptive::strategy_profile::StrategyProfileRegistry::default();
        Self::new_with_registry(&registry)
    }

    pub fn new_with_registry(
        registry: &crate::adaptive::strategy_profile::StrategyProfileRegistry,
    ) -> Self {
        let registry_capacity = registry.len();
        let dynamic_capacity = 32; // allocate 32 extra slots for dynamic/test profiles
        let total_capacity = registry_capacity + dynamic_capacity;

        let mut metrics = Vec::with_capacity(total_capacity);
        let mut name_to_id = std::collections::HashMap::new();
        let mut overrides = Vec::with_capacity(total_capacity);

        for i in 0..total_capacity {
            metrics.push(StrategyMetrics::new());
            overrides.push(None);
            if i < registry_capacity {
                if let Some(profile) = registry
                    .get_by_profile_id(crate::adaptive::strategy_profile::ProfileId(i as u32))
                {
                    name_to_id.insert(profile.name.clone(), profile.id);
                }
            }
        }

        Self {
            metrics_by_profile: metrics.into_boxed_slice(),
            name_to_id,
            overrides: ArcSwap::from_pointee(overrides),
            tune_threshold: 0.5,
            dynamic_names: std::sync::Mutex::new(std::collections::HashMap::new()),
            dynamic_start_idx: registry_capacity,
        }
    }

    fn get_index_for_name(&self, name: &str) -> Option<usize> {
        if let Some(&id) = self.name_to_id.get(name) {
            return Some(id.0 as usize);
        }

        let mut dynamic = self.dynamic_names.lock().unwrap();
        if let Some(&idx) = dynamic.get(name) {
            return Some(idx);
        }

        let next_slot = self.dynamic_start_idx + dynamic.len();
        if next_slot < self.metrics_by_profile.len() {
            dynamic.insert(name.to_string(), next_slot);
            Some(next_slot)
        } else {
            // Wrap around or fallback to first dynamic slot if exhausted
            Some(self.dynamic_start_idx)
        }
    }

    pub fn set_override(&self, strategy_name: &str, params: TuneParams) {
        if let Some(idx) = self.get_index_for_name(strategy_name) {
            let mut curr = (**self.overrides.load()).clone();
            if idx < curr.len() {
                curr[idx] = Some(params);
                self.overrides.store(Arc::new(curr));
            }
        }
    }

    pub fn clear_override(&self, strategy_name: &str) {
        if let Some(idx) = self.get_index_for_name(strategy_name) {
            let mut curr = (**self.overrides.load()).clone();
            if idx < curr.len() {
                curr[idx] = None;
                self.overrides.store(Arc::new(curr));
            }
        }
    }

    /// P0-07: Записывает сетевое событие-исход (RST, ESTABLISHED, TIMEOUT).
    /// Только этот метод обновляет success/fail — то, что влияет на Thompson sampling
    /// и should_escalate. Вызывается из engine при наблюдении реального исхода
    /// для соединения (inbound RST = fail, inbound SYN-ACK/Established = success).
    pub fn record_outcome(&self, strategy_name: &str, success: bool, latency_us: u64) {
        if let Some(idx) = self.get_index_for_name(strategy_name) {
            self.record_outcome_by_id_index(idx, success, latency_us);
        }
    }

    pub fn record_outcome_by_id(
        &self,
        id: crate::adaptive::strategy_profile::ProfileId,
        success: bool,
        latency_us: u64,
    ) {
        self.record_outcome_by_id_index(id.0 as usize, success, latency_us);
    }

    #[inline]
    fn record_outcome_by_id_index(&self, idx: usize, success: bool, latency_us: u64) {
        if let Some(m) = self.metrics_by_profile.get(idx) {
            if success {
                m.success_count.fetch_add(1, Ordering::Relaxed);
                m.total_latency_us.fetch_add(latency_us, Ordering::Relaxed);
            } else {
                m.fail_count.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// P0-07: Записывает факт локального применения desync (без влияния на Thompson).
    /// Инкрементирует application_count для отслеживания статистики.
    pub fn record_application(&self, strategy_name: &str) {
        if let Some(idx) = self.get_index_for_name(strategy_name) {
            self.record_application_by_id_index(idx);
        }
    }

    pub fn record_application_by_id(&self, id: crate::adaptive::strategy_profile::ProfileId) {
        self.record_application_by_id_index(id.0 as usize);
    }

    #[inline]
    fn record_application_by_id_index(&self, idx: usize) {
        if let Some(m) = self.metrics_by_profile.get(idx) {
            m.application_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Thompson sampling: sample from Beta posterior and return strategy with highest sample.
    ///
    /// Beta(a, b) approximated via Gamma(a, 1) / (Gamma(a, 1) + Gamma(b, 1)).
    /// Gamma shape approximated using Marsaglia's method.
    pub fn thompson_sample(&self) -> Option<String> {
        if self.name_to_id.is_empty() && self.dynamic_names.lock().unwrap().is_empty() {
            return None;
        }

        let mut best_name = None;
        let mut best_sample = 0.0_f64;

        let mut process_candidate = |name: &str, idx: usize| {
            if let Some(m) = self.metrics_by_profile.get(idx) {
                let s = m.success_count.load(Ordering::Relaxed) as f64 + 1.0;
                let f = m.fail_count.load(Ordering::Relaxed) as f64 + 1.0;

                // Sample from Gamma(shape, 1) using Marsaglia's method
                let ga = Self::sample_gamma(s);
                let gb = Self::sample_gamma(f);
                let sample = ga / (ga + gb);

                if sample > best_sample {
                    best_sample = sample;
                    best_name = Some(name.to_string());
                }
            }
        };

        for (name, &id) in &self.name_to_id {
            process_candidate(name, id.0 as usize);
        }

        let dynamic = self.dynamic_names.lock().unwrap();
        for (name, &idx) in &*dynamic {
            process_candidate(name, idx);
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
        let idx = self.get_index_for_name(strategy_name)?;
        let m = self.metrics_by_profile.get(idx)?;
        Some(StrategySnapshot {
            success_count: m.success_count.load(Ordering::Relaxed),
            fail_count: m.fail_count.load(Ordering::Relaxed),
            application_count: m.application_count.load(Ordering::Relaxed),
            avg_latency_us: m.avg_latency_us(),
        })
    }

    /// All metrics as snapshots.
    pub fn all_metrics(&self) -> std::collections::HashMap<String, StrategySnapshot> {
        let mut res = std::collections::HashMap::new();
        for (name, &id) in &self.name_to_id {
            if let Some(m) = self.metrics_by_profile.get(id.0 as usize) {
                res.insert(
                    name.clone(),
                    StrategySnapshot {
                        success_count: m.success_count.load(Ordering::Relaxed),
                        fail_count: m.fail_count.load(Ordering::Relaxed),
                        application_count: m.application_count.load(Ordering::Relaxed),
                        avg_latency_us: m.avg_latency_us(),
                    },
                );
            }
        }

        let dynamic = self.dynamic_names.lock().unwrap();
        for (name, &idx) in &*dynamic {
            if let Some(m) = self.metrics_by_profile.get(idx) {
                res.insert(
                    name.clone(),
                    StrategySnapshot {
                        success_count: m.success_count.load(Ordering::Relaxed),
                        fail_count: m.fail_count.load(Ordering::Relaxed),
                        application_count: m.application_count.load(Ordering::Relaxed),
                        avg_latency_us: m.avg_latency_us(),
                    },
                );
            }
        }
        res
    }

    /// Проверяет, нужно ли сменить стратегию.
    pub fn should_escalate(&self, strategy_name: &str) -> bool {
        let Some(idx) = self.get_index_for_name(strategy_name) else {
            return false;
        };
        let Some(m) = self.metrics_by_profile.get(idx) else {
            return false;
        };
        let f = m.fail_count.load(Ordering::Relaxed);
        m.success_rate() < 0.2 && f >= 5
    }

    /// T57: Проверяет наличие manual override для стратегии.
    pub fn has_manual_override(&self, strategy_name: &str) -> bool {
        if let Some(idx) = self.get_index_for_name(strategy_name) {
            if let Some(Some(_)) = self.overrides.load().get(idx) {
                return true;
            }
        }
        false
    }

    /// T57: Проверяет, активна ли стратегия (через manual override или success_count > 0).
    pub fn is_strategy_active(&self, strategy_name: &str) -> bool {
        if self.has_manual_override(strategy_name) {
            return true;
        }
        if let Some(idx) = self.get_index_for_name(strategy_name) {
            if let Some(m) = self.metrics_by_profile.get(idx) {
                return m.success_count.load(Ordering::Relaxed) > 0;
            }
        }
        false
    }

    /// Gets recommended params for a strategy.
    pub fn recommend(&self, strategy_name: &str) -> TuneParams {
        if let Some(idx) = self.get_index_for_name(strategy_name) {
            if let Some(Some(overridden)) = self.overrides.load().get(idx) {
                return overridden.clone();
            }
            if let Some(m) = self.metrics_by_profile.get(idx) {
                let mut params = TuneParams::default();
                if m.success_rate() < self.tune_threshold {
                    params.split_size = Some(1);
                    params.split_count = Some(5);
                    params.fake_ttl_offset = Some(2);
                } else if m.avg_latency_us() > 50_000 {
                    params.split_count = Some(2);
                    params.fake_ttl_offset = Some(1);
                } else if m.success_rate() > 0.8 {
                    params.split_size = Some(1);
                    params.split_count = Some(2);
                }
                return params;
            }
        }
        TuneParams::default()
    }

    #[inline]
    pub fn recommend_by_id(&self, id: crate::adaptive::strategy_profile::ProfileId) -> TuneParams {
        let idx = id.0 as usize;
        if let Some(Some(overridden)) = self.overrides.load().get(idx) {
            return overridden.clone();
        }
        let Some(m) = self.metrics_by_profile.get(idx) else {
            return TuneParams::default();
        };
        let mut params = TuneParams::default();

        if m.success_rate() < self.tune_threshold {
            params.split_size = Some(1);
            params.split_count = Some(5);
            params.fake_ttl_offset = Some(2);
            let mut strategy_name = "unknown";
            for (name, &profile_id) in &self.name_to_id {
                if profile_id == id {
                    strategy_name = name;
                    break;
                }
            }
            debug!(
                "AutoTune: {} low success ({:.1}%) → aggressive split",
                strategy_name,
                m.success_rate() * 100.0
            );
        } else if m.avg_latency_us() > 50_000 {
            params.split_count = Some(2);
            params.fake_ttl_offset = Some(1);
            let mut strategy_name = "unknown";
            for (name, &profile_id) in &self.name_to_id {
                if profile_id == id {
                    strategy_name = name;
                    break;
                }
            }
            debug!(
                "AutoTune: {} high latency ({}us) → simplified",
                strategy_name,
                m.avg_latency_us()
            );
        } else if m.success_rate() > 0.8 {
            params.split_size = Some(1);
            params.split_count = Some(2);
            let mut strategy_name = "unknown";
            for (name, &profile_id) in &self.name_to_id {
                if profile_id == id {
                    strategy_name = name;
                    break;
                }
            }
            debug!(
                "AutoTune: {} good ({:.1}%) → minimal",
                strategy_name,
                m.success_rate() * 100.0
            );
        }

        params
    }

    /// Reset all metrics.
    pub fn reset(&self) {
        for m in &*self.metrics_by_profile {
            m.success_count.store(0, Ordering::Relaxed);
            m.fail_count.store(0, Ordering::Relaxed);
            m.total_latency_us.store(0, Ordering::Relaxed);
            m.application_count.store(0, Ordering::Relaxed);
        }
        let capacity = self.metrics_by_profile.len();
        let mut new_overrides = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            new_overrides.push(None);
        }
        self.overrides.store(Arc::new(new_overrides));
        self.dynamic_names.lock().unwrap().clear();
    }
}

/// Snapshot of strategy metrics (for read-only access).
#[derive(Debug, Clone)]
pub struct StrategySnapshot {
    pub success_count: u64,
    pub fail_count: u64,
    pub application_count: u64,
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

/// Pseudo-random f64 in (0, 1) using the project's thread-local ChaCha12Rng.
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
        let tune = AutoTune::new();
        tune.record_outcome("FakeSni", true, 1000);
        tune.record_outcome("FakeSni", true, 1500);
        tune.record_outcome("FakeSni", false, 0);

        let m = tune.get_metrics("FakeSni").unwrap();
        assert_eq!(m.success_count, 2);
        assert_eq!(m.fail_count, 1);
        assert!((m.success_rate() - 0.667).abs() < 0.01);
    }

    #[test]
    fn test_auto_tune_recommend_low_success() {
        let tune = AutoTune::new();
        for _ in 0..3 {
            tune.record_outcome("Test", false, 0);
        }
        let params = tune.recommend("Test");
        assert_eq!(params.split_size, Some(1));
        assert_eq!(params.split_count, Some(5));
    }

    #[test]
    fn test_auto_tune_should_escalate() {
        let tune = AutoTune::new();
        for _ in 0..6 {
            tune.record_outcome("Test", false, 0);
        }
        assert!(tune.should_escalate("Test"));
    }

    #[test]
    fn test_auto_tune_no_escalate_good() {
        let tune = AutoTune::new();
        for _ in 0..10 {
            tune.record_outcome("Test", true, 500);
        }
        assert!(!tune.should_escalate("Test"));
    }

    #[test]
    fn test_thompson_sample_returns_something() {
        let tune = AutoTune::new();
        tune.record_outcome("A", true, 100);
        tune.record_outcome("A", true, 100);
        tune.record_outcome("B", false, 0);
        let sampled = tune.thompson_sample();
        assert!(sampled.is_some());
    }

    #[test]
    fn test_is_strategy_active_and_manual_override() {
        let tune = AutoTune::new();
        // inactive by default
        assert!(!tune.is_strategy_active("Test"));
        assert!(!tune.has_manual_override("Test"));

        // active after manual override
        tune.set_override("Test", TuneParams::default());
        assert!(tune.has_manual_override("Test"));
        assert!(tune.is_strategy_active("Test"));

        // active after success
        let tune2 = AutoTune::new();
        tune2.record_outcome("Test", true, 100);
        assert!(!tune2.has_manual_override("Test"));
        assert!(tune2.is_strategy_active("Test"));
    }
}
