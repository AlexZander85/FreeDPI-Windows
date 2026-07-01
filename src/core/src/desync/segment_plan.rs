//! Custom Segment Plans + Noise (из SpoofDPI).
//!
//! TOML-конфигурация точных позиций split в ClientHello
//! с параметром noise для jitter.
//!
//! ## Принцип
//! Каждый план описывает позицию split:
//! - `ref`: "head" (начало пакета) или "sni" (начало SNI)
//! - `offset`: смещение от ref в байтах
//! - `lazy`: флаг для disorder (TTL=1)
//! - `noise`: ±random(N) байт jitter к offset
//!
//! Планы сортируются по позиции независимо от порядка объявления.
//! Noise делает каждый пакет уникальным — DPI не может натренировать паттерн.

use std::f64::consts::PI;

use serde::{Deserialize, Serialize};

/// Log-normal distributed jitter using Box-Muller transform.
/// Small values occur often, large values rarely — matching natural TCP scheduling jitter.
///
/// # Arguments
/// * `max` — maximum output value (inclusive)
/// * `conn_rng` — per-connection PRNG (internal, non-observable)
///
/// # Returns
/// Jitter in [0, max] with log-normal distribution.
pub fn natural_jitter(max: u32, conn_rng: &mut crate::desync::rand::PerConnRng) -> u32 {
    if max == 0 {
        return 0;
    }

    // Box-Muller: two uniform -> one standard normal
    let u1_raw = (conn_rng.next_internal_u64() as f64) / (u64::MAX as f64);
    let u2_raw = (conn_rng.next_internal_u64() as f64) / (u64::MAX as f64);
    // Clamp u1 away from 0 to avoid ln(0)
    let u1 = if u1_raw <= 0.0 {
        f64::MIN_POSITIVE
    } else if u1_raw >= 1.0 {
        0.9999
    } else {
        u1_raw
    };
    let u2 = if u2_raw <= 0.0 {
        f64::MIN_POSITIVE
    } else if u2_raw >= 1.0 {
        0.9999
    } else {
        u2_raw
    };

    let z = (-2.0 * u1.ln()).sqrt() * (2.0 * PI * u2).cos();

    // Log-normal: exp(N(mu, sigma^2)). Median at max/3, sigma=0.8 for moderate spread.
    let mu = (max as f64 / 3.0).ln();
    let sigma = 0.8;
    let log_normal = (mu + sigma * z).exp();

    (log_normal.max(0.0).min(max as f64) as u32).min(max)
}

/// Референсная точка для split.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SplitRef {
    /// Начало пакета (байт 0).
    Head,
    /// Начало SNI extension в ClientHello.
    Sni,
}

/// Один сегмент-план: позиция split + флаги.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentPlan {
    /// Референсная точка.
    pub ref_point: SplitRef,
    /// Смещение от ref в байтах.
    pub offset: i32,
    /// Disorder: отправить сегмент с TTL=1 (умрёт у первого хопа, DPI видит).
    #[serde(default)]
    pub lazy: bool,
    /// Noise: ±random(noise) байт jitter к offset.
    /// Делает паттерн фрагментации непредсказуемым.
    #[serde(default)]
    pub noise: u32,
}

/// Набор сегмент-планов для одного соединения.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentPlanSet {
    /// Имя плана (для отладки / GUI).
    #[serde(default)]
    pub name: String,
    /// Планы split (будут отсортированы по позиции).
    pub plans: Vec<SegmentPlan>,
}

/// Рассчитанная позиция split (после применения noise).
#[derive(Debug, Clone, Copy)]
pub struct SplitPosition {
    /// Абсолютная позиция split в пакете.
    pub position: usize,
    /// Отправлять ли этот сегмент с TTL=1 (disorder).
    pub lazy: bool,
}

impl SegmentPlanSet {
    /// Вычисляет отсортированные позиции split для конкретного пакета.
    ///
    /// # Arguments
    /// * `sni_offset` — абсолютный байт начала SNI в ClientHello (0 если нет SNI).
    /// * `conn_rng` — per-connection PRNG для jitter.
    ///
    /// # Returns
    /// Вектор SplitPosition, отсортированный по position.
    pub fn resolve(
        &self,
        sni_offset: usize,
        conn_rng: &mut crate::desync::rand::PerConnRng,
    ) -> Vec<SplitPosition> {
        let mut positions: Vec<SplitPosition> = self
            .plans
            .iter()
            .map(|plan| {
                let base = match plan.ref_point {
                    SplitRef::Head => 0usize,
                    SplitRef::Sni => sni_offset,
                };
                let noise = if plan.noise > 0 {
                    natural_jitter(plan.noise, conn_rng) as i32
                } else {
                    0
                };
                let raw = base as i32 + plan.offset + noise;
                let position = raw.max(0) as usize;
                SplitPosition {
                    position,
                    lazy: plan.lazy,
                }
            })
            .filter(|p| p.position > 0)
            .collect();

        positions.sort_by_key(|p| p.position);
        positions
    }
}

/// Парсит SegmentPlanSet из TOML строки.
pub fn parse_plan_set(toml_str: &str) -> anyhow::Result<SegmentPlanSet> {
    Ok(toml::from_str(toml_str)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::desync::rand::PerConnRng;

    #[test]
    fn test_basic_plan() {
        let mut rng = PerConnRng::new(1);
        let plan = SegmentPlanSet {
            name: "test".into(),
            plans: vec![
                SegmentPlan {
                    ref_point: SplitRef::Sni,
                    offset: 0,
                    lazy: false,
                    noise: 0,
                },
                SegmentPlan {
                    ref_point: SplitRef::Sni,
                    offset: 5,
                    lazy: false,
                    noise: 0,
                },
            ],
        };
        let positions = plan.resolve(100, &mut rng);
        assert_eq!(positions.len(), 2);
        assert_eq!(positions[0].position, 100);
        assert_eq!(positions[1].position, 105);
    }

    #[test]
    fn test_plan_with_noise() {
        let mut rng = PerConnRng::new(42);
        let plan = SegmentPlanSet {
            name: "noisy".into(),
            plans: vec![SegmentPlan {
                ref_point: SplitRef::Head,
                offset: 10,
                lazy: false,
                noise: 5,
            }],
        };
        // Position should be in range [10, 15] with log-normal distribution
        let positions = plan.resolve(0, &mut rng);
        assert_eq!(positions.len(), 1);
        assert!(positions[0].position >= 10);
        assert!(positions[0].position <= 15);
    }

    #[test]
    fn test_lazy_flag() {
        let mut rng = PerConnRng::new(7);
        let plan = SegmentPlanSet {
            name: "lazy-test".into(),
            plans: vec![SegmentPlan {
                ref_point: SplitRef::Sni,
                offset: 3,
                lazy: true,
                noise: 0,
            }],
        };
        let positions = plan.resolve(50, &mut rng);
        assert_eq!(positions[0].position, 53);
        assert!(positions[0].lazy);
    }

    #[test]
    fn test_sorted_by_position() {
        let mut rng = PerConnRng::new(99);
        let plan = SegmentPlanSet {
            name: "sort-test".into(),
            plans: vec![
                SegmentPlan {
                    ref_point: SplitRef::Sni,
                    offset: 10,
                    lazy: false,
                    noise: 0,
                },
                SegmentPlan {
                    ref_point: SplitRef::Head,
                    offset: 5,
                    lazy: false,
                    noise: 0,
                },
                SegmentPlan {
                    ref_point: SplitRef::Sni,
                    offset: -3,
                    lazy: false,
                    noise: 0,
                },
            ],
        };
        let positions = plan.resolve(20, &mut rng);
        // Head+5=5, Sni-3=17, Sni+10=30
        assert_eq!(positions[0].position, 5);
        assert_eq!(positions[1].position, 17);
        assert_eq!(positions[2].position, 30);
    }

    #[test]
    fn test_toml_parse() {
        let toml = r#"
name = "aggressive"
[[plans]]
ref_point = "sni"
offset = 0
lazy = false
noise = 3

[[plans]]
ref_point = "sni"
offset = 10
lazy = true
noise = 5
"#;
        let plan_set = parse_plan_set(toml).unwrap();
        assert_eq!(plan_set.name, "aggressive");
        assert_eq!(plan_set.plans.len(), 2);
        assert!(plan_set.plans[1].lazy);
    }

    #[test]
    fn test_natural_jitter_distribution() {
        let mut rng = PerConnRng::new(12345);
        let max = 100u32;
        let n = 10000;
        let mut sum = 0u64;
        let mut min_seen = u32::MAX;
        let mut max_seen = 0u32;

        for _ in 0..n {
            let j = natural_jitter(max, &mut rng);
            assert!(j <= max, "jitter {j} exceeded max {max}");
            sum += j as u64;
            min_seen = min_seen.min(j);
            max_seen = max_seen.max(j);
        }

        let mean = sum as f64 / n as f64;
        // Log-normal: mean should be less than max/2, and most values small
        assert!(
            mean < max as f64 / 2.0,
            "mean {mean} too high for log-normal"
        );
        assert!(
            min_seen < max / 2,
            "min_seen {min_seen} too high, expected small values"
        );
        assert!(max_seen > 0, "max_seen should be > 0");
    }
}
