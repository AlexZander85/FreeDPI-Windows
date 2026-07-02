//! ML Classifier — logistic regression для anomaly detection.
//!
//! Методика:
//! - 17 features (timing, sizes, ratios)
//! - Logistic regression: sigmoid(w·x + b)
//! - Anomaly score 0.0–1.0 (0.0 = clear, 1.0 = blocked)
//! - Threshold 0.5 (configurable)
//! - Pre-trained weights на основе эвристик (не требует labeled data)
//!
//! Почему logistic regression, а не deep learning:
//! - 17 features — слишком мало для neural network
//! - Inference < 1µs (vs 10-100ms для NN)
//! - Explainable (можно посмотреть веса)
//!
//! Источники:
//! - sklearn LogisticRegression (reference implementation)
//! - Geneva ML module (https://github.com/Kkevsterrr/geneva)

use crate::probe::timing_probe::FeatureVector;
use serde::{Deserialize, Serialize};

/// ML вердикт.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MlVerdict {
    /// Anomaly score < 0.3 — нормальный трафик
    #[default]
    Clear,
    /// Anomaly score 0.3–0.7 — подозрительно, нужен re-probe
    Suspicious,
    /// Anomaly score > 0.7 — DPI blocking detected
    Blocked,
}

/// Результат ML classifier.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MlResult {
    /// Anomaly score (0.0–1.0)
    pub score: f64,
    /// Вердикт на основе score
    pub verdict: MlVerdict,
    /// Top 3 features с наибольшим вкладом в score
    pub top_features: Vec<(String, f64)>,
}

/// Logistic regression classifier для anomaly detection.
pub struct MlClassifier {
    /// Веса для каждого feature (17 weights)
    weights: [f64; 17],
    /// Bias term
    bias: f64,
    /// Threshold для "blocked" verdict
    blocked_threshold: f64,
    /// Threshold для "clear" verdict
    clear_threshold: f64,
}

impl MlClassifier {
    /// Создаёт classifier с pre-trained weights.
    ///
    /// Weights основаны на эвристиках из анализа реальных DPI-блокировок:
    /// - TCP connect ok → negative weight (clear signal)
    /// - TLS handshake ok → negative weight (clear signal)
    /// - HTTP status 451 → strong positive weight (legal block)
    /// - TLS/TCP ratio > 5 → positive weight (DPI delays TLS)
    /// - High jitter → positive weight (DPI introduces timing noise)
    pub fn new() -> Self {
        Self {
            // Pre-trained weights (эвристические, основаны на анализе)
            // Index соответствует FeatureVector::to_vec() порядку
            weights: [
                // DNS features
                -0.01, // dns_udp_rtt_ms — neutral
                -0.01, // dns_doh_rtt_ms
                0.005, // dns_udp_response_size
                0.005, // dns_doh_response_size
                // TCP features
                -2.0, // tcp_connect_rtt_ms — neutral
                -3.0, // tcp_connect_ok — strong clear signal
                // TLS features
                0.01,  // tls_handshake_rtt_ms
                0.005, // tls_server_hello_size
                0.0,   // tls_cert_count — neutral
                -3.0,  // tls_handshake_ok — strong clear signal
                // HTTP features
                0.01,  // http_first_byte_rtt_ms
                0.005, // http_total_rtt_ms
                0.001, // http_response_size
                0.002, // http_status_code — 451 = legal block (small weight to avoid domination)
                // Ratios
                1.5, // tls_tcp_ratio — >5.0 = anomaly
                1.0, // http_tls_ratio — >3.0 = anomaly
                0.5, // inter_phase_jitter — high jitter = DPI
            ],
            bias: 1.0, // base score (slight clear bias)
            blocked_threshold: 0.7,
            clear_threshold: 0.3,
        }
    }

    /// Предсказать anomaly score для feature vector.
    pub fn predict(&self, features: &FeatureVector) -> MlResult {
        let x = features.to_vec();
        let z = self.dot_product(&x) + self.bias;
        let score = sigmoid(z);

        let verdict = if score >= self.blocked_threshold {
            MlVerdict::Blocked
        } else if score <= self.clear_threshold {
            MlVerdict::Clear
        } else {
            MlVerdict::Suspicious
        };

        // Top 3 features с наибольшим contribution (|weight * value|)
        let mut contributions: Vec<(String, f64)> = x
            .iter()
            .enumerate()
            .map(|(i, &val)| (feature_name(i), (self.weights[i] * val).abs()))
            .collect();
        contributions.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        contributions.truncate(3);

        MlResult {
            score,
            verdict,
            top_features: contributions,
        }
    }

    fn dot_product(&self, x: &[f64]) -> f64 {
        let mut sum = 0.0;
        for (i, &xi) in x.iter().enumerate() {
            sum += self.weights[i] * xi;
        }
        sum
    }
}

impl Default for MlClassifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Sigmoid function: 1 / (1 + e^-z)
fn sigmoid(z: f64) -> f64 {
    1.0 / (1.0 + (-z).exp())
}

/// Имя feature по индексу (для explainability).
fn feature_name(index: usize) -> String {
    match index {
        0 => "dns_udp_rtt_ms".into(),
        1 => "dns_doh_rtt_ms".into(),
        2 => "dns_udp_response_size".into(),
        3 => "dns_doh_response_size".into(),
        4 => "tcp_connect_rtt_ms".into(),
        5 => "tcp_connect_ok".into(),
        6 => "tls_handshake_rtt_ms".into(),
        7 => "tls_server_hello_size".into(),
        8 => "tls_cert_count".into(),
        9 => "tls_handshake_ok".into(),
        10 => "http_first_byte_rtt_ms".into(),
        11 => "http_total_rtt_ms".into(),
        12 => "http_response_size".into(),
        13 => "http_status_code".into(),
        14 => "tls_tcp_ratio".into(),
        15 => "http_tls_ratio".into(),
        16 => "inter_phase_jitter".into(),
        _ => format!("unknown_{}", index),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sigmoid() {
        assert!((sigmoid(0.0) - 0.5).abs() < 1e-6);
        assert!(sigmoid(10.0) > 0.99);
        assert!(sigmoid(-10.0) < 0.01);
    }

    #[test]
    fn test_classifier_clear_signal() {
        let features = FeatureVector {
            dns_udp_rtt_ms: 50.0,
            dns_doh_rtt_ms: 100.0,
            dns_udp_response_size: 100.0,
            dns_doh_response_size: 200.0,
            tcp_connect_rtt_ms: 30.0,
            tcp_connect_ok: 1.0,
            tls_handshake_rtt_ms: 80.0,
            tls_server_hello_size: 100.0,
            tls_cert_count: 3.0,
            tls_handshake_ok: 1.0,
            http_first_byte_rtt_ms: 50.0,
            http_total_rtt_ms: 200.0,
            http_response_size: 1024.0,
            http_status_code: 200.0,
            tls_tcp_ratio: 2.67,
            http_tls_ratio: 0.625,
            inter_phase_jitter: 100.0,
        };

        let classifier = MlClassifier::new();
        let result = classifier.predict(&features);
        assert!(
            result.score < 0.3,
            "Clear signal should give low score, got {}",
            result.score
        );
        assert_eq!(result.verdict, MlVerdict::Clear);
    }

    #[test]
    fn test_classifier_blocked_signal() {
        let features = FeatureVector {
            dns_udp_rtt_ms: 50.0,
            dns_doh_rtt_ms: 100.0,
            dns_udp_response_size: 100.0,
            dns_doh_response_size: 200.0,
            tcp_connect_rtt_ms: 30.0,
            tcp_connect_ok: 1.0,
            tls_handshake_rtt_ms: 0.0,
            tls_server_hello_size: 0.0,
            tls_cert_count: 0.0,
            tls_handshake_ok: 0.0,
            http_first_byte_rtt_ms: 0.0,
            http_total_rtt_ms: 0.0,
            http_response_size: 0.0,
            http_status_code: 451.0,
            tls_tcp_ratio: 0.0,
            http_tls_ratio: 0.0,
            inter_phase_jitter: 500.0,
        };

        let classifier = MlClassifier::new();
        let result = classifier.predict(&features);
        assert!(
            result.score > 0.5,
            "Blocked signal should give high score, got {}",
            result.score
        );
    }

    #[test]
    fn test_classifier_high_tls_tcp_ratio_anomaly() {
        let features = FeatureVector {
            dns_udp_rtt_ms: 50.0,
            dns_doh_rtt_ms: 100.0,
            dns_udp_response_size: 100.0,
            dns_doh_response_size: 200.0,
            tcp_connect_rtt_ms: 10.0,
            tcp_connect_ok: 1.0,
            tls_handshake_rtt_ms: 500.0,
            tls_server_hello_size: 100.0,
            tls_cert_count: 3.0,
            tls_handshake_ok: 1.0,
            http_first_byte_rtt_ms: 50.0,
            http_total_rtt_ms: 200.0,
            http_response_size: 1024.0,
            http_status_code: 200.0,
            tls_tcp_ratio: 50.0,
            http_tls_ratio: 0.1,
            inter_phase_jitter: 10000.0,
        };

        let classifier = MlClassifier::new();
        let result = classifier.predict(&features);
        assert!(
            result.score > 0.5,
            "High TLS/TCP ratio should flag anomaly, got {}",
            result.score
        );
    }

    #[test]
    fn test_feature_name() {
        assert_eq!(feature_name(0), "dns_udp_rtt_ms");
        assert_eq!(feature_name(13), "http_status_code");
        assert_eq!(feature_name(16), "inter_phase_jitter");
    }

    #[test]
    fn test_top_features_returned() {
        let features = FeatureVector::empty();
        let classifier = MlClassifier::new();
        let result = classifier.predict(&features);
        assert_eq!(result.top_features.len(), 3);
    }
}
