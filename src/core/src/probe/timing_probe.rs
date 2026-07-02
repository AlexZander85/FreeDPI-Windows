//! Timing Probe — сбор timing features для ML-анализа.
//!
//! Методика:
//! Во время normal probe (DNS → TCP → TLS → HTTP) собираем timing features:
//! - RTT per phase
//! - Inter-packet delays
//! - Response sizes
//! - Entropy of TLS Random / session_id
//!
//! Эти features → MlClassifier → anomaly score → verdict.

use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Feature vector для ML classifier.
/// 17 features — достаточно для logistic regression без overfitting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureVector {
    // DNS phase
    /// DNS UDP response time (ms), 0 if failed
    pub dns_udp_rtt_ms: f64,
    /// DNS DoH response time (ms), 0 if failed
    pub dns_doh_rtt_ms: f64,
    /// DNS UDP response size (bytes)
    pub dns_udp_response_size: f64,
    /// DNS DoH response size (bytes)
    pub dns_doh_response_size: f64,

    // TCP phase
    /// TCP connect time (ms), 0 if failed
    pub tcp_connect_rtt_ms: f64,
    /// TCP connect succeeded (1.0 = yes, 0.0 = no)
    pub tcp_connect_ok: f64,

    // TLS phase
    /// TLS handshake time (ms), 0 if failed
    pub tls_handshake_rtt_ms: f64,
    /// TLS ServerHello size (bytes)
    pub tls_server_hello_size: f64,
    /// TLS Certificate count
    pub tls_cert_count: f64,
    /// TLS handshake succeeded (1.0 = yes, 0.0 = no)
    pub tls_handshake_ok: f64,

    // HTTP phase
    /// HTTP first byte time (ms), 0 if failed
    pub http_first_byte_rtt_ms: f64,
    /// HTTP total response time (ms)
    pub http_total_rtt_ms: f64,
    /// HTTP response size (bytes)
    pub http_response_size: f64,
    /// HTTP response status code (200, 451, etc.)
    pub http_status_code: f64,

    // Cross-phase
    /// Ratio: tls_handshake_rtt / tcp_connect_rtt (>5.0 = anomaly)
    pub tls_tcp_ratio: f64,
    /// Ratio: http_first_byte_rtt / tls_handshake_rtt (>3.0 = anomaly)
    pub http_tls_ratio: f64,
    /// Variance of inter-phase delays (jitter)
    pub inter_phase_jitter: f64,
}

impl FeatureVector {
    /// Преобразовать в Vec<f64> для ML classifier.
    pub fn to_vec(&self) -> Vec<f64> {
        vec![
            self.dns_udp_rtt_ms,
            self.dns_doh_rtt_ms,
            self.dns_udp_response_size,
            self.dns_doh_response_size,
            self.tcp_connect_rtt_ms,
            self.tcp_connect_ok,
            self.tls_handshake_rtt_ms,
            self.tls_server_hello_size,
            self.tls_cert_count,
            self.tls_handshake_ok,
            self.http_first_byte_rtt_ms,
            self.http_total_rtt_ms,
            self.http_response_size,
            self.http_status_code,
            self.tls_tcp_ratio,
            self.http_tls_ratio,
            self.inter_phase_jitter,
        ]
    }

    /// Создать пустой feature vector (все 0.0).
    pub fn empty() -> Self {
        Self {
            dns_udp_rtt_ms: 0.0,
            dns_doh_rtt_ms: 0.0,
            dns_udp_response_size: 0.0,
            dns_doh_response_size: 0.0,
            tcp_connect_rtt_ms: 0.0,
            tcp_connect_ok: 0.0,
            tls_handshake_rtt_ms: 0.0,
            tls_server_hello_size: 0.0,
            tls_cert_count: 0.0,
            tls_handshake_ok: 0.0,
            http_first_byte_rtt_ms: 0.0,
            http_total_rtt_ms: 0.0,
            http_response_size: 0.0,
            http_status_code: 0.0,
            tls_tcp_ratio: 0.0,
            http_tls_ratio: 0.0,
            inter_phase_jitter: 0.0,
        }
    }
}

/// Timing Probe — собирает timing features во время normal probe.
pub struct TimingProbe {
    /// Timestamps для каждого phase
    dns_udp_start: Option<Instant>,
    dns_udp_end: Option<Instant>,
    dns_doh_start: Option<Instant>,
    dns_doh_end: Option<Instant>,
    tcp_start: Option<Instant>,
    tcp_end: Option<Instant>,
    tls_start: Option<Instant>,
    tls_end: Option<Instant>,
    http_start: Option<Instant>,
    http_end: Option<Instant>,
    http_first_byte: Option<Instant>,
}

impl TimingProbe {
    pub fn new() -> Self {
        Self {
            dns_udp_start: None,
            dns_udp_end: None,
            dns_doh_start: None,
            dns_doh_end: None,
            tcp_start: None,
            tcp_end: None,
            tls_start: None,
            tls_end: None,
            http_start: None,
            http_end: None,
            http_first_byte: None,
        }
    }

    // === Phase markers ===
    pub fn mark_dns_start(&mut self) {
        self.dns_udp_start = Some(Instant::now());
    }
    pub fn mark_dns_end(&mut self) {
        self.dns_udp_end = Some(Instant::now());
    }
    pub fn mark_dns_udp_start(&mut self) {
        self.dns_udp_start = Some(Instant::now());
    }
    pub fn mark_dns_udp_end(&mut self) {
        self.dns_udp_end = Some(Instant::now());
    }
    pub fn mark_dns_doh_start(&mut self) {
        self.dns_doh_start = Some(Instant::now());
    }
    pub fn mark_dns_doh_end(&mut self) {
        self.dns_doh_end = Some(Instant::now());
    }
    pub fn mark_tcp_start(&mut self) {
        self.tcp_start = Some(Instant::now());
    }
    pub fn mark_tcp_end(&mut self) {
        self.tcp_end = Some(Instant::now());
    }
    pub fn mark_tls_start(&mut self) {
        self.tls_start = Some(Instant::now());
    }
    pub fn mark_tls_end(&mut self) {
        self.tls_end = Some(Instant::now());
    }
    pub fn mark_http_start(&mut self) {
        self.http_start = Some(Instant::now());
    }
    pub fn mark_http_first_byte(&mut self) {
        self.http_first_byte = Some(Instant::now());
    }
    pub fn mark_http_end(&mut self) {
        self.http_end = Some(Instant::now());
    }

    pub fn set_dns_udp_rtt(&mut self, rtt_ms: f64) {
        let now = Instant::now();
        self.dns_udp_start = Some(now);
        self.dns_udp_end = Some(now + std::time::Duration::from_millis(rtt_ms as u64));
    }

    pub fn set_dns_doh_rtt(&mut self, rtt_ms: f64) {
        let now = Instant::now();
        self.dns_doh_start = Some(now);
        self.dns_doh_end = Some(now + std::time::Duration::from_millis(rtt_ms as u64));
    }

    pub fn set_http_first_byte_rtt(&mut self, rtt_ms: f64) {
        if let Some(start) = self.http_start {
            self.http_first_byte = Some(start + std::time::Duration::from_millis(rtt_ms as u64));
        } else {
            let now = Instant::now();
            self.http_start = Some(now);
            self.http_first_byte = Some(now + std::time::Duration::from_millis(rtt_ms as u64));
        }
    }

    pub fn set_http_total_rtt(&mut self, rtt_ms: f64) {
        if let Some(start) = self.http_start {
            self.http_end = Some(start + std::time::Duration::from_millis(rtt_ms as u64));
        } else {
            let now = Instant::now();
            self.http_start = Some(now);
            self.http_end = Some(now + std::time::Duration::from_millis(rtt_ms as u64));
        }
    }

    /// Построить feature vector из собранных timings + auxiliary data.
    #[allow(clippy::too_many_arguments)]
    pub fn build_feature_vector(
        &self,
        dns_udp_response_size: usize,
        dns_doh_response_size: usize,
        tcp_connect_ok: bool,
        tls_handshake_ok: bool,
        tls_server_hello_size: usize,
        tls_cert_count: usize,
        http_response_size: usize,
        http_status_code: u16,
    ) -> FeatureVector {
        let dns_udp_rtt_ms = self.duration_ms(self.dns_udp_start, self.dns_udp_end);
        let dns_doh_rtt_ms = self.duration_ms(self.dns_doh_start, self.dns_doh_end);
        let tcp_connect_rtt_ms = self.duration_ms(self.tcp_start, self.tcp_end);
        let tls_handshake_rtt_ms = self.duration_ms(self.tls_start, self.tls_end);
        let http_first_byte_rtt_ms = self.duration_ms(self.http_start, self.http_first_byte);
        let http_total_rtt_ms = self.duration_ms(self.http_start, self.http_end);

        // Ratios (anomaly indicators)
        let tls_tcp_ratio = if tcp_connect_rtt_ms > 0.0 {
            tls_handshake_rtt_ms / tcp_connect_rtt_ms
        } else {
            0.0
        };
        let http_tls_ratio = if tls_handshake_rtt_ms > 0.0 {
            http_first_byte_rtt_ms / tls_handshake_rtt_ms
        } else {
            0.0
        };

        // Inter-phase jitter (variance of phase durations)
        let phase_durations = vec![
            dns_udp_rtt_ms,
            tcp_connect_rtt_ms,
            tls_handshake_rtt_ms,
            http_first_byte_rtt_ms,
        ];
        let jitter = variance(&phase_durations);

        FeatureVector {
            dns_udp_rtt_ms,
            dns_doh_rtt_ms,
            dns_udp_response_size: dns_udp_response_size as f64,
            dns_doh_response_size: dns_doh_response_size as f64,
            tcp_connect_rtt_ms,
            tcp_connect_ok: if tcp_connect_ok { 1.0 } else { 0.0 },
            tls_handshake_rtt_ms,
            tls_server_hello_size: tls_server_hello_size as f64,
            tls_cert_count: tls_cert_count as f64,
            tls_handshake_ok: if tls_handshake_ok { 1.0 } else { 0.0 },
            http_first_byte_rtt_ms,
            http_total_rtt_ms,
            http_response_size: http_response_size as f64,
            http_status_code: http_status_code as f64,
            tls_tcp_ratio,
            http_tls_ratio,
            inter_phase_jitter: jitter,
        }
    }

    fn duration_ms(&self, start: Option<Instant>, end: Option<Instant>) -> f64 {
        match (start, end) {
            (Some(s), Some(e)) => e.duration_since(s).as_millis() as f64,
            _ => 0.0,
        }
    }
}

impl Default for TimingProbe {
    fn default() -> Self {
        Self::new()
    }
}

/// Вычисляет variance для Vec<f64>.
fn variance(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let sum_sq: f64 = values.iter().map(|v| (v - mean).powi(2)).sum();
    sum_sq / values.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_feature_vector_to_vec_length() {
        let fv = FeatureVector::empty();
        assert_eq!(fv.to_vec().len(), 17);
    }

    #[test]
    fn test_timing_probe_durations() {
        let mut probe = TimingProbe::new();
        probe.mark_tcp_start();
        std::thread::sleep(Duration::from_millis(10));
        probe.mark_tcp_end();

        let fv = probe.build_feature_vector(100, 200, true, true, 100, 3, 1024, 200);

        assert!(fv.tcp_connect_rtt_ms >= 8.0 && fv.tcp_connect_rtt_ms <= 50.0);
        assert_eq!(fv.tcp_connect_ok, 1.0);
        assert_eq!(fv.tls_handshake_ok, 1.0);
        assert_eq!(fv.http_status_code, 200.0);
    }

    #[test]
    fn test_variance_empty() {
        assert_eq!(variance(&[]), 0.0);
    }

    #[test]
    fn test_variance_uniform() {
        assert_eq!(variance(&[5.0, 5.0, 5.0]), 0.0);
    }

    #[test]
    fn test_variance_non_uniform() {
        let v = variance(&[1.0, 5.0, 9.0]);
        assert!(v > 0.0);
        assert!((v - 10.6667).abs() < 0.1);
    }
}
