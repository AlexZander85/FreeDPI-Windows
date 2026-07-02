//! DPI Probe Module — превентивное определение типа DPI-блокировки.
//!
//! ## Архитектура
//! Pipeline из 5 phases:
//! 1. DNS Integrity (UDP vs DoH cross-validation)
//! 2. TCP Connectivity (parallel dial racing)
//! 3. TLS Handshake (staged: 1.3 → 1.2)
//! 4. HTTP Application Layer (GET, cutoff detection)
//! 5. Data-Volume (TCP 16-20KB)
//!
//! ## Источники
//! - Pipeline от [Ladon](https://github.com/nickspaargaren/ladon)
//! - Классификатор от [dpi-detector](https://github.com/Runnin4ik/dpi-detector)
//! - Data-volume от [dpi-checkers](https://github.com/hyperion-cs/dpi-checkers)
//! - Preset-списки из [ByeByeDPI](https://github.com/nickspaargaren/ByeByeDPI)

pub mod accumulator;
pub mod classifier;
pub mod config;
pub mod decision_engine;
pub mod discriminator;
pub mod dns_probe;
pub mod http_probe;
pub mod ja4_probe;
pub mod ml_classifier;
pub mod presets;
pub mod quic_probe;
pub mod rkn_stub;
pub mod strategy_map;
pub mod tcp16_probe;
pub mod tcp_probe;
pub mod timing_probe;
pub mod tls_probe;

use accumulator::Accumulator;
use classifier::*;
use config::ProbeConfig;
use decision_engine::{decide, Decision};
use discriminator::{discriminate, DiscriminationResult};
use dns_probe::DnsProbeResult;
use http_probe::HttpProbeResult;
use ja4_probe::{Ja4FingerprintProbe, Ja4ProbeResult};
use ml_classifier::{MlClassifier, MlResult};
use quic_probe::{QuicProbe, QuicProbeResult, QuicVerdict};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use tcp16_probe::Tcp16ProbeResult;
use tcp_probe::TcpProbeResult;
use timing_probe::{FeatureVector, TimingProbe};
use tls_probe::TlsProbeResult;
use tracing::info;

/// Результат probe'а одного домена.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    /// Домен
    pub domain: String,
    /// IP-адрес сервера (первый из DNS)
    pub ip: Option<Ipv4Addr>,
    /// Вердикт
    pub verdict: ProbeVerdict,
    /// Confidence (0.0–1.0)
    pub confidence: f64,
    /// Результат Phase 1: DNS
    pub dns: DnsProbeResult,
    /// Результат Phase 2: TCP
    pub tcp: TcpProbeResult,
    /// Результат Phase 3: TLS
    pub tls: Option<TlsProbeResult>,
    /// Результат Phase 4: HTTP
    pub http: Option<HttpProbeResult>,
    /// Результат Phase 5: Data-Volume (TCP 16-20KB)
    pub tcp16: Option<Tcp16ProbeResult>,
    /// Дискриминация: server-active vs path-active
    pub discrimination: Option<DiscriminationResult>,
    /// Результат Phase 6: JA4 Fingerprint Probe (T45)
    pub ja4: Option<Ja4ProbeResult>,
    /// Результат Phase 7: QUIC Probe (T46)
    pub quic: Option<QuicProbeResult>,
    /// QUIC verdict относительно TCP (T46)
    pub quic_verdict: Option<QuicVerdict>,
    /// Timing features для ML-анализа (T47)
    pub features: Option<FeatureVector>,
    /// ML classifier результат (T47)
    pub ml: Option<MlResult>,
    /// Accumulation verdict (should_tunnel)
    pub should_tunnel: bool,
    /// Timestamp
    pub timestamp: String,
    /// T54: Финальное решение decision engine (explainability).
    /// None если decision engine не вызывался (legacy path).
    pub decision: Option<Decision>,
}

/// DPI Probe Module — оркестратор pipeline.
pub struct ProbeModule {
    config: ProbeConfig,
    dns: dns_probe::DnsProbe,
    tcp: tcp_probe::TcpProbe,
    tls: tls_probe::TlsProbe,
    http: http_probe::HttpProbe,
    tcp16: tcp16_probe::Tcp16Probe,
    ja4: Ja4FingerprintProbe,
    quic: QuicProbe,
    ml: MlClassifier,
    accumulator: Accumulator,
}

impl ProbeModule {
    /// Создаёт новый ProbeModule с конфигурацией по умолчанию.
    pub fn new() -> Self {
        Self::with_config(ProbeConfig::default())
    }

    /// Создаёт ProbeModule с указанной конфигурацией.
    pub fn with_config(config: ProbeConfig) -> Self {
        let dns = dns_probe::DnsProbe::new(&config);
        let tcp = tcp_probe::TcpProbe::new(&config);
        let tls = tls_probe::TlsProbe::new(&config);
        let http = http_probe::HttpProbe::new(&config);
        let tcp16 = tcp16_probe::Tcp16Probe::new(&config);
        let accumulator = Accumulator::new(
            config.promote_threshold,
            config.family_threshold,
            config.hot_ttl,
        );

        let ja4 = Ja4FingerprintProbe::new(config.tls_connect_timeout, config.tls_read_timeout);
        let quic = QuicProbe::new(config.tls_connect_timeout);
        let ml = MlClassifier::new();

        Self {
            config,
            dns,
            tcp,
            tls,
            http,
            tcp16,
            ja4,
            quic,
            ml,
            accumulator,
        }
    }

    /// Запуск pipeline probe для одного домена.
    ///
    /// Выполняет Phase 1 (DNS) + Phase 2 (TCP) + Phase 3 (TLS) + Phase 4 (HTTP)
    /// + Phase 5 (Data-Volume) + Discrimination + Accumulation.
    pub async fn probe(&self, domain: &str) -> ProbeResult {
        info!("Probing domain: {}", domain);

        let mut timing = TimingProbe::new();

        // Phase 1: DNS Integrity
        let dns = self.dns.probe(domain).await;
        timing.set_dns_udp_rtt(dns.udp_rtt_ms);
        timing.set_dns_doh_rtt(dns.doh_rtt_ms);

        // Resolve IPs из DNS probe result
        let ips = if dns.verdict == DnsFailureCode::Ok {
            dns.resolved_ips.clone()
        } else {
            vec![]
        };

        let ip = ips.first().copied();

        // Phase 2: TCP Connectivity (parallel race)
        timing.mark_tcp_start();
        let tcp = if !ips.is_empty() {
            self.tcp.probe(&ips, 443).await
        } else {
            TcpProbeResult {
                verdict: TcpFailureCode::Timeout,
                rtt_us: 0,
                ip: None,
            }
        };
        timing.mark_tcp_end();

        // Phase 3: TLS Handshake (staged: 1.3 → 1.2)
        timing.mark_tls_start();
        let tls = if tcp.verdict == TcpFailureCode::ConnectOk {
            if let Some(ip) = ip {
                Some(self.tls.probe(ip, domain).await)
            } else {
                None
            }
        } else {
            None
        };
        timing.mark_tls_end();

        // Phase 4: HTTP Application Layer (only if TLS succeeded)
        timing.mark_http_start();
        let http = if tls.as_ref().is_some_and(|t| !t.verdict.is_tls_fail()) {
            if let Some(ip) = ip {
                Some(self.http.probe(ip, domain).await)
            } else {
                None
            }
        } else {
            None
        };
        timing.mark_http_end();
        if let Some(ref h) = http {
            timing.set_http_first_byte_rtt(h.first_byte_rtt_ms);
            timing.set_http_total_rtt(h.total_rtt_ms);
        }

        // Phase 5: Data-Volume (only if HTTP detected cutoff)
        let tcp16 = if http
            .as_ref()
            .is_some_and(|h| h.verdict == HttpFailureCode::Cutoff)
        {
            if let Some(ip) = ip {
                Some(self.tcp16.probe(ip, domain).await)
            } else {
                None
            }
        } else {
            None
        };

        // If TCP16 detected data-volume cutoff, update TCP verdict
        let tcp = if tcp16.as_ref().is_some_and(|t| t.detected) {
            TcpProbeResult {
                verdict: TcpFailureCode::DataVolumeCut,
                rtt_us: tcp.rtt_us,
                ip: tcp.ip,
            }
        } else {
            tcp
        };

        // Discriminate: server-active vs path-active (TLS + HTTP)
        let discrimination = match (&tls, &http) {
            (Some(t), Some(h)) => Some(discriminate(&t.verdict, &h.verdict)),
            (Some(t), None) => Some(discriminate(&t.verdict, &HttpFailureCode::Ok)),
            _ => None,
        };

        // Phase 6: JA4 Fingerprint Probe (T45) — only if TLS fingerprint blocking suspected
        let ja4 = if tls.as_ref().is_some_and(|t| t.verdict.is_tls_fail()) {
            if let Some(ip) = ip {
                Some(self.ja4.probe(ip, domain).await)
            } else {
                None
            }
        } else {
            None
        };

        // Phase 7: QUIC Probe (T46) — always if we have IP
        let quic = if let Some(ip) = ip {
            Some(self.quic.probe(ip, domain, None).await)
        } else {
            None
        };
        let quic_verdict = quic
            .as_ref()
            .map(|q| QuicProbe::discriminate(q, tcp.verdict));

        // Build feature vector for ML analysis (T47)
        let features = Some(timing.build_feature_vector(
            dns.udp_response_size,
            dns.doh_response_size,
            tcp.verdict == TcpFailureCode::ConnectOk,
            tls.as_ref().is_some_and(|t| !t.verdict.is_tls_fail()),
            tls.as_ref().map(|t| t.server_hello_size).unwrap_or(0),
            tls.as_ref().map(|t| t.cert_count).unwrap_or(0),
            http.as_ref().map(|h| h.bytes_read as usize).unwrap_or(0),
            http.as_ref().map(|h| h.status_code).unwrap_or(0),
        ));
        let features_ref = features.as_ref().unwrap(); // всегда Some
        let ml = Some(self.ml.predict(features_ref));

        // Decision engine: объединяет все сигналы в финальный вердикт
        let probe_result_input = ProbeResult {
            domain: domain.to_string(),
            ip,
            verdict: ProbeVerdict::Ambiguous,
            confidence: 0.0,
            dns: dns.clone(),
            tcp: tcp.clone(),
            tls: tls.clone(),
            http: http.clone(),
            tcp16: tcp16.clone(),
            discrimination: discrimination.clone(),
            should_tunnel: false,
            timestamp: chrono::Utc::now().to_rfc3339(),
            ja4: ja4.clone(),
            quic: quic.clone(),
            quic_verdict,
            features: features.clone(),
            ml: ml.clone(),
            decision: None,
        };
        let engine_decision = decide(&probe_result_input);
        let verdict = engine_decision.verdict;
        let confidence = engine_decision.confidence;

        // Log decision rationale + signals
        info!(
            "Probe result for {}: verdict={:?}, confidence={:.0}%, should_tunnel={}, signals={}",
            domain,
            verdict,
            confidence * 100.0,
            false,
            engine_decision
                .signals
                .iter()
                .map(|s| format!("{}({:?}:{:+.2})", s.signal_name, s.effect, s.delta))
                .collect::<Vec<_>>()
                .join(", ")
        );
        if !engine_decision.rationale.is_empty() {
            info!("Decision rationale: {}", engine_decision.rationale);
        }

        // Accumulate verdict
        self.accumulator.record(domain, &verdict);
        let should_tunnel = self.accumulator.should_tunnel(domain);

        ProbeResult {
            domain: domain.to_string(),
            ip,
            verdict,
            confidence,
            dns,
            tcp,
            tls,
            http,
            tcp16,
            discrimination,
            ja4,
            quic,
            quic_verdict,
            features,
            ml,
            should_tunnel,
            timestamp: chrono::Utc::now().to_rfc3339(),
            decision: Some(engine_decision),
        }
    }

    /// Probe нескольких доменов.
    pub async fn probe_batch(&self, domains: &[&str]) -> Vec<ProbeResult> {
        let mut results = Vec::with_capacity(domains.len());
        for domain in domains {
            results.push(self.probe(domain).await);
        }
        results
    }

    /// Возвращает конфигурацию.
    pub fn config(&self) -> &ProbeConfig {
        &self.config
    }

    /// Возвращает accumulator.
    pub fn accumulator(&self) -> &Accumulator {
        &self.accumulator
    }
}

impl Default for ProbeModule {
    fn default() -> Self {
        Self::new()
    }
}

// === T54.5: Default implementation for ProbeResult ===
impl Default for ProbeResult {
    fn default() -> Self {
        Self {
            domain: String::new(),
            ip: None,
            verdict: ProbeVerdict::Ambiguous,
            confidence: 0.0,
            dns: DnsProbeResult::default(),
            tcp: TcpProbeResult::default(),
            tls: None,
            http: None,
            tcp16: None,
            discrimination: None,
            should_tunnel: false,
            timestamp: String::new(),
            ja4: None,
            quic: None,
            quic_verdict: None,
            features: None,
            ml: None,
            decision: None,
        }
    }
}

/// Вычисление итогового вердикта и confidence по фазам DNS + TCP.
/// Сохранён для обратной совместимости (legacy).
#[allow(dead_code)]
fn compute_verdict(dns: &DnsProbeResult, tcp: &TcpProbeResult) -> (ProbeVerdict, f64) {
    match (&dns.verdict, &tcp.verdict) {
        // DNS poisoned — 95% blocked
        (DnsFailureCode::Poisoned, _) => (ProbeVerdict::Blocked, 0.95),
        (DnsFailureCode::NxdomainSpoof, _) => (ProbeVerdict::Blocked, 0.90),
        (DnsFailureCode::EmptySpoof, _) => (ProbeVerdict::Blocked, 0.85),
        (DnsFailureCode::Intercepted, _) => (ProbeVerdict::Blocked, 0.90),
        (DnsFailureCode::DohBlocked, _) => (ProbeVerdict::Blocked, 0.80),

        // DNS OK + TCP OK — needs further TLS/HTTP phases
        (DnsFailureCode::Ok, TcpFailureCode::ConnectOk) => {
            (ProbeVerdict::Ambiguous, 0.30) // not final
        }

        // DNS OK + TCP blocked
        (DnsFailureCode::Ok, TcpFailureCode::Reset) => (ProbeVerdict::Blocked, 0.85),
        (DnsFailureCode::Ok, TcpFailureCode::Timeout) => (ProbeVerdict::Blocked, 0.75),

        // DNS ambiguous + TCP issues
        (_, TcpFailureCode::Reset) => (ProbeVerdict::Blocked, 0.80),
        (_, TcpFailureCode::Timeout) => (ProbeVerdict::Blocked, 0.60),

        // DNS fail + TCP refuse/unreachable
        (_, TcpFailureCode::Refused) => (ProbeVerdict::Ambiguous, 0.40),
        (_, TcpFailureCode::Unreachable) => (ProbeVerdict::Ambiguous, 0.30),

        // Data-volume cutoff — DPI обрывает на N КБ
        (_, TcpFailureCode::DataVolumeCut) => (ProbeVerdict::Blocked, 0.85),

        // DNS unresolvable
        (DnsFailureCode::Unresolvable, _) => (ProbeVerdict::Ambiguous, 0.50),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_verdict_dns_poisoned() {
        let dns = DnsProbeResult {
            verdict: DnsFailureCode::Poisoned,
            resolved_ips: vec![],
            udp_ips: vec![],
            doh_ips: vec![],
            latency_us: 0,
            fake_ip_detected: false,
            udp_rtt_ms: 0.0,
            doh_rtt_ms: 0.0,
            udp_response_size: 0,
            doh_response_size: 0,
        };
        let tcp = TcpProbeResult {
            verdict: TcpFailureCode::ConnectOk,
            rtt_us: 10000,
            ip: None,
        };
        let (v, c) = compute_verdict(&dns, &tcp);
        assert_eq!(v, ProbeVerdict::Blocked);
        assert!(c > 0.9);
    }

    #[test]
    fn test_compute_verdict_tcp_ok_dns_ok() {
        let dns = DnsProbeResult {
            verdict: DnsFailureCode::Ok,
            resolved_ips: vec![Ipv4Addr::new(8, 8, 8, 8)],
            udp_ips: vec![Ipv4Addr::new(8, 8, 8, 8)],
            doh_ips: vec![Ipv4Addr::new(8, 8, 8, 8)],
            latency_us: 50000,
            fake_ip_detected: false,
            udp_rtt_ms: 25.0,
            doh_rtt_ms: 50.0,
            udp_response_size: 50,
            doh_response_size: 100,
        };
        let tcp = TcpProbeResult {
            verdict: TcpFailureCode::ConnectOk,
            rtt_us: 12000,
            ip: Some(Ipv4Addr::new(8, 8, 8, 8)),
        };
        let (v, _c) = compute_verdict(&dns, &tcp);
        assert_eq!(v, ProbeVerdict::Ambiguous); // needs TLS/HTTP
    }

    #[test]
    fn test_compute_verdict_tcp_reset() {
        let dns = DnsProbeResult {
            verdict: DnsFailureCode::Ok,
            resolved_ips: vec![Ipv4Addr::new(8, 8, 8, 8)],
            udp_ips: vec![Ipv4Addr::new(8, 8, 8, 8)],
            doh_ips: vec![Ipv4Addr::new(8, 8, 8, 8)],
            latency_us: 50000,
            fake_ip_detected: false,
            udp_rtt_ms: 25.0,
            doh_rtt_ms: 50.0,
            udp_response_size: 50,
            doh_response_size: 100,
        };
        let tcp = TcpProbeResult {
            verdict: TcpFailureCode::Reset,
            rtt_us: 5000,
            ip: Some(Ipv4Addr::new(8, 8, 8, 8)),
        };
        let (v, c) = compute_verdict(&dns, &tcp);
        assert_eq!(v, ProbeVerdict::Blocked);
        assert!(c >= 0.8);
    }
}

// === T54.5: Default implementation tests ===
#[cfg(test)]
pub mod default_tests {
    use crate::probe::classifier::{
        ConnectionStage, DnsFailureCode, HttpFailureCode, TcpFailureCode, TlsFailureCode,
    };
    use crate::probe::discriminator::{BlockOrigin, DiscriminationResult};
    use crate::probe::dns_probe::DnsProbeResult;
    use crate::probe::http_probe::HttpProbeResult;
    use crate::probe::ja4_probe::{FingerprintVerdict, Ja4ProbeResult};
    use crate::probe::ml_classifier::{MlResult, MlVerdict};
    use crate::probe::quic_probe::{QuicProbeResult, QuicResponseType, QuicVerdict};
    use crate::probe::tcp16_probe::Tcp16ProbeResult;
    use crate::probe::tcp_probe::TcpProbeResult;
    use crate::probe::tls_probe::TlsProbeResult;
    use crate::probe::ProbeResult;

    // --- Test 1: Classifier enums (5 types) ---
    #[test]
    fn test_default_classifier_enums() {
        assert_eq!(DnsFailureCode::default(), DnsFailureCode::Ok);
        assert_eq!(TcpFailureCode::default(), TcpFailureCode::ConnectOk);
        assert_eq!(TlsFailureCode::default(), TlsFailureCode::HandshakeOk);
        assert_eq!(HttpFailureCode::default(), HttpFailureCode::Ok);
        assert_eq!(ConnectionStage::default(), ConnectionStage::TcpConnect);
    }

    // --- Test 2: Probe result structs (5 types) ---
    #[test]
    fn test_default_probe_results() {
        // DnsProbeResult
        let dns = DnsProbeResult::default();
        assert_eq!(dns.verdict, DnsFailureCode::Ok);
        assert!(dns.resolved_ips.is_empty());
        assert_eq!(dns.latency_us, 0);
        assert!(!dns.fake_ip_detected);

        // TcpProbeResult
        let tcp = TcpProbeResult::default();
        assert_eq!(tcp.verdict, TcpFailureCode::ConnectOk);
        assert_eq!(tcp.rtt_us, 0);
        assert!(tcp.ip.is_none());

        // TlsProbeResult
        let tls = TlsProbeResult::default();
        assert!(!tls.verdict.is_tls_fail());
        assert_eq!(tls.server_hello_size, 0);
        assert_eq!(tls.cert_count, 0);

        // HttpProbeResult
        let http = HttpProbeResult::default();
        assert_eq!(http.verdict, HttpFailureCode::Ok);
        assert_eq!(http.status_code, 0);
        assert_eq!(http.bytes_read, 0);

        // Tcp16ProbeResult
        let tcp16 = Tcp16ProbeResult::default();
        assert!(!tcp16.detected);
    }

    // --- Test 3: Discrimination (2 types) ---
    #[test]
    fn test_default_discrimination() {
        assert_eq!(BlockOrigin::default(), BlockOrigin::Ambiguous);

        let disc = DiscriminationResult::default();
        assert_eq!(disc.origin, BlockOrigin::Ambiguous);
        assert_eq!(
            disc.verdict,
            crate::probe::classifier::ProbeVerdict::Ambiguous
        );
        assert_eq!(disc.confidence, 0.0);
        assert!(disc.rationale.is_empty());
    }

    // --- Test 4: JA4 types (2 types) ---
    #[test]
    fn test_default_ja4() {
        assert_eq!(
            FingerprintVerdict::default(),
            FingerprintVerdict::NoFingerprintBlocking
        );

        let ja4 = Ja4ProbeResult::default();
        assert_eq!(ja4.verdict, FingerprintVerdict::NoFingerprintBlocking);
        assert!(ja4.profiles.is_empty());
        assert_eq!(ja4.blocked_count, 0);
        assert_eq!(ja4.ok_count, 0);
    }

    // --- Test 5: QUIC types (2 types) ---
    #[test]
    fn test_default_quic() {
        assert_eq!(QuicVerdict::default(), QuicVerdict::Ambiguous);

        let quic = QuicProbeResult::default();
        assert_eq!(quic.response_type, QuicResponseType::Timeout);
        assert_eq!(quic.rtt_ms, 0);
        assert_eq!(quic.response_size, 0);
    }

    // --- Test 6: ML types (2 types) + ProbeResult ---
    #[test]
    fn test_default_ml_and_probe_result() {
        assert_eq!(MlVerdict::default(), MlVerdict::Clear);

        let ml = MlResult::default();
        assert_eq!(ml.score, 0.0);
        assert_eq!(ml.verdict, MlVerdict::Clear);
        assert!(ml.top_features.is_empty());

        // ProbeResult — объединяет все Default-структуры
        let pr = ProbeResult::default();
        assert_eq!(
            pr.verdict,
            crate::probe::classifier::ProbeVerdict::Ambiguous
        );
        assert_eq!(pr.confidence, 0.0);
        assert!(pr.domain.is_empty());
        assert!(pr.ip.is_none());
        assert_eq!(pr.dns.verdict, DnsFailureCode::Ok);
        assert_eq!(pr.tcp.verdict, TcpFailureCode::ConnectOk);
        assert!(pr.tls.is_none());
        assert!(pr.http.is_none());
        assert!(pr.tcp16.is_none());
        assert!(pr.discrimination.is_none());
        assert!(pr.ja4.is_none());
        assert!(pr.quic.is_none());
        assert!(pr.quic_verdict.is_none());
        assert!(pr.features.is_none());
        assert!(pr.ml.is_none());
        assert!(!pr.should_tunnel);
        assert!(pr.timestamp.is_empty());
        assert!(pr.decision.is_none());
    }
}
