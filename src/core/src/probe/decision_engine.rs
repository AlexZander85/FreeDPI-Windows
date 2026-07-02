//! Decision Engine — взвешенное объединение всех probe сигналов в финальный вердикт.
//!
//! ## Приоритеты сигналов
//!
//! 1. **Hard rules** (override everything):
//!    - DNS poisoning → Blocked 0.95
//!    - Server-active discrimination (TLS alert, MITM, HTTP 451) → Clear
//!    - QUIC bypass (TCP blocked, QUIC works) → Ambiguous 0.70 (partial bypass)
//!
//! 2. **Strong signals** (high confidence):
//!    - Path-active discrimination (RST, garbage, cutoff) → Blocked
//!    - JA4 fingerprint blocking → Blocked
//!    - ML score > 0.8 → Blocked
//!
//! 3. **Confidence adjustment** (delta на base verdict):
//!    - ML score 0.3–0.8 → ±0.1 to confidence
//!    - T50: tls ok but server_hello_size=0 → -0.15 (anomaly)
//!    - T50: tls ok but cert_count=0 → -0.15 (anomaly)
//!    - T50: udp_rtt > 3× doh_rtt → +0.10 (DNS manipulation)
//!    - T50: tls_rtt > 5× tcp_rtt → +0.10 (DPI delay)
//!
//! 4. **Default**: All ok → Ambiguous 0.30 (нужен re-probe)

use crate::probe::classifier::{DnsFailureCode, ProbeVerdict, TcpFailureCode};
use crate::probe::discriminator::BlockOrigin;
use crate::probe::ja4_probe::FingerprintVerdict;
use crate::probe::quic_probe::QuicVerdict;
use crate::probe::ProbeResult;
use serde::{Deserialize, Serialize};

/// Пороги для confidence adjustment.
const ML_HIGH_THRESHOLD: f64 = 0.8;
const ML_LOW_THRESHOLD: f64 = 0.3;
const ML_DELTA: f64 = 0.1;

/// Аномалия: TLS ok но server_hello_size = 0.
const TLS_ZERO_FEATURES_DELTA: f64 = -0.15;

/// DNS manipulation: udp_rtt > 3× doh_rtt.
const DNS_MANIP_RATIO: f64 = 3.0;
const DNS_MANIP_DELTA: f64 = 0.10;

/// DPI delay: tls_rtt > 5× tcp_rtt.
const DPI_DELAY_RATIO: f64 = 5.0;
const DPI_DELAY_DELTA: f64 = 0.10;

/// Базовый confidence для Ambiguous.
const AMBIGUOUS_BASE_CONFIDENCE: f64 = 0.30;

/// Результат decision engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub verdict: ProbeVerdict,
    pub confidence: f64,
    pub rationale: String,
    /// Сигналы, которые повлияли на решение (для explainability).
    pub signals: Vec<SignalContribution>,
}

/// Вклад одного сигнала в финальное решение.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalContribution {
    pub signal_name: String,
    pub effect: SignalEffect,
    pub delta: f64,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignalEffect {
    /// Сигнал установил финальный вердикт (hard rule).
    HardRule,
    /// Сигнал поддержал текущий вердикт.
    Support,
    /// Сигнал скорректировал confidence.
    ConfidenceAdjust,
    /// Сигнал не повлиял (нейтральный).
    Neutral,
}

/// Главная функция — объединяет все сигналы в финальный вердикт.
pub fn decide(result: &ProbeResult) -> Decision {
    let mut signals: Vec<SignalContribution> = Vec::new();

    // === Phase 1: Hard rules ===
    // DNS poisoning — абсолютный сигнал блокировки
    if matches!(
        result.dns.verdict,
        DnsFailureCode::Poisoned | DnsFailureCode::NxdomainSpoof | DnsFailureCode::EmptySpoof
    ) {
        signals.push(SignalContribution {
            signal_name: "dns_poisoning".into(),
            effect: SignalEffect::HardRule,
            delta: 0.0,
            description: format!("DNS poisoned: {:?}", result.dns.verdict),
        });
        return Decision {
            verdict: ProbeVerdict::Blocked,
            confidence: 0.95,
            rationale: format!(
                "DNS poisoning detected ({:?}) — blocked at DNS level",
                result.dns.verdict
            ),
            signals,
        };
    }

    // DNS interception — тоже блокировка, но ниже confidence
    if result.dns.verdict == DnsFailureCode::Intercepted {
        signals.push(SignalContribution {
            signal_name: "dns_intercepted".into(),
            effect: SignalEffect::HardRule,
            delta: 0.0,
            description: "DNS intercepted (UDP blocked, DoH works)".into(),
        });
        return Decision {
            verdict: ProbeVerdict::Blocked,
            confidence: 0.90,
            rationale: "DNS intercepted — UDP DNS blocked, DoH works".into(),
            signals,
        };
    }

    // Server-active discrimination — сервер сам ответил, не DPI
    if let Some(ref disc) = result.discrimination {
        if disc.origin == BlockOrigin::ServerActive {
            signals.push(SignalContribution {
                signal_name: "server_active".into(),
                effect: SignalEffect::HardRule,
                delta: 0.0,
                description: disc.rationale.clone(),
            });
            return Decision {
                verdict: ProbeVerdict::Clear,
                confidence: disc.confidence,
                rationale: format!("Server-active: {}", disc.rationale),
                signals,
            };
        }
    }

    // QUIC bypass — TCP blocked, но QUIC работает → частичный обход
    // Ambiguous (не Clear) потому что:
    // - не все сайты поддерживают HTTP/3 (TCP blocked → пользователь не получит доступ)
    // - QUIC может быть нестабильным (DPI может начать блокировать QUIC позже)
    // - temporal accumulation должен подтвердить что QUIC стабильно работает
    if let Some(ref quic_verdict) = result.quic_verdict {
        if *quic_verdict == QuicVerdict::QuicBypass {
            signals.push(SignalContribution {
                signal_name: "quic_bypass".into(),
                effect: SignalEffect::HardRule,
                delta: 0.0,
                description: "TCP blocked, QUIC works — partial bypass".into(),
            });
            return Decision {
                verdict: ProbeVerdict::Ambiguous,
                confidence: 0.70,
                rationale: "QUIC partial bypass: TCP blocked but QUIC works. User can use HTTP/3 if server supports it. Needs temporal accumulation to confirm.".into(),
                signals,
            };
        }
    }

    // === Phase 2: Strong signals ===
    // Path-active discrimination — DPI на пути
    if let Some(ref disc) = result.discrimination {
        if disc.origin == BlockOrigin::PathActive {
            signals.push(SignalContribution {
                signal_name: "path_active".into(),
                effect: SignalEffect::Support,
                delta: 0.0,
                description: disc.rationale.clone(),
            });
            let mut confidence = disc.confidence;
            // ML adjustment
            if let Some(ref ml) = result.ml {
                confidence = apply_ml_adjustment(ml.score, confidence, &mut signals);
            }
            // T50 adjustments
            confidence = apply_t50_adjustments(result, confidence, &mut signals);
            return Decision {
                verdict: ProbeVerdict::Blocked,
                confidence: confidence.clamp(0.0, 1.0),
                rationale: format!("Path-active DPI: {}", disc.rationale),
                signals,
            };
        }
    }

    // JA4 fingerprint blocking — DPI блокирует по fingerprint
    if let Some(ref ja4) = result.ja4 {
        if ja4.verdict == FingerprintVerdict::FingerprintBlocking {
            signals.push(SignalContribution {
                signal_name: "ja4_fingerprint_blocking".into(),
                effect: SignalEffect::Support,
                delta: 0.0,
                description: format!(
                    "Fingerprint blocking: blocked={:?}, working={:?}",
                    ja4.blocked_profile, ja4.working_profile
                ),
            });
            let mut confidence = 0.85;
            if let Some(ref ml) = result.ml {
                confidence = apply_ml_adjustment(ml.score, confidence, &mut signals);
            }
            confidence = apply_t50_adjustments(result, confidence, &mut signals);
            return Decision {
                verdict: ProbeVerdict::Blocked,
                confidence: confidence.clamp(0.0, 1.0),
                rationale: format!(
                    "JA4 fingerprint blocking detected (blocked={:?}, works={:?})",
                    ja4.blocked_profile, ja4.working_profile
                ),
                signals,
            };
        }
        // Если все 4 fingerprint заблокированы → SNI-based, не fingerprint
        if ja4.verdict == FingerprintVerdict::SniBasedBlocking {
            signals.push(SignalContribution {
                signal_name: "ja4_sni_blocking".into(),
                effect: SignalEffect::Support,
                delta: 0.0,
                description: "All 4 fingerprints blocked — SNI-based blocking".into(),
            });
        }
    }

    // ML score > 0.8 — сильная аномалия
    if let Some(ref ml) = result.ml {
        if ml.score >= ML_HIGH_THRESHOLD {
            signals.push(SignalContribution {
                signal_name: "ml_high_anomaly".into(),
                effect: SignalEffect::Support,
                delta: 0.0,
                description: format!("ML anomaly score {:.2} — DPI blocking likely", ml.score),
            });
            let mut confidence = ml.score;
            confidence = apply_t50_adjustments(result, confidence, &mut signals);
            return Decision {
                verdict: ProbeVerdict::Blocked,
                confidence: confidence.clamp(0.0, 1.0),
                rationale: format!(
                    "ML anomaly detection: score {:.2}, top features: {:?}",
                    ml.score,
                    ml.top_features
                        .iter()
                        .map(|(n, v)| format!("{}={:.2}", n, v))
                        .collect::<Vec<_>>()
                ),
                signals,
            };
        }
    }

    // === Phase 3: Base verdict from DNS+TCP + confidence adjustment ===
    let (verdict, mut confidence) = compute_base_verdict(&result.dns.verdict, &result.tcp.verdict);

    // ML adjustment
    if let Some(ref ml) = result.ml {
        confidence = apply_ml_adjustment(ml.score, confidence, &mut signals);
    }

    // T50 adjustments
    confidence = apply_t50_adjustments(result, confidence, &mut signals);

    // === Phase 4: Если все OK и нет аномалий → Ambiguous (нужен re-probe) ===
    // Если DNS ok, TCP ok, TLS ok, HTTP ok, ML low — всё хорошо, но нужен re-probe для подтверждения
    if verdict == ProbeVerdict::Ambiguous
        && result.dns.verdict == DnsFailureCode::Ok
        && result.tcp.verdict == TcpFailureCode::ConnectOk
        && result
            .tls
            .as_ref()
            .is_some_and(|t| !t.verdict.is_tls_fail())
        && result.http.as_ref().is_some_and(|h| !h.verdict.is_error())
    {
        // Все фазы прошли — Ambiguous с base confidence (не Clear — нужен temporal accumulation)
        signals.push(SignalContribution {
            signal_name: "all_phases_ok".into(),
            effect: SignalEffect::Neutral,
            delta: 0.0,
            description: "All phases OK — needs temporal accumulation for Clear".into(),
        });
        return Decision {
            verdict: ProbeVerdict::Ambiguous,
            confidence: confidence.clamp(0.0, 0.5),
            rationale: "All probe phases passed — needs accumulation for Clear verdict".into(),
            signals,
        };
    }

    // === Fallback ===
    signals.push(SignalContribution {
        signal_name: "fallback".into(),
        effect: SignalEffect::Neutral,
        delta: 0.0,
        description: "No strong signal — fallback to base verdict".into(),
    });

    Decision {
        verdict,
        confidence: confidence.clamp(0.0, 1.0),
        rationale: format!(
            "Base verdict from DNS+TCP: {:?}+{:?}, adjusted by ML/T50 signals",
            result.dns.verdict, result.tcp.verdict
        ),
        signals,
    }
}

/// Базовый вердикт из DNS+TCP (legacy compute_verdict logic, для обратной совместимости).
fn compute_base_verdict(dns: &DnsFailureCode, tcp: &TcpFailureCode) -> (ProbeVerdict, f64) {
    match (dns, tcp) {
        (DnsFailureCode::Poisoned, _) => (ProbeVerdict::Blocked, 0.95),
        (DnsFailureCode::NxdomainSpoof, _) => (ProbeVerdict::Blocked, 0.90),
        (DnsFailureCode::EmptySpoof, _) => (ProbeVerdict::Blocked, 0.85),
        (DnsFailureCode::Intercepted, _) => (ProbeVerdict::Blocked, 0.90),
        (DnsFailureCode::DohBlocked, _) => (ProbeVerdict::Blocked, 0.80),
        (DnsFailureCode::Ok, TcpFailureCode::ConnectOk) => {
            (ProbeVerdict::Ambiguous, AMBIGUOUS_BASE_CONFIDENCE)
        }
        (DnsFailureCode::Ok, TcpFailureCode::Reset) => (ProbeVerdict::Blocked, 0.85),
        (DnsFailureCode::Ok, TcpFailureCode::Timeout) => (ProbeVerdict::Blocked, 0.75),
        (_, TcpFailureCode::Reset) => (ProbeVerdict::Blocked, 0.80),
        (_, TcpFailureCode::Timeout) => (ProbeVerdict::Blocked, 0.60),
        (_, TcpFailureCode::Refused) => (ProbeVerdict::Ambiguous, 0.40),
        (_, TcpFailureCode::Unreachable) => (ProbeVerdict::Ambiguous, AMBIGUOUS_BASE_CONFIDENCE),
        (_, TcpFailureCode::DataVolumeCut) => (ProbeVerdict::Blocked, 0.85),
        (DnsFailureCode::Unresolvable, _) => (ProbeVerdict::Ambiguous, 0.50),
    }
}

/// ML adjustment: если score в диапазоне 0.3-0.8, корректируем confidence.
fn apply_ml_adjustment(
    ml_score: f64,
    mut confidence: f64,
    signals: &mut Vec<SignalContribution>,
) -> f64 {
    if ml_score > ML_LOW_THRESHOLD && ml_score < ML_HIGH_THRESHOLD {
        // Suspicious range — корректируем confidence
        let delta = if ml_score > 0.5 {
            ML_DELTA // towards blocked
        } else {
            -ML_DELTA // towards clear
        };
        confidence += delta;
        signals.push(SignalContribution {
            signal_name: "ml_suspicious".into(),
            effect: SignalEffect::ConfidenceAdjust,
            delta,
            description: format!(
                "ML score {:.2} in suspicious range, confidence adjusted by {:.2}",
                ml_score, delta
            ),
        });
    } else if ml_score <= ML_LOW_THRESHOLD {
        signals.push(SignalContribution {
            signal_name: "ml_low".into(),
            effect: SignalEffect::Neutral,
            delta: 0.0,
            description: format!("ML score {:.2} low — no adjustment", ml_score),
        });
    }
    // ML_HIGH_THRESHOLD handled separately in Phase 2
    confidence
}

/// T50 adjustments: server_hello_size=0, cert_count=0, udp_rtt > 3× doh_rtt, tls_rtt > 5× tcp_rtt.
fn apply_t50_adjustments(
    result: &ProbeResult,
    mut confidence: f64,
    signals: &mut Vec<SignalContribution>,
) -> f64 {
    // T50: TLS ok but server_hello_size = 0 — anomaly (raw probe не собрал данные)
    if let Some(ref tls) = result.tls {
        if !tls.verdict.is_tls_fail() && tls.server_hello_size == 0 {
            confidence += TLS_ZERO_FEATURES_DELTA;
            signals.push(SignalContribution {
                signal_name: "tls_zero_server_hello".into(),
                effect: SignalEffect::ConfidenceAdjust,
                delta: TLS_ZERO_FEATURES_DELTA,
                description:
                    "TLS ok but server_hello_size=0 — raw probe anomaly, confidence reduced".into(),
            });
        }
        // T50: TLS ok but cert_count = 0 — anomaly
        if !tls.verdict.is_tls_fail() && tls.cert_count == 0 {
            confidence += TLS_ZERO_FEATURES_DELTA;
            signals.push(SignalContribution {
                signal_name: "tls_zero_certs".into(),
                effect: SignalEffect::ConfidenceAdjust,
                delta: TLS_ZERO_FEATURES_DELTA,
                description: "TLS ok but cert_count=0 — raw probe anomaly, confidence reduced"
                    .into(),
            });
        }
    }

    // T50: udp_rtt > 3× doh_rtt — DNS manipulation hint
    let udp_rtt = result.dns.udp_rtt_ms;
    let doh_rtt = result.dns.doh_rtt_ms;
    if doh_rtt > 0.0 && udp_rtt > doh_rtt * DNS_MANIP_RATIO {
        confidence += DNS_MANIP_DELTA;
        signals.push(SignalContribution {
            signal_name: "dns_udp_doh_ratio".into(),
            effect: SignalEffect::ConfidenceAdjust,
            delta: DNS_MANIP_DELTA,
            description: format!(
                "UDP RTT {}ms > {}× DoH RTT {}ms — DNS manipulation hint",
                udp_rtt as u64, DNS_MANIP_RATIO, doh_rtt as u64
            ),
        });
    }

    // T50: tls_rtt > 5× tcp_rtt — DPI delay hint
    if let Some(ref tls) = result.tls {
        let tcp_rtt = result.tcp.rtt_us as f64 / 1000.0; // µs → ms
        let tls_rtt = tls.latency_us as f64 / 1000.0;
        if tcp_rtt > 0.0 && tls_rtt > tcp_rtt * DPI_DELAY_RATIO {
            confidence += DPI_DELAY_DELTA;
            signals.push(SignalContribution {
                signal_name: "tls_tcp_ratio".into(),
                effect: SignalEffect::ConfidenceAdjust,
                delta: DPI_DELAY_DELTA,
                description: format!(
                    "TLS RTT {:.0}ms > {}× TCP RTT {:.0}ms — DPI delay hint",
                    tls_rtt, DPI_DELAY_RATIO, tcp_rtt
                ),
            });
        }
    }

    confidence
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::classifier::{
        ConnectionStage, HttpFailureCode, ProbeVerdict, TlsFailureCode,
    };
    use crate::probe::discriminator::{BlockOrigin, DiscriminationResult};
    use crate::probe::dns_probe::DnsProbeResult;
    use crate::probe::http_probe::HttpProbeResult;
    use crate::probe::ja4_probe::{FingerprintVerdict, Ja4ProbeResult};
    use crate::probe::ml_classifier::{MlResult, MlVerdict};
    use crate::probe::quic_probe::{QuicProbeResult, QuicResponseType, QuicVerdict};
    use crate::probe::tcp_probe::TcpProbeResult;
    use crate::probe::tls_probe::TlsProbeResult;
    use crate::probe::ProbeResult;
    use std::net::Ipv4Addr;

    /// Helper: строит ProbeResult с заданными полями, остальные — default.
    fn make_result(
        dns_verdict: DnsFailureCode,
        tcp_verdict: TcpFailureCode,
        tls_verdict: Option<TlsFailureCode>,
    ) -> ProbeResult {
        ProbeResult {
            domain: "test.com".into(),
            ip: Some(Ipv4Addr::new(8, 8, 8, 8)),
            verdict: ProbeVerdict::Ambiguous,
            confidence: 0.5,
            dns: DnsProbeResult {
                verdict: dns_verdict,
                resolved_ips: vec![Ipv4Addr::new(8, 8, 8, 8)],
                udp_ips: vec![],
                doh_ips: vec![],
                latency_us: 50000,
                fake_ip_detected: false,
                udp_rtt_ms: 50.0,
                doh_rtt_ms: 100.0,
                udp_response_size: 100,
                doh_response_size: 200,
            },
            tcp: TcpProbeResult {
                verdict: tcp_verdict,
                rtt_us: 10000,
                ip: Some(Ipv4Addr::new(8, 8, 8, 8)),
            },
            tls: tls_verdict.map(|v| TlsProbeResult {
                verdict: v,
                tls13_ok: false,
                tls12_ok: false,
                stage: ConnectionStage::TlsConnected,
                latency_us: 80000,
                server_hello_size: 100,
                cert_count: 3,
                negotiated_version: Some("1.3".into()),
                negotiated_cipher: Some("TLS_AES_128_GCM_SHA256".into()),
            }),
            http: Some(HttpProbeResult {
                verdict: HttpFailureCode::Ok,
                bytes_read: 1024,
                redirect_url: None,
                latency_us: 200000,
                status_code: 200,
                headers_size: 500,
                first_byte_rtt_ms: 50.0,
                total_rtt_ms: 200.0,
            }),
            tcp16: None,
            discrimination: None,
            should_tunnel: false,
            timestamp: "2026-07-01T00:00:00Z".into(),
            ja4: None,
            quic: None,
            quic_verdict: None,
            features: None,
            ml: None,
            decision: None,
        }
    }

    /// Test 1: DNS poisoned — любые другие сигналы не важны.
    #[test]
    fn test_decision_dns_poisoned() {
        let mut result = make_result(
            DnsFailureCode::Poisoned,
            TcpFailureCode::ConnectOk,
            Some(TlsFailureCode::Version13Ok),
        );
        // Даже если TLS ok, HTTP ok, ML low — DNS poisoned = Blocked
        result.ml = Some(MlResult {
            score: 0.1,
            verdict: MlVerdict::Clear,
            top_features: vec![],
        });

        let decision = decide(&result);
        assert_eq!(decision.verdict, ProbeVerdict::Blocked);
        assert!(decision.confidence >= 0.95);
        assert!(decision.rationale.contains("DNS poisoning"));
    }

    /// Test 2: Server-active — Clear даже при ML blocked.
    #[test]
    fn test_decision_server_active() {
        let mut result = make_result(
            DnsFailureCode::Ok,
            TcpFailureCode::ConnectOk,
            Some(TlsFailureCode::AlertSniblock),
        );
        result.discrimination = Some(DiscriminationResult {
            origin: BlockOrigin::ServerActive,
            verdict: ProbeVerdict::Clear,
            confidence: 0.90,
            rationale: "TLS alert from server: SNI rejected".into(),
        });
        // ML says blocked, but server-active overrides
        result.ml = Some(MlResult {
            score: 0.85,
            verdict: MlVerdict::Blocked,
            top_features: vec![("tls_tcp_ratio".into(), 5.0)],
        });

        let decision = decide(&result);
        assert_eq!(decision.verdict, ProbeVerdict::Clear);
        assert!(decision.confidence >= 0.85);
        assert!(decision.rationale.contains("Server-active"));
    }

    /// Test 3: Path-active + ML blocked — Blocked с повышенным confidence.
    #[test]
    fn test_decision_path_active_ml_blocked() {
        let mut result = make_result(
            DnsFailureCode::Ok,
            TcpFailureCode::ConnectOk,
            Some(TlsFailureCode::Reset),
        );
        result.discrimination = Some(DiscriminationResult {
            origin: BlockOrigin::PathActive,
            verdict: ProbeVerdict::Blocked,
            confidence: 0.85,
            rationale: "TCP RST during TLS — DPI killing connection".into(),
        });
        result.ml = Some(MlResult {
            score: 0.75,
            verdict: MlVerdict::Suspicious,
            top_features: vec![("tls_tcp_ratio".into(), 8.0)],
        });

        let decision = decide(&result);
        assert_eq!(decision.verdict, ProbeVerdict::Blocked);
        // ML score 0.75 > 0.5 → +0.1 confidence
        assert!(
            decision.confidence > 0.85,
            "confidence should be > 0.85, got {}",
            decision.confidence
        );
    }

    /// Test 4: TLS ok but server_hello_size=0 and cert_count=0 — T50 признаки понижают confidence.
    #[test]
    fn test_decision_tls_ok_zero_features() {
        let mut result = make_result(
            DnsFailureCode::Ok,
            TcpFailureCode::ConnectOk,
            Some(TlsFailureCode::Version13Ok),
        );
        // TLS ok но raw probe не собрал данные
        if let Some(ref mut tls) = result.tls {
            tls.server_hello_size = 0;
            tls.cert_count = 0;
        }

        let decision = decide(&result);
        // Без других сигналов — Ambiguous (all phases ok), но confidence понижен
        assert_eq!(decision.verdict, ProbeVerdict::Ambiguous);
        // T50 adjustments: -0.15 (server_hello_size=0) + -0.15 (cert_count=0) = -0.30
        assert!(
            decision.confidence < AMBIGUOUS_BASE_CONFIDENCE,
            "confidence should be reduced by T50 anomalies, got {}",
            decision.confidence
        );
    }

    /// Test 5: QUIC bypass — Ambiguous (частичный обход).
    #[test]
    fn test_decision_quic_bypass() {
        let mut result = make_result(DnsFailureCode::Ok, TcpFailureCode::Reset, None);
        // TCP blocked, QUIC works
        result.quic = Some(QuicProbeResult {
            response_type: QuicResponseType::Handshake,
            rtt_ms: 50,
            response_size: 200,
            response_preview: vec![],
            version: Some(1),
        });
        result.quic_verdict = Some(QuicVerdict::QuicBypass);

        let decision = decide(&result);
        // Ambiguous (не Clear) — частичный обход, нужен temporal accumulation
        assert_eq!(decision.verdict, ProbeVerdict::Ambiguous);
        assert!(
            decision.confidence >= 0.65 && decision.confidence <= 0.75,
            "confidence should be ~0.70 for partial bypass, got {}",
            decision.confidence
        );
        assert!(decision.rationale.contains("QUIC partial bypass"));
    }

    /// Test 6: All ok — Ambiguous (нужен re-probe).
    #[test]
    fn test_decision_all_ok() {
        let mut result = make_result(
            DnsFailureCode::Ok,
            TcpFailureCode::ConnectOk,
            Some(TlsFailureCode::Version13Ok),
        );
        result.ml = Some(MlResult {
            score: 0.1,
            verdict: MlVerdict::Clear,
            top_features: vec![],
        });

        let decision = decide(&result);
        assert_eq!(decision.verdict, ProbeVerdict::Ambiguous);
        assert!(
            decision.confidence <= 0.5,
            "should be Ambiguous with low confidence, got {}",
            decision.confidence
        );
    }

    /// Test 7: ML high anomaly (>0.8) — Blocked.
    #[test]
    fn test_decision_ml_high_anomaly() {
        let mut result = make_result(
            DnsFailureCode::Ok,
            TcpFailureCode::ConnectOk,
            Some(TlsFailureCode::Version13Ok),
        );
        // ML score very high — even though TLS ok
        result.ml = Some(MlResult {
            score: 0.92,
            verdict: MlVerdict::Blocked,
            top_features: vec![
                ("tls_tcp_ratio".into(), 12.0),
                ("inter_phase_jitter".into(), 5000.0),
            ],
        });

        let decision = decide(&result);
        assert_eq!(decision.verdict, ProbeVerdict::Blocked);
        assert!(decision.confidence >= 0.8);
    }

    /// Test 8: JA4 fingerprint blocking — Blocked.
    #[test]
    fn test_decision_ja4_fingerprint_blocking() {
        let mut result = make_result(
            DnsFailureCode::Ok,
            TcpFailureCode::ConnectOk,
            Some(TlsFailureCode::Reset),
        );
        result.ja4 = Some(Ja4ProbeResult {
            profiles: vec![],
            verdict: FingerprintVerdict::FingerprintBlocking,
            blocked_count: 1,
            ok_count: 3,
            working_profile: Some("curl_8".into()),
            blocked_profile: Some("chrome_130".into()),
        });

        let decision = decide(&result);
        assert_eq!(decision.verdict, ProbeVerdict::Blocked);
        assert!(decision.rationale.contains("JA4 fingerprint"));
    }

    /// Test 9: DNS manipulation — udp_rtt > 3× doh_rtt increases blocked confidence.
    #[test]
    fn test_decision_dns_manipulation() {
        let mut result = make_result(DnsFailureCode::Ok, TcpFailureCode::Reset, None);
        // UDP DNS very slow (300ms), DoH fast (50ms) — ratio 6× > 3×
        result.dns.udp_rtt_ms = 300.0;
        result.dns.doh_rtt_ms = 50.0;

        let decision = decide(&result);
        assert_eq!(decision.verdict, ProbeVerdict::Blocked);
        // Base 0.85 (TCP Reset) + DNS manip +0.10 = 0.95
        assert!(
            decision.confidence >= 0.90,
            "confidence should be boosted by DNS manipulation, got {}",
            decision.confidence
        );
    }

    /// Test 10: DPI delay — tls_rtt > 5× tcp_rtt increases confidence.
    #[test]
    fn test_decision_dpi_delay() {
        let mut result = make_result(
            DnsFailureCode::Ok,
            TcpFailureCode::ConnectOk,
            Some(TlsFailureCode::Version13Ok),
        );
        // TCP fast (10ms), TLS very slow (200ms) — ratio 20× > 5×
        result.tcp.rtt_us = 10000; // 10ms
        if let Some(ref mut tls) = result.tls {
            tls.latency_us = 200000; // 200ms
        }

        let decision = decide(&result);
        // Should be Ambiguous (all ok), but with DPI delay hint
        // confidence = AMBIGUOUS_BASE (0.30) + DPI_DELAY_DELTA (0.10) = 0.40
        assert!(
            decision.confidence > AMBIGUOUS_BASE_CONFIDENCE,
            "confidence should be boosted by DPI delay hint, got {}",
            decision.confidence
        );
    }

    /// Test 11: Signals list is populated (explainability).
    #[test]
    fn test_decision_signals_populated() {
        let mut result = make_result(
            DnsFailureCode::Ok,
            TcpFailureCode::Reset,
            Some(TlsFailureCode::Reset),
        );
        result.discrimination = Some(DiscriminationResult {
            origin: BlockOrigin::PathActive,
            verdict: ProbeVerdict::Blocked,
            confidence: 0.85,
            rationale: "TCP RST".into(),
        });
        result.ml = Some(MlResult {
            score: 0.7,
            verdict: MlVerdict::Suspicious,
            top_features: vec![("test".into(), 1.0)],
        });

        let decision = decide(&result);
        assert!(!decision.signals.is_empty(), "signals should be populated");
        assert!(decision
            .signals
            .iter()
            .any(|s| s.signal_name == "path_active"));
        assert!(decision
            .signals
            .iter()
            .any(|s| s.signal_name == "ml_suspicious"));
    }
}
