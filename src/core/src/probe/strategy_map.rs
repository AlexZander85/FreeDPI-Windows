//! Strategy Map — связка типа блокировки с рекомендуемой стратегией desync.
//!
//! На основе ProbeResult определяет, какую стратегию desync использовать
//! для обхода DPI-блокировки конкретного типа.
//!
//! Источники:
//! - Собственная разработка на основе анализа проектов Ladon, dpi-detector, dpi-checkers

use crate::adaptive::strategy::StrategyCategory;
use crate::probe::classifier::*;
use crate::probe::ja4_probe::FingerprintVerdict;
use crate::probe::ml_classifier::MlVerdict;
use crate::probe::quic_probe::QuicVerdict;
use crate::probe::ProbeResult;
use serde::{Deserialize, Serialize};

/// Рекомендация стратегии.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyRecommendation {
    pub strategy_id: u32,
    pub strategy_name: String,
    /// T55: имя профиля в StrategyProfileRegistry
    pub profile_name: String,
    pub category: StrategyCategory,
    pub confidence: f64,
    pub rationale: String,
}

/// Определить рекомендованные стратегии на основе результатов probe.
pub fn recommend(result: &ProbeResult) -> Vec<StrategyRecommendation> {
    let mut recs = Vec::new();

    // DNS-level recommendations
    match result.dns.verdict {
        DnsFailureCode::Poisoned | DnsFailureCode::NxdomainSpoof | DnsFailureCode::EmptySpoof => {
            recs.push(StrategyRecommendation {
                strategy_id: 100,
                strategy_name: "doh_dns".into(),
                profile_name: "dns_doh".into(),
                category: StrategyCategory::Dns,
                confidence: 0.95,
                rationale: "DNS poisoned — force DoH resolver".into(),
            });
        }
        DnsFailureCode::Intercepted => {
            recs.push(StrategyRecommendation {
                strategy_id: 100,
                strategy_name: "doh_dns".into(),
                profile_name: "dns_doh".into(),
                category: StrategyCategory::Dns,
                confidence: 0.90,
                rationale: "DNS intercepted — UDP blocked, use DoH".into(),
            });
        }
        _ => {}
    }

    // TCP-level recommendations
    match result.tcp.verdict {
        TcpFailureCode::Reset => {
            recs.push(StrategyRecommendation {
                strategy_id: 1,
                strategy_name: "tcp_split".into(),
                profile_name: "outbound_tls".into(),
                category: StrategyCategory::Tcp,
                confidence: 0.85,
                rationale: "TCP RST — DPI inspecting SYN/CH, apply split".into(),
            });
        }
        TcpFailureCode::Timeout => {
            recs.push(StrategyRecommendation {
                strategy_id: 3,
                strategy_name: "fake_sni".into(),
                profile_name: "outbound_tls".into(),
                category: StrategyCategory::Tls,
                confidence: 0.80,
                rationale: "TCP timeout — SYN drop, use fake SNI with low TTL".into(),
            });
        }
        TcpFailureCode::DataVolumeCut => {
            recs.push(StrategyRecommendation {
                strategy_id: 9,
                strategy_name: "mss_clamp".into(),
                profile_name: "tcp_mss_clamp".into(),
                category: StrategyCategory::Tcp,
                confidence: 0.85,
                rationale: "Data-volume cut — DPI counting packets, use MSS clamp + reorder".into(),
            });
        }
        _ => {}
    }

    // TLS-level recommendations
    if let Some(ref tls) = result.tls {
        match tls.verdict {
            TlsFailureCode::Version12Only => {
                recs.push(StrategyRecommendation {
                    strategy_id: 15,
                    strategy_name: "tls_record_frag".into(),
                    profile_name: "outbound_tls_tlsfrag".into(),
                    category: StrategyCategory::Tls,
                    confidence: 0.90,
                    rationale: "TLS 1.3 blocked, 1.2 works — force TLS 1.2 + record frag".into(),
                });
            }
            TlsFailureCode::Garbage => {
                recs.push(StrategyRecommendation {
                    strategy_id: 6,
                    strategy_name: "seq_number_spoof".into(),
                    profile_name: "outbound_tls_seqspoof".into(),
                    category: StrategyCategory::Tcp,
                    confidence: 0.85,
                    rationale: "TLS garbage injection — DPI injecting fake records, use SEQ spoof".into(),
                });
            }
            TlsFailureCode::Reset => {
                recs.push(StrategyRecommendation {
                    strategy_id: 7,
                    strategy_name: "disorder".into(),
                    profile_name: "outbound_tls_disorder".into(),
                    category: StrategyCategory::Tcp,
                    confidence: 0.80,
                    rationale: "TLS RST — DPI killing handshake, use disorder".into(),
                });
            }
            TlsFailureCode::AlertSniblock => {
                recs.push(StrategyRecommendation {
                    strategy_id: 4,
                    strategy_name: "hostfake".into(),
                    profile_name: "outbound_tls_hostfake".into(),
                    category: StrategyCategory::Tcp,
                    confidence: 0.85,
                    rationale: "SNI blocked — use hostfake with allowed SNI".into(),
                });
            }
            TlsFailureCode::Mitm | TlsFailureCode::MitmSelfSigned | TlsFailureCode::MitmExpired => {
                recs.push(StrategyRecommendation {
                    strategy_id: 35,
                    strategy_name: "socks5_fallback".into(),
                    profile_name: "socks5_fallback".into(),
                    category: StrategyCategory::General,
                    confidence: 0.90,
                    rationale: "Certificate substitution — MITM detected, use proxy".into(),
                });
            }
            _ => {}
        }
    }

    // HTTP-level recommendations
    if let Some(ref http) = result.http {
        match http.verdict {
            HttpFailureCode::Cutoff => {
                recs.push(StrategyRecommendation {
                    strategy_id: 8,
                    strategy_name: "tcp_window_clamp".into(),
                    profile_name: "tcp_window_clamp".into(),
                    category: StrategyCategory::Tcp,
                    confidence: 0.80,
                    rationale: "HTTP cutoff — DPI counting packets, use window clamp".into(),
                });
            }
            HttpFailureCode::Http451 => {
                recs.push(StrategyRecommendation {
                    strategy_id: 35,
                    strategy_name: "socks5_fallback".into(),
                    profile_name: "socks5_fallback".into(),
                    category: StrategyCategory::General,
                    confidence: 0.95,
                    rationale: "HTTP 451 — legal block, proxy required".into(),
                });
            }
            HttpFailureCode::RedirectForeign => {
                recs.push(StrategyRecommendation {
                    strategy_id: 35,
                    strategy_name: "socks5_fallback".into(),
                    profile_name: "socks5_fallback".into(),
                    category: StrategyCategory::General,
                    confidence: 0.85,
                    rationale: "ISP block page — redirect to foreign domain, use proxy".into(),
                });
            }
            HttpFailureCode::StubPage => {
                recs.push(StrategyRecommendation {
                    strategy_id: 35,
                    strategy_name: "socks5_fallback".into(),
                    profile_name: "socks5_fallback".into(),
                    category: StrategyCategory::General,
                    confidence: 0.90,
                    rationale: "RKN stub page detected — use proxy".into(),
                });
            }
            _ => {}
        }
    }

    // JA4 Fingerprint recommendations (T45)
    if let Some(ref ja4) = result.ja4 {
        match ja4.verdict {
            FingerprintVerdict::FingerprintBlocking => {
                let working = ja4.working_profile.as_deref().unwrap_or("unknown");
                recs.push(StrategyRecommendation {
                    strategy_id: 50,
                    strategy_name: "ja4_spoof".into(),
                    profile_name: "outbound_tls".into(),
                    category: StrategyCategory::Tls,
                    confidence: 0.90,
                    rationale: format!("Fingerprint blocking detected — spoof JA4 of {}", working,),
                });
            }
            FingerprintVerdict::SniBasedBlocking => {
                recs.push(StrategyRecommendation {
                    strategy_id: 4,
                    strategy_name: "hostfake".into(),
                    profile_name: "outbound_tls_hostfake".into(),
                    category: StrategyCategory::Tcp,
                    confidence: 0.85,
                    rationale:
                        "SNI-based blocking confirmed by JA4 probe (all fingerprints blocked)"
                            .into(),
                });
            }
            _ => {}
        }
    }

    // QUIC recommendations (T46)
    if let Some(ref quic_verdict) = result.quic_verdict {
        match quic_verdict {
            QuicVerdict::QuicBlocked => {
                recs.push(StrategyRecommendation {
                    strategy_id: 60,
                    strategy_name: "force_tcp_http2".into(),
                    profile_name: "socks5_fallback".into(),
                    category: StrategyCategory::General,
                    confidence: 0.85,
                    rationale: "QUIC blocked — force HTTP/2 over TCP (disable HTTP/3)".into(),
                });
            }
            QuicVerdict::QuicBypass => {
                recs.push(StrategyRecommendation {
                    strategy_id: 61,
                    strategy_name: "force_quic".into(),
                    profile_name: "outbound_quic".into(),
                    category: StrategyCategory::General,
                    confidence: 0.90,
                    rationale: "TCP blocked, QUIC works — force HTTP/3 (disable TCP fallback)"
                        .into(),
                });
            }
            _ => {}
        }
    }

    // ML-based recommendations (T47)
    if let Some(ref ml) = result.ml {
        match ml.verdict {
            MlVerdict::Blocked => {
                recs.push(StrategyRecommendation {
                    strategy_id: 70,
                    strategy_name: "ml_anomaly_response".into(),
                    profile_name: "outbound_tls".into(),
                    category: StrategyCategory::Tcp,
                    confidence: ml.score,
                    rationale: format!(
                        "ML anomaly score {:.2} — timing analysis suggests DPI interference",
                        ml.score,
                    ),
                });
            }
            MlVerdict::Suspicious => {
                // Suspicious — soft recommendation, lower confidence
                recs.push(StrategyRecommendation {
                    strategy_id: 70,
                    strategy_name: "ml_anomaly_response".into(),
                    profile_name: "outbound_tls".into(),
                    category: StrategyCategory::Tcp,
                    confidence: ml.score * 0.7,
                    rationale: format!(
                        "ML anomaly score {:.2} — suspicious timing, consider reprobe",
                        ml.score,
                    ),
                });
            }
            MlVerdict::Clear => {
                // Clear signal — no ML-based action needed
            }
        }
    }

    // Data-volume recommendations
    if let Some(ref tcp16) = result.tcp16 {
        if tcp16.detected {
            recs.push(StrategyRecommendation {
                strategy_id: 9,
                strategy_name: "mss_clamp".into(),
                profile_name: "tcp_mss_clamp".into(),
                category: StrategyCategory::Tcp,
                confidence: 0.80,
                rationale: format!(
                    "Data-volume cutoff at {}KB — use MSS clamp + reorder",
                    tcp16.detected_at_kb
                ),
            });
        }
    }

    // CIDR whitelist detection (github fails, ya.ru works)
    if result.dns.verdict == DnsFailureCode::Ok && result.tcp.verdict == TcpFailureCode::Timeout {
        recs.push(StrategyRecommendation {
            strategy_id: 35,
            strategy_name: "socks5_fallback".into(),
            profile_name: "socks5_fallback".into(),
            category: StrategyCategory::General,
            confidence: 0.70,
            rationale: "TCP timeout on foreign IP — possible CIDR whitelist, use proxy".into(),
        });
    }

    recs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::dns_probe::DnsProbeResult;
    use crate::probe::http_probe::HttpProbeResult;
    use crate::probe::tcp_probe::TcpProbeResult;
    use crate::probe::tls_probe::TlsProbeResult;
    use std::net::Ipv4Addr;

    fn make_test_result(
        dns: DnsFailureCode,
        tcp: TcpFailureCode,
        tls: Option<TlsFailureCode>,
    ) -> ProbeResult {
        ProbeResult {
            domain: "test.com".into(),
            ip: Some(Ipv4Addr::new(8, 8, 8, 8)),
            verdict: ProbeVerdict::Ambiguous,
            confidence: 0.5,
            dns: DnsProbeResult {
                verdict: dns,
                resolved_ips: vec![],
                udp_ips: vec![],
                doh_ips: vec![],
                latency_us: 0,
                fake_ip_detected: false,
                udp_rtt_ms: 0.0,
                doh_rtt_ms: 0.0,
                udp_response_size: 0,
                doh_response_size: 0,
            },
            tcp: TcpProbeResult {
                verdict: tcp,
                rtt_us: 10000,
                ip: Some(Ipv4Addr::new(8, 8, 8, 8)),
            },
            tls: tls.map(|v| TlsProbeResult {
                verdict: v,
                tls13_ok: false,
                tls12_ok: false,
                stage: crate::probe::classifier::ConnectionStage::TlsConnected,
                latency_us: 50000,
                server_hello_size: 0,
                cert_count: 0,
                negotiated_version: None,
                negotiated_cipher: None,
            }),
            http: None,
            tcp16: None,
            discrimination: None,
            ja4: None,
            quic: None,
            quic_verdict: None,
            features: None,
            ml: None,
            should_tunnel: false,
            timestamp: "".into(),
            decision: None,
        }
    }

    #[test]
    fn test_recommend_dns_poisoned() {
        let result = make_test_result(DnsFailureCode::Poisoned, TcpFailureCode::ConnectOk, None);
        let recs = recommend(&result);
        assert!(recs.iter().any(|r| r.strategy_name == "doh_dns"));
    }

    #[test]
    fn test_recommend_tcp_reset() {
        let result = make_test_result(DnsFailureCode::Ok, TcpFailureCode::Reset, None);
        let recs = recommend(&result);
        assert!(recs.iter().any(|r| r.strategy_name == "tcp_split"));
    }

    #[test]
    fn test_recommend_tls_version12only() {
        let result = make_test_result(
            DnsFailureCode::Ok,
            TcpFailureCode::ConnectOk,
            Some(TlsFailureCode::Version12Only),
        );
        let recs = recommend(&result);
        assert!(recs.iter().any(|r| r.strategy_name == "tls_record_frag"));
    }

    #[test]
    fn test_recommend_tls_garbage() {
        let result = make_test_result(
            DnsFailureCode::Ok,
            TcpFailureCode::ConnectOk,
            Some(TlsFailureCode::Garbage),
        );
        let recs = recommend(&result);
        assert!(recs.iter().any(|r| r.strategy_name == "seq_number_spoof"));
    }

    #[test]
    fn test_recommend_http_451() {
        let mut result = make_test_result(
            DnsFailureCode::Ok,
            TcpFailureCode::ConnectOk,
            Some(TlsFailureCode::HandshakeOk),
        );
        result.http = Some(HttpProbeResult {
            verdict: HttpFailureCode::Http451,
            bytes_read: 0,
            redirect_url: None,
            latency_us: 0,
            status_code: 451,
            headers_size: 0,
            first_byte_rtt_ms: 0.0,
            total_rtt_ms: 0.0,
        });
        let recs = recommend(&result);
        assert!(recs.iter().any(|r| r.strategy_name == "socks5_fallback"));
    }

    #[test]
    fn test_recommend_ml_blocked() {
        let mut result = make_test_result(
            DnsFailureCode::Ok,
            TcpFailureCode::ConnectOk,
            Some(TlsFailureCode::HandshakeOk),
        );
        result.ml = Some(crate::probe::ml_classifier::MlResult {
            score: 0.85,
            verdict: MlVerdict::Blocked,
            top_features: vec![("tls_tcp_ratio".into(), 1.5)],
        });
        let recs = recommend(&result);
        assert!(recs
            .iter()
            .any(|r| r.strategy_name == "ml_anomaly_response"));
    }

    #[test]
    fn test_recommend_ml_suspicious() {
        let mut result = make_test_result(
            DnsFailureCode::Ok,
            TcpFailureCode::ConnectOk,
            Some(TlsFailureCode::HandshakeOk),
        );
        result.ml = Some(crate::probe::ml_classifier::MlResult {
            score: 0.45,
            verdict: MlVerdict::Suspicious,
            top_features: vec![("inter_phase_jitter".into(), 0.8)],
        });
        let recs = recommend(&result);
        assert!(recs
            .iter()
            .any(|r| r.strategy_name == "ml_anomaly_response"));
    }

    #[test]
    fn test_recommend_includes_profile_name() {
        let result = make_test_result(DnsFailureCode::Ok, TcpFailureCode::Reset, None);
        let recs = recommend(&result);
        let rec = recs.iter().find(|r| r.strategy_name == "tcp_split").unwrap();
        assert_eq!(rec.profile_name, "outbound_tls");
    }
}
