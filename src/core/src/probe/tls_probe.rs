//! TLS Probe — staged TLS handshake (1.3 → 1.2) + stage tracking.
//!
//! Методика (из Ladon + dpi-detector):
//! 1. Attempt 1: TLS 1.3 (через native-tls с强制ой версией)
//! 2. Attempt 2: TLS 1.2 (fallback если 1.3 fail)
//! 3. TLS version split detection: 1.3 fail + 1.2 ok = Version12Only (DPI атакует ClientHello!)
//! 4. Stage-aware classification: RST/timeout/garbage/alert/MITM
//!
//! Источники:
//! - [Ladon](https://github.com/nickspaargaren/ladon): TLS version split detection
//! - [dpi-detector](https://github.com/Runnin4ik/dpi-detector): stage tracking + MITM detection

use crate::probe::classifier::{ConnectionStage, TlsFailureCode};
use crate::probe::config::ProbeConfig;
use native_tls::Protocol;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use tracing::{debug, info};

/// Результат TLS probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsProbeResult {
    pub verdict: TlsFailureCode,
    pub tls13_ok: bool,
    pub tls12_ok: bool,
    pub stage: ConnectionStage,
    pub latency_us: u64,
    // T50.1 / T53: raw handshake features
    /// ServerHello handshake record size (bytes), 0 if not available
    pub server_hello_size: usize,
    /// Number of certificates in Certificate message, 0 if not available
    pub cert_count: usize,
    /// Negotiated TLS version (e.g. "1.3", "1.2")
    pub negotiated_version: Option<String>,
    /// Negotiated cipher suite name (e.g. "TLS_AES_128_GCM_SHA256")
    pub negotiated_cipher: Option<String>,
}

// === T54.5: Default implementation ===
impl Default for TlsProbeResult {
    fn default() -> Self {
        Self {
            verdict: TlsFailureCode::HandshakeOk,
            tls13_ok: false,
            tls12_ok: false,
            stage: ConnectionStage::TcpConnect,
            latency_us: 0,
            server_hello_size: 0,
            cert_count: 0,
            negotiated_version: None,
            negotiated_cipher: None,
        }
    }
}

/// Features, собранные из raw TLS handshake response (T53).
#[derive(Debug, Clone, Default)]
pub struct RawHandshakeFeatures {
    pub server_hello_size: usize,
    pub cert_count: usize,
    pub negotiated_version: Option<String>,
    pub negotiated_cipher: Option<String>,
}

/// TLS Probe — staged handshake (1.3 → 1.2) + stage tracking + raw handshake features (T53).
pub struct TlsProbe {
    config: ProbeConfig,
    http_client: reqwest::Client,
}

impl TlsProbe {
    pub fn new(config: &ProbeConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(config.tls_connect_timeout)
            .danger_accept_invalid_certs(true)
            .build()
            .expect("Failed to create HTTP client for TLS probe");

        Self {
            config: config.clone(),
            http_client,
        }
    }

    /// TLS probe: raw socket for features + native-tls for verdict.
    pub async fn probe(&self, ip: Ipv4Addr, domain: &str) -> TlsProbeResult {
        let start = std::time::Instant::now();
        let addr: SocketAddr = SocketAddr::new(ip.into(), 443);

        // Stage 1: TCP connect check
        let tcp_ok = match tokio::time::timeout(
            self.config.tcp_connect_timeout,
            tokio::net::TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(stream)) => {
                drop(stream);
                true
            }
            Ok(Err(e)) => {
                let err_str = e.to_string().to_lowercase();
                let verdict = if err_str.contains("reset") || err_str.contains("refused") {
                    TlsFailureCode::Reset
                } else {
                    TlsFailureCode::SilentDrop
                };
                return TlsProbeResult {
                    verdict,
                    tls13_ok: false,
                    tls12_ok: false,
                    stage: ConnectionStage::TcpConnected,
                    latency_us: start.elapsed().as_micros() as u64,
                    server_hello_size: 0,
                    cert_count: 0,
                    negotiated_version: None,
                    negotiated_cipher: None,
                };
            }
            Err(_) => {
                return TlsProbeResult {
                    verdict: TlsFailureCode::SilentDrop,
                    tls13_ok: false,
                    tls12_ok: false,
                    stage: ConnectionStage::TcpConnect,
                    latency_us: start.elapsed().as_micros() as u64,
                    server_hello_size: 0,
                    cert_count: 0,
                    negotiated_version: None,
                    negotiated_cipher: None,
                };
            }
        };

        // Stage 2: Raw socket probe — собираем handshake features
        let raw_features = if tcp_ok {
            self.raw_handshake_probe(ip, domain).await
        } else {
            RawHandshakeFeatures::default()
        };

        // Stage 3: native-tls probe — получаем verdict
        let tls13_verdict = self
            .probe_version_native(ip, domain, Protocol::Tlsv13)
            .await;
        let tls13_ok = tls13_verdict == TlsFailureCode::HandshakeOk
            || tls13_verdict == TlsFailureCode::Version13Ok;

        debug!(
            "TLS 1.3 probe for {}: {:?} (ok={})",
            domain, tls13_verdict, tls13_ok
        );

        // If TLS 1.3 succeeded, also try to confirm it's really 1.3
        if tls13_ok {
            let reqwest_ok = self.probe_reqwest(domain).await;
            if reqwest_ok {
                return TlsProbeResult {
                    verdict: TlsFailureCode::Version13Ok,
                    tls13_ok: true,
                    tls12_ok: true,
                    stage: ConnectionStage::TlsConnected,
                    latency_us: start.elapsed().as_micros() as u64,
                    server_hello_size: raw_features.server_hello_size,
                    cert_count: raw_features.cert_count,
                    negotiated_version: raw_features.negotiated_version,
                    negotiated_cipher: raw_features.negotiated_cipher,
                };
            }
        }

        // Attempt 2: TLS 1.2 (fallback)
        let tls12_verdict = self
            .probe_version_native(ip, domain, Protocol::Tlsv12)
            .await;
        let tls12_ok = tls12_verdict == TlsFailureCode::HandshakeOk;

        debug!(
            "TLS 1.2 probe for {}: {:?} (ok={})",
            domain, tls12_verdict, tls12_ok
        );

        // TLS version split detection
        if !tls13_ok && tls12_ok {
            info!(
                "Version12Only detected for {}: TLS 1.3 blocked, 1.2 works — DPI attacking ClientHello",
                domain
            );
            return TlsProbeResult {
                verdict: TlsFailureCode::Version12Only,
                tls13_ok: false,
                tls12_ok: true,
                stage: ConnectionStage::TlsConnected,
                latency_us: start.elapsed().as_micros() as u64,
                server_hello_size: raw_features.server_hello_size,
                cert_count: raw_features.cert_count,
                negotiated_version: raw_features.negotiated_version,
                negotiated_cipher: raw_features.negotiated_cipher,
            };
        }

        // If both failed
        if !tls12_ok && !tls13_ok {
            let verdict = if tls13_verdict.is_tls_fail() {
                tls13_verdict
            } else {
                tls12_verdict
            };
            return TlsProbeResult {
                verdict,
                tls13_ok: false,
                tls12_ok: false,
                stage: ConnectionStage::TlsHandshake,
                latency_us: start.elapsed().as_micros() as u64,
                server_hello_size: raw_features.server_hello_size,
                cert_count: raw_features.cert_count,
                negotiated_version: raw_features.negotiated_version,
                negotiated_cipher: raw_features.negotiated_cipher,
            };
        }

        // TLS 1.2 ok
        TlsProbeResult {
            verdict: TlsFailureCode::HandshakeOk,
            tls13_ok,
            tls12_ok,
            stage: ConnectionStage::TlsConnected,
            latency_us: start.elapsed().as_micros() as u64,
            server_hello_size: raw_features.server_hello_size,
            cert_count: raw_features.cert_count,
            negotiated_version: raw_features.negotiated_version,
            negotiated_cipher: raw_features.negotiated_cipher,
        }
    }

    /// Raw socket probe — отправляет ClientHello, читает response, извлекает features.
    async fn raw_handshake_probe(&self, ip: Ipv4Addr, domain: &str) -> RawHandshakeFeatures {
        use crate::adaptive::ch_gen;
        use crate::desync::rand::PerConnRng;

        let mut rng = PerConnRng::new(42);
        let client_hello = ch_gen::build_client_hello(domain, &mut rng);

        let connect_timeout = self.config.tls_connect_timeout;
        let read_timeout = self.config.tls_read_timeout;
        let ch_owned = client_hello.clone();

        let result = tokio::task::spawn_blocking(move || {
            let addr = SocketAddr::new(ip.into(), 443);

            // TCP connect
            let mut stream = match TcpStream::connect_timeout(&addr, connect_timeout) {
                Ok(s) => s,
                Err(_) => return RawHandshakeFeatures::default(),
            };
            let _ = stream.set_read_timeout(Some(read_timeout));
            let _ = stream.set_write_timeout(Some(read_timeout));

            // Send ClientHello
            if stream.write_all(&ch_owned).is_err() {
                return RawHandshakeFeatures::default();
            }

            // Read response (up to 16KB — достаточно для ServerHello + Certificate chain)
            let mut buf = vec![0u8; 16384];
            let mut total = 0;
            let read_deadline = std::time::Instant::now() + read_timeout;
            while total < buf.len() {
                if std::time::Instant::now() > read_deadline {
                    break;
                }
                match stream.read(&mut buf[total..]) {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        total += n;
                        // Проверяем — прочитали ли ServerHelloDone или хотя бы 8KB
                        if total >= 6 {
                            let found_done = buf[..total].windows(6).any(|w| {
                                w[0] == 0x16          // ContentType = Handshake
                                    && w[1] == 0x03    // Version major
                                    && w[5] == 0x0E // HandshakeType = ServerHelloDone
                            });
                            if found_done || total > 8192 {
                                break;
                            }
                        }
                    }
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        break
                    }
                    Err(_) => break,
                }
            }

            // Parse features
            let (server_hello_size, cert_count, negotiated_version, negotiated_cipher) =
                crate::probe::ja4_probe::extract_tls_handshake_features(&buf[..total]);

            RawHandshakeFeatures {
                server_hello_size,
                cert_count,
                negotiated_version,
                negotiated_cipher,
            }
        })
        .await;

        result.unwrap_or_default()
    }

    /// native-tls probe — только для verdict (HandshakeOk/Reset/Alert).
    /// Переименовано из probe_version.
    async fn probe_version_native(
        &self,
        ip: Ipv4Addr,
        domain: &str,
        protocol: Protocol,
    ) -> TlsFailureCode {
        let addr = SocketAddr::new(ip.into(), 443);
        let domain = domain.to_string();
        let timeout = self.config.tls_connect_timeout;

        let result = tokio::time::timeout(
            timeout,
            tokio::task::spawn_blocking(move || {
                // Build TLS connector with specific version
                let connector = native_tls::TlsConnector::builder()
                    .min_protocol_version(Some(protocol))
                    .max_protocol_version(Some(protocol))
                    .danger_accept_invalid_certs(true)
                    .build();

                let connector = match connector {
                    Ok(c) => c,
                    Err(_) => return TlsFailureCode::Garbage,
                };

                // TCP connect
                let tcp_stream = match std::net::TcpStream::connect(addr) {
                    Ok(s) => s,
                    Err(e) => {
                        let err = e.to_string().to_lowercase();
                        if err.contains("reset") || err.contains("refused") {
                            return TlsFailureCode::Reset;
                        }
                        return TlsFailureCode::SilentDrop;
                    }
                };

                // TLS handshake
                match connector.connect(&domain, tcp_stream) {
                    Ok(_stream) => TlsFailureCode::HandshakeOk,
                    Err(e) => classify_handshake_error(&e),
                }
            }),
        )
        .await;

        match result {
            Ok(Ok(verdict)) => verdict,
            Ok(Err(_)) => TlsFailureCode::Garbage,
            Err(_) => TlsFailureCode::SilentDrop,
        }
    }

    /// Fallback probe using reqwest (confirms TLS works).
    async fn probe_reqwest(&self, domain: &str) -> bool {
        let url = format!("https://{}/", domain);
        matches!(
            tokio::time::timeout(
                self.config.tls_connect_timeout,
                self.http_client.get(&url).send(),
            )
            .await,
            Ok(Ok(_))
        )
    }
}

/// Классификация ошибок TLS handshake.
fn classify_handshake_error(e: &native_tls::HandshakeError<std::net::TcpStream>) -> TlsFailureCode {
    match e {
        native_tls::HandshakeError::Failure(tls_err) => {
            let err_str = tls_err.to_string().to_lowercase();

            if err_str.contains("certificate") || err_str.contains("cert") {
                if err_str.contains("expired") {
                    return TlsFailureCode::MitmExpired;
                }
                if err_str.contains("self-signed") || err_str.contains("unknown issuer") {
                    return TlsFailureCode::MitmSelfSigned;
                }
                if err_str.contains("hostname") || err_str.contains("mismatch") {
                    return TlsFailureCode::MitmHostnameMismatch;
                }
                return TlsFailureCode::Mitm;
            }

            if err_str.contains("alert") {
                if err_str.contains("unrecognized") || err_str.contains("sni") {
                    return TlsFailureCode::AlertSniblock;
                }
                if err_str.contains("handshake") {
                    return TlsFailureCode::AlertHandshake;
                }
                if err_str.contains("protocol") {
                    return TlsFailureCode::AlertProtocol;
                }
                return TlsFailureCode::Alert;
            }

            if err_str.contains("decode")
                || err_str.contains("oversized")
                || err_str.contains("illegal")
            {
                return TlsFailureCode::Garbage;
            }

            TlsFailureCode::Garbage
        }
        native_tls::HandshakeError::WouldBlock(_mid) => {
            // WouldBlock means TLS handshake is incomplete (timeout or non-blocking)
            TlsFailureCode::SilentDrop
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_probe_result_serialization() {
        let result = TlsProbeResult {
            verdict: TlsFailureCode::Version12Only,
            tls13_ok: false,
            tls12_ok: true,
            stage: ConnectionStage::TlsConnected,
            latency_us: 50000,
            server_hello_size: 128,
            cert_count: 2,
            negotiated_version: Some("1.2".to_string()),
            negotiated_cipher: Some("ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string()),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: TlsProbeResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.verdict, TlsFailureCode::Version12Only);
        assert!(back.tls12_ok);
        assert_eq!(back.server_hello_size, 128);
        assert_eq!(back.cert_count, 2);
        assert_eq!(back.negotiated_version, Some("1.2".to_string()));
    }

    #[test]
    fn test_tls_handshake_error_types() {
        // Verify error classification logic exists
        let verdict = TlsFailureCode::SilentDrop;
        assert!(verdict.is_tls_fail());
        let ok = TlsFailureCode::HandshakeOk;
        assert!(!ok.is_tls_fail());
    }
}
