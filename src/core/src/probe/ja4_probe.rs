//! JA4 Fingerprint Probe — определение DPI, блокирующего по TLS fingerprint.
//!
//! Методика:
//! 1. Construct 4 ClientHello variants with different JA4 (Chrome, Firefox, Safari, curl)
//! 2. Send each to target via raw TCP (не native_tls — полный контроль над CH)
//! 3. Classify response: ServerHello / RST / timeout / garbage
//! 4. Discriminate:
//!    - All 4 fail → SNI-based blocking (не fingerprint)
//!    - Some fail, some ok → fingerprint-based blocking
//!    - All ok → no fingerprint blocking
//!
//! Источники:
//! - JA4: https://github.com/FoxIO-LLC/ja4 (Salesforce 2023)

use crate::adaptive::ch_gen;
use crate::desync::rand::PerConnRng;
use crate::probe::classifier::TlsFailureCode;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};
use tracing::debug;

/// JA4 fingerprint string (12-char hash components).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ja4Fingerprint {
    pub protocol: String,  // "t13", "t12"
    pub sni_present: bool, // true = "d", false = "u"
    pub cipher_count: u32,
    pub ext_count: u32,
    pub alpn: String,        // "h2", "h1", "00"
    pub cipher_hash: String, // 12 hex chars
    pub ext_hash: String,    // 12 hex chars
}

impl std::fmt::Display for Ja4Fingerprint {
    /// Полная JA4 строка: t13d1516h2_8daaf6152771_b186095e22b6
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sni_char = if self.sni_present { 'd' } else { 'u' };
        write!(
            f,
            "{}{}{:02}{:02}{}_{}_{}",
            self.protocol,
            sni_char,
            self.cipher_count,
            self.ext_count,
            self.alpn,
            self.cipher_hash,
            self.ext_hash
        )
    }
}

impl Ja4Fingerprint {
    /// Парсит JA4 строку вида t13d1516h2_8daaf6152771_b186095e22b6
    pub fn from_string(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.splitn(3, '_').collect();
        if parts.len() < 3 {
            return None;
        }
        let prefix = parts[0];
        if prefix.len() < 8 {
            return None;
        }
        let protocol = prefix[..3].to_string();
        let sni_present = &prefix[3..4] == "d";
        let cipher_count: u32 = prefix[4..6].parse().ok()?;
        let ext_count: u32 = prefix[6..8].parse().ok()?;
        let alpn = prefix[8..].to_string();
        let cipher_hash = parts[1].to_string();
        let ext_hash = parts[2].to_string();
        Some(Self {
            protocol,
            sni_present,
            cipher_count,
            ext_count,
            alpn,
            cipher_hash,
            ext_hash,
        })
    }
}

/// Профиль TLS клиента с известным JA4.
#[derive(Debug, Clone)]
pub struct TlsFingerprintProfile {
    pub name: &'static str,
    pub ja4_expected: &'static str,
    /// Функция построения ClientHello (через ch_gen с правильными параметрами)
    pub build_ch: fn(sni: &str, rng: &mut PerConnRng) -> Vec<u8>,
}

/// 4 стандартных профиля для fingerprint probe.
pub fn standard_profiles() -> Vec<TlsFingerprintProfile> {
    vec![
        TlsFingerprintProfile {
            name: "chrome_130",
            ja4_expected: "t13d1516h2_8daaf6152771_b186095e22b6",
            build_ch: build_chrome_130_ch,
        },
        TlsFingerprintProfile {
            name: "firefox_120",
            ja4_expected: "t13d2816h2_4be751f23922_7e0c33c2a5f5",
            build_ch: build_firefox_120_ch,
        },
        TlsFingerprintProfile {
            name: "safari_17",
            ja4_expected: "t13d1216h2_7719d2f23977_5681e26e1a45",
            build_ch: build_safari_17_ch,
        },
        TlsFingerprintProfile {
            name: "curl_8",
            ja4_expected: "t13d1016h2_4889f7323315_0f23edc22a8b",
            build_ch: build_curl_8_ch,
        },
    ]
}

// === Profile builders ===
// Каждый возвращает ClientHello с правильным набором extensions/cipher_suites
// для соответствия JA4 профиля. Используют ch_gen::build_client_hello как base.

fn build_chrome_130_ch(sni: &str, rng: &mut PerConnRng) -> Vec<u8> {
    ch_gen::build_chrome_130_ch(sni, rng)
}

fn build_firefox_120_ch(sni: &str, rng: &mut PerConnRng) -> Vec<u8> {
    ch_gen::build_firefox_120_ch(sni, rng)
}

fn build_safari_17_ch(sni: &str, rng: &mut PerConnRng) -> Vec<u8> {
    ch_gen::build_safari_17_ch(sni, rng)
}

fn build_curl_8_ch(sni: &str, rng: &mut PerConnRng) -> Vec<u8> {
    ch_gen::build_curl_8_ch(sni, rng)
}

/// Результат probe одного fingerprint профиля.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintProbeResult {
    pub profile_name: String,
    pub ja4_expected: String,
    pub ja4_actual: Option<String>,
    pub verdict: TlsFailureCode,
    pub rtt_ms: u64,
    /// Response bytes (first 64 bytes для debugging)
    pub response_preview: Vec<u8>,
}

/// Результат всего fingerprint probe (4 профиля).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Ja4ProbeResult {
    /// Результаты по каждому профилю
    pub profiles: Vec<FingerprintProbeResult>,
    /// Итоговый вердикт discriminate
    pub verdict: FingerprintVerdict,
    /// Сколько профилей blocked/ok
    pub blocked_count: usize,
    pub ok_count: usize,
    /// Имя blocked профиля (если fingerprint blocking)
    pub blocked_profile: Option<String>,
    /// Имя working профиля (если fingerprint blocking)
    pub working_profile: Option<String>,
}

/// Fingerprint blocking verdict.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FingerprintVerdict {
    /// All 4 profiles work — no fingerprint blocking
    #[default]
    NoFingerprintBlocking,
    /// All 4 fail — SNI-based blocking (not fingerprint-specific)
    SniBasedBlocking,
    /// Some fail, some work — DPI blocks by fingerprint
    FingerprintBlocking,
}

/// JA4 Fingerprint Probe — отправляет 4 ClientHello варианта и сравнивает результаты.
#[derive(Debug, Clone)]
pub struct Ja4FingerprintProbe {
    connect_timeout: Duration,
    read_timeout: Duration,
    profiles: Vec<TlsFingerprintProfile>,
}

impl Ja4FingerprintProbe {
    pub fn new(connect_timeout: Duration, read_timeout: Duration) -> Self {
        Self {
            connect_timeout,
            read_timeout,
            profiles: standard_profiles(),
        }
    }

    /// Полный probe: отправляет все 4 профиля, discriminate.
    pub async fn probe(&self, ip: Ipv4Addr, domain: &str) -> Ja4ProbeResult {
        let mut profile_results = Vec::with_capacity(self.profiles.len());
        let conn_id = u64::from(ip.to_bits());
        let mut rng = PerConnRng::new(conn_id);
        let sni = if domain.is_empty() {
            "example.com"
        } else {
            domain
        };

        for profile in &self.profiles {
            let client_hello = (profile.build_ch)(sni, &mut rng);
            let result = self.probe_profile(ip, profile, &client_hello).await;
            profile_results.push(result);
        }

        // Count successes vs failures
        let blocked_count = profile_results
            .iter()
            .filter(|r| r.verdict.is_error())
            .count();
        let ok_count = profile_results.len() - blocked_count;

        let verdict = discriminate(&profile_results);
        let blocked_profile = profile_results
            .iter()
            .find(|r| r.verdict.is_error())
            .map(|r| r.profile_name.clone());
        let working_profile = profile_results
            .iter()
            .find(|r| !r.verdict.is_error())
            .map(|r| r.profile_name.clone());

        Ja4ProbeResult {
            profiles: profile_results,
            verdict,
            blocked_count,
            ok_count,
            blocked_profile,
            working_profile,
        }
    }

    /// Probe одного профиля: connect, send ClientHello, classify response.
    async fn probe_profile(
        &self,
        ip: Ipv4Addr,
        profile: &TlsFingerprintProfile,
        client_hello: &[u8],
    ) -> FingerprintProbeResult {
        let start = Instant::now();
        let addr = SocketAddr::new(std::net::IpAddr::V4(ip), 443);
        let connect_timeout = self.connect_timeout;
        let read_timeout = self.read_timeout;
        let client_hello_vec = client_hello.to_vec();
        let profile_name = profile.name.to_string();
        let ja4_expected = profile.ja4_expected.to_string();

        let result = std::thread::spawn(move || {
            let socket = TcpStream::connect_timeout(&addr, connect_timeout);
            match socket {
                Ok(mut stream) => {
                    let _ = stream.set_read_timeout(Some(read_timeout));
                    if stream.write_all(&client_hello_vec).is_err() {
                        let elapsed = start.elapsed().as_millis() as u64;
                        return (TlsFailureCode::Eof, elapsed, Vec::new());
                    }
                    let mut buf = [0u8; 1024];
                    match stream.read(&mut buf) {
                        Ok(n) if n > 0 => {
                            let elapsed = start.elapsed().as_millis() as u64;
                            let code = classify_tls_response(&buf[..n]);
                            (code, elapsed, buf[..n.min(64)].to_vec())
                        }
                        Ok(_) => {
                            let elapsed = start.elapsed().as_millis() as u64;
                            (TlsFailureCode::Eof, elapsed, Vec::new())
                        }
                        Err(_) => {
                            let elapsed = start.elapsed().as_millis() as u64;
                            (TlsFailureCode::Reset, elapsed, Vec::new())
                        }
                    }
                }
                Err(_) => (TlsFailureCode::Reset, 0, Vec::new()),
            }
        })
        .join()
        .unwrap_or((TlsFailureCode::Reset, 0, Vec::new()));

        let (verdict, rtt_ms, response_preview) = result;

        debug!(
            "JA4 probe {} {} -> {:?} ({}ms)",
            profile_name, ip, verdict, rtt_ms
        );

        FingerprintProbeResult {
            profile_name,
            ja4_expected,
            ja4_actual: None,
            verdict,
            rtt_ms,
            response_preview,
        }
    }
}

/// Классифицирует TLS response bytes в TlsFailureCode.
fn classify_tls_response(response: &[u8]) -> TlsFailureCode {
    if response.is_empty() || response.len() < 5 {
        return TlsFailureCode::Garbage;
    }
    let content_type = response[0];
    let version_major = response[1];

    match content_type {
        // 0x16 = Handshake
        0x16 if response.len() >= 6 => {
            let handshake_type = response[5];
            match handshake_type {
                0x02 => TlsFailureCode::HandshakeOk,               // ServerHello
                0x0b | 0x0e | 0x04 => TlsFailureCode::HandshakeOk, // Certificate, CertReq, NewSessionTicket
                _ => TlsFailureCode::HandshakeOk,
            }
        }
        // 0x15 = Alert
        0x15 if version_major == 0x03 => {
            if response.len() >= 7 {
                let alert_description = response[6];
                match alert_description {
                    40 => TlsFailureCode::AlertHandshake,
                    70 => TlsFailureCode::AlertProtocol,
                    112 => TlsFailureCode::AlertSniblock,
                    _ => TlsFailureCode::Alert,
                }
            } else {
                TlsFailureCode::Alert
            }
        }
        _ => TlsFailureCode::Garbage,
    }
}

/// Discriminate: fingerprint blocking vs SNI blocking vs none.
pub fn discriminate(results: &[FingerprintProbeResult]) -> FingerprintVerdict {
    let error_count = results.iter().filter(|r| r.verdict.is_error()).count();
    let ok_count = results.len() - error_count;

    if error_count > 0 && ok_count > 0 {
        FingerprintVerdict::FingerprintBlocking
    } else if error_count == results.len() {
        FingerprintVerdict::SniBasedBlocking
    } else {
        FingerprintVerdict::NoFingerprintBlocking
    }
}

/// Извлекает TLS handshake features из raw response bytes.
///
/// Response содержит один или несколько TLS records:
/// - ServerHello (ContentType=0x16, HandshakeType=0x02)
/// - Certificate (ContentType=0x16, HandshakeType=0x0B)
/// - ServerHelloDone (ContentType=0x16, HandshakeType=0x0E)
///
/// Возвращает (server_hello_size, cert_count, negotiated_version, negotiated_cipher).
/// Если парсинг не удался — (0, 0, None, None).
///
/// Поддерживает TLS 1.2 и 1.3 форматы Certificate message.
pub fn extract_tls_handshake_features(
    response: &[u8],
) -> (usize, usize, Option<String>, Option<String>) {
    let mut server_hello_size = 0usize;
    let mut cert_count = 0usize;
    let mut negotiated_version: Option<String> = None;
    let mut negotiated_cipher: Option<String> = None;
    // Флаг: parsed ServerHello — знаем negotiated version для парсинга Certificate
    let mut is_tls13 = false;

    let mut offset = 0;
    while offset + 5 <= response.len() {
        let content_type = response[offset];
        let _record_version = u16::from_be_bytes([response[offset + 1], response[offset + 2]]);
        let record_len = u16::from_be_bytes([response[offset + 3], response[offset + 4]]) as usize;

        if offset + 5 + record_len > response.len() {
            break; // truncated record
        }

        let record_body = &response[offset + 5..offset + 5 + record_len];

        // TLS Handshake records (ContentType = 0x16)
        if content_type == 0x16 && !record_body.is_empty() {
            let handshake_type = record_body[0];
            let handshake_len =
                u32::from_be_bytes([0, record_body[1], record_body[2], record_body[3]]) as usize;

            if 4 + handshake_len <= record_body.len() {
                let handshake_body = &record_body[4..4 + handshake_len];

                match handshake_type {
                    // ServerHello (0x02)
                    0x02 => {
                        server_hello_size = 4 + handshake_len; // full ServerHello handshake record

                        // Negotiated version: bytes 0-1 of ServerHello body
                        if handshake_body.len() >= 2 {
                            let ver = u16::from_be_bytes([handshake_body[0], handshake_body[1]]);
                            let (ver_str, tls13) = match ver {
                                0x0304 => ("1.3".to_string(), true),
                                0x0303 => ("1.2".to_string(), false),
                                0x0302 => ("1.1".to_string(), false),
                                0x0301 => ("1.0".to_string(), false),
                                _ => (format!("0x{:04x}", ver), false),
                            };
                            negotiated_version = Some(ver_str);
                            is_tls13 = tls13;
                        }

                        // Negotiated cipher: skip legacy_version(2) + random(32) + session_id
                        // ServerHello body layout (RFC 8446 §4.1.3):
                        //   legacy_version(2) + random(32) + legacy_session_id_echo(1+len) +
                        //   cipher_suite(2) + legacy_compression_method(1) + extensions(2+...)
                        if handshake_body.len() > 34 {
                            let session_id_len = handshake_body[34] as usize;
                            let cipher_offset = 35 + session_id_len;
                            if cipher_offset + 2 <= handshake_body.len() {
                                let cipher = u16::from_be_bytes([
                                    handshake_body[cipher_offset],
                                    handshake_body[cipher_offset + 1],
                                ]);
                                negotiated_cipher = Some(match cipher {
                                    0x1301 => "TLS_AES_128_GCM_SHA256".to_string(),
                                    0x1302 => "TLS_AES_256_GCM_SHA384".to_string(),
                                    0x1303 => "TLS_CHACHA20_POLY1305_SHA256".to_string(),
                                    0xC02B => "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_string(),
                                    0xC02C => "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".to_string(),
                                    0xC02F => "ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
                                    0xC030 => "ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
                                    _ => format!("0x{:04x}", cipher),
                                });
                            }
                        }
                    }
                    // Certificate (0x0B)
                    0x0B => {
                        if handshake_body.len() >= 3 {
                            if is_tls13 {
                                // TLS 1.3 Certificate format:
                                //   certificate_request_context(1+len) + certificate_list(3+entries)
                                let context_len = handshake_body[0] as usize;
                                let list_start = 1 + context_len;
                                if list_start + 3 <= handshake_body.len() {
                                    let certs_total_len = u32::from_be_bytes([
                                        0,
                                        handshake_body[list_start],
                                        handshake_body[list_start + 1],
                                        handshake_body[list_start + 2],
                                    ])
                                        as usize;
                                    let mut cert_offset = list_start + 3;
                                    // TLS 1.3 entries include extensions field (2 bytes) after cert data
                                    while cert_offset + 3 <= list_start + 3 + certs_total_len {
                                        let cert_len = u32::from_be_bytes([
                                            0,
                                            handshake_body[cert_offset],
                                            handshake_body[cert_offset + 1],
                                            handshake_body[cert_offset + 2],
                                        ])
                                            as usize;
                                        if cert_len == 0
                                            || cert_offset + 3 + cert_len + 2
                                                > list_start + 3 + certs_total_len
                                        {
                                            break;
                                        }
                                        cert_count += 1;
                                        cert_offset += 3 + cert_len + 2; // +2 for extensions
                                    }
                                }
                            } else {
                                // TLS 1.2 Certificate format:
                                //   certificate_list(3+entries)
                                let certs_total_len = u32::from_be_bytes([
                                    0,
                                    handshake_body[0],
                                    handshake_body[1],
                                    handshake_body[2],
                                ]) as usize;
                                if 3 + certs_total_len <= handshake_body.len() {
                                    let mut cert_offset = 3;
                                    while cert_offset + 3 <= 3 + certs_total_len {
                                        let cert_len = u32::from_be_bytes([
                                            0,
                                            handshake_body[cert_offset],
                                            handshake_body[cert_offset + 1],
                                            handshake_body[cert_offset + 2],
                                        ])
                                            as usize;
                                        if cert_len == 0
                                            || cert_offset + 3 + cert_len > 3 + certs_total_len
                                        {
                                            break;
                                        }
                                        cert_count += 1;
                                        cert_offset += 3 + cert_len;
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        offset += 5 + record_len;
    }

    (
        server_hello_size,
        cert_count,
        negotiated_version,
        negotiated_cipher,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ja4_fingerprint_to_string() {
        let ja4 = Ja4Fingerprint {
            protocol: "t13".into(),
            sni_present: true,
            cipher_count: 15,
            ext_count: 16,
            alpn: "h2".into(),
            cipher_hash: "8daaf6152771".into(),
            ext_hash: "b186095e22b6".into(),
        };
        assert_eq!(ja4.to_string(), "t13d1516h2_8daaf6152771_b186095e22b6");
    }

    #[test]
    fn test_ja4_fingerprint_parse_roundtrip() {
        let s = "t13d1516h2_8daaf6152771_b186095e22b6";
        let parsed = Ja4Fingerprint::from_string(s).unwrap();
        assert_eq!(parsed.to_string(), s);
    }

    #[test]
    fn test_standard_profiles_count() {
        let profiles = standard_profiles();
        assert_eq!(profiles.len(), 4);
    }

    // === classify_tls_response tests ===

    #[test]
    fn test_classify_tls_response_server_hello() {
        // Minimal ServerHello: ContentType=0x16, Version=0x0303, Length=2,
        // HandshakeType=0x02
        let data = vec![0x16, 0x03, 0x03, 0x00, 0x05, 0x02, 0x00, 0x00, 0x00];
        assert_eq!(classify_tls_response(&data), TlsFailureCode::HandshakeOk);
    }

    #[test]
    fn test_classify_tls_response_alert_sniblock() {
        // Alert: ContentType=0x15, Version=0x0303, Length=2, Level=0x02, Description=112
        let data = vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 112];
        assert_eq!(classify_tls_response(&data), TlsFailureCode::AlertSniblock);
    }

    #[test]
    fn test_classify_tls_response_alert_handshake_failure() {
        let data = vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 40];
        assert_eq!(classify_tls_response(&data), TlsFailureCode::AlertHandshake);
    }

    #[test]
    fn test_classify_tls_response_garbage() {
        let data = vec![0x00, 0x01, 0x02];
        assert_eq!(classify_tls_response(&data), TlsFailureCode::Garbage);
    }

    // === discriminate tests ===

    fn make_result(verdict: TlsFailureCode) -> FingerprintProbeResult {
        FingerprintProbeResult {
            profile_name: "test".into(),
            ja4_expected: "".into(),
            ja4_actual: None,
            verdict,
            rtt_ms: 0,
            response_preview: vec![],
        }
    }

    #[test]
    fn test_discriminate_no_blocking() {
        let results = vec![
            make_result(TlsFailureCode::HandshakeOk),
            make_result(TlsFailureCode::HandshakeOk),
            make_result(TlsFailureCode::Version13Ok),
            make_result(TlsFailureCode::HandshakeOk),
        ];
        assert_eq!(
            discriminate(&results),
            FingerprintVerdict::NoFingerprintBlocking
        );
    }

    #[test]
    fn test_discriminate_fingerprint_blocking() {
        let results = vec![
            make_result(TlsFailureCode::AlertSniblock),
            make_result(TlsFailureCode::Reset),
            make_result(TlsFailureCode::HandshakeOk),
            make_result(TlsFailureCode::HandshakeOk),
        ];
        assert_eq!(
            discriminate(&results),
            FingerprintVerdict::FingerprintBlocking
        );
    }

    #[test]
    fn test_discriminate_sni_blocking() {
        let results = vec![
            make_result(TlsFailureCode::AlertSniblock),
            make_result(TlsFailureCode::Alert),
            make_result(TlsFailureCode::Reset),
            make_result(TlsFailureCode::Garbage),
        ];
        assert_eq!(discriminate(&results), FingerprintVerdict::SniBasedBlocking);
    }

    // === extract_tls_handshake_features tests (T53) ===

    #[test]
    fn test_extract_server_hello_size() {
        // ServerHello: TLS 1.2, cipher TLS_AES_128_GCM_SHA256
        // Record: ContentType=0x16, Version=0x0303, Length=0x0032 (50)
        // Handshake: Type=0x02, Length=0x00002E (46)
        // Body: legacy_version=0x0303, random(32), session_id_len=0,
        //       cipher=0x1301, compression=0x00, extensions(0)
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
        body.extend(vec![0xAAu8; 32]); // random
        body.push(0x00); // session_id_len = 0
        body.extend_from_slice(&[0x13, 0x01]); // cipher TLS_AES_128_GCM_SHA256
        body.push(0x00); // compression
        body.extend_from_slice(&[0x00, 0x00]); // extensions length = 0

        let handshake_len = body.len() as u16; // 38
        let mut record = Vec::new();
        record.push(0x16); // ContentType Handshake
        record.extend_from_slice(&[0x03, 0x03]); // Version
        record.extend_from_slice(&(4 + handshake_len).to_be_bytes()); // Record Length
        record.push(0x02); // HandshakeType ServerHello
        record.extend_from_slice(&[0x00, (body.len() >> 8) as u8, (body.len() & 0xFF) as u8]); // HS len
        record.extend_from_slice(&body);

        let (sh_size, _, ver, cipher) = extract_tls_handshake_features(&record);
        assert!(sh_size > 0, "ServerHello size should be > 0");
        assert_eq!(ver, Some("1.2".to_string()));
        assert_eq!(cipher, Some("TLS_AES_128_GCM_SHA256".to_string()));
    }

    #[test]
    fn test_extract_negotiated_cipher() {
        // TLS 1.3 ServerHello with TLS_AES_256_GCM_SHA384 (0x1302)
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x04]); // legacy_version TLS 1.3
        body.extend(vec![0xCCu8; 32]); // random
        body.push(0x00); // session_id_len = 0
        body.extend_from_slice(&[0x13, 0x02]); // cipher TLS_AES_256_GCM_SHA384
        body.push(0x00); // compression
        body.extend_from_slice(&[0x00, 0x00]); // extensions length = 0

        let handshake_len = body.len() as u16;
        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(4 + handshake_len).to_be_bytes());
        record.push(0x02);
        record.extend_from_slice(&[0x00, (body.len() >> 8) as u8, (body.len() & 0xFF) as u8]);
        record.extend_from_slice(&body);

        let (_, _, ver, cipher) = extract_tls_handshake_features(&record);
        assert_eq!(ver, Some("1.3".to_string()));
        assert_eq!(cipher, Some("TLS_AES_256_GCM_SHA384".to_string()));
    }

    #[test]
    fn test_extract_cert_count_tls12() {
        // Certificate message with 2 certificates (TLS 1.2 format).
        // Cert 1: length=3, data=[0xAA, 0xBB, 0xCC]
        // Cert 2: length=4, data=[0xDD, 0xEE, 0xFF, 0x00]
        let cert1: Vec<u8> = vec![0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC];
        let cert2: Vec<u8> = vec![0x00, 0x00, 0x04, 0xDD, 0xEE, 0xFF, 0x00];
        let cert_total_len = (cert1.len() + cert2.len()) as u16; // 6 + 7 = 13

        let mut body = Vec::new();
        body.extend_from_slice(&[
            0x00,
            (cert_total_len >> 8) as u8,
            (cert_total_len & 0xFF) as u8,
        ]);
        body.extend_from_slice(&cert1);
        body.extend_from_slice(&cert2);

        let handshake_len = body.len() as u16;
        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(4 + handshake_len).to_be_bytes());
        record.push(0x0B); // HandshakeType Certificate
        record.extend_from_slice(&[0x00, (body.len() >> 8) as u8, (body.len() & 0xFF) as u8]);
        record.extend_from_slice(&body);

        let (_, cert_count, _, _) = extract_tls_handshake_features(&record);
        assert_eq!(cert_count, 2, "Should find 2 certificates");
    }

    #[test]
    fn test_extract_cert_count_tls13() {
        // Certificate message with 1 certificate (TLS 1.3 format).
        // TLS 1.3: request_context(1) + cert_list(3+entries)
        // Entry: cert_len(3) + data(5) + extensions_len(2) + no extensions
        let cert_data: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04, 0x05]; // 5 bytes cert
        let entry_body: Vec<u8> = {
            let mut v = Vec::new();
            v.extend_from_slice(&[0x00, 0x00, 0x05]); // cert_len = 5
            v.extend_from_slice(&cert_data);
            v.extend_from_slice(&[0x00, 0x00]); // extensions = 0
            v
        };
        let cert_list_len = entry_body.len() as u16; // 10

        let mut body = Vec::new();
        body.push(0x00); // request_context_len = 0
        body.extend_from_slice(&[
            0x00,
            (cert_list_len >> 8) as u8,
            (cert_list_len & 0xFF) as u8,
        ]);
        body.extend_from_slice(&entry_body);

        // We need is_tls13=true — send ServerHello with version 0x0304 first
        let sh_body: Vec<u8> = {
            let mut v = Vec::new();
            v.extend_from_slice(&[0x03, 0x04]); // legacy_version TLS 1.3
            v.extend(vec![0xBBu8; 32]); // random
            v.push(0x00); // session_id_len = 0
            v.extend_from_slice(&[0x13, 0x01]); // cipher
            v.push(0x00); // compression
            v.extend_from_slice(&[0x00, 0x00]); // extensions = 0
            v
        };

        let mut response = Vec::new();
        // ServerHello record
        response.push(0x16);
        response.extend_from_slice(&[0x03, 0x03]);
        let sh_hs_len = sh_body.len() as u16;
        response.extend_from_slice(&(4 + sh_hs_len).to_be_bytes());
        response.push(0x02);
        response.extend_from_slice(&[
            0x00,
            (sh_body.len() >> 8) as u8,
            (sh_body.len() & 0xFF) as u8,
        ]);
        response.extend_from_slice(&sh_body);
        // Certificate record
        let hs_len = body.len() as u16;
        response.push(0x16);
        response.extend_from_slice(&[0x03, 0x03]);
        response.extend_from_slice(&(4 + hs_len).to_be_bytes());
        response.push(0x0B);
        response.extend_from_slice(&[0x00, (body.len() >> 8) as u8, (body.len() & 0xFF) as u8]);
        response.extend_from_slice(&body);

        let (_, cert_count, ver, _) = extract_tls_handshake_features(&response);
        assert_eq!(ver, Some("1.3".to_string()), "should detect TLS 1.3");
        assert_eq!(cert_count, 1, "Should find 1 certificate");
    }

    #[test]
    fn test_extract_empty_response() {
        let (sh_size, cert_count, ver, cipher) = extract_tls_handshake_features(&[]);
        assert_eq!(sh_size, 0);
        assert_eq!(cert_count, 0);
        assert_eq!(ver, None);
        assert_eq!(cipher, None);
    }

    #[test]
    fn test_extract_truncated_response() {
        // Truncated record — should not panic
        let response = vec![0x16, 0x03, 0x03, 0x00, 0xFF]; // claims 255 bytes but only header
        let (sh_size, cert_count, _, _) = extract_tls_handshake_features(&response);
        assert_eq!(sh_size, 0);
        assert_eq!(cert_count, 0);
    }
}
