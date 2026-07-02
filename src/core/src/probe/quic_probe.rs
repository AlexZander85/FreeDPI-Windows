//! QUIC Probe — определение DPI, блокирующего QUIC (UDP:443).
//!
//! Методика:
//! 1. Construct QUIC Initial с fake SNI (использует quic_v1_initial_encrypt)
//! 2. Send via UDP:443
//! 3. Read response с timeout
//! 4. Parse response: Retry / Handshake / ConnectionClose / Timeout / ICMP
//! 5. Сравнить с TCP probe:
//!    - TCP ok + QUIC ok → no blocking
//!    - TCP ok + QUIC fail → QUIC-specific blocking
//!    - TCP fail + QUIC fail → general blocking (не QUIC-specific)
//!    - TCP fail + QUIC ok → QUIC works (TCP blocked, QUIC bypass)
//!
//! Источники:
//! - RFC 9000: QUIC v1
//! - RFC 9001: QUIC Initial encryption

use crate::adaptive::ch_gen;
use crate::desync::quic;
use crate::desync::rand::PerConnRng;
use crate::probe::classifier::TcpFailureCode;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Тип QUIC response.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuicResponseType {
    /// QUIC Retry packet (server responding normally, asking for retry)
    Retry,
    /// QUIC Handshake packet (handshake in progress)
    Handshake,
    /// QUIC Initial packet (server responding with Initial)
    Initial,
    /// QUIC Connection Close (server rejected)
    ConnectionClose,
    /// ICMP Port Unreachable (UDP blocked at firewall)
    IcmpUnreachable,
    /// Timeout — no response (DPI silent drop)
    #[default]
    Timeout,
    /// Garbage data — invalid QUIC packet
    Garbage,
    /// Send error
    SendError,
}

impl QuicResponseType {
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Retry | Self::Handshake | Self::Initial)
    }

    pub fn is_blocked(&self) -> bool {
        matches!(
            self,
            Self::Timeout | Self::IcmpUnreachable | Self::ConnectionClose
        )
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Retry => "QUIC Retry packet — server responding normally",
            Self::Handshake => "QUIC Handshake packet — handshake in progress",
            Self::Initial => "QUIC Initial packet — server responding",
            Self::ConnectionClose => "QUIC Connection Close — server rejected",
            Self::IcmpUnreachable => "ICMP Port Unreachable — UDP blocked at firewall",
            Self::Timeout => "Timeout — DPI silent drop (no response)",
            Self::Garbage => "Garbage data — invalid QUIC response",
            Self::SendError => "UDP send error — local firewall or routing issue",
        }
    }
}

/// Результат QUIC probe.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct QuicProbeResult {
    /// Тип response
    pub response_type: QuicResponseType,
    /// RTT (мс) или 0 если timeout
    pub rtt_ms: u64,
    /// Размер response (байт)
    pub response_size: usize,
    /// Первые 64 байта response (для debugging)
    pub response_preview: Vec<u8>,
    /// QUIC version в response (если parseable)
    pub version: Option<u32>,
}

/// Вердикт QUIC probe относительно TCP.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuicVerdict {
    /// TCP ok + QUIC ok → нет блокировки
    NoBlocking,
    /// TCP ok + QUIC fail → QUIC-specific blocking
    QuicBlocked,
    /// TCP fail + QUIC ok → QUIC работает, TCP заблокирован (QUIC bypass)
    QuicBypass,
    /// TCP fail + QUIC fail → общая блокировка (не QUIC-specific)
    GeneralBlocking,
    /// Недостаточно данных
    #[default]
    Ambiguous,
}

/// QUIC Probe.
pub struct QuicProbe {
    timeout: Duration,
}

impl QuicProbe {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Запуск QUIC probe: отправка QUIC Initial с fake SNI, чтение response.
    ///
    /// # Arguments
    /// * `ip` — IP адрес сервера
    /// * `domain` — SNI для ClientHello внутри QUIC CRYPTO frame
    /// * `fake_sni` — fake SNI для QUIC Initial (если None, используется domain)
    pub async fn probe(
        &self,
        ip: Ipv4Addr,
        domain: &str,
        fake_sni: Option<&str>,
    ) -> QuicProbeResult {
        let sni = fake_sni.unwrap_or(domain).to_string();
        let domain_owned = domain.to_string();
        let timeout = self.timeout;

        let result =
            tokio::task::spawn_blocking(move || probe_blocking(ip, &domain_owned, &sni, timeout))
                .await;

        match result {
            Ok(r) => r,
            Err(e) => {
                warn!("QUIC probe panicked: {}", e);
                QuicProbeResult {
                    response_type: QuicResponseType::Garbage,
                    rtt_ms: 0,
                    response_size: 0,
                    response_preview: vec![],
                    version: None,
                }
            }
        }
    }

    /// Дискриминация: сравнить QUIC result с TCP result.
    pub fn discriminate(quic: &QuicProbeResult, tcp_verdict: TcpFailureCode) -> QuicVerdict {
        let quic_ok = quic.response_type.is_ok();
        let tcp_ok = tcp_verdict == TcpFailureCode::ConnectOk;

        match (tcp_ok, quic_ok) {
            (true, true) => QuicVerdict::NoBlocking,
            (true, false) => QuicVerdict::QuicBlocked,
            (false, true) => QuicVerdict::QuicBypass,
            (false, false) => QuicVerdict::GeneralBlocking,
        }
    }
}

/// Blocking QUIC probe (runs in spawn_blocking).
fn probe_blocking(ip: Ipv4Addr, domain: &str, sni: &str, timeout: Duration) -> QuicProbeResult {
    let start = Instant::now();

    // 1. Generate random DCID (8 bytes)
    let mut rng = PerConnRng::new(start.elapsed().as_nanos() as u64);
    let mut dcid = [0u8; 8];
    rng.fill_wire_bytes(&mut dcid);

    // 2. Build QUIC Initial with fake ClientHello
    let fake_ch = ch_gen::build_client_hello(sni, &mut rng);
    let quic_packet = match build_quic_initial_packet(&dcid, &fake_ch) {
        Some(p) => p,
        None => {
            return QuicProbeResult {
                response_type: QuicResponseType::Garbage,
                rtt_ms: 0,
                response_size: 0,
                response_preview: vec![],
                version: None,
            };
        }
    };

    // 3. UDP socket + send
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            warn!("UDP socket bind failed: {}", e);
            return QuicProbeResult {
                response_type: QuicResponseType::SendError,
                rtt_ms: 0,
                response_size: 0,
                response_preview: vec![],
                version: None,
            };
        }
    };

    let _ = socket.set_read_timeout(Some(timeout));
    let dst_addr = SocketAddr::new(ip.into(), 443);

    if let Err(e) = socket.send_to(&quic_packet, dst_addr) {
        warn!("UDP send_to failed: {}", e);
        return QuicProbeResult {
            response_type: QuicResponseType::SendError,
            rtt_ms: start.elapsed().as_millis() as u64,
            response_size: 0,
            response_preview: vec![],
            version: None,
        };
    }

    // 4. Read response
    let mut buf = [0u8; 1500]; // MTU
    let (n, _src) = match socket.recv_from(&mut buf) {
        Ok(result) => result,
        Err(e) => {
            let err = e.to_string().to_lowercase();
            let response_type = if err.contains("timed out") {
                QuicResponseType::Timeout
            } else if err.contains("unreachable") || err.contains("port unreachable") {
                QuicResponseType::IcmpUnreachable
            } else {
                QuicResponseType::Garbage
            };
            return QuicProbeResult {
                response_type,
                rtt_ms: start.elapsed().as_millis() as u64,
                response_size: 0,
                response_preview: vec![],
                version: None,
            };
        }
    };

    let rtt = start.elapsed().as_millis() as u64;
    let response = &buf[..n];

    // 5. Parse QUIC response
    let (response_type, version) = parse_quic_response(response);

    debug!(
        "QUIC probe for {} ({}): type={:?}, size={}, rtt={}ms",
        domain, sni, response_type, n, rtt
    );

    QuicProbeResult {
        response_type,
        rtt_ms: rtt,
        response_size: n,
        response_preview: response[..n.min(64)].to_vec(),
        version,
    }
}

/// Строит QUIC Initial packet с CRYPTO frame содержащим ClientHello.
fn build_quic_initial_packet(dcid: &[u8], client_hello: &[u8]) -> Option<Vec<u8>> {
    // QUIC Long Header for Initial (RFC 9000 §17.2.2):
    // Byte 0: 1 (Long) | 1 (Fixed) | 00 (Initial) | 00 (Reserved) | 11 (PN=4 bytes) = 0xC3
    // Bytes 1-4: Version = 0x00000001 (QUIC v1)
    // Byte 5: DCID Length = 8
    // Bytes 6-13: DCID
    // Byte 14: SCID Length = 0
    // Byte 15: Token Length = 0 (varint 1-byte)
    // Bytes 16-17: Length (varint 2-byte)
    // Bytes 18+: Packet Number + encrypted payload

    let mut header = Vec::new();
    header.push(0xC3); // Long + Initial + PN=4
    header.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // QUIC v1
    header.push(dcid.len() as u8);
    header.extend_from_slice(dcid);
    header.push(0x00); // SCID length = 0
    header.push(0x00); // Token length = 0

    // CRYPTO frame: type=0x06, offset=0 (varint), length (varint), data
    let mut crypto_frame = Vec::new();
    crypto_frame.push(0x06); // CRYPTO frame type
    crypto_frame.push(0x00); // offset = 0 (varint 1-byte)
                             // length = client_hello.len() as varint
    crypto_frame.extend_from_slice(&encode_varint(client_hello.len() as u64));
    crypto_frame.extend_from_slice(client_hello);

    // Pad to 1200 bytes minimum (QUIC requirement for Initial)
    let mut payload = crypto_frame;
    let pn_len = 4;
    let aead_tag_len = 16;
    let min_payload = 1200 - header.len() - 2 - pn_len - aead_tag_len;
    while payload.len() < min_payload {
        payload.push(0x00); // PADDING frame (type=0x00)
    }

    // Length field: PN(4) + encrypted_payload_len (which includes AEAD tag 16)
    let total_remaining = pn_len + payload.len() + aead_tag_len;
    let length_varint = encode_varint(total_remaining as u64);
    header.extend_from_slice(&length_varint);

    // Encrypt using QUIC v1 Initial protection
    let packet_number: u64 = 0;
    let encrypted = quic::quic_v1_initial_encrypt(&header, packet_number, pn_len, &payload, dcid)?;

    Some(encrypted)
}

/// Encode integer as QUIC variable-length integer (RFC 9000 §16).
fn encode_varint(value: u64) -> Vec<u8> {
    if value < 64 {
        vec![value as u8]
    } else if value < 16384 {
        let mut buf = (value as u16).to_be_bytes();
        buf[0] |= 0x40; // 2-byte prefix
        buf.to_vec()
    } else if value < 1073741824 {
        let mut buf = (value as u32).to_be_bytes();
        buf[0] |= 0x80; // 4-byte prefix
        buf.to_vec()
    } else {
        let mut buf = value.to_be_bytes();
        buf[0] |= 0xC0; // 8-byte prefix
        buf.to_vec()
    }
}

/// Парсит QUIC response и определяет тип.
fn parse_quic_response(response: &[u8]) -> (QuicResponseType, Option<u32>) {
    if response.is_empty() {
        return (QuicResponseType::Garbage, None);
    }

    let first_byte = response[0];

    // Check if Long Header (bit 7 = 1)
    if first_byte & 0x80 != 0 {
        // Long Header — parse version
        if response.len() < 5 {
            return (QuicResponseType::Garbage, None);
        }
        let version = u32::from_be_bytes([response[1], response[2], response[3], response[4]]);

        if version == 0 {
            return (QuicResponseType::Garbage, Some(0)); // Version Negotiation
        }

        // Long Packet Type (bits 4-5)
        let packet_type = (first_byte >> 4) & 0x03;
        match packet_type {
            0 => (QuicResponseType::Initial, Some(version)), // Initial
            1 => (QuicResponseType::Retry, Some(version)),   // Retry (0b01)
            2 => (QuicResponseType::Handshake, Some(version)), // Handshake (0b10)
            3 => (QuicResponseType::Garbage, Some(version)), // 0-RTT (не ожидаем в response)
            _ => (QuicResponseType::Garbage, Some(version)),
        }
    } else {
        // Short Header (bit 7 = 0) — это 1-RTT packet (handshake complete)
        (QuicResponseType::Handshake, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quic_response_type_is_ok() {
        assert!(QuicResponseType::Retry.is_ok());
        assert!(QuicResponseType::Handshake.is_ok());
        assert!(QuicResponseType::Initial.is_ok());
        assert!(!QuicResponseType::Timeout.is_ok());
        assert!(!QuicResponseType::IcmpUnreachable.is_ok());
    }

    #[test]
    fn test_quic_response_type_is_blocked() {
        assert!(QuicResponseType::Timeout.is_blocked());
        assert!(QuicResponseType::IcmpUnreachable.is_blocked());
        assert!(QuicResponseType::ConnectionClose.is_blocked());
        assert!(!QuicResponseType::Retry.is_blocked());
    }

    #[test]
    fn test_discriminate_no_blocking() {
        let quic = QuicProbeResult {
            response_type: QuicResponseType::Retry,
            rtt_ms: 50,
            response_size: 100,
            response_preview: vec![],
            version: Some(1),
        };
        let verdict = QuicProbe::discriminate(&quic, TcpFailureCode::ConnectOk);
        assert_eq!(verdict, QuicVerdict::NoBlocking);
    }

    #[test]
    fn test_discriminate_quic_blocked() {
        let quic = QuicProbeResult {
            response_type: QuicResponseType::Timeout,
            rtt_ms: 3000,
            response_size: 0,
            response_preview: vec![],
            version: None,
        };
        let verdict = QuicProbe::discriminate(&quic, TcpFailureCode::ConnectOk);
        assert_eq!(verdict, QuicVerdict::QuicBlocked);
    }

    #[test]
    fn test_discriminate_quic_bypass() {
        let quic = QuicProbeResult {
            response_type: QuicResponseType::Handshake,
            rtt_ms: 50,
            response_size: 200,
            response_preview: vec![],
            version: Some(1),
        };
        let verdict = QuicProbe::discriminate(&quic, TcpFailureCode::Reset);
        assert_eq!(verdict, QuicVerdict::QuicBypass);
    }

    #[test]
    fn test_discriminate_general_blocking() {
        let quic = QuicProbeResult {
            response_type: QuicResponseType::Timeout,
            rtt_ms: 3000,
            response_size: 0,
            response_preview: vec![],
            version: None,
        };
        let verdict = QuicProbe::discriminate(&quic, TcpFailureCode::Reset);
        assert_eq!(verdict, QuicVerdict::GeneralBlocking);
    }

    #[test]
    fn test_parse_quic_response_retry() {
        // Retry packet: Long Header, type=0b01, version=1
        let response = vec![0xD0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x12, 0x34];
        let (rt, version) = parse_quic_response(&response);
        assert_eq!(rt, QuicResponseType::Retry);
        assert_eq!(version, Some(1));
    }

    #[test]
    fn test_parse_quic_response_handshake() {
        let response = vec![0xE0, 0x00, 0x00, 0x00, 0x01, 0x08];
        let (rt, version) = parse_quic_response(&response);
        assert_eq!(rt, QuicResponseType::Handshake);
        assert_eq!(version, Some(1));
    }

    #[test]
    fn test_parse_quic_response_empty() {
        let (rt, version) = parse_quic_response(&[]);
        assert_eq!(rt, QuicResponseType::Garbage);
        assert_eq!(version, None);
    }

    #[test]
    fn test_encode_varint_1byte() {
        assert_eq!(encode_varint(37), vec![0x25]);
    }

    #[test]
    fn test_encode_varint_2byte() {
        let encoded = encode_varint(15293);
        assert_eq!(encoded.len(), 2);
        assert_eq!(encoded[0] & 0xC0, 0x40);
    }

    #[test]
    fn test_encode_varint_4byte() {
        let encoded = encode_varint(15293000);
        assert_eq!(encoded.len(), 4);
        assert_eq!(encoded[0] & 0xC0, 0x80);
    }
}
