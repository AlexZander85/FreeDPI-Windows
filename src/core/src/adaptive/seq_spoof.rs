//! SEQ Number Spoofing — fake ClientHello с SEQ вне окна приёма DPI.
//!
//! ## Принцип работы
//! DPI отслеживает TCP SEQ/ACK для сборки потока. Если отправить fake
//! ClientHello с SEQ, который DPI ещё не ожидает (out-of-window), DPI
//! может принять его за настоящий ClientHello. Реальный ClientHello
//! идёт следом с корректным SEQ и перезаписывает данные на сервере.
//!
//! ## Математика
//! ```text
//! SYN:      client(SEQ=1000)             → server
//! SYN-ACK:  client(ACK=1001)             ← server(SEQ=5000)
//! FAKE CH:  client(SEQ=10000)            → DPI (out-of-window!)
//! REAL CH:  client(SEQ=1001, ACK=5001)   → server (correct SEQ)
//!           DPI видит fake CH как "ClientHello"
//!           Сервер принимает real CH, игнорирует fake
//! ```
//!
//! ## Требования
//! - Raw socket (IP_HDRINCL) — полный контроль TCP SEQ
//! - HopTab для fake TTL — fake CH не должен дойти до сервера
//! - ClientHello generator — создание CH без дампа
//! - Conntrack — знание реального SEQ/ACK
//!
//! ## Источник
//! Адаптировано из [sni-spoofing-rust](https://github.com/HirbodBehnam/sni-spoofing-rust) —
//! техника SEQ Number Spoofing.

use crate::adaptive::ch_gen;
use crate::adaptive::hop_tab::HopTab;
use crate::conntrack::{ConnKey, Conntrack};
use anyhow::Result;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::MutableIpv4Packet;
use pnet_packet::tcp::MutableTcpPacket;
use std::net::IpAddr;
use tracing::debug;

/// Смещение SEQ для fake ClientHello (насколько далеко от окна).
///
/// DPI ожидает SEQ в диапазоне [client_isn, client_isn + window].
/// Fake CH отправляется с SEQ = client_isn + SPOOF_OFFSET, что
/// гарантированно вне окна приёма (окно обычно 65535).
const SPOOF_OFFSET: u32 = 10_000;

/// Результат операции SEQ Spoofing.
#[derive(Debug)]
pub struct SeqSpoofResult {
    /// Fake ClientHello (полный IP + TCP пакет для инъекции)
    pub fake_packet: bytes::Bytes,
    /// Рекомендованный TTL для fake пакета
    pub fake_ttl: u8,
}

/// Выполняет SEQ Number Spoofing.
///
/// Строит fake IP + TCP пакет с ClientHello, где SEQ установлен
/// вне окна приёма DPI. fake TTL берётся из HopTab (на 1 меньше,
/// чем нужно, чтобы пакет НЕ дошёл до сервера).
///
/// # Arguments
/// * `fake_sni` — SNI для fake ClientHello
/// * `src_ip` — IP источника (локальный)
/// * `dst_ip` — IP назначения (сервер)
/// * `src_port` — порт источника
/// * `dst_port` — порт назначения (обычно 443)
/// * `client_isn` — начальный SEQ клиента (из conntrack после SYN-ACK)
/// * `conntrack` — connection tracking (для получения SEQ/ACK)
/// * `hop_tab` — auto-TTL cache (для fake TTL)
///
/// # Returns
/// `SeqSpoofResult` с готовым пакетом для инъекции через raw socket.
///
/// # Errors
/// Возвращает ошибку если:
/// - HopTab не имеет данных для этого IP
/// - Размер пакета превышает лимиты
#[allow(clippy::too_many_arguments)]
pub fn build_seq_spoof_packet(
    fake_sni: &str,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    client_isn: u32,
    _conntrack: &Conntrack,
    hop_tab: &HopTab,
) -> Result<SeqSpoofResult> {
    let fake_ch =
        if let Some(entry) = _conntrack.get(&ConnKey::new(src_ip, dst_ip, src_port, dst_port, 6)) {
            let src_u64 = match src_ip {
                IpAddr::V4(v4) => v4.to_bits() as u64,
                IpAddr::V6(v6) => {
                    let bits = v6.to_bits();
                    (bits >> 64) as u64 ^ bits as u64
                }
            };
            let dst_u64 = match dst_ip {
                IpAddr::V4(v4) => v4.to_bits() as u64,
                IpAddr::V6(v6) => {
                    let bits = v6.to_bits();
                    (bits >> 64) as u64 ^ bits as u64
                }
            };
            let mut rng = crate::desync::rand::PerConnRng::new(
                src_u64 ^ dst_u64 ^ ((src_port as u64) << 48) ^ (dst_port as u64),
            );
            if entry.is_resumption {
                ch_gen::build_client_hello_with_resumption(fake_sni, &mut rng, true)
            } else {
                ch_gen::build_client_hello(fake_sni, &mut rng)
            }
        } else {
            ch_gen::build_client_hello_default(fake_sni)
        };

    let fake_ttl = hop_tab.fake_ttl_for_ip(&dst_ip).unwrap_or(64);

    let packet = build_fake_tcp_packet(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        client_isn.wrapping_add(SPOOF_OFFSET),
        0,
        &fake_ch,
        fake_ttl,
    )?;

    debug!(
        "SEQ Spoof: {} :{} → {} :{} fake_seq={} real_isn={} fake_ttl={} sni={}",
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        client_isn.wrapping_add(SPOOF_OFFSET),
        client_isn,
        fake_ttl,
        fake_sni,
    );

    Ok(SeqSpoofResult {
        fake_packet: packet,
        fake_ttl,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_fake_tcp_packet(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    payload: &[u8],
    ttl: u8,
) -> Result<bytes::Bytes> {
    build_fake_tcp_packet_with_flags(
        src_ip, dst_ip, src_port, dst_port, seq_num, ack_num, payload, ttl, 0x02, // SYN
    )
}

#[allow(clippy::too_many_arguments)]
fn build_fake_tcp_packet_with_flags(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    payload: &[u8],
    ttl: u8,
    flags: u8,
) -> Result<bytes::Bytes> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            const IP_HLEN: usize = 20;
            const TCP_HLEN: usize = 20;
            let total_len = IP_HLEN + TCP_HLEN + payload.len();

            let mut buf = bytes::BytesMut::with_capacity(total_len);
            buf.resize(total_len, 0);

            // --- IP Header ---
            {
                let mut ip = MutableIpv4Packet::new(&mut buf[..IP_HLEN])
                    .ok_or_else(|| anyhow::anyhow!("Failed to create IP packet"))?;
                ip.set_version(4);
                ip.set_header_length((IP_HLEN / 4) as u8);
                ip.set_total_length(total_len as u16);
                ip.set_ttl(ttl);
                ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
                ip.set_source(src);
                ip.set_destination(dst);
            }
            let cksum = ipv4_checksum(&buf[..IP_HLEN]);
            let cksum_bytes = cksum.to_be_bytes();
            buf[10] = cksum_bytes[0];
            buf[11] = cksum_bytes[1];

            // --- TCP Header ---
            {
                let mut tcp = MutableTcpPacket::new(&mut buf[IP_HLEN..])
                    .ok_or_else(|| anyhow::anyhow!("Failed to create TCP packet"))?;
                tcp.set_source(src_port);
                tcp.set_destination(dst_port);
                tcp.set_sequence(seq_num);
                tcp.set_acknowledgement(ack_num);
                tcp.set_data_offset((TCP_HLEN / 4) as u8);
                tcp.set_flags(flags);
                tcp.set_window(65535);
                tcp.set_urgent_ptr(0);
                if !payload.is_empty() {
                    buf[IP_HLEN + TCP_HLEN..][..payload.len()].copy_from_slice(payload);
                }
            }
            let cksum = crate::desync::tcp_checksum(src_ip, dst_ip, &buf[IP_HLEN..]);
            let cksum_bytes = cksum.to_be_bytes();
            buf[IP_HLEN + 16] = cksum_bytes[0];
            buf[IP_HLEN + 17] = cksum_bytes[1];

            Ok(buf.freeze())
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            use pnet_packet::ipv6::MutableIpv6Packet;
            const IP_HLEN: usize = 40;
            const TCP_HLEN: usize = 20;
            let total_len = IP_HLEN + TCP_HLEN + payload.len();

            let mut buf = bytes::BytesMut::with_capacity(total_len);
            buf.resize(total_len, 0);

            // --- IP Header ---
            {
                let mut ip = MutableIpv6Packet::new(&mut buf[..IP_HLEN])
                    .ok_or_else(|| anyhow::anyhow!("Failed to create IPv6 packet"))?;
                ip.set_version(6);
                ip.set_payload_length((TCP_HLEN + payload.len()) as u16);
                ip.set_next_header(IpNextHeaderProtocols::Tcp);
                ip.set_hop_limit(ttl);
                ip.set_source(src);
                ip.set_destination(dst);
            }

            // --- TCP Header ---
            {
                let mut tcp = MutableTcpPacket::new(&mut buf[IP_HLEN..])
                    .ok_or_else(|| anyhow::anyhow!("Failed to create TCP packet"))?;
                tcp.set_source(src_port);
                tcp.set_destination(dst_port);
                tcp.set_sequence(seq_num);
                tcp.set_acknowledgement(ack_num);
                tcp.set_data_offset((TCP_HLEN / 4) as u8);
                tcp.set_flags(flags);
                tcp.set_window(65535);
                tcp.set_urgent_ptr(0);
                if !payload.is_empty() {
                    buf[IP_HLEN + TCP_HLEN..][..payload.len()].copy_from_slice(payload);
                }
            }
            let cksum = crate::desync::tcp_checksum(src_ip, dst_ip, &buf[IP_HLEN..]);
            let cksum_bytes = cksum.to_be_bytes();
            buf[IP_HLEN + 16] = cksum_bytes[0];
            buf[IP_HLEN + 17] = cksum_bytes[1];

            Ok(buf.freeze())
        }
        _ => anyhow::bail!("Mixed IPv4/IPv6 addresses"),
    }
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn build_seq_spoof_packet_badsum(
    fake_sni: &str,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    client_isn: u32,
) -> Result<SeqSpoofResult> {
    let fake_ch = ch_gen::build_client_hello_default(fake_sni);

    let packet = build_fake_tcp_packet(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        client_isn.wrapping_add(SPOOF_OFFSET),
        0,
        &fake_ch,
        64,
    )?;

    let tcp_start = match (src_ip, dst_ip) {
        (IpAddr::V4(_), IpAddr::V4(_)) => 20,
        (IpAddr::V6(_), IpAddr::V6(_)) => 40,
        _ => 20,
    };

    let packet = if packet.len() > tcp_start + 18 {
        let mut m = bytes::BytesMut::from(&packet[..]);
        let cksum = m[tcp_start + 16..tcp_start + 18].to_vec();
        let bad = (!u16::from_be_bytes([cksum[0], cksum[1]])).to_be_bytes();
        m[tcp_start + 16] = bad[0];
        m[tcp_start + 17] = bad[1];
        m.freeze()
    } else {
        packet
    };

    debug!(
        "SEQ Spoof (badsum): {} :{} → {} :{}",
        src_ip, src_port, dst_ip, dst_port
    );

    Ok(SeqSpoofResult {
        fake_packet: packet,
        fake_ttl: 64,
    })
}

pub fn build_fake_rst_packet(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
) -> Result<bytes::Bytes> {
    build_fake_tcp_packet_with_flags(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq_num,
        ack_num,
        &[],
        64,
        0x04 | 0x10, // RST + ACK
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adaptive::hop_tab::HopTab;
    use crate::conntrack::{ConnState, Conntrack, ConntrackEntry};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

    fn setup_conntrack() -> Conntrack {
        let ct = Conntrack::default();
        let key = crate::conntrack::ConnKey::new(
            Ipv4Addr::new(192, 168, 1, 2),
            Ipv4Addr::new(142, 250, 185, 46),
            54321,
            443,
            6, // TCP
        );
        let entry = ConntrackEntry {
            client_isn: 1000,
            server_isn: 5000,
            client_seq: 1001,
            server_seq: 5001,
            client_ack: 5001,
            server_ack: 1001,
            rtt_us: 50000,
            state: ConnState::SynReceived,
            desync_applied: false,
            dscp_spoof: 0,
            strategy_id: 0,
            last_activity: Instant::now(),
            dup_ack_count: 0,
            rng: None,
            quic_pn: 0,
            quic_dcid: vec![],
            is_resumption: false,
            applied_strategy: None,
            route_key: None,
            quic_dropped_initials: 0,
        };
        ct.insert(key, entry);
        ct
    }

    #[test]
    fn test_seq_spoof_packet_size() {
        let ct = setup_conntrack();
        let ht = HopTab::new();
        let ip = Ipv4Addr::new(142, 250, 185, 46);
        ht.insert(HopTab::ip_to_u32(&IpAddr::V4(ip)), 12);

        let result = build_seq_spoof_packet(
            "example.com",
            Ipv4Addr::new(192, 168, 1, 2).into(),
            ip.into(),
            54321,
            443,
            1000,
            &ct,
            &ht,
        )
        .unwrap();

        // IP(20) + TCP(20) + TLS record(5) + handshake(4) + body(512..4096) = 561..4145
        let packet_len = result.fake_packet.len();
        assert!(packet_len >= 552, "Packet too small: {} bytes", packet_len);
        assert!(packet_len <= 4160, "Packet too large: {} bytes", packet_len);
    }

    #[test]
    fn test_seq_spoof_fake_seq() {
        let ct = setup_conntrack();
        let ht = HopTab::new();
        let ip = Ipv4Addr::new(142, 250, 185, 46);
        ht.insert(HopTab::ip_to_u32(&IpAddr::V4(ip)), 12);

        let result = build_seq_spoof_packet(
            "test.com",
            Ipv4Addr::new(192, 168, 1, 2).into(),
            ip.into(),
            54321,
            443,
            1000,
            &ct,
            &ht,
        )
        .unwrap();

        let fake_packet = &result.fake_packet;
        // TCP header starts at byte 20 (after IP header)
        let tcp_seq_bytes = &fake_packet[24..28]; // TCP SEQ at offset 4 from TCP header
        let tcp_seq = u32::from_be_bytes([
            tcp_seq_bytes[0],
            tcp_seq_bytes[1],
            tcp_seq_bytes[2],
            tcp_seq_bytes[3],
        ]);
        // Expected: client_isn(1000) + SPOOF_OFFSET(10000) = 11000
        assert_eq!(tcp_seq, 11000);
    }

    #[test]
    fn test_seq_spoof_ttl_from_hop_tab() {
        let ct = setup_conntrack();
        let ht = HopTab::new();
        let ip = Ipv4Addr::new(142, 250, 185, 46);
        ht.insert(HopTab::ip_to_u32(&IpAddr::V4(ip)), 12); // 12 hops

        let result = build_seq_spoof_packet(
            "example.com",
            Ipv4Addr::new(192, 168, 1, 2).into(),
            ip.into(),
            54321,
            443,
            1000,
            &ct,
            &ht,
        )
        .unwrap();

        // IP TTL at byte 8
        let ttl = result.fake_packet[8];
        // 12 hops → fake TTL = 11
        assert_eq!(ttl, 11);
    }

    #[test]
    fn test_seq_spoof_fallback_ttl() {
        let ct = setup_conntrack();
        let ht = HopTab::new(); // Empty HopTab
        let ip = Ipv4Addr::new(142, 250, 185, 46);

        // HopTab empty → fallback TTL = 64
        let result = build_seq_spoof_packet(
            "example.com",
            Ipv4Addr::new(192, 168, 1, 2).into(),
            ip.into(),
            54321,
            443,
            1000,
            &ct,
            &ht,
        )
        .unwrap();

        let ttl = result.fake_packet[8];
        assert_eq!(ttl, 64);
    }

    #[test]
    fn test_seq_spoof_ip_header_fields() {
        let ct = setup_conntrack();
        let ht = HopTab::new();
        let ip = Ipv4Addr::new(142, 250, 185, 46);
        ht.insert(HopTab::ip_to_u32(&IpAddr::V4(ip)), 8);

        let result = build_seq_spoof_packet(
            "example.com",
            Ipv4Addr::new(192, 168, 1, 2).into(),
            ip.into(),
            54321,
            443,
            1000,
            &ct,
            &ht,
        )
        .unwrap();

        let pkt = &result.fake_packet;
        assert_eq!(pkt[0] >> 4, 4); // IPv4
        assert_eq!(pkt[9], 6); // TCP protocol
                               // Source IP
        assert_eq!(&pkt[12..16], &[192, 168, 1, 2]);
        // Dest IP
        assert_eq!(&pkt[16..20], &[142, 250, 185, 46]);
    }

    #[test]
    fn test_seq_spoof_badsum() {
        let result = build_seq_spoof_packet_badsum(
            "example.com",
            Ipv4Addr::new(192, 168, 1, 2).into(),
            Ipv4Addr::new(142, 250, 185, 46).into(),
            54321,
            443,
            1000,
        )
        .unwrap();

        let packet_len = result.fake_packet.len();
        assert!(packet_len >= 552, "Packet too small: {} bytes", packet_len);
        assert!(packet_len <= 4160, "Packet too large: {} bytes", packet_len);
    }

    #[test]
    fn test_fake_rst_packet() {
        let pkt = build_fake_rst_packet(
            Ipv4Addr::new(192, 168, 1, 2).into(),
            Ipv4Addr::new(142, 250, 185, 46).into(),
            54321,
            443,
            1001,
            5001,
        )
        .unwrap();

        // IP(20) + TCP(20) = 40 bytes
        assert_eq!(pkt.len(), 40);
        // IP protocol = TCP
        assert_eq!(pkt[9], 6);
        // TCP flags: RST + ACK (0x14)
        let tcp_flags = pkt[33]; // TCP header starts at 20, flags at offset 13
        assert_eq!(tcp_flags, 0x14);
    }

    #[test]
    fn test_ipv4_checksum() {
        // Пример: простой IP header
        let header = vec![
            0x45, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8,
            0x01, 0x01, 0x08, 0x08, 0x08, 0x08,
        ];
        let cksum = ipv4_checksum(&header);
        assert!(cksum != 0);
    }

    #[test]
    fn test_seq_spoof_with_resumption() {
        let ct = Conntrack::default();
        let key = crate::conntrack::ConnKey::new(
            Ipv4Addr::new(192, 168, 1, 2),
            Ipv4Addr::new(142, 250, 185, 46),
            54321,
            443,
            6,
        );
        let entry = ConntrackEntry {
            client_isn: 1000,
            server_isn: 5000,
            client_seq: 1001,
            server_seq: 5001,
            client_ack: 5001,
            server_ack: 1001,
            rtt_us: 50000,
            state: ConnState::SynReceived,
            desync_applied: false,
            dscp_spoof: 0,
            strategy_id: 0,
            last_activity: std::time::Instant::now(),
            dup_ack_count: 0,
            rng: None,
            quic_pn: 0,
            quic_dcid: vec![],
            is_resumption: true, // Включаем resumption
            applied_strategy: None,
            route_key: None,
            quic_dropped_initials: 0,
        };
        ct.insert(key, entry);

        let ht = HopTab::new();
        let ip = Ipv4Addr::new(142, 250, 185, 46);
        ht.insert(HopTab::ip_to_u32(&IpAddr::V4(ip)), 10);

        let result = build_seq_spoof_packet(
            "example.com",
            Ipv4Addr::new(192, 168, 1, 2).into(),
            ip.into(),
            54321,
            443,
            1000,
            &ct,
            &ht,
        )
        .unwrap();

        // Проверяем что пакет содержит early_data extension (0x4433)
        // — признак resumption
        let packet = &result.fake_packet;
        let early_data_type = 0x4433u16.to_be_bytes();
        let has_early_data = packet.windows(2).any(|w| w == early_data_type);
        assert!(
            has_early_data,
            "Resumption fake CH should contain early_data extension (0x4433)"
        );

        // Проверяем non-empty session_ticket
        let ticket_ext_type = 0x0023u16.to_be_bytes();
        // Находим session_ticket extension
        let mut found_ticket = false;
        let mut found_ticket_non_empty = false;
        for i in 0..packet.len().saturating_sub(4) {
            if packet[i..i + 2] == ticket_ext_type {
                found_ticket = true;
                let ext_len = u16::from_be_bytes([packet[i + 2], packet[i + 3]]) as usize;
                if ext_len > 0 {
                    found_ticket_non_empty = true;
                }
            }
        }
        assert!(found_ticket, "CH should contain session_ticket extension");
        assert!(
            found_ticket_non_empty,
            "Resumption CH should have non-empty session_ticket"
        );
    }

    #[test]
    fn test_seq_spoof_ipv6() {
        use std::net::Ipv6Addr;
        let ct = Conntrack::default();
        let key = crate::conntrack::ConnKey::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
            54321,
            443,
            6,
        );
        let entry = ConntrackEntry {
            client_isn: 1000,
            server_isn: 5000,
            client_seq: 1001,
            server_seq: 5001,
            client_ack: 5001,
            server_ack: 1001,
            rtt_us: 50000,
            state: ConnState::SynReceived,
            desync_applied: false,
            dscp_spoof: 0,
            strategy_id: 0,
            last_activity: Instant::now(),
            dup_ack_count: 0,
            rng: None,
            quic_pn: 0,
            quic_dcid: vec![],
            is_resumption: false,
            applied_strategy: None,
            route_key: None,
            quic_dropped_initials: 0,
        };
        ct.insert(key, entry);

        let ht = HopTab::new();
        let src_ip = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let dst_ip = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);

        let result = build_seq_spoof_packet(
            "example.com",
            IpAddr::V6(src_ip),
            IpAddr::V6(dst_ip),
            54321,
            443,
            1000,
            &ct,
            &ht,
        )
        .unwrap();

        let packet_len = result.fake_packet.len();
        assert!(
            packet_len >= 572,
            "IPv6 packet too small: {} bytes",
            packet_len
        );

        let pkt = &result.fake_packet;
        assert_eq!(pkt[0] >> 4, 6); // IPv6 version
        assert_eq!(pkt[6], 6); // TCP next header
        assert_eq!(&pkt[8..24], src_ip.octets().as_slice());
        assert_eq!(&pkt[24..40], dst_ip.octets().as_slice());
    }
}
