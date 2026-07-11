//! Packet Classifier — классификация пакетов по протоколу и направлению.
//! Поддерживает IPv4 и IPv6.

use crate::conntrack::ConnKey;
use pnet_packet::{ipv4::Ipv4Packet, ipv6::Ipv6Packet, tcp::TcpPacket, udp::UdpPacket};
use std::net::IpAddr;

/// Направление пакета относительно origin.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PacketDirection {
    /// От клиента к серверу (outbound)
    Outbound,
    /// От сервера к клиенту (inbound)
    Inbound,
}

/// Классифицированный пакет.
#[derive(Debug)]
pub struct ClassifiedPacket {
    /// Исходный IP (IPv4 или IPv6)
    pub src_ip: IpAddr,
    /// IP назначения (IPv4 или IPv6)
    pub dst_ip: IpAddr,
    /// Порт источника
    pub src_port: u16,
    /// Порт назначения
    pub dst_port: u16,
    /// Протокол
    pub protocol: u8,
    /// Направление
    pub direction: PacketDirection,
    /// Ключ соединения (для conntrack)
    pub conn_key: ConnKey,
    /// Указатель на начало payload (TCP/UDP data)
    pub payload_offset: usize,
    /// Длина payload
    pub payload_len: usize,
}

/// Результат классификации.
pub enum Classification {
    /// TLS (TCP:443)
    Tls(ClassifiedPacket),
    /// QUIC (UDP:443)
    Quic(ClassifiedPacket),
    /// DNS (UDP:53)
    Dns(ClassifiedPacket),
    /// HTTP (TCP:80)
    Http(ClassifiedPacket),
    /// Другой протокол
    Other(ClassifiedPacket),
    /// Не смогли разобрать пакет
    Unknown,
}

/// Классификатор пакетов.
pub struct Classifier;

impl Classifier {
    /// Классифицирует raw IP пакет (IPv4 или IPv6).
    pub fn classify(packet: &[u8]) -> Classification {
        if packet.is_empty() {
            return Classification::Unknown;
        }
        let version = packet[0] >> 4;
        match version {
            4 => Self::classify_ipv4(packet),
            6 => Self::classify_ipv6(packet),
            _ => Classification::Unknown,
        }
    }

    fn classify_other(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        protocol: u8,
        payload_offset: usize,
        packet_len: usize,
    ) -> Classification {
        Classification::Other(ClassifiedPacket {
            src_ip,
            dst_ip,
            src_port: 0,
            dst_port: 0,
            protocol,
            direction: PacketDirection::Outbound,
            conn_key: ConnKey::new(src_ip, dst_ip, 0, 0, protocol),
            payload_offset,
            payload_len: packet_len.saturating_sub(payload_offset),
        })
    }

    fn classify_ipv4(packet: &[u8]) -> Classification {
        let ip = match Ipv4Packet::new(packet) {
            Some(ip) => ip,
            None => return Classification::Unknown,
        };

        let src_ip = IpAddr::V4(ip.get_source());
        let dst_ip = IpAddr::V4(ip.get_destination());
        let protocol = ip.get_next_level_protocol().0;
        let header_len = (ip.get_header_length() as usize) * 4;
        if header_len < 20 || packet.len() < header_len {
            return Classification::Unknown;
        }

        let flags = ip.get_flags();
        let fragment_offset = ip.get_fragment_offset();
        let more_fragments = (flags & 0x1) != 0;
        if fragment_offset != 0 || more_fragments {
            return Self::classify_other(
                src_ip,
                dst_ip,
                protocol,
                header_len.min(packet.len()),
                packet.len(),
            );
        }

        Self::classify_transport(packet, src_ip, dst_ip, protocol, header_len)
    }

    fn classify_ipv6(packet: &[u8]) -> Classification {
        let parsed = match crate::desync::parse_ipv6_header(packet) {
            Some(h) => h,
            None => return Classification::Unknown,
        };

        if parsed.fragment_offset.is_some() {
            return Self::classify_other(
                IpAddr::V6(parsed.src),
                IpAddr::V6(parsed.dst),
                parsed.protocol.0,
                parsed.header_len,
                packet.len(),
            );
        }

        let src_ip = IpAddr::V6(parsed.src);
        let dst_ip = IpAddr::V6(parsed.dst);
        let protocol = parsed.protocol.0;
        let header_len = parsed.header_len;

        Self::classify_transport(packet, src_ip, dst_ip, protocol, header_len)
    }

    fn classify_transport(
        packet: &[u8],
        src_ip: IpAddr,
        dst_ip: IpAddr,
        protocol: u8,
        header_len: usize,
    ) -> Classification {
        match protocol {
            6 => {
                let transport = match packet.get(header_len..) {
                    Some(s) => s,
                    None => return Classification::Unknown,
                };
                let tcp = match TcpPacket::new(transport) {
                    Some(tcp) => tcp,
                    None => return Classification::Unknown,
                };
                let src_port = tcp.get_source();
                let dst_port = tcp.get_destination();
                let tcp_header_len = (tcp.get_data_offset() as usize) * 4;
                if tcp_header_len < 20 || transport.len() < tcp_header_len {
                    return Classification::Unknown;
                }
                let payload_offset = match header_len.checked_add(tcp_header_len) {
                    Some(val) => val,
                    None => return Classification::Unknown,
                };
                let payload = match packet.get(payload_offset..) {
                    Some(p) => p,
                    None => return Classification::Unknown,
                };

                let cp = ClassifiedPacket {
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    protocol,
                    direction: PacketDirection::Outbound,
                    conn_key: ConnKey::new(src_ip, dst_ip, src_port, dst_port, protocol),
                    payload_offset,
                    payload_len: payload.len(),
                };

                if payload.len() >= 5 {
                    if payload[0] == 0x16 && payload[1] == 0x03 && payload[2] <= 0x03 {
                        return Classification::Tls(cp);
                    }
                    if payload.starts_with(b"GET ")
                        || payload.starts_with(b"POST ")
                        || payload.starts_with(b"PUT ")
                        || payload.starts_with(b"HEAD ")
                        || payload.starts_with(b"DELETE ")
                        || payload.starts_with(b"CONNECT ")
                        || payload.starts_with(b"OPTIONS ")
                    {
                        return Classification::Http(cp);
                    }
                    if payload.len() >= 24 && &payload[..24] == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                    {
                        return Classification::Http(cp);
                    }
                }

                match dst_port {
                    443 => Classification::Tls(cp),
                    80 => Classification::Http(cp),
                    _ => Classification::Other(cp),
                }
            }
            17 => {
                let transport = match packet.get(header_len..) {
                    Some(s) => s,
                    None => return Classification::Unknown,
                };
                let udp = match UdpPacket::new(transport) {
                    Some(udp) => udp,
                    None => return Classification::Unknown,
                };
                if transport.len() < 8 {
                    return Classification::Unknown;
                }
                let src_port = udp.get_source();
                let dst_port = udp.get_destination();
                let payload_offset = match header_len.checked_add(8) {
                    Some(val) => val,
                    None => return Classification::Unknown,
                };
                let payload = match packet.get(payload_offset..) {
                    Some(p) => p,
                    None => return Classification::Unknown,
                };

                let cp = ClassifiedPacket {
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    protocol,
                    direction: PacketDirection::Outbound,
                    conn_key: ConnKey::new(src_ip, dst_ip, src_port, dst_port, protocol),
                    payload_offset,
                    payload_len: payload.len(),
                };

                if !payload.is_empty() && (payload[0] & 0x80) != 0 {
                    return Classification::Quic(cp);
                }

                match dst_port {
                    53 => Classification::Dns(cp),
                    443 => Classification::Quic(cp),
                    _ => Classification::Other(cp),
                }
            }
            _ => Self::classify_other(
                src_ip,
                dst_ip,
                protocol,
                header_len.min(packet.len()),
                packet.len(),
            ),
        }
    }

    /// Определяет направление пакета на основе conntrack.
    ///
    /// Если src_ip — локальный → Outbound.
    /// Иначе → Inbound (ответ сервера).
    pub fn determine_direction(local_ips: &[IpAddr], cp: &ClassifiedPacket) -> PacketDirection {
        if local_ips.contains(&cp.src_ip) {
            PacketDirection::Outbound
        } else {
            PacketDirection::Inbound
        }
    }

    /// Проверяет, является ли пакет TLS ClientHello.
    pub fn is_client_hello(payload: &[u8]) -> bool {
        payload.len() > 5
            && payload[0] == 0x16 // ContentType: Handshake
            && (payload[1] == 0x03) // TLS version major
            && payload[5] == 0x01 // HandshakeType: ClientHello
    }

    /// Проверяет, является ли payload десинхронизируемой целью.
    /// Только ClientHello (первый раз) — не application data, не alert, не ретрансмиссия.
    pub fn is_desync_target(payload: &[u8], desync_applied: bool) -> bool {
        if !Self::is_client_hello(payload) {
            return false;
        }
        if desync_applied {
            return false;
        }
        if payload.len() < 50 {
            return false;
        }
        true
    }

    /// Проверяет, является ли пакет TLS ServerHello.
    pub fn is_server_hello(payload: &[u8]) -> bool {
        payload.len() > 5 && payload[0] == 0x16 && (payload[1] == 0x03) && payload[5] == 0x02
        // HandshakeType: ServerHello
    }

    /// Извлекает SNI из TLS ClientHello.
    ///
    /// Возвращает Some(domain) если найден.
    pub fn extract_sni(payload: &[u8]) -> Option<String> {
        if !Self::is_client_hello(payload) || payload.len() < 44 {
            return None;
        }

        // Парсим extensions в ClientHello
        // Позиция после session_id
        let session_id_len = payload[43] as usize;

        if 44 + session_id_len + 2 > payload.len() {
            return None;
        }

        let cipher_suites_len = ((payload[44 + session_id_len] as usize) << 8)
            | (payload[45 + session_id_len] as usize);

        let mut pos = 46 + session_id_len + cipher_suites_len;

        if pos + 1 >= payload.len() {
            return None;
        }

        let compression_len = payload[pos] as usize;
        pos += 1 + compression_len;

        if pos + 2 > payload.len() {
            return None;
        }

        let ext_total_len = ((payload[pos] as usize) << 8) | (payload[pos + 1] as usize);
        pos += 2;

        let end = pos + ext_total_len;
        while pos + 4 <= end && pos + 4 <= payload.len() {
            let ext_type = ((payload[pos] as usize) << 8) | (payload[pos + 1] as usize);
            let ext_len = ((payload[pos + 2] as usize) << 8) | (payload[pos + 3] as usize);

            pos += 4;

            if ext_type == 0x0000 {
                // SNI extension
                if pos + 3 > payload.len() {
                    return None;
                }
                let sni_list_len = ((payload[pos] as usize) << 8) | (payload[pos + 1] as usize);
                if pos + 3 + sni_list_len > payload.len() {
                    return None;
                }
                let name_type = payload[pos + 2];
                if name_type == 0 {
                    // host_name
                    let name_len = ((payload[pos + 3] as usize) << 8) | (payload[pos + 4] as usize);
                    if pos + 5 + name_len <= payload.len() {
                        return String::from_utf8(payload[pos + 5..pos + 5 + name_len].to_vec())
                            .ok();
                    }
                }
                return None;
            }

            pos += ext_len;
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_classify_tcp_syn() {
        // Build a minimal TCP SYN packet
        let pkt = vec![
            0x45, 0x00, 0x00, 0x28, // IP header
            0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, // TCP proto
            0xc0, 0xa8, 0x01, 0x01, // src: 192.168.1.1
            0x08, 0x08, 0x08, 0x08, // dst: 8.8.8.8
            // TCP header (20 bytes)
            0x30, 0x39, // src port: 12345
            0x01, 0xbb, // dst port: 443
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x02, 0x71, 0x10, // data offset + flags + window
            0x00, 0x00, // checksum
            0x00, 0x00, // urgent ptr
        ];

        match Classifier::classify(&pkt) {
            Classification::Tls(cp) => {
                assert_eq!(cp.dst_port, 443);
                assert_eq!(cp.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
            }
            _ => panic!("Expected TLS classification"),
        }
    }

    #[test]
    fn test_classify_dns() {
        let pkt = vec![
            0x45, 0x00, 0x00, 0x1c, // IP header
            0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, // UDP proto
            0xc0, 0xa8, 0x01, 0x01, 0x08, 0x08, 0x08, 0x08, // UDP header (8 bytes)
            0x00, 0x35, // src port: 53
            0x00, 0x35, // dst port: 53
            0x00, 0x08, 0x00, 0x00, // length + checksum
        ];

        match Classifier::classify(&pkt) {
            Classification::Dns(cp) => {
                assert_eq!(cp.dst_port, 53);
            }
            _ => panic!("Expected DNS classification"),
        }
    }

    #[test]
    fn test_client_hello_detection() {
        let ch = vec![
            0x16, 0x03, 0x01, 0x00, 0x02, // record
            0x01, // ClientHello
        ];
        assert!(Classifier::is_client_hello(&ch));

        let not_ch = vec![0x16, 0x03, 0x01, 0x00, 0x02, 0x02]; // ServerHello
        assert!(!Classifier::is_client_hello(&not_ch));
    }

    #[test]
    fn test_direction_detection() {
        let local_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let remote = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let local_ips = vec![local_ip];

        let cp = ClassifiedPacket {
            src_ip: local_ip,
            dst_ip: remote,
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            direction: PacketDirection::Outbound,
            conn_key: ConnKey::new(local_ip, remote, 12345, 443, 6),
            payload_offset: 40,
            payload_len: 0,
        };

        assert_eq!(
            Classifier::determine_direction(&local_ips, &cp),
            PacketDirection::Outbound
        );
    }

    #[test]
    fn test_unknown_packet() {
        let pkt = vec![0x00; 10]; // Too short for IP
        match Classifier::classify(&pkt) {
            Classification::Unknown => {} // expected
            _ => panic!("Expected Unknown"),
        }
    }

    #[test]
    fn test_classify_ipv4_fragment() {
        // Minimal IPv4 fragment (Fragment Offset = 180)
        let pkt = vec![
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x20,
            0xb4, // Flags (0x20) + FragOffset (0xb4 = 180)
            0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01, 0x08, 0x08, 0x08, 0x08,
        ];
        match Classifier::classify(&pkt) {
            Classification::Other(cp) => {
                assert_eq!(cp.src_port, 0);
                assert_eq!(cp.dst_port, 0);
            }
            _ => panic!("Expected fragment to be classified as Other"),
        }
    }

    #[test]
    fn test_classify_ipv6_extension_headers() {
        // Minimal IPv6 packet with Hop-by-Hop extension header + TCP
        let mut pkt = vec![0u8; 40 + 8 + 20];
        // IPv6 Header: Version 6 (0x60), NextHeader = 0 (Hop-by-Hop), payload len = 28
        pkt[0] = 0x60;
        pkt[6] = 0; // Hop-by-Hop
        pkt[7] = 64; // Hop limit
                     // Source/Dest IP dummy bytes
        pkt[8..24].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        pkt[24..40].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

        // Hop-by-Hop header: NextHeader = 6 (TCP), HeaderExtLen = 0 (8 bytes total)
        pkt[40] = 6; // NextHeader: TCP
        pkt[41] = 0; // Length = 0 (8 bytes)

        // TCP header at offset 48: source 12345 (0x3039), dest 443 (0x01bb)
        pkt[48] = 0x30;
        pkt[49] = 0x39;
        pkt[50] = 0x01;
        pkt[51] = 0xbb;
        pkt[60] = 0x50; // Offset = 5 (20 bytes)

        match Classifier::classify(&pkt) {
            Classification::Tls(cp) => {
                assert_eq!(cp.src_port, 12345);
                assert_eq!(cp.dst_port, 443);
                assert_eq!(cp.payload_offset, 68); // 40 (IP) + 8 (Hop-by-Hop) + 20 (TCP)
            }
            _ => panic!("Expected TLS classification with extensions"),
        }
    }

    // === P0-12: Short/truncated packet no-panic tests ===

    #[test]
    fn test_short_ip_header_no_panic() {
        // IP header too short (< 20 bytes) — must not panic
        let pkt = vec![0x45; 15];
        let _ = Classifier::classify(&pkt);
    }

    #[test]
    fn test_short_tcp_no_panic() {
        // TCP data offset (48..) would be out of bounds
        let pkt = vec![
            0x45, 0x00, 0x00, 0x28, // IP header
            0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, // TCP proto
            0xc0, 0xa8, 0x01, 0x01, // src: 192.168.1.1
            0x08, 0x08, 0x08, 0x08, // dst: 8.8.8.8
            // TCP header — only 10 bytes (truncated)
            0x30, 0x39, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        ];
        let _ = Classifier::classify(&pkt);
    }

    #[test]
    fn test_short_udp_no_panic() {
        // UDP header truncated (< 8 bytes)
        let pkt = vec![
            0x45, 0x00, 0x00, 0x18, // IP header
            0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, // UDP proto
            0xc0, 0xa8, 0x01, 0x01, // src
            0x08, 0x08, 0x08, 0x08, // dst
            0x00, 0x35, 0x00, 0x35, // src/dst port — only 4 bytes of UDP header
        ];
        let _ = Classifier::classify(&pkt);
    }

    #[test]
    fn test_ipv6_truncated_no_panic() {
        // IPv6 packet with payload length > actual data
        let mut pkt = vec![0u8; 30]; // 40-byte IPv6 header would need 40 bytes
        pkt[0] = 0x60; // IPv6, TC=0, FlowLabel=0
        pkt[4] = 0; // Payload Length high byte = 0 (claims 65535.. wait just 0)
        pkt[5] = 10; // Payload Length = 10, but only 30 bytes total
        pkt[6] = 6; // Next Header: TCP
        pkt[7] = 64; // Hop Limit
        let _ = Classifier::classify(&pkt);
    }

    #[test]
    fn test_empty_packet_no_panic() {
        let pkt: Vec<u8> = vec![];
        let _ = Classifier::classify(&pkt);
    }

    #[test]
    fn test_ipv6_extension_chain_truncated_no_panic() {
        // IPv6 with Fragment extension header, truncated after extension
        let mut pkt = vec![0u8; 50];
        pkt[0] = 0x60;
        pkt[4] = 0;
        pkt[5] = 10; // payload len = 10 (but extension needs 8)
        pkt[6] = 44; // Next Header: Fragment Header (44)
        pkt[7] = 64;
        // Extension header starts at offset 40
        pkt[40] = 6; // Next Header: TCP (but truncated after)
        pkt[41] = 0; // Reserved
                     // Fragment offset bits
        pkt[42] = 0;
        pkt[43] = 0; // More fragments = 0, Fragment offset = 0
                     // Only 46 bytes total, extension header is 8 bytes
        let _ = Classifier::classify(&pkt);
    }
}
