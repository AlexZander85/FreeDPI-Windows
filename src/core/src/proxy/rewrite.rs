use anyhow::{anyhow, Result};
use pnet_packet::ipv4::checksum as ipv4_checksum;
use pnet_packet::ipv4::MutableIpv4Packet;
use pnet_packet::ipv6::MutableIpv6Packet;
use pnet_packet::tcp::ipv4_checksum as tcp_checksum_v4;
use pnet_packet::tcp::ipv6_checksum as tcp_checksum_v6;
use pnet_packet::tcp::MutableTcpPacket;
use std::net::IpAddr;

enum ParsedIpHeader {
    V4 {
        src: IpAddr,
        dst: IpAddr,
        header_len: usize,
    },
    V6 {
        src: IpAddr,
        dst: IpAddr,
        header_len: usize,
    },
}

impl ParsedIpHeader {
    fn header_len(&self) -> usize {
        match self {
            Self::V4 { header_len, .. } | Self::V6 { header_len, .. } => *header_len,
        }
    }
    fn src(&self) -> IpAddr {
        match self {
            Self::V4 { src, .. } | Self::V6 { src, .. } => *src,
        }
    }
    fn dst(&self) -> IpAddr {
        match self {
            Self::V4 { dst, .. } | Self::V6 { dst, .. } => *dst,
        }
    }
}

fn parse_ip_header_local(buf: &[u8]) -> Option<ParsedIpHeader> {
    if buf.is_empty() {
        return None;
    }
    let version = buf[0] >> 4;
    if version == 4 {
        let pkt = pnet_packet::ipv4::Ipv4Packet::new(buf)?;
        let ihl = (pkt.get_header_length() as usize) * 4;
        Some(ParsedIpHeader::V4 {
            src: IpAddr::V4(pkt.get_source()),
            dst: IpAddr::V4(pkt.get_destination()),
            header_len: ihl,
        })
    } else if version == 6 {
        let pkt = pnet_packet::ipv6::Ipv6Packet::new(buf)?;
        Some(ParsedIpHeader::V6 {
            src: IpAddr::V6(pkt.get_source()),
            dst: IpAddr::V6(pkt.get_destination()),
            header_len: 40,
        })
    } else {
        None
    }
}

/// Переписывает IP-назначение и TCP-порт назначения, пересчитывает IP- и
/// TCP-чексуммы (включая pseudo-header, который меняется при смене IP).
pub fn rewrite_dst_addr(
    packet_data: &[u8],
    new_dst_ip: IpAddr,
    new_dst_port: u16,
) -> Result<Vec<u8>> {
    let mut buf = packet_data.to_vec();
    let ip_hdr = parse_ip_header_local(&buf).ok_or_else(|| anyhow!("invalid ip header"))?;
    let ip_hdr_len = ip_hdr.header_len();
    let orig_src = ip_hdr.src();

    match (&ip_hdr, new_dst_ip) {
        (ParsedIpHeader::V4 { .. }, IpAddr::V4(new_ip)) => {
            let mut ip_pkt = MutableIpv4Packet::new(&mut buf[..ip_hdr_len])
                .ok_or_else(|| anyhow!("bad ipv4 slice"))?;
            ip_pkt.set_destination(new_ip);
            ip_pkt.set_checksum(0);
            let csum = ipv4_checksum(&ip_pkt.to_immutable());
            ip_pkt.set_checksum(csum);
        }
        (ParsedIpHeader::V6 { .. }, IpAddr::V6(new_ip)) => {
            let mut ip_pkt = MutableIpv6Packet::new(&mut buf[..ip_hdr_len])
                .ok_or_else(|| anyhow!("bad ipv6 slice"))?;
            ip_pkt.set_destination(new_ip);
        }
        _ => return Err(anyhow!("ip version mismatch between packet and new_dst_ip")),
    }

    {
        let mut tcp_pkt = MutableTcpPacket::new(&mut buf[ip_hdr_len..])
            .ok_or_else(|| anyhow!("invalid tcp header"))?;
        tcp_pkt.set_destination(new_dst_port);
        tcp_pkt.set_checksum(0);
    }

    let new_csum = match (orig_src, new_dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let tcp_view = pnet_packet::tcp::TcpPacket::new(&buf[ip_hdr_len..]).unwrap();
            tcp_checksum_v4(&tcp_view, &s, &d)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let tcp_view = pnet_packet::tcp::TcpPacket::new(&buf[ip_hdr_len..]).unwrap();
            tcp_checksum_v6(&tcp_view, &s, &d)
        }
        _ => return Err(anyhow!("mixed ip versions in checksum calc")),
    };
    let mut tcp_pkt = MutableTcpPacket::new(&mut buf[ip_hdr_len..]).unwrap();
    tcp_pkt.set_checksum(new_csum);

    Ok(buf)
}

/// Переписывает IP-источник и TCP-порт источника (обратный путь: ответ
/// локального редиректора → клиенту, подмена под адрес оригинальной цели).
pub fn rewrite_src_addr(
    packet_data: &[u8],
    new_src_ip: IpAddr,
    new_src_port: u16,
) -> Result<Vec<u8>> {
    let mut buf = packet_data.to_vec();
    let ip_hdr = parse_ip_header_local(&buf).ok_or_else(|| anyhow!("invalid ip header"))?;
    let ip_hdr_len = ip_hdr.header_len();
    let orig_dst = ip_hdr.dst();

    match (&ip_hdr, new_src_ip) {
        (ParsedIpHeader::V4 { .. }, IpAddr::V4(new_ip)) => {
            let mut ip_pkt = MutableIpv4Packet::new(&mut buf[..ip_hdr_len])
                .ok_or_else(|| anyhow!("bad ipv4 slice"))?;
            ip_pkt.set_source(new_ip);
            ip_pkt.set_checksum(0);
            let csum = ipv4_checksum(&ip_pkt.to_immutable());
            ip_pkt.set_checksum(csum);
        }
        (ParsedIpHeader::V6 { .. }, IpAddr::V6(new_ip)) => {
            let mut ip_pkt = MutableIpv6Packet::new(&mut buf[..ip_hdr_len])
                .ok_or_else(|| anyhow!("bad ipv6 slice"))?;
            ip_pkt.set_source(new_ip);
        }
        _ => return Err(anyhow!("ip version mismatch between packet and new_src_ip")),
    }

    {
        let mut tcp_pkt = MutableTcpPacket::new(&mut buf[ip_hdr_len..])
            .ok_or_else(|| anyhow!("invalid tcp header"))?;
        tcp_pkt.set_source(new_src_port);
        tcp_pkt.set_checksum(0);
    }

    let new_csum = match (new_src_ip, orig_dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let tcp_view = pnet_packet::tcp::TcpPacket::new(&buf[ip_hdr_len..]).unwrap();
            tcp_checksum_v4(&tcp_view, &s, &d)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let tcp_view = pnet_packet::tcp::TcpPacket::new(&buf[ip_hdr_len..]).unwrap();
            tcp_checksum_v6(&tcp_view, &s, &d)
        }
        _ => return Err(anyhow!("mixed ip versions in checksum calc")),
    };
    let mut tcp_pkt = MutableTcpPacket::new(&mut buf[ip_hdr_len..]).unwrap();
    tcp_pkt.set_checksum(new_csum);

    Ok(buf)
}

/// UDP-чексумма — обязательна для IPv6 (RFC 8200 запрещает нулевую), опциональна
/// для IPv4. Используется при сборке DNS-ответов (Часть 6).
pub fn udp_checksum(src: IpAddr, dst: IpAddr, udp_packet: &[u8]) -> u16 {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let pkt = pnet_packet::udp::UdpPacket::new(udp_packet).unwrap();
            pnet_packet::udp::ipv4_checksum(&pkt, &s, &d)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let pkt = pnet_packet::udp::UdpPacket::new(udp_packet).unwrap();
            pnet_packet::udp::ipv6_checksum(&pkt, &s, &d)
        }
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet_packet::ipv4::Ipv4Packet;
    use pnet_packet::tcp::TcpPacket;
    use std::net::Ipv4Addr;

    #[test]
    fn test_rewrite_checksum_verification() {
        // Construct a mock TCP SYN packet
        let mut ip_hdr = [0u8; 20];
        ip_hdr[0] = 0x45; // Version 4, IHL 5
        ip_hdr[8] = 64; // TTL
        ip_hdr[9] = 6; // Protocol TCP
        ip_hdr[12..16].copy_from_slice(&[192, 168, 1, 100]); // Src IP
        ip_hdr[16..20].copy_from_slice(&[8, 8, 8, 8]); // Dst IP

        let mut tcp_hdr = [0u8; 20];
        tcp_hdr[0..2].copy_from_slice(&12345u16.to_be_bytes()); // Src Port
        tcp_hdr[2..4].copy_from_slice(&443u16.to_be_bytes()); // Dst Port
        tcp_hdr[12] = 0x50; // Data Offset 5 (20 bytes)
        tcp_hdr[13] = 0x02; // Flags SYN

        let mut pkt = Vec::new();
        pkt.extend_from_slice(&ip_hdr);
        pkt.extend_from_slice(&tcp_hdr);

        // Update lengths
        let total_len = pkt.len() as u16;
        pkt[2..4].copy_from_slice(&total_len.to_be_bytes());

        // Perform rewrite destination
        let new_dst = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let rewritten = rewrite_dst_addr(&pkt, new_dst, 17650).unwrap();

        // Verify checksum is valid using pnet_packet
        let ip_pkt = Ipv4Packet::new(&rewritten).unwrap();
        let tcp_pkt = TcpPacket::new(&rewritten[20..]).unwrap();

        let calculated_csum =
            tcp_checksum_v4(&tcp_pkt, &ip_pkt.get_source(), &ip_pkt.get_destination());
        assert_eq!(calculated_csum, tcp_pkt.get_checksum());
    }
}
