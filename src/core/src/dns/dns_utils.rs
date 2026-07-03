use anyhow::{anyhow, Result};
use std::net::IpAddr;

pub struct DnsQuery {
    pub transaction_id: u16,
    pub domain: String,
    pub query_type: u16, // 1 = A, 28 = AAAA
    pub raw_question: Vec<u8>,
}

/// Parses a DNS query from a raw IP+UDP packet.
pub fn parse_dns_query(packet: &[u8]) -> Option<DnsQuery> {
    let ip_hdr = crate::desync::parse_ip_header(packet)?;
    if ip_hdr.protocol().0 != 17 {
        return None;
    } // Not UDP

    let udp_start = ip_hdr.header_len();
    if packet.len() < udp_start + 8 {
        return None;
    }
    let udp_data = &packet[udp_start + 8..];

    if udp_data.len() < 12 {
        return None;
    }
    let transaction_id = u16::from_be_bytes([udp_data[0], udp_data[1]]);
    let qdcount = u16::from_be_bytes([udp_data[4], udp_data[5]]);
    if qdcount == 0 {
        return None;
    }

    let mut pos = 12;
    let mut labels = Vec::new();
    while pos < udp_data.len() {
        let label_len = udp_data[pos] as usize;
        if label_len == 0 {
            pos += 1;
            break;
        }
        if label_len & 0xC0 == 0xC0 {
            // Compressed label in question section (uncommon for simple requests, but we skip)
            return None;
        }
        if pos + 1 + label_len > udp_data.len() {
            return None;
        }
        let label = std::str::from_utf8(&udp_data[pos + 1..pos + 1 + label_len]).ok()?;
        labels.push(label);
        pos += 1 + label_len;
    }
    let domain = labels.join(".");

    if pos + 4 > udp_data.len() {
        return None;
    }
    let query_type = u16::from_be_bytes([udp_data[pos], udp_data[pos + 1]]);

    Some(DnsQuery {
        transaction_id,
        domain,
        query_type,
        raw_question: udp_data[12..pos + 4].to_vec(),
    })
}

/// Builds a complete IP+UDP+DNS packet-response (swapping src/dst from the original query).
pub fn build_dns_response(
    original_packet: &[u8],
    query: &DnsQuery,
    answer: Option<IpAddr>,
    ttl: u32,
    rcode: u8,
) -> Result<Vec<u8>> {
    let ip_hdr = crate::desync::parse_ip_header(original_packet)
        .ok_or_else(|| anyhow!("invalid original ip header"))?;

    let (src_ip, dst_ip) = match &ip_hdr {
        crate::desync::ParsedIpHeader::V4(v4) => (IpAddr::V4(v4.dst), IpAddr::V4(v4.src)),
        crate::desync::ParsedIpHeader::V6(v6) => (IpAddr::V6(v6.dst), IpAddr::V6(v6.src)),
    };

    let mut dns_response = Vec::new();
    dns_response.extend_from_slice(&query.transaction_id.to_be_bytes());
    let flags: u16 = 0x8000 | 0x0080 | (rcode as u16 & 0x0F); // QR=1, RA=1, RCODE
    dns_response.extend_from_slice(&flags.to_be_bytes());
    dns_response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    dns_response.extend_from_slice(&(if answer.is_some() { 1u16 } else { 0u16 }).to_be_bytes()); // ANCOUNT
    dns_response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    dns_response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    dns_response.extend_from_slice(&query.raw_question);

    if let Some(ip) = answer {
        dns_response.extend_from_slice(&[0xC0, 0x0C]); // Pointer to QNAME at offset 12
        dns_response.extend_from_slice(&query.query_type.to_be_bytes());
        dns_response.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN (0x0001)
        dns_response.extend_from_slice(&ttl.to_be_bytes());
        match ip {
            IpAddr::V4(v4) => {
                dns_response.extend_from_slice(&4u16.to_be_bytes());
                dns_response.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                dns_response.extend_from_slice(&16u16.to_be_bytes());
                dns_response.extend_from_slice(&v6.octets());
            }
        }
    }

    let udp_start = ip_hdr.header_len();
    let orig_src_port =
        u16::from_be_bytes([original_packet[udp_start], original_packet[udp_start + 1]]);
    let orig_dst_port = u16::from_be_bytes([
        original_packet[udp_start + 2],
        original_packet[udp_start + 3],
    ]);
    let (resp_src_port, resp_dst_port) = (orig_dst_port, orig_src_port);

    let udp_len = 8 + dns_response.len();
    let mut udp_packet = Vec::with_capacity(udp_len);
    udp_packet.extend_from_slice(&resp_src_port.to_be_bytes());
    udp_packet.extend_from_slice(&resp_dst_port.to_be_bytes());
    udp_packet.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp_packet.extend_from_slice(&[0, 0]); // Checksum placeholder
    udp_packet.extend_from_slice(&dns_response);

    // Calculate UDP checksum for IPv6 or IPv4
    let checksum = match (src_ip, dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let pkt = pnet_packet::udp::UdpPacket::new(&udp_packet).unwrap();
            pnet_packet::udp::ipv4_checksum(&pkt, &s, &d)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let pkt = pnet_packet::udp::UdpPacket::new(&udp_packet).unwrap();
            pnet_packet::udp::ipv6_checksum(&pkt, &s, &d)
        }
        _ => 0,
    };
    udp_packet[6] = (checksum >> 8) as u8;
    udp_packet[7] = (checksum & 0xFF) as u8;

    let res_bytes = crate::desync::build_ip_packet(
        src_ip,
        dst_ip,
        pnet_packet::ip::IpNextHeaderProtocols::Udp,
        64,
        0,
        &udp_packet,
    );

    Ok(res_bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_dns_query_basic() {
        // Construct a mock UDP DNS query packet for "netflix.com"
        // IPv4 Header (20 bytes)
        let mut ip_hdr = [0u8; 20];
        ip_hdr[0] = 0x45; // Version 4, IHL 5
        ip_hdr[9] = 17; // Protocol UDP
        ip_hdr[12..16].copy_from_slice(&[192, 168, 1, 100]); // Src IP
        ip_hdr[16..20].copy_from_slice(&[8, 8, 8, 8]); // Dst IP

        // UDP Header (8 bytes)
        let mut udp_hdr = [0u8; 8];
        udp_hdr[0..2].copy_from_slice(&5353u16.to_be_bytes()); // Src Port
        udp_hdr[2..4].copy_from_slice(&53u16.to_be_bytes()); // Dst Port

        // DNS Query Header (12 bytes)
        let mut dns_hdr = [0u8; 12];
        dns_hdr[0..2].copy_from_slice(&0x1234u16.to_be_bytes()); // Tx ID
        dns_hdr[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1

        // DNS Question: "netflix.com" (7netflix3com0) type A (1) class IN (1)
        let qname = b"\x07netflix\x03com\x00\x00\x01\x00\x01";

        let mut pkt = Vec::new();
        pkt.extend_from_slice(&ip_hdr);
        pkt.extend_from_slice(&udp_hdr);
        pkt.extend_from_slice(&dns_hdr);
        pkt.extend_from_slice(qname);

        // Adjust lengths
        let total_len = pkt.len() as u16;
        pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
        let udp_len = (pkt.len() - 20) as u16;
        pkt[24..26].copy_from_slice(&udp_len.to_be_bytes());

        let query = parse_dns_query(&pkt).unwrap();
        assert_eq!(query.transaction_id, 0x1234);
        assert_eq!(query.domain, "netflix.com");
        assert_eq!(query.query_type, 1);
    }
}
