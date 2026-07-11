#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketInvalidReason {
    TooShort,
    UnsupportedIpVersion(u8),
    Ipv4HeaderTooShort,
    Ipv4TotalLengthMismatch,
    Ipv4BadHeaderChecksum,
    Ipv6PayloadLengthMismatch,
    TcpHeaderTooShort,
    UdpHeaderTooShort,
    UdpLengthMismatch,
    QuicInitialTooSmall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationMode {
    Fast,
    Strict,
}

pub fn validate_before_send(
    packet: &[u8],
    mode: ValidationMode,
) -> Result<(), PacketInvalidReason> {
    let Some(first) = packet.first().copied() else {
        return Err(PacketInvalidReason::TooShort);
    };

    match first >> 4 {
        4 => validate_ipv4(packet, mode),
        6 => validate_ipv6(packet),
        v => Err(PacketInvalidReason::UnsupportedIpVersion(v)),
    }
}

fn validate_ipv4(packet: &[u8], mode: ValidationMode) -> Result<(), PacketInvalidReason> {
    if packet.len() < 20 {
        return Err(PacketInvalidReason::TooShort);
    }

    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return Err(PacketInvalidReason::Ipv4HeaderTooShort);
    }

    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len != packet.len() {
        return Err(PacketInvalidReason::Ipv4TotalLengthMismatch);
    }

    if matches!(mode, ValidationMode::Strict) {
        let mut header = packet[..ihl].to_vec();
        header[10] = 0;
        header[11] = 0;
        let expected = crate::desync::ipv4_checksum(&header);
        let actual = u16::from_be_bytes([packet[10], packet[11]]);
        if expected != actual {
            return Err(PacketInvalidReason::Ipv4BadHeaderChecksum);
        }
    }

    if ihl < packet.len() {
        match packet[9] {
            6 => validate_tcp(packet, ihl),
            17 => validate_udp(packet, ihl),
            _ => Ok(()),
        }
    } else {
        Ok(())
    }
}

fn validate_ipv6(packet: &[u8]) -> Result<(), PacketInvalidReason> {
    if packet.len() < 40 {
        return Err(PacketInvalidReason::TooShort);
    }

    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    if payload_len + 40 > packet.len() {
        return Err(PacketInvalidReason::Ipv6PayloadLengthMismatch);
    }

    // В IPv6 Next Header находится на 6-м байте
    let next_header = packet[6];
    if next_header == 6 {
        validate_tcp(packet, 40)?;
    } else if next_header == 17 {
        validate_udp(packet, 40)?;
    }

    Ok(())
}

fn validate_tcp(packet: &[u8], tcp_off: usize) -> Result<(), PacketInvalidReason> {
    if packet.len() < tcp_off + 20 {
        return Err(PacketInvalidReason::TcpHeaderTooShort);
    }

    let data_offset = ((packet[tcp_off + 12] >> 4) as usize) * 4;
    if data_offset < 20 || packet.len() < tcp_off + data_offset {
        return Err(PacketInvalidReason::TcpHeaderTooShort);
    }

    Ok(())
}

fn validate_udp(packet: &[u8], udp_off: usize) -> Result<(), PacketInvalidReason> {
    if packet.len() < udp_off + 8 {
        return Err(PacketInvalidReason::UdpHeaderTooShort);
    }

    let udp_len = u16::from_be_bytes([packet[udp_off + 4], packet[udp_off + 5]]) as usize;
    if udp_len < 8 || udp_off + udp_len > packet.len() {
        return Err(PacketInvalidReason::UdpLengthMismatch);
    }

    let dst_port = u16::from_be_bytes([packet[udp_off + 2], packet[udp_off + 3]]);
    if dst_port == 443 {
        let payload = &packet[udp_off + 8..udp_off + udp_len];
        if is_quic_initial(payload) && payload.len() < 1200 {
            return Err(PacketInvalidReason::QuicInitialTooSmall);
        }
    }

    Ok(())
}

fn is_quic_initial(payload: &[u8]) -> bool {
    payload.len() >= 6
        && (payload[0] & 0x80) != 0
        && (payload[0] & 0x40) != 0
        && (payload[0] & 0x30) == 0x00
        && payload[1..5] != [0, 0, 0, 0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_checksum_and_length_validation() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45; // Version 4, IHL 5 (20 bytes)
                       // Total Length = 40 bytes
        pkt[2] = 0x00;
        pkt[3] = 0x28;
        pkt[9] = 6; // TCP

        // TCP header
        pkt[20 + 12] = 0x50; // data offset = 5 (20 bytes)

        // Calculate valid checksum
        pkt[10] = 0;
        pkt[11] = 0;
        let csum = crate::desync::ipv4_checksum(&pkt[..20]);
        pkt[10] = (csum >> 8) as u8;
        pkt[11] = (csum & 0xff) as u8;

        // Fast validation (no checksum) should pass
        assert_eq!(validate_before_send(&pkt, ValidationMode::Fast), Ok(()));
        // Strict validation (checksum included) should pass
        assert_eq!(validate_before_send(&pkt, ValidationMode::Strict), Ok(()));

        // Corrupt checksum
        pkt[10] ^= 0xff;
        assert_eq!(validate_before_send(&pkt, ValidationMode::Fast), Ok(()));
        assert_eq!(
            validate_before_send(&pkt, ValidationMode::Strict),
            Err(PacketInvalidReason::Ipv4BadHeaderChecksum)
        );

        // Corrupt total length
        pkt[3] = 0x20;
        assert_eq!(
            validate_before_send(&pkt, ValidationMode::Fast),
            Err(PacketInvalidReason::Ipv4TotalLengthMismatch)
        );
    }

    #[test]
    fn test_quic_initial_size_limit() {
        let mut pkt = vec![0u8; 48];
        pkt[0] = 0x45;
        pkt[2] = 0x00;
        pkt[3] = 0x30; // Total length 48
        pkt[9] = 17; // UDP

        // UDP header
        pkt[20 + 2] = 0x01; // dst port 443 (0x01bb)
        pkt[20 + 3] = 0xbb;
        pkt[20 + 4] = 0x00;
        pkt[20 + 5] = 28; // UDP length 28 (header 8 + payload 20)

        // UDP payload (QUIC Initial packet signature)
        pkt[28] = 0xc0; // Long header + Initial type
        pkt[29] = 0x01; // Version
        pkt[30] = 0x02;
        pkt[31] = 0x03;
        pkt[32] = 0x04;

        // QUIC Initial is smaller than 1200 -> error
        assert_eq!(
            validate_before_send(&pkt, ValidationMode::Fast),
            Err(PacketInvalidReason::QuicInitialTooSmall)
        );
    }
}
