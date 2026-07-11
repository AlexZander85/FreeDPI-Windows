use freedpi_core::classifier::{Classification, Classifier};
use freedpi_core::packet_invariants::{validate_before_send, ValidationMode};
use freedpi_core::test_support::pcap::{network_packet, read_pcap, LinkType};
use std::fs::File;
use std::io::Write;

fn generate_synthetic_pcap() -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().unwrap();
    let mut writer = File::create(file.path()).unwrap();

    // 1. PCAP Global Header (24 bytes, Big Endian)
    // Magic: 0xa1b2c3d4
    // Major: 2, Minor: 4
    // Snaplen: 65535
    // Network: 101 (Raw IP)
    let global_header = [
        0xa1, 0xb2, 0xc3, 0xd4, // magic
        0x00, 0x02, // major
        0x00, 0x04, // minor
        0x00, 0x00, 0x00, 0x00, // gmt to local correction
        0x00, 0x00, 0x00, 0x00, // accuracy of timestamps
        0x00, 0x00, 0xff, 0xff, // snaplen
        0x00, 0x00, 0x00, 0x65, // network (101 = LinkType::RawIp)
    ];
    writer.write_all(&global_header).unwrap();

    // 2. Add an IPv4 TCP Packet (Total Length = 40 bytes)
    let mut ip_tcp_packet = vec![0u8; 40];
    ip_tcp_packet[0] = 0x45; // Version 4, IHL 5
    ip_tcp_packet[2] = 0x00;
    ip_tcp_packet[3] = 0x28; // Total Length 40
    ip_tcp_packet[9] = 6; // Protocol TCP
                          // Checksum placeholder
    let csum = freedpi_core::desync::ipv4_checksum(&ip_tcp_packet[..20]);
    ip_tcp_packet[10] = (csum >> 8) as u8;
    ip_tcp_packet[11] = (csum & 0xff) as u8;
    // TCP Header data offset = 5 (20 bytes)
    ip_tcp_packet[20 + 12] = 0x50;

    let len_be = (ip_tcp_packet.len() as u32).to_be_bytes();
    let pcap_pkt_hdr = [
        0x00, 0x00, 0x00, 0x00, // ts_sec
        0x00, 0x00, 0x00, 0x00, // ts_usec
        len_be[0], len_be[1], len_be[2], len_be[3], // incl_len
        len_be[0], len_be[1], len_be[2], len_be[3], // orig_len
    ];
    writer.write_all(&pcap_pkt_hdr).unwrap();
    writer.write_all(&ip_tcp_packet).unwrap();

    file
}

#[test]
fn test_synthetic_pcap_replay_runs_correctly() {
    let pcap_temp = generate_synthetic_pcap();
    let pcap = read_pcap(pcap_temp.path()).expect("Should parse synthetic pcap file");

    assert_eq!(pcap.link_type, LinkType::RawIp);
    assert_eq!(pcap.packets.len(), 1);

    let pkt = &pcap.packets[0];
    let ip = network_packet(pcap.link_type, &pkt.data).expect("Should parse RawIp frame");

    let class = Classifier::classify(ip);
    assert!(matches!(class, Classification::Other(_)));

    let val = validate_before_send(ip, ValidationMode::Strict);
    assert_eq!(val, Ok(()));
}
