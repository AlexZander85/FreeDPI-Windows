//! IP-level Desync техники.
//!
//! ## Техники
//! - [W1] FragOverlap — IP fragmentation overlap с SNI overwrite
//! - [Z14] BadChecksum — инъекция пакета с неверной контрольной суммой
//! - [19] TtlManipulation — манипуляция TTL (fixed per-connection)
//! - [Z15] IpFragPrimitives — примитивы IP фрагментации
//! - [OF4] RstDropIpId — дроп RST с низким IP ID
//! - [CT4] DscpRandom — случайная DSCP метка per-connection
//!
//! ## Источник
//! Адаптировано из [dpibreak](https://github.com/hufrea/dpibreak) и
//! [zapret](https://github.com/bol-van/zapret).

use crate::adaptive::ch_gen;
use crate::desync::{ipv4_checksum, parse_ip_header, DesyncResult};
use pnet_packet::ip::IpNextHeaderProtocol;
use pnet_packet::ipv4::MutableIpv4Packet;
use pnet_packet::MutablePacket;
use std::net::Ipv4Addr;
use tracing::debug;

/// [W1] FragOverlap: IP fragmentation с перекрытием и SNI overwrite.
///
/// ## Принцип
/// Два IP фрагмента с одним identification, перекрывающиеся по offset.
/// Frag1 = fake ClientHello с fake SNI (TTL-1).
/// Frag2 = оригинальный payload начиная с реального SNI (normal TTL).
/// DPI собирает из Frag1 (видит fake SNI). Сервер собирает из Frag2
/// (offset больше → перезаписывает → видит real SNI).
///
/// ## Returns
/// - inject: [frag1, frag2] — два фрагмента
pub fn frag_overlap(packet: &[u8], fake_sni: &str, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let payload = &packet[ip.header_len..];
    if payload.is_empty() {
        return DesyncResult::passthrough();
    }

    // Fake CH с fake SNI — это Frag1 payload
    let fake_payload = ch_gen::build_client_hello_default(fake_sni);
    let frag1_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
    let frag_id = ip.identification;

    let frag1 = build_ip_fragment(
        ip.src,
        ip.dst,
        ip.protocol,
        frag_id,
        0,
        true,
        frag1_ttl,
        &fake_payload,
    );

    // Найти позицию реального SNI в оригинальном payload
    let sni_offset_in_payload = crate::desync::tls::find_sni_offset_in_ch(payload);

    // Вычислить offset для Frag2: 8-byte aligned, ближайший к SNI
    let overlap_offset = if let Some(sni_pos) = sni_offset_in_payload {
        // SNI найден — align к 8-byte boundary, ближайший к позиции SNI
        (sni_pos + 7) & !7 // round up to next 8-byte boundary
    } else {
        // Fallback: offset = TCP header length (20 bytes = 160 bits / 8 = 20 units)
        let tcp_start = ip.header_len;
        let tcp_header_len = if packet.len() > tcp_start + 12 {
            ((packet[tcp_start + 12] >> 4) & 0xF) as usize * 4
        } else {
            20
        };
        (tcp_header_len + 7) & !7
    };
    let frag2_offset_units = (overlap_offset / 8) as u16;

    // Frag2: оригинальный payload, начиная с overlap_offset
    let frag2_payload = if overlap_offset < payload.len() {
        &payload[overlap_offset..]
    } else {
        // offset за пределами payload — берём весь payload
        payload
    };

    let frag2 = build_ip_fragment(
        ip.src,
        ip.dst,
        ip.protocol,
        frag_id,
        frag2_offset_units,
        false,
        ip.ttl,
        frag2_payload,
    );

    debug!(
        "[W1] FragOverlap: fake SNI='{}' overlap_offset={} frag2_units={}",
        fake_sni, overlap_offset, frag2_offset_units
    );

    DesyncResult::inject_many(vec![frag1, frag2])
}

/// [Z14] BadChecksum: инъекция пакета с неверной контрольной суммой.
///
/// ## Принцип
/// DPI проверяет целостность пакета по IP/TCP checksum.
/// Пакет с неверным checksum отбрасывается DPI и не инспектируется.
/// Сервер обычно принимает (некоторые ОС игнорируют checksum).
///
/// ## Returns
/// - inject: [badsum_packet] — копия с неверным IP и TCP checksum
/// - modified: None (оригинал проходит без изменений)
pub fn bad_checksum(packet: &[u8]) -> DesyncResult {
    if packet.len() < 20 {
        return DesyncResult::passthrough();
    }

    let mut badsum = packet.to_vec();

    // IP checksum
    let old_ip_csum = u16::from_be_bytes([badsum[10], badsum[11]]);
    let ip_delta = crate::desync::rand::random_range(1, 65535) as u16;
    let new_ip_csum = old_ip_csum.wrapping_add(ip_delta);
    badsum[10..12].copy_from_slice(&new_ip_csum.to_be_bytes());

    // TCP checksum (если есть)
    let ip = parse_ip_header(packet);
    if let Some(h) = ip {
        let tcp_csum_offset = h.header_len + 16;
        if tcp_csum_offset + 2 <= badsum.len() {
            let old_tcp_csum =
                u16::from_be_bytes([badsum[tcp_csum_offset], badsum[tcp_csum_offset + 1]]);
            let tcp_delta = crate::desync::rand::random_range(1, 65535) as u16;
            let new_tcp_csum = old_tcp_csum.wrapping_add(tcp_delta);
            badsum[tcp_csum_offset..tcp_csum_offset + 2]
                .copy_from_slice(&new_tcp_csum.to_be_bytes());
        }
    }

    debug!("[Z14] BadChecksum: inject-only (original passes through)");

    DesyncResult::inject_only(badsum)
}

/// [19] TtlManipulation: манипуляция TTL (fixed per-connection).
///
/// ## Принцип
/// Устанавливаем фиксированный TTL в IP header. Per-packet variation —
/// anomaly для DPI fingerprinting, поэтому TTL фиксирован на всё соединение.
///
/// ## Стратегии
/// - TTL=64 (Linux default)
/// - TTL=128 (Windows default)
pub fn ttl_manipulation(packet: &[u8], new_ttl: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let mut modified = packet.to_vec();

    // TTL — байт 8 в IP header; протокол — байт 9.
    // RFC 1624: инкрементальное обновление checksum при изменении TTL.
    if 12 <= modified.len() {
        modified[8] = new_ttl;

        // TTL и Protocol образуют одно 16-битное слово в checksum
        let old_word = ((ip.ttl as u16) << 8) | (packet[9] as u16);
        let new_word = ((new_ttl as u16) << 8) | (packet[9] as u16);
        let old_csum = u16::from_be_bytes([packet[10], packet[11]]);
        let new_csum = crate::desync::update_checksum_word(old_csum, old_word, new_word);
        modified[10..12].copy_from_slice(&new_csum.to_be_bytes());
    }

    debug!("[19] TtlManipulation: TTL {} → {}", ip.ttl, new_ttl);

    DesyncResult::modified_only(modified)
}

/// [Z15] IpFragPrimitives: примитивы IP фрагментации.
///
/// ## Принцип
/// Разделяем TCP сегмент на несколько IP фрагментов. DPI может
/// не собрать фрагменты правильно, что приведёт к пропуску
/// DPI-инспекции.
pub fn ip_frag_primitives(packet: &[u8], frag_size: usize, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let payload = &packet[ip.header_len..];

    if payload.len() <= frag_size {
        return DesyncResult::passthrough();
    }

    let mut inject: Vec<bytes::Bytes> = Vec::new();
    let mut pos = 0;
    let frag_id = ip.identification.wrapping_add(1);

    while pos < payload.len() {
        let end = (pos + frag_size).min(payload.len());
        let frag_payload = &payload[pos..end];
        let is_last = end >= payload.len();

        let frag_ttl = if is_last {
            ip.ttl
        } else {
            ip.ttl.saturating_sub(fake_ttl_offset)
        };

        let frag = build_ip_fragment(
            ip.src,
            ip.dst,
            ip.protocol,
            frag_id,
            (pos / 8) as u16,
            !is_last,
            frag_ttl,
            frag_payload,
        );
        inject.push(frag);
        pos = end;
    }

    debug!(
        "[Z15] IpFragPrimitives: {} fragments × {} bytes max",
        inject.len(),
        frag_size
    );

    DesyncResult::inject_many(inject)
}

/// [OF4] RstDropIpId: дроп RST пакетов с IP ID ≤ 0x000F.
///
/// ## Принцип
/// DPI инжектирует RST-пакеты для разрыва соединения.
/// У таких пакетов IP ID обычно очень мал (≤ 15), так как они
/// генерируются автоматически без нормального счётчика.
pub fn rst_drop_ip_id(packet: &[u8]) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    if ip.identification > 0x000F {
        return DesyncResult::passthrough();
    }

    let tcp_data = &packet[ip.header_len..];
    let tcp = match pnet_packet::tcp::TcpPacket::new(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    let flags = tcp.get_flags();
    let is_rst = (flags & 0x04) != 0;

    if !is_rst {
        return DesyncResult::passthrough();
    }

    debug!(
        "[OF4] RstDropIpId: dropping RST with IP ID={} (≤15)",
        ip.identification
    );

    DesyncResult::drop_packet()
}

/// [CT4] DscpRandom: случайная DSCP метка per-connection.
///
/// ## Принцип
/// DPI анализирует DSCP для классификации трафика.
/// Случайная DSCP метка сбивает классификацию.
/// DSCP постоянный per-connection (не per-packet) — иначе anomaly.
///
/// Использует инкрементальный checksum (RFC 1624: HC' = ~(~HC + ~m + m')).
pub fn dscp_random(packet: &[u8], dscp_value: u8) -> DesyncResult {
    let _ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let current_dscp = (packet[1] >> 2) & 0x3F;
    let new_dscp = dscp_value & 0x3F;

    if new_dscp == current_dscp {
        return DesyncResult::passthrough();
    }

    let mut modified = packet.to_vec();
    let ecn = modified[1] & 0x03;
    modified[1] = (new_dscp << 2) | ecn;

    // Инкрементальный checksum: RFC 1624
    // HC' = ~(~HC + ~m + m')
    let old_byte = ((current_dscp << 2) | ecn) as u32;
    let new_byte = ((new_dscp << 2) | ecn) as u32;
    let old_csum = u32::from(u16::from_be_bytes([modified[10], modified[11]]));
    let mut sum = (!old_csum & 0xFFFF)
        .wrapping_add(!old_byte & 0xFFFF)
        .wrapping_add(new_byte);
    // Fold carries
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF).wrapping_add(sum >> 16);
    }
    let new_csum = !(sum as u16);
    modified[10..12].copy_from_slice(&new_csum.to_be_bytes());

    debug!("[CT4] DscpRandom: DSCP {} → {}", current_dscp, new_dscp);
    DesyncResult::modified_only(modified)
}

/// [CT1] MutualSpoof: удалён — пакет уходил обратно к клиенту.
pub fn mutual_spoof(_packet: &[u8]) -> DesyncResult {
    tracing::warn!("MutualSpoof is removed — technique was broken by design (src=dst swap sends packet back to client)");
    DesyncResult::passthrough()
}

// ==================== Вспомогательные функции ====================

/// Строит IP фрагмент.
#[allow(clippy::too_many_arguments)]
fn build_ip_fragment(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: IpNextHeaderProtocol,
    identification: u16,
    fragment_offset: u16,
    more_fragments: bool,
    ttl: u8,
    payload: &[u8],
) -> bytes::Bytes {
    let total_len = 20 + payload.len();
    let mut buf = bytes::BytesMut::with_capacity(total_len);
    buf.resize(total_len, 0);

    {
        let mut ip = MutableIpv4Packet::new(&mut buf).unwrap();

        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(total_len as u16);
        ip.set_identification(identification);

        let flags: u8 = if more_fragments { 1 } else { 0 };
        ip.set_flags(flags);
        ip.set_fragment_offset(fragment_offset);

        ip.set_ttl(ttl);
        ip.set_next_level_protocol(protocol);
        ip.set_source(src);
        ip.set_destination(dst);

        ip.payload_mut().copy_from_slice(payload);
    }

    let checksum = ipv4_checksum(&buf[..20]);
    buf[10..12].copy_from_slice(&checksum.to_be_bytes());
    buf.freeze()
}
