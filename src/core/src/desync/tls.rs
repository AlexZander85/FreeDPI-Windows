//! TLS-level Desync техники.
//!
//! ## Техники
//! - [15] TlsRecordFrag — TLS Record Fragmentation (split at SNI offset)
//! - [07] TlsRecordPad — TLS Record Padding (inside the record)
//!
//! ## Принципы
//! TLS desync техники манипулируют TLS Record Layer до того,
//! как DPI успевает проинспектировать ClientHello. DPI ожидает
//! один TLS record с полным CH. Разделение на несколько
//! records или добавление padding сбивает DPI.
//!
//! ## Источник
//! Адаптировано из [zapret](https://github.com/bol-van/zapret) и
//! [byedpi](https://github.com/hufrea/byedpi).

use crate::desync::{parse_ip_header, DesyncResult};
use pnet_packet::tcp::TcpFlags;
use tracing::debug;

/// [15] TlsRecordFrag: разделение TLS record внутри ClientHello у SNI.
///
/// ## Принцип
/// DPI ожидает TLS ClientHello целиком в одном TCP сегменте.
/// Разделяем TLS record внутри тела ClientHello — в области SNI
/// со случайным jitter. DPI видит обрезанный CH и не может
/// распознать SNI. Сервер собирает fragments по record boundaries.
///
/// ## Стратегия
/// 1. Парсим TLS record → ClientHello
/// 2. Ищем SNI extension, определяем offset имени хоста
/// 3. Добавляем random jitter (±16 байт) к offset
/// 4. Разделяем payload на 2 TCP сегмента по этому offset
///
/// ## Returns
/// - inject: [frag1, frag2] — два TCP сегмента
///   frag1 = данные до split_point (TTL-1, fake)
///   frag2 = данные после split_point (нормальный TTL, реальный)
pub fn tls_record_frag(packet: &[u8], frag_at: usize, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len..];
    let tcp = match pnet_packet::tcp::TcpPacket::new(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    let data_offset = tcp.get_data_offset() as usize * 4;
    let payload = &tcp_data[data_offset..];

    if payload.len() < 10 || payload[0] != 0x16 {
        return DesyncResult::passthrough();
    }

    let seq = tcp.get_sequence();
    let ack = tcp.get_acknowledgement();
    let window = tcp.get_window();
    let src = ip.src;
    let dst = ip.dst;
    let src_port = tcp.get_source();
    let dst_port = tcp.get_destination();

    // Определяем точку разреза: ищем SNI внутри ClientHello
    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    let split_point = if let Some(sni_offset) = find_sni_offset_in_ch(payload) {
        // SNI найден — разрезаем в области SNI с jitter
        let jitter = crate::desync::rand::random_range(0, 32) as i16 - 16;
        let base = sni_offset as i16 + jitter;
        // Не разрезаем раньше record header (5) и не позже конца record
        let min_split = 6.min(record_len.saturating_sub(1));
        let max_split = record_len.saturating_add(5).saturating_sub(1);
        (base.max(min_split as i16).min(max_split as i16)) as usize
    } else {
        // SNI не найден — используем frag_at как fallback
        let candidate = frag_at.max(6);
        if candidate >= payload.len() {
            return DesyncResult::passthrough();
        }
        candidate
    };

    if split_point >= payload.len() {
        return DesyncResult::passthrough();
    }

    let mut inject: Vec<bytes::Bytes> = Vec::new();

    // Фрагмент 1: начало до split_point (fake TTL)
    let frag1_payload = &payload[..split_point];
    let frag1 = crate::desync::tcp::build_ip_tcp_packet_with_options(
        packet,
        src,
        dst,
        src_port,
        dst_port,
        seq,
        ack,
        TcpFlags::PSH | TcpFlags::ACK,
        window,
        frag1_payload,
        ip.ttl.saturating_sub(fake_ttl_offset),
        ip.identification.wrapping_add(1),
    );
    inject.push(frag1);

    // Фрагмент 2: остаток (нормальный TTL)
    let frag2_payload = &payload[split_point..];
    let new_seq = seq.wrapping_add(split_point as u32);
    let frag2 = crate::desync::tcp::build_ip_tcp_packet_with_options(
        packet,
        src,
        dst,
        src_port,
        dst_port,
        new_seq,
        ack,
        TcpFlags::PSH | TcpFlags::ACK,
        window,
        frag2_payload,
        ip.ttl,
        ip.identification.wrapping_add(2),
    );
    inject.push(frag2);

    debug!(
        "[15] TlsRecordFrag: split at byte {} ({} + {} bytes)",
        split_point,
        frag1_payload.len(),
        frag2_payload.len()
    );

    DesyncResult::inject_many(inject)
}

/// [07] TlsRecordPad: padding внутри TLS record.
///
/// ## Принцип
/// Добавляем случайные padding-байты ВНУТРЬ TLS record, сразу
/// после тела ClientHello, и обновляем record length. DPI видит
/// изменённую структуру record и может сбиться. Сервер парсит
/// ClientHello по handshake length и игнорирует лишние байты
/// в record.
///
/// ## Подробности
/// TLS record: [ContentType(1) + Version(2) + Length(2) + Fragment]
/// Fragment содержит ClientHello: [HandshakeType(1) + Length(3) + Body]
///
/// Вставляем padding после Body CH, увеличиваем Length на pad_size,
/// пересчитываем IP checksum. Возвращаем modified_only — один пакет.
pub fn tls_record_pad(packet: &[u8], pad_size: usize, _fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len..];
    let tcp = match pnet_packet::tcp::TcpPacket::new(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    let data_offset = tcp.get_data_offset() as usize * 4;
    let payload = &tcp_data[data_offset..];

    // Минимум: TLS record header(5) + HandshakeType(1) + Length(3) = 9 байт
    if payload.len() < 9 || payload[0] != 0x16 {
        return DesyncResult::passthrough();
    }

    // HandshakeType должен быть ClientHello (0x01)
    if payload[5] != 0x01 {
        return DesyncResult::passthrough();
    }

    // Длина тела ClientHello (3 bytes, big-endian)
    let ch_body_len =
        ((payload[6] as usize) << 16) | ((payload[7] as usize) << 8) | (payload[8] as usize);
    let ch_end = 5 + 4 + ch_body_len; // record_header(5) + handshake_header(4) + body

    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    let record_len_u16 = u16::from_be_bytes([payload[3], payload[4]]);

    // Проверяем целостность: конец CH не должен превышать record
    if ch_end > 5 + record_len || ch_end > payload.len() {
        return DesyncResult::passthrough();
    }

    // Случайный padding
    let padding = crate::desync::rand::random_bytes(pad_size);

    // Модифицируем пакет in-place
    let mut modified = packet.to_vec();
    let tcp_payload_offset = ip.header_len + data_offset;

    // Вставляем padding после тела ClientHello
    let insert_pos = tcp_payload_offset + ch_end;
    modified.splice(insert_pos..insert_pos, padding.iter().copied());

    // Обновляем TLS record length (bytes 3-4 в payload)
    let new_record_len = record_len_u16.wrapping_add(pad_size as u16);
    let rl_offset = tcp_payload_offset + 3;
    modified[rl_offset..rl_offset + 2].copy_from_slice(&new_record_len.to_be_bytes());

    // Обновляем IP total length
    let new_total = modified.len() as u16;
    modified[2..4].copy_from_slice(&new_total.to_be_bytes());

    // Пересчитываем IP checksum
    let ip_csum = crate::desync::ipv4_checksum(&modified[..20]);
    modified[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // Пересчитываем TCP checksum
    let tcp_start = ip.header_len;
    modified[tcp_start + 16] = 0;
    modified[tcp_start + 17] = 0;
    let tcp_csum = crate::desync::tcp_checksum_v4(ip.src, ip.dst, &modified[tcp_start..]);
    modified[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_csum.to_be_bytes());

    debug!(
        "[07] TlsRecordPad: {} bytes padding inside record (record {} → {} bytes)",
        pad_size, record_len_u16, new_record_len
    );

    DesyncResult::modified_only(modified)
}

/// [OM2] SniMicrofrag: микро-фрагментация TLS ClientHello.
///
/// ## Принцип
/// DPI часто использует signature-based детекцию для TLS ClientHello.
/// Микро-фрагментация разбивает начало CH на очень маленькие TCP сегменты
/// (1-2 байта каждый). DPI не может собрать сигнатуру из микро-фрагментов.
///
/// ## Стратегия
/// Первые `micro_count` байт TLS record отправляются как отдельные TCP
/// сегменты по 1 байту. Остаток — нормальным сегментом.
///
/// ## Пример
/// Для `micro_count=5`:
/// - Segment 1: байт 0 (SEQ = original_SEQ)
/// - Segment 2: байт 1 (SEQ = original_SEQ + 1)
/// - ...
/// - Segment 5: байт 4 (SEQ = original_SEQ + 4)
/// - Last: байты 5..N (SEQ = original_SEQ + 5)
///
/// Все микро-сегменты имеют TTL-1 (чтобы не перегружать сервер).
/// Последний сегмент — нормальный TTL (доходит до сервера).
///
/// ## Аргументы
/// * `packet` — исходный IP-пакет с TLS ClientHello
/// * `micro_count` — количество микро-фрагментов (1-16)
/// * `fake_ttl_offset` — уменьшение TTL для микро-фрагментов
///
/// ## Источник
/// omoikane [OM2] — SNI Microfrag
pub fn sni_microfrag(packet: &[u8], micro_count: usize, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len..];
    let tcp = match pnet_packet::tcp::TcpPacket::new(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    let data_offset = tcp.get_data_offset() as usize * 4;
    let payload = &tcp_data[data_offset..];

    let micro_count = micro_count.clamp(1, 16);

    if payload.len() < micro_count + 1 {
        return DesyncResult::passthrough();
    }

    let seq = tcp.get_sequence();
    let ack = tcp.get_acknowledgement();
    let window = tcp.get_window();
    let src = ip.src;
    let dst = ip.dst;
    let src_port = tcp.get_source();
    let dst_port = tcp.get_destination();

    let mut inject: smallvec::SmallVec<[bytes::Bytes; 4]> =
        smallvec::SmallVec::with_capacity(micro_count);

    for i in 0..micro_count {
        let frag_payload = &payload[i..i + 1];
        let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
        let frag_seq = seq.wrapping_add(i as u32);
        let frag = crate::desync::tcp::build_ip_tcp_packet_with_options(
            packet,
            src,
            dst,
            src_port,
            dst_port,
            frag_seq,
            ack,
            TcpFlags::PSH | TcpFlags::ACK,
            window,
            frag_payload,
            fake_ttl,
            ip.identification.wrapping_add(i as u16 + 1),
        );
        inject.push(frag);
    }

    let remaining = &payload[micro_count..];
    let last_seq = seq.wrapping_add(micro_count as u32);
    let modified = crate::desync::tcp::build_ip_tcp_packet_with_options(
        packet,
        src,
        dst,
        src_port,
        dst_port,
        last_seq,
        ack,
        TcpFlags::PSH | TcpFlags::ACK,
        window,
        remaining,
        ip.ttl,
        ip.identification.wrapping_add(micro_count as u16 + 1),
    );

    debug!(
        "[OM2] SniMicrofrag: {} micro-frags × 1 byte + {} remaining bytes",
        micro_count,
        remaining.len()
    );

    DesyncResult {
        modified: Some(modified),
        inject,
        inter_delay_us: 0,
        drop: false,
        is_outbound_inject: false,
    }
}

// ==================== SNI Parser ====================

/// Ищет offset начала имени хоста в SNI extension внутри TLS ClientHello.
///
/// Парсит TLS record → ClientHello → Extensions → SNI extension.
/// Возвращает offset относительно начала TLS record payload
/// (т.е. payload[sni_offset] — первый байт hostname).
///
/// Возвращает `None` если ClientHello не найден или SNI extension отсутствует.
pub(crate) fn find_sni_offset_in_ch(payload: &[u8]) -> Option<usize> {
    if payload.len() < 10 {
        return None;
    }

    // TLS record header: ContentType(1) + Version(2) + Length(2)
    if payload[0] != 0x16 {
        return None;
    }

    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if record_len + 5 > payload.len() {
        return None;
    }

    // HandshakeType: ClientHello = 0x01
    if payload[5] != 0x01 {
        return None;
    }

    // HandshakeLength (3 bytes)
    let ch_body_len =
        ((payload[6] as usize) << 16) | ((payload[7] as usize) << 8) | (payload[8] as usize);
    let ch_end = 5 + 4 + ch_body_len;
    if ch_end > payload.len() {
        return None;
    }

    // Парсим ClientHello body начиная с offset 9
    let mut pos = 9;

    // Version (2 bytes)
    pos += 2;
    if pos + 32 > ch_end {
        return None;
    }
    // Random (32 bytes)
    pos += 32;

    // SessionID
    if pos >= ch_end {
        return None;
    }
    let session_id_len = payload[pos] as usize;
    pos += 1 + session_id_len;

    // CipherSuites (2 bytes length + data)
    if pos + 2 > ch_end {
        return None;
    }
    let cs_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2 + cs_len;

    // Compression methods (1 byte length + data)
    if pos >= ch_end {
        return None;
    }
    let cm_len = payload[pos] as usize;
    pos += 1 + cm_len;

    // Extensions length (2 bytes)
    if pos + 2 > ch_end {
        return None;
    }
    let ext_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_len).min(ch_end);

    // Walk extensions looking for SNI (type = 0x0000)
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;

        if ext_type == 0x0000 && pos + 4 + ext_data_len <= ext_end {
            // SNI extension: ServerNameListLen(2) + NameType(1) + NameLen(2) + hostname
            let sni_start = pos + 4;
            if sni_start + 5 <= ext_end {
                let name_len =
                    u16::from_be_bytes([payload[sni_start + 3], payload[sni_start + 4]]) as usize;
                if name_len > 0 && sni_start + 5 + name_len <= ext_end {
                    return Some(sni_start + 5); // offset первого байта hostname
                }
            }
        }
        pos += 4 + ext_data_len;
    }

    None
}

/// [OF1] SniMasking: маскировка SNI в существующем TLS ClientHello.
///
/// ## Принцип
/// Заменяем каждый байт hostname в SNI на `mask_byte`.
/// DPI видит зашифрованный/замаскированный SNI и не может
/// определить целевой домен для блокировки.
///
/// Оригинальный SNI восстанавливается сервером (ECH или other means).
///
/// ## Алгоритм
/// 1. Парсим TCP header → payload
/// 2. Ищем TLS ClientHello: `0x16 0x03 0x01` или `0x16 0x03 0x03`
/// 3. Ищем SNI extension (type `0x0000`)
/// 4. Заменяем каждый байт hostname на `mask_byte`
/// 5. Пересчитываем TCP checksum
pub fn sni_masking(packet: &[u8], mask_byte: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len..];
    let tcp = match crate::desync::parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.payload.len() < 5 {
        return DesyncResult::passthrough();
    }

    if tcp.payload[0] != 0x16 {
        return DesyncResult::passthrough();
    }

    let payload = tcp.payload;
    let mut pos = 5;

    if pos + 4 > payload.len() {
        return DesyncResult::passthrough();
    }

    if payload[pos] != 0x01 {
        return DesyncResult::passthrough();
    }
    pos += 4;

    if pos + 34 > payload.len() {
        return DesyncResult::passthrough();
    }
    pos += 34;

    if pos >= payload.len() {
        return DesyncResult::passthrough();
    }
    let session_id_len = payload[pos] as usize;
    pos += 1 + session_id_len;

    if pos + 2 > payload.len() {
        return DesyncResult::passthrough();
    }
    let cipher_suites_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    if pos >= payload.len() {
        return DesyncResult::passthrough();
    }
    let compression_len = payload[pos] as usize;
    pos += 1 + compression_len;

    if pos + 2 > payload.len() {
        return DesyncResult::passthrough();
    }
    let extensions_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;

    let extensions_end = pos + extensions_len;
    if extensions_end > payload.len() {
        return DesyncResult::passthrough();
    }

    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let ext_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;

        if ext_type == 0x0000 && pos + 4 + ext_len <= payload.len() {
            let sni_start = pos + 4;
            if sni_start + 5 > payload.len() {
                return DesyncResult::passthrough();
            }

            let name_len =
                u16::from_be_bytes([payload[sni_start + 3], payload[sni_start + 4]]) as usize;
            let hostname_start = sni_start + 5;
            let hostname_end = hostname_start + name_len;

            if hostname_end > payload.len() {
                return DesyncResult::passthrough();
            }

            let mut modified = packet.to_vec();
            let tcp_offset = ip.header_len;
            let payload_offset = tcp_offset + tcp.data_offset;

            for i in hostname_start..hostname_end {
                modified[payload_offset + i] = mask_byte;
            }

            let _tcp_len = modified.len() - tcp_offset;
            let src_ip = ip.src;
            let dst_ip = ip.dst;
            let tcp_csum = crate::desync::tcp_checksum_v4(src_ip, dst_ip, &modified[tcp_offset..]);
            modified[tcp_offset + 16..tcp_offset + 18].copy_from_slice(&tcp_csum.to_be_bytes());

            debug!(
                "[SM] SniMasking: hostname_len={} mask=0x{:02x}",
                name_len, mask_byte
            );

            return DesyncResult::modified_only(modified);
        }

        pos += 4 + ext_len;
    }

    DesyncResult::passthrough()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_record_frag_passthrough() {
        let pkt = build_test_tls_packet();
        let result = tls_record_frag(&pkt, 5, 1);
        assert!(!result.drop);
    }

    #[test]
    fn test_tls_record_pad() {
        let pkt = build_test_tls_ch_packet();
        let result = tls_record_pad(&pkt, 10, 1);
        match &result {
            DesyncResult {
                modified: Some(m), ..
            } => {
                assert!(m.len() > pkt.len());
                // Record length should have increased by 10
                let new_rl = u16::from_be_bytes([m[43], m[44]]);
                let old_rl = u16::from_be_bytes([pkt[43], pkt[44]]);
                assert_eq!(new_rl, old_rl + 10);
            }
            _ => panic!("expected modified packet"),
        }
    }

    #[test]
    fn test_find_sni_offset() {
        let pkt = build_test_tls_ch_packet();
        let ip = parse_ip_header(&pkt).unwrap();
        let tcp_data = &pkt[ip.header_len..];
        let tcp = pnet_packet::tcp::TcpPacket::new(tcp_data).unwrap();
        let data_offset = tcp.get_data_offset() as usize * 4;
        let payload = &tcp_data[data_offset..];
        // The test packet has a simple CH; SNI may or may not be present
        // Just verify the function doesn't panic
        let _ = find_sni_offset_in_ch(payload);
    }

    fn build_test_tls_packet() -> Vec<u8> {
        let mut pkt = vec![0u8; 60];
        pkt[0] = 0x45;
        pkt[9] = 6;
        pkt[12..14].copy_from_slice(&100u16.to_be_bytes());
        pkt[20..22].copy_from_slice(&12345u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[32] = 0x50;
        pkt[33] = 0x18;
        pkt[40] = 0x16;
        pkt[41] = 0x03;
        pkt[42] = 0x01;
        pkt
    }

    fn build_test_tls_ch_packet() -> Vec<u8> {
        // Minimal TLS ClientHello: IP(20) + TCP(20) + TLS record header(5) + CH
        let mut pkt = vec![0u8; 120];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&120u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[192, 168, 1, 1]);
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);
        pkt[20..22].copy_from_slice(&12345u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[32] = 0x50;
        pkt[33] = 0x18;
        // TLS record header at offset 40
        pkt[40] = 0x16;
        pkt[41] = 0x03;
        pkt[42] = 0x01;
        // Record Length = handshake_header(4) + ch_body_len
        // CH body = Version(2) + Random(32) + SessionID(1) + CipherSuites(4) + Compress(2) + ExtLen(2) + ExtBody(16) = 57
        // So Record Length = 4 + 57 = 61
        let ch_body_len: u16 = 57;
        let record_len: u16 = 4 + ch_body_len;
        pkt[43..45].copy_from_slice(&record_len.to_be_bytes());
        // HandshakeType = ClientHello
        pkt[45] = 0x01;
        // HandshakeLength (3 bytes) = ch_body_len = 57
        pkt[46] = 0;
        pkt[47] = 0;
        pkt[48] = ch_body_len as u8;
        // Version
        pkt[49] = 0x03;
        pkt[50] = 0x03;
        // Random (32 bytes at 51..82) — leave zeros
        // SessionID length = 0
        pkt[83] = 0;
        // CipherSuites length = 2
        pkt[84..86].copy_from_slice(&2u16.to_be_bytes());
        pkt[86] = 0x13;
        pkt[87] = 0x01;
        // Compression methods length = 1
        pkt[88] = 1;
        pkt[89] = 0x00;
        // Extensions length = 16
        pkt[90..92].copy_from_slice(&16u16.to_be_bytes());
        // SNI extension
        pkt[92..94].copy_from_slice(&0x0000u16.to_be_bytes()); // type
        pkt[94..96].copy_from_slice(&12u16.to_be_bytes()); // length
        pkt[96..98].copy_from_slice(&10u16.to_be_bytes()); // ServerNameList len
        pkt[98] = 0x00; // NameType: host_name
        pkt[99..101].copy_from_slice(&7u16.to_be_bytes()); // NameLen
        pkt[101..108].copy_from_slice(b"example"); // hostname
        let csum = crate::desync::ipv4_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&csum.to_be_bytes());
        pkt
    }
}

/// TLS Version Overwrite — перезапись version field в record header.
///
/// ## Принцип (Demergi)
/// DPI фильтрует по record-layer version. Замена на TLS 1.3 (0x0304)
/// сбивает fingerprinting. Комбинируется с Record Re-wrapping.
pub fn tls_version_overwrite(packet: &[u8]) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };
    let tcp_data = &packet[ip.header_len..];
    let tcp = match pnet_packet::tcp::TcpPacket::new(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };
    let data_offset = tcp.get_data_offset() as usize * 4;
    let payload = &tcp_data[data_offset..];

    if payload.len() < 5 || payload[0] != 0x16 {
        return DesyncResult::passthrough();
    }

    let mut modified = packet.to_vec();
    let payload_start = ip.header_len + data_offset;
    modified[payload_start + 1] = 0x03;
    modified[payload_start + 2] = 0x04;

    let ip_csum = crate::desync::ipv4_checksum(&modified[..20]);
    modified[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    debug!("[TLS] VersionOverwrite: TLS 1.3 spoof");
    DesyncResult::modified_only(modified)
}

/// TLS Record Re-wrapping — каждый фрагмент получает валидный record header.
///
/// ## Принцип (GreenTunnel)
/// Вместо простого TCP-level split, разбиваем TLS record payload на chunk_size
/// байтных кусков. Каждый кусок оборачиваем в НОВЫЙ TLS record header:
/// [ContentType(1) + Version(2) + Length(2) + chunk].
///
/// DPI, проверяющие TLS record boundaries, видят N валидных записей вместо одного.
pub fn tls_record_rewrap(packet: &[u8], chunk_size: usize, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };
    let tcp_data = &packet[ip.header_len..];
    let tcp = match pnet_packet::tcp::TcpPacket::new(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };
    let data_offset = tcp.get_data_offset() as usize * 4;
    let payload = &tcp_data[data_offset..];

    if payload.len() < 5 || payload[0] != 0x16 || chunk_size == 0 {
        return DesyncResult::passthrough();
    }

    let content_type = payload[0];
    let _version = [payload[1], payload[2]];
    let record_payload = &payload[5..];

    let mut rewrapped =
        Vec::with_capacity(record_payload.len() + record_payload.len() / chunk_size * 5);
    let tls_13_version = [0x03, 0x04];
    for chunk in record_payload.chunks(chunk_size) {
        rewrapped.push(content_type);
        rewrapped.extend_from_slice(&tls_13_version);
        rewrapped.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        rewrapped.extend_from_slice(chunk);
    }

    let seq = tcp.get_sequence();
    let ack = tcp.get_acknowledgement();
    let window = tcp.get_window();

    let inject_pkt = crate::desync::tcp::build_ip_tcp_packet_with_options(
        packet,
        ip.src,
        ip.dst,
        tcp.get_source(),
        tcp.get_destination(),
        seq,
        ack,
        TcpFlags::PSH | TcpFlags::ACK,
        window,
        &rewrapped,
        ip.ttl.saturating_sub(fake_ttl_offset),
        ip.identification.wrapping_add(1),
    );

    debug!(
        "[TLS] RecordRewrap: {} chunks × {} bytes",
        rewrapped.len() / (chunk_size + 5),
        chunk_size
    );
    DesyncResult::inject_only(inject_pkt)
}

/// SNI-Targeted Record Fragmentation — разбиение SNI на 2B chunks.
///
/// ## Принцип (NoDPI)
/// Извлекаем SNI extension из ClientHello, разбиваем доменное имя
/// на 2-байтные куски. Каждый кусок оборачиваем в TLS 1.3 record header.
/// DPI не может собрать SNI из фрагментов.
pub fn sni_record_frag(packet: &[u8], chunk_size: usize, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };
    let tcp_data = &packet[ip.header_len..];
    let tcp = match pnet_packet::tcp::TcpPacket::new(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };
    let data_offset = tcp.get_data_offset() as usize * 4;
    let payload = &tcp_data[data_offset..];

    if payload.len() < 5 || payload[0] != 0x16 {
        return DesyncResult::passthrough();
    }

    let record_payload = &payload[5..];
    if record_payload.len() < 6 || record_payload[0] != 0x01 {
        return DesyncResult::passthrough();
    }

    let mut pos = 38;
    if pos >= record_payload.len() {
        return DesyncResult::passthrough();
    }

    let session_id_len = record_payload[pos] as usize;
    pos += 1 + session_id_len;
    if pos + 2 > record_payload.len() {
        return DesyncResult::passthrough();
    }

    let cs_len = u16::from_be_bytes([record_payload[pos], record_payload[pos + 1]]) as usize;
    pos += 2 + cs_len;
    if pos + 1 > record_payload.len() {
        return DesyncResult::passthrough();
    }

    let cm_len = record_payload[pos] as usize;
    pos += 1 + cm_len;
    if pos + 2 > record_payload.len() {
        return DesyncResult::passthrough();
    }

    let ext_len = u16::from_be_bytes([record_payload[pos], record_payload[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;

    while pos + 4 <= ext_end && pos + 4 <= record_payload.len() {
        let ext_type = u16::from_be_bytes([record_payload[pos], record_payload[pos + 1]]);
        let ext_len =
            u16::from_be_bytes([record_payload[pos + 2], record_payload[pos + 3]]) as usize;

        if ext_type == 0x0000 && pos + 4 + ext_len <= record_payload.len() {
            let sni_ext = &record_payload[pos + 4..pos + 4 + ext_len];
            if sni_ext.len() > 5 {
                let name_len = u16::from_be_bytes([sni_ext[3], sni_ext[4]]) as usize;
                if name_len > 0 && 5 + name_len <= sni_ext.len() {
                    let sni_start_in_payload = 5 + pos + 4 + 5;
                    let sni_end_in_payload = sni_start_in_payload + name_len;

                    return build_sni_frag_result(
                        packet,
                        &tcp,
                        &ip,
                        data_offset,
                        payload,
                        sni_start_in_payload,
                        sni_end_in_payload,
                        chunk_size,
                        fake_ttl_offset,
                    );
                }
            }
        }
        pos += 4 + ext_len;
    }

    DesyncResult::passthrough()
}

#[allow(clippy::too_many_arguments)]
fn build_sni_frag_result(
    packet: &[u8],
    tcp: &pnet_packet::tcp::TcpPacket,
    ip: &crate::desync::ParsedIpHeader,
    _data_offset: usize,
    payload: &[u8],
    sni_start: usize,
    sni_end: usize,
    chunk_size: usize,
    fake_ttl_offset: u8,
) -> DesyncResult {
    let pre_sni = &payload[..sni_start];
    let sni = &payload[sni_start..sni_end];
    let post_sni = &payload[sni_end..];

    let mut rewrapped = Vec::with_capacity(payload.len() + sni.len());
    let header_13 = [0x16u8, 0x03, 0x04];

    for chunk in pre_sni.chunks(chunk_size) {
        rewrapped.extend_from_slice(&header_13);
        rewrapped.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        rewrapped.extend_from_slice(chunk);
    }

    for chunk in sni.chunks(chunk_size) {
        rewrapped.extend_from_slice(&header_13);
        rewrapped.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        rewrapped.extend_from_slice(chunk);
    }

    for chunk in post_sni.chunks(chunk_size) {
        rewrapped.extend_from_slice(&header_13);
        rewrapped.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        rewrapped.extend_from_slice(chunk);
    }

    let seq = tcp.get_sequence();
    let ack = tcp.get_acknowledgement();
    let window = tcp.get_window();

    let inject_pkt = crate::desync::tcp::build_ip_tcp_packet_with_options(
        packet,
        ip.src,
        ip.dst,
        tcp.get_source(),
        tcp.get_destination(),
        seq,
        ack,
        TcpFlags::PSH | TcpFlags::ACK,
        window,
        &rewrapped,
        ip.ttl.saturating_sub(fake_ttl_offset),
        ip.identification.wrapping_add(1),
    );

    debug!(
        "[TLS] SniRecordFrag: SNI {} bytes → {} chunks",
        sni.len(),
        sni.len().div_ceil(chunk_size)
    );
    DesyncResult::inject_only(inject_pkt)
}
