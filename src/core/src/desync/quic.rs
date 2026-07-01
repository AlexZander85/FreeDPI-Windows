//! QUIC Desync техники.
//!
//! ## Техники
//! - QUIC Initial Injection — инъекция fake Initial пакета
//! - QUIC Short Header Poisoning — отравление short header пакетов
//! - QUIC Padding Flood — flooding padding-only пакетами
//! - UDP Coalescing — объединение UDP дейтаграмм
//! - Doppelganger GREASE — GREASE версии для обхода DPI
//! - QUIC Normalizer — нормализация QUIC пакетов
//! - [OF8] Long Header Drop — дроп QUIC Long Header пакетов от DPI
//!
//! ## Источник
//! Адаптировано из [zapret](https://github.com/bol-van/zapret) и
//! [offveil](https://github.com/nickel-org/offveil).

use crate::desync::{ipv4_checksum, parse_ip_header, DesyncResult};
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit};
use aes::Aes128;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Key, Nonce};
use hmac::{Hmac, Mac};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::MutableIpv4Packet;
use pnet_packet::udp::MutableUdpPacket;
use sha2::Sha256;
use std::net::Ipv4Addr;
use tracing::debug;

/// QUIC Version 1 (RFC 9000).
const QUIC_VERSION_1: u32 = 0x0000_0001;

/// QUIC Version 2 (RFC 9369).
#[allow(dead_code)]
const QUIC_VERSION_2: u32 = 0x6b33_43cf;

/// QUIC Initial packet type (Long Header, Type=0x00).
const QUIC_INITIAL_TYPE: u8 = 0xC0; // Fixed bit + Long Header + Initial

/// QUIC Initial packet: Long Header + Initial type.
///
/// ## Принцип
/// DPI анализирует QUIC Initial пакеты для определения SNI.
/// Инъекция fake Initial пакета с белым SNI может сбить DPI.
///
/// ## Структура QUIC Initial packet
/// ```text
/// Header Form (1 bit) = 1 (Long)
/// Fixed Bit (1 bit) = 1
/// Long Packet Type (2 bits) = 0 (Initial)
/// Reserved Bits (2 bits) = 0
/// Packet Number Length (2 bits) = 0 (1 byte)
/// Version (4 bytes) = 0x00000001
/// Destination Connection ID Length (1 byte)
/// Destination Connection ID (N bytes)
/// Source Connection ID Length (1 byte)
/// Source Connection ID (N bytes)
/// Token Length (1-8 bytes)
/// Token (variable)
/// Length (1-8 bytes)
/// Packet Number (1-4 bytes)
/// Payload (encrypted)
/// ```
pub fn quic_initial_inject(packet: &[u8], fake_sni: &str, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let udp_data = &packet[ip.header_len + 8..]; // skip UDP header
    if udp_data.len() < 20 {
        return DesyncResult::passthrough();
    }

    // Проверяем, что это QUIC Long Header (первый бит = 1)
    if udp_data[0] & 0x80 == 0 {
        return DesyncResult::passthrough();
    }

    // Извлекаем Connection ID из оригинального пакета
    let version = u32::from_be_bytes([udp_data[1], udp_data[2], udp_data[3], udp_data[4]]);

    if version == 0 {
        return DesyncResult::passthrough(); // Version negotiation
    }

    let dcid_len = udp_data[5] as usize;
    if 6 + dcid_len > udp_data.len() {
        return DesyncResult::passthrough();
    }
    let dcid = &udp_data[6..6 + dcid_len];

    let scid_offset = 6 + dcid_len;
    if scid_offset >= udp_data.len() {
        return DesyncResult::passthrough();
    }
    let scid_len = udp_data[scid_offset] as usize;
    let scid_end = scid_offset + 1 + scid_len;
    if scid_end > udp_data.len() {
        return DesyncResult::passthrough();
    }
    let scid: &[u8] = &udp_data[scid_offset + 1..scid_end];

    // Строим fake QUIC Initial пакет с CRYPTO frame + шифрованием
    let fake_payload = build_quic_initial_with_crypto(dcid, scid, fake_sni)
        .unwrap_or_else(|| build_quic_initial(dcid, fake_sni));

    // Fake UDP дейтаграмм
    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
    let fake_src_port = extract_src_port(packet).unwrap_or(443);
    let fake_udp = build_udp_packet(
        ip.src,
        ip.dst,
        fake_src_port,
        443,
        &fake_payload,
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!(
        "[QUIC] Initial inject: fake '{}' ({} bytes)",
        fake_sni,
        fake_payload.len()
    );

    DesyncResult::inject_only(fake_udp)
}

/// QUIC Short Header Poisoning.
///
/// ## Принцип
/// Отравление short header пакетов (0-RTT, 1-RTT) fake данными.
/// DPI может потерять sync с QUIC потоком.
pub fn quic_short_header_poison(packet: &[u8], fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let udp_data = &packet[ip.header_len + 8..];
    if udp_data.is_empty() {
        return DesyncResult::passthrough();
    }

    // Short Header: первый бит = 0
    if udp_data[0] & 0x80 != 0 {
        return DesyncResult::passthrough();
    }

    // Фейковый short header пакет (8 байт padding)
    let fake_payload = vec![0u8; 8];
    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);

    // Извлекаем source port из UDP
    let udp = pnet_packet::udp::UdpPacket::new(&packet[ip.header_len..]);
    let src_port = udp.map(|u| u.get_source()).unwrap_or(443);

    let fake_udp = build_udp_packet(
        ip.src,
        ip.dst,
        src_port,
        443,
        &fake_payload,
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!("[QUIC] Short header poison: 8 bytes fake payload");

    DesyncResult::inject_only(fake_udp)
}

/// QUIC Padding Flood.
///
/// ## Принцип
/// Отправляем несколько padding-only пакетов для переполнения
/// conntrack DPI. QUIC padding пакеты не содержат полезных данных,
/// но DPI должен их обрабатывать.
pub fn quic_padding_flood(packet: &[u8], count: usize, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let src_port = extract_src_port(packet).unwrap_or(443);
    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
    let mut inject = Vec::with_capacity(count);

    for _ in 0..count {
        let pad_size = (crate::desync::rand::random_range(1, 21)) as usize;
        let mut fake_payload = vec![0u8; pad_size];
        crate::desync::rand::fill_random_bytes(&mut fake_payload);

        let ip_id = crate::desync::rand::random_u32() as u16;
        let fake_udp = build_udp_packet(
            ip.src,
            ip.dst,
            src_port,
            443,
            &fake_payload,
            fake_ttl,
            ip_id,
        );
        inject.push(fake_udp);
    }

    debug!("[QUIC] Padding flood: {} packets", count);

    DesyncResult::inject_many(inject)
}

/// UDP Coalescing — объединение UDP дейтаграмм.
///
/// ## Принцип
/// Объединяем несколько маленьких UDP пакетов в один большой.
/// DPI может не обработать коалесцированный пакет.
pub fn udp_coalescing(packet: &[u8], extra_packets: &[&[u8]], fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    if extra_packets.is_empty() {
        return DesyncResult::passthrough();
    }

    // Объединяем payload
    let mut combined = Vec::new();
    let udp_start = ip.header_len + 8;
    if udp_start < packet.len() {
        combined.extend_from_slice(&packet[udp_start..]);
    }
    for extra in extra_packets {
        combined.extend_from_slice(extra);
    }

    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
    let combined_udp = build_udp_packet(
        ip.src,
        ip.dst,
        extract_src_port(packet).unwrap_or(443),
        443,
        &combined,
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!(
        "[QUIC] UDP coalescing: {} packets → {} bytes",
        extra_packets.len() + 1,
        combined.len()
    );

    DesyncResult::inject_only(combined_udp)
}

/// Doppelganger GREASE — отправка QUIC с fake версией.
///
/// ## Принцип
/// Отправляем пакет с GREASE версией (0x?a?a?a?a). DPI может
/// не распознать QUIC и пропустить пакет.
pub fn doppelganger_grease(packet: &[u8], fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    // GREASE version: 0x?a?a?a?a (RFC 8701)
    let grease_version: u32 = 0x0a0a_0a0a;
    let mut fake_payload = Vec::new();
    fake_payload.push(0xC0); // Long Header + Initial
    fake_payload.extend_from_slice(&grease_version.to_be_bytes());
    fake_payload.extend_from_slice(&[0u8; 8]); // CID placeholder

    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
    let fake_udp = build_udp_packet(
        ip.src,
        ip.dst,
        extract_src_port(packet).unwrap_or(443),
        443,
        &fake_payload,
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!("[QUIC] Doppelganger GREASE: version={:#x}", grease_version);

    DesyncResult::inject_only(fake_udp)
}

/// [OF8] Long Header Drop: дроп QUIC Long Header пакетов от DPI.
///
/// ## Принцип
/// DPI часто инжектирует QUIC пакеты с Long Header (ServerHello,
/// NewToken, etc.) для анализа. Если пакет содержит Long Header
/// и отправлен от клиента — это很可能 инъекция DPI.
///
/// Проверяем: если пакет — QUIC Long Header (бит 0x80 установлен)
/// и это ответ (не outbound) — дропаем.
pub fn quic_long_header_drop(packet: &[u8]) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let udp_data = &packet[ip.header_len + 8..];
    if udp_data.is_empty() {
        return DesyncResult::passthrough();
    }

    // Long Header: первый бит = 1
    if udp_data[0] & 0x80 == 0 {
        return DesyncResult::passthrough();
    }

    debug!(
        "[OF8] LongHeaderDrop: dropping QUIC Long Header packet from {}",
        ip.src
    );

    DesyncResult::drop_packet()
}

/// QUIC Normalizer — нормализация QUIC пакетов для DPI.
///
/// ## Принцип
/// Нормализуем QUIC Initial пакет: убираем GREASE, исправляем
/// version, чистим padding. DPI может сбиться на аномальных пакетах.
pub fn quic_normalizer(packet: &[u8]) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let udp_data = &packet[ip.header_len + 8..];
    if udp_data.len() < 5 {
        return DesyncResult::passthrough();
    }

    // Проверяем Long Header
    if udp_data[0] & 0x80 == 0 {
        return DesyncResult::passthrough();
    }

    let version = u32::from_be_bytes([udp_data[1], udp_data[2], udp_data[3], udp_data[4]]);

    // Нормализуем GREASE версию на Version 1
    if (version & 0x0a0a_0a0a) == 0x0a0a_0a0a {
        let mut modified = packet.to_vec();
        let version_offset = ip.header_len + 8 + 1; // +1 for first byte
        modified[version_offset..version_offset + 4].copy_from_slice(&QUIC_VERSION_1.to_be_bytes());

        // Пересчитываем IP checksum
        let checksum = ipv4_checksum(&modified[..20]);
        modified[10..12].copy_from_slice(&checksum.to_be_bytes());

        debug!("[QUIC] Normalizer: GREASE version → Version 1");

        return DesyncResult::modified_only(modified);
    }

    DesyncResult::passthrough()
}

// ==================== P5: Оставшиеся QUIC техники ====================

/// [Z20] QUIC Blocking: блокировка QUIC для fallback на TCP.
///
/// ## Принцип
/// Блокируем все QUIC пакеты (UDP:443). Клиент вынужден
/// использовать TCP fallback. DPI может не блокировать TCP
/// (или блокировать слабее).
pub fn quic_blocking(packet: &[u8]) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    // Проверяем UDP:443
    if ip.protocol.0 != 17 {
        return DesyncResult::passthrough();
    }

    let udp_data = &packet[ip.header_len..];
    if udp_data.len() < 8 {
        return DesyncResult::passthrough();
    }

    let dst_port = u16::from_be_bytes([udp_data[2], udp_data[3]]);
    if dst_port != 443 {
        return DesyncResult::passthrough();
    }

    debug!("[Z20] QUIC Blocking: dropping UDP:443 from {}", ip.src);

    DesyncResult::drop_packet()
}

/// [Z21] QUIC Version Downgrade: принудительный downgrade версии.
///
/// ## Принцип
/// Отправляем fake Version Negotiation пакет с unsupported версией.
/// Клиент должен повторить handshake с поддерживаемой версией.
/// DPI может потерять sync с QUIC потоком.
pub fn quic_version_downgrade(
    packet: &[u8],
    fake_version: u32,
    fake_ttl_offset: u8,
) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let udp_data = &packet[ip.header_len + 8..];
    if udp_data.len() < 5 || udp_data[0] & 0x80 == 0 {
        return DesyncResult::passthrough();
    }

    let version = u32::from_be_bytes([udp_data[1], udp_data[2], udp_data[3], udp_data[4]]);

    if version == 0 || version == fake_version {
        return DesyncResult::passthrough();
    }

    // Version Negotiation: Long Header + Type=0x7F + version=0
    let mut fake_payload = Vec::with_capacity(64);
    fake_payload.push(0xFF); // Header Form + Fixed Bit + Long Packet Type (0x3F = VN)
    fake_payload.extend_from_slice(&fake_version.to_be_bytes()); // fake version
    fake_payload.push(0x08); // DCID length
                             // Copy DCID from original
    let dcid_start = 6;
    if dcid_start + 8 <= udp_data.len() {
        fake_payload.extend_from_slice(&udp_data[dcid_start..dcid_start + 8]);
    }
    fake_payload.push(0x08); // SCID length
    let scid_start = dcid_start + 8 + 1;
    if scid_start + 8 <= udp_data.len() {
        fake_payload.extend_from_slice(&udp_data[scid_start..scid_start + 8]);
    }

    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
    let fake_udp = build_udp_packet(
        ip.src,
        ip.dst,
        extract_src_port(packet).unwrap_or(443),
        443,
        &fake_payload,
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!(
        "[Z21] QUIC VersionDowngrade: fake version={:#x}",
        fake_version
    );

    DesyncResult::inject_only(fake_udp)
}

/// [Z22] QUIC Retry Injection: инъекция fake Retry пакета.
///
/// ## Принцип
/// Отправляем fake Retry пакет с невалидным токеном.
/// Клиент должен повторить handshake с токеном. DPI
/// может сбиться при обработке Retry.
pub fn quic_retry_inject(packet: &[u8], fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let udp_data = &packet[ip.header_len + 8..];
    if udp_data.len() < 5 || udp_data[0] & 0x80 == 0 {
        return DesyncResult::passthrough();
    }

    let version = u32::from_be_bytes([udp_data[1], udp_data[2], udp_data[3], udp_data[4]]);

    if version == 0 {
        return DesyncResult::passthrough();
    }

    // Retry: Long Header + Type=0x7E (Retry Packet)
    let mut fake_payload = Vec::with_capacity(64);
    fake_payload.push(0xFE); // Retry packet type
    fake_payload.extend_from_slice(&version.to_be_bytes());

    let dcid_start = 6;
    let dcid_len = if dcid_start < udp_data.len() {
        udp_data[dcid_start] as usize
    } else {
        0
    };
    if dcid_start + 1 + dcid_len <= udp_data.len() {
        fake_payload.push(dcid_len as u8);
        fake_payload.extend_from_slice(&udp_data[dcid_start + 1..dcid_start + 1 + dcid_len]);
    }

    // Random SCID (server chosen)
    fake_payload.push(0x08);
    for _ in 0..8 {
        fake_payload.push(crate::desync::rand::random_u32() as u8);
    }

    // Retry Token (16 bytes random)
    for _ in 0..16 {
        fake_payload.push(crate::desync::rand::random_u32() as u8);
    }

    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
    let fake_udp = build_udp_packet(
        ip.src,
        ip.dst,
        extract_src_port(packet).unwrap_or(443),
        443,
        &fake_payload,
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!("[Z22] QUIC RetryInject: fake Retry token injected");

    DesyncResult::inject_only(fake_udp)
}

/// [Z23] QUIC ConnectionClose: инъекция CONNECTION_CLOSE.
///
/// ## Принцип
/// Отправляем fake CONNECTION_CLOSE frame. DPI видит
/// закрытие соединения и может перестать инспектировать.
/// Клиент создаст новое соединение.
pub fn quic_connection_close(packet: &[u8], error_code: u64, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let udp_data = &packet[ip.header_len + 8..];
    if udp_data.len() < 5 || udp_data[0] & 0x80 == 0 {
        return DesyncResult::passthrough();
    }

    let version = u32::from_be_bytes([udp_data[1], udp_data[2], udp_data[3], udp_data[4]]);

    if version == 0 {
        return DesyncResult::passthrough();
    }

    // CONNECTION_CLOSE frame: type=0x1C, error_code(varint), frame_type(varint)
    let mut frame = Vec::with_capacity(20);
    frame.push(0x1C); // CONNECTION_CLOSE frame type
                      // error_code as varint (simple encoding)
    if error_code < 64 {
        frame.push(error_code as u8);
    } else {
        frame.push(0x40 | ((error_code >> 8) & 0x3F) as u8);
        frame.push((error_code & 0xFF) as u8);
    }
    // frame_type that caused error: 0x00 (unknown)
    frame.push(0x00);
    // reason phrase length: 0
    frame.push(0x00);

    // Wrap in Initial packet
    let dcid_start = 6;
    let mut initial = Vec::with_capacity(64);
    initial.push(QUIC_INITIAL_TYPE);
    initial.extend_from_slice(&version.to_be_bytes());

    let dcid_len = if dcid_start < udp_data.len() {
        udp_data[dcid_start] as usize
    } else {
        0
    };
    initial.push(dcid_len as u8);
    if dcid_start + 1 + dcid_len <= udp_data.len() {
        initial.extend_from_slice(&udp_data[dcid_start + 1..dcid_start + 1 + dcid_len]);
    }

    // SCID = DCID
    initial.push(dcid_len as u8);
    if dcid_start + 1 + dcid_len <= udp_data.len() {
        initial.extend_from_slice(&udp_data[dcid_start + 1..dcid_start + 1 + dcid_len]);
    }

    // Token length = 0
    initial.push(0x00);
    // Length
    let remaining = frame.len() + 16; // + padding
    initial.push(((remaining >> 8) | 0xC0) as u8);
    initial.push((remaining & 0xFF) as u8);
    // Packet number
    initial.push(0x00);
    // Frame
    initial.extend_from_slice(&frame);
    // Padding
    initial.resize(initial.len() + 16, 0);

    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
    let fake_udp = build_udp_packet(
        ip.src,
        ip.dst,
        extract_src_port(packet).unwrap_or(443),
        443,
        &initial,
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!("[Z23] QUIC ConnectionClose: error_code={}", error_code);

    DesyncResult::inject_only(fake_udp)
}

/// [Z24] QUIC StreamReset: инъекция RESET_STREAM.
///
/// ## Принцип
/// Отправляем fake RESET_STREAM frame для stream 0.
/// DPI видит сброс потока и может перестать инспектировать.
pub fn quic_stream_reset(packet: &[u8], fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let udp_data = &packet[ip.header_len + 8..];
    if udp_data.len() < 5 || udp_data[0] & 0x80 == 0 {
        return DesyncResult::passthrough();
    }

    let version = u32::from_be_bytes([udp_data[1], udp_data[2], udp_data[3], udp_data[4]]);

    if version == 0 {
        return DesyncResult::passthrough();
    }

    // RESET_STREAM frame: type=0x04, stream_id=0, error_code=0
    let mut frame = Vec::with_capacity(5);
    frame.push(0x04); // RESET_STREAM type
    frame.push(0x00); // stream_id=0 (varint)
    frame.push(0x00); // error_code=0
    frame.push(0x00); // final_size=0

    // Wrap in 1-RTT packet (Short Header)
    let mut short = Vec::with_capacity(20);
    short.push(0x40); // Short Header: Fixed bit=1, spin=0
                      // Use random packet number
    short.push(crate::desync::rand::random_u32() as u8);
    short.extend_from_slice(&frame);
    short.resize(short.len() + 8, 0); // padding

    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
    let fake_udp = build_udp_packet(
        ip.src,
        ip.dst,
        extract_src_port(packet).unwrap_or(443),
        443,
        &short,
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!("[Z24] QUIC StreamReset: RESET_STREAM for stream 0");

    DesyncResult::inject_only(fake_udp)
}

/// [Z25] QUIC MaxStreams: инъекция MAX_STREAMS frame.
///
/// ## Принцип
/// Отправляем MAX_STREAMS frame с large value.
/// DPI должен обновить лимит потоков. Это может
/// переполнить state machine DPI.
pub fn quic_max_streams(packet: &[u8], max_streams: u32, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let udp_data = &packet[ip.header_len + 8..];
    if udp_data.len() < 5 || udp_data[0] & 0x80 == 0 {
        return DesyncResult::passthrough();
    }

    let version = u32::from_be_bytes([udp_data[1], udp_data[2], udp_data[3], udp_data[4]]);

    if version == 0 {
        return DesyncResult::passthrough();
    }

    // MAX_STREAMS frame: type=0x12 (bidi), count as varint
    let mut frame = Vec::with_capacity(5);
    frame.push(0x12); // MAX_STREAMS type
                      // max_streams as varint
    if max_streams < 64 {
        frame.push(max_streams as u8);
    } else {
        frame.push(0x40 | ((max_streams >> 8) & 0x3F) as u8);
        frame.push((max_streams & 0xFF) as u8);
    }

    // Wrap in Initial packet
    let mut initial = Vec::with_capacity(40);
    initial.push(QUIC_INITIAL_TYPE);
    initial.extend_from_slice(&version.to_be_bytes());
    let dcid_start = 6;
    let dcid_len = if dcid_start < udp_data.len() {
        udp_data[dcid_start] as usize
    } else {
        0
    };
    initial.push(dcid_len as u8);
    if dcid_start + 1 + dcid_len <= udp_data.len() {
        initial.extend_from_slice(&udp_data[dcid_start + 1..dcid_start + 1 + dcid_len]);
    }
    initial.push(dcid_len as u8);
    if dcid_start + 1 + dcid_len <= udp_data.len() {
        initial.extend_from_slice(&udp_data[dcid_start + 1..dcid_start + 1 + dcid_len]);
    }
    initial.push(0x00); // token length
    let remaining = frame.len() + 8;
    initial.push(((remaining >> 8) | 0xC0) as u8);
    initial.push((remaining & 0xFF) as u8);
    initial.push(0x00); // packet number
    initial.extend_from_slice(&frame);
    initial.resize(initial.len() + 8, 0);

    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
    let fake_udp = build_udp_packet(
        ip.src,
        ip.dst,
        extract_src_port(packet).unwrap_or(443),
        443,
        &initial,
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!("[Z25] QUIC MaxStreams: max={}", max_streams);

    DesyncResult::inject_only(fake_udp)
}

/// [Z26] QUIC NewConnectionID: инъекция NEW_CONNECTION_ID.
///
/// ## Принцип
/// Отправляем fake NEW_CONNECTION_ID frame. DPI должен
/// отслеживать connection ID смены. Это может сбить DPI.
pub fn quic_new_connection_id(packet: &[u8], fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let udp_data = &packet[ip.header_len + 8..];
    if udp_data.len() < 5 || udp_data[0] & 0x80 == 0 {
        return DesyncResult::passthrough();
    }

    let version = u32::from_be_bytes([udp_data[1], udp_data[2], udp_data[3], udp_data[4]]);

    if version == 0 {
        return DesyncResult::passthrough();
    }

    // NEW_CONNECTION_ID frame: type=0x18, sequence_number=1, cid_len=8, cid, stateless_reset_token=16
    let mut frame = Vec::with_capacity(40);
    frame.push(0x18); // type
    frame.push(0x01); // sequence_number=1
    frame.push(0x08); // connection_id_length=8
                      // Random connection ID
    for _ in 0..8 {
        frame.push(crate::desync::rand::random_u32() as u8);
    }
    // Stateless Reset Token (16 bytes random)
    for _ in 0..16 {
        frame.push(crate::desync::rand::random_u32() as u8);
    }

    // Wrap in 1-RTT Short Header
    let mut short = Vec::with_capacity(40);
    short.push(0x40);
    short.push(crate::desync::rand::random_u32() as u8);
    short.extend_from_slice(&frame);
    short.resize(short.len() + 8, 0);

    let fake_ttl = ip.ttl.saturating_sub(fake_ttl_offset);
    let fake_udp = build_udp_packet(
        ip.src,
        ip.dst,
        extract_src_port(packet).unwrap_or(443),
        443,
        &short,
        fake_ttl,
        ip.identification.wrapping_add(1),
    );

    debug!("[Z26] QUIC NewConnectionID: fake CID injected");

    DesyncResult::inject_only(fake_udp)
}

// ==================== Вспомогательные функции ====================

/// Extracts the UDP source port from a raw IP+UDP packet.
fn extract_src_port(packet: &[u8]) -> Option<u16> {
    if packet.len() < 28 {
        return None;
    }
    let ihl = (packet[0] & 0x0F) as usize * 4;
    if packet.len() < ihl + 8 {
        return None;
    }
    Some(u16::from_be_bytes([packet[ihl], packet[ihl + 1]]))
}

/// Строит fake QUIC Initial пакет.
fn build_quic_initial(dcid: &[u8], _sni: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(128);

    // Long Header: Header Form(1) + Fixed Bit(1) + Type(2) = 0xC0
    // Reserved Bits(2) = 0 + Packet Number Length(2) = 0
    payload.push(QUIC_INITIAL_TYPE);

    // Version: 0x00000001 (QUIC v1)
    payload.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());

    // Destination Connection ID Length + CID
    payload.push(dcid.len() as u8);
    payload.extend_from_slice(dcid);

    // Source Connection ID Length = 0
    payload.push(0);

    // Token Length = 0 (no token)
    payload.push(0);

    // Length: placeholder (will be filled)
    let length_offset = payload.len();
    payload.extend_from_slice(&[0u8; 2]); // placeholder

    // Packet Number: 0
    payload.push(0);

    // RFC 9000 §14.1: Initial packets must be ≥ 1200 bytes
    const QUIC_MIN_INITIAL_SIZE: usize = 1200;
    let current_len = payload.len();
    if current_len < QUIC_MIN_INITIAL_SIZE {
        payload.resize(QUIC_MIN_INITIAL_SIZE, 0);
    }

    // Fill length (remaining bytes after length field)
    let length = payload.len() - length_offset - 2;
    payload[length_offset..length_offset + 2].copy_from_slice(&(length as u16).to_be_bytes());

    payload
}

/// QUIC v1 Initial salt (RFC 9001 §5.2).
const QUIC_V1_INITIAL_SALT: [u8; 20] = [
    // RFC 9001 Section 5.2, Errata-free version
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

const QUIC_INITIAL_KEY_LEN: usize = 16;
const QUIC_INITIAL_IV_LEN: usize = 12;
const QUIC_INITIAL_HP_LEN: usize = 16;
#[allow(dead_code)]
const QUIC_AEAD_TAG_LEN: usize = 16;

struct QuicInitialKeys {
    key: [u8; QUIC_INITIAL_KEY_LEN],
    iv: [u8; QUIC_INITIAL_IV_LEN],
    hp: [u8; QUIC_INITIAL_HP_LEN],
}

type HmacSha256 = Hmac<Sha256>;

/// HKDF-Extract(salt, IKM) → PRK (32 bytes). RFC 5869 §2.2.
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(salt).expect("HMAC accepts any key length");
    mac.update(ikm);
    let result = mac.finalize().into_bytes();
    let mut prk = [0u8; 32];
    prk.copy_from_slice(&result);
    prk
}

/// HKDF-Expand(PRK, info, length) → OKM. RFC 5869 §2.3.
/// T(N) = HMAC(PRK, T(N-1) | info | N), T(0) = empty
fn hkdf_expand(prk: &[u8; 32], info: &[u8], length: usize) -> Vec<u8> {
    let mut okm = Vec::with_capacity(length);
    let mut t: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while okm.len() < length {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(prk).expect("HMAC accepts any key length");
        mac.update(&t);
        mac.update(info);
        mac.update(&[counter]);
        t = mac.finalize().into_bytes().to_vec();
        okm.extend_from_slice(&t);
        counter = counter.wrapping_add(1);
        if counter == 0 {
            break;
        }
    }
    okm.truncate(length);
    okm
}

/// HKDF-Expand-Label (RFC 8446 §7.1, используется в QUIC).
/// info = length(2) | label_len(1) | "tls13 " + label | context_len(1) | context
fn hkdf_expand_label(prk: &[u8; 32], label: &[u8], context: &[u8], length: u16) -> Vec<u8> {
    let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
    info.extend_from_slice(&length.to_be_bytes());
    let label_full = [b"tls13 ", label].concat();
    info.push(label_full.len() as u8);
    info.extend_from_slice(&label_full);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand(prk, &info, length as usize)
}

/// Выводит QUIC v1 Initial keys из DCID (RFC 9001 §5.2).
fn derive_quic_initial_keys(dcid: &[u8]) -> Option<QuicInitialKeys> {
    let initial_secret = hkdf_extract(&QUIC_V1_INITIAL_SALT, dcid);

    let client_secret_bytes = hkdf_expand_label(&initial_secret, b"client in", b"", 32);
    let mut client_secret = [0u8; 32];
    client_secret.copy_from_slice(&client_secret_bytes);

    let key_bytes = hkdf_expand_label(
        &client_secret,
        b"quic key",
        b"",
        QUIC_INITIAL_KEY_LEN as u16,
    );
    let mut key = [0u8; QUIC_INITIAL_KEY_LEN];
    key.copy_from_slice(&key_bytes);

    let iv_bytes = hkdf_expand_label(&client_secret, b"quic iv", b"", QUIC_INITIAL_IV_LEN as u16);
    let mut iv = [0u8; QUIC_INITIAL_IV_LEN];
    iv.copy_from_slice(&iv_bytes);

    let hp_bytes = hkdf_expand_label(&client_secret, b"quic hp", b"", QUIC_INITIAL_HP_LEN as u16);
    let mut hp = [0u8; QUIC_INITIAL_HP_LEN];
    hp.copy_from_slice(&hp_bytes);

    Some(QuicInitialKeys { key, iv, hp })
}

/// QUIC header protection mask (RFC 9001 §5.4).
fn header_protection_mask(hp_key: &[u8; 16], sample: &[u8; 16]) -> [u8; 5] {
    let cipher = Aes128::new(GenericArray::from_slice(hp_key));
    let mut block = GenericArray::clone_from_slice(sample);
    cipher.encrypt_block(&mut block);
    let mut mask = [0u8; 5];
    mask.copy_from_slice(&block[..5]);
    mask
}

/// Применяет header protection к QUIC пакету (RFC 9001 §5.4).
/// Операция self-inverse: повторное применение снимает protection.
fn apply_header_protection(packet: &mut [u8], pn_offset: usize, pn_len: usize, hp_key: &[u8; 16]) {
    let sample_start = pn_offset + 4;
    if sample_start + 16 > packet.len() {
        return;
    }
    let mut sample = [0u8; 16];
    sample.copy_from_slice(&packet[sample_start..sample_start + 16]);

    let mask = header_protection_mask(hp_key, &sample);

    // Mask first byte: low 4 bits (Long Header: reserved + PN length)
    packet[0] ^= mask[0] & 0x0F;

    // Mask packet number bytes
    for i in 0..pn_len {
        packet[pn_offset + i] ^= mask[1 + i];
    }
}

/// AEAD encrypt QUIC payload с AES-128-GCM (RFC 9001 §5.3).
fn aead_encrypt_payload(
    payload: &[u8],
    packet_number: u64,
    associated_data: &[u8],
    key: &[u8; 16],
    iv: &[u8; 12],
) -> Option<Vec<u8>> {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(iv);
    let pn_bytes = packet_number.to_be_bytes();
    for i in 0..8 {
        nonce_bytes[4 + i] ^= pn_bytes[i];
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(key));
    let ciphertext = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: payload,
                aad: associated_data,
            },
        )
        .ok()?;
    Some(ciphertext)
}

/// Полная QUIC v1 Initial encryption (RFC 9001 §5.2-5.4).
///
/// ## Алгоритм:
/// 1. Derive client_initial_secret, client_key, client_iv, client_hp from DCID
/// 2. Build AAD = header + PN
/// 3. AEAD encrypt: plaintext = PN + payload → ciphertext (includes 16-byte AEAD tag)
/// 4. Build packet = header + ciphertext
/// 5. Apply header protection to first byte + PN bytes
///
/// # Arguments
/// * `header` — QUIC Initial header bytes (everything before packet number)
/// * `packet_number` — full packet number (u64, will be truncated to pn_len bytes)
/// * `pn_len` — number of bytes used for PN encoding (1, 2, or 4)
/// * `payload` — CRYPTO frames + PADDING
/// * `dcid` — Destination Connection ID (for key derivation)
pub fn quic_v1_initial_encrypt(
    header: &[u8],
    packet_number: u64,
    pn_len: usize,
    payload: &[u8],
    dcid: &[u8],
) -> Option<Vec<u8>> {
    let keys = derive_quic_initial_keys(dcid)?;

    // Build PN bytes (big-endian, truncated to pn_len)
    let pn_bytes = packet_number.to_be_bytes();
    let pn_truncated = &pn_bytes[8 - pn_len..8];

    // Build full header = header || PN (RFC 9001 §5.3: AAD includes PN)
    let mut full_header = Vec::with_capacity(header.len() + pn_len);
    full_header.extend_from_slice(header);
    full_header.extend_from_slice(pn_truncated);

    // AEAD encrypt: plaintext = payload ONLY (PN is in AAD, not plaintext)
    let ciphertext =
        aead_encrypt_payload(payload, packet_number, &full_header, &keys.key, &keys.iv)?;

    // Build final packet: full_header || ciphertext (encrypted payload + AEAD tag)
    let mut packet = Vec::with_capacity(full_header.len() + ciphertext.len());
    packet.extend_from_slice(&full_header);
    packet.extend_from_slice(&ciphertext);

    // Apply header protection to first byte + PN bytes (RFC 9001 §5.4)
    let pn_offset = header.len();
    apply_header_protection(&mut packet, pn_offset, pn_len, &keys.hp);

    Some(packet)
}

/// Дешифровка для тестов (verify roundtrip).
#[cfg(test)]
pub fn quic_v1_initial_decrypt(
    packet: &[u8],
    header_len: usize,
    pn_len: usize,
    dcid: &[u8],
) -> Option<Vec<u8>> {
    let keys = derive_quic_initial_keys(dcid)?;

    // Remove header protection (XOR is self-inverse, RFC 9001 §5.4.1)
    let mut packet_mut = packet.to_vec();
    apply_header_protection(&mut packet_mut, header_len, pn_len, &keys.hp);

    // Extract PN from the header (now exposed after HP removal)
    let pn_bytes = &packet_mut[header_len..header_len + pn_len];
    let mut pn_full = [0u8; 8];
    pn_full[8 - pn_len..].copy_from_slice(pn_bytes);
    let packet_number = u64::from_be_bytes(pn_full);

    // Full header (including PN) is bytes 0 .. header_len+pn_len
    let full_header = &packet_mut[..header_len + pn_len];
    // Ciphertext (encrypted payload + AEAD tag) is after PN
    let ciphertext = &packet_mut[header_len + pn_len..];

    // Build nonce: iv XOR PN (RFC 9001 §5.3)
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&keys.iv);
    let pn_be = packet_number.to_be_bytes();
    for i in 0..8 {
        nonce_bytes[4 + i] ^= pn_be[i];
    }

    // AEAD decrypt: full_header serves as AAD (RFC 9001 §5.3)
    let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&keys.key));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad: full_header,
            },
        )
        .ok()?;

    Some(plaintext)
}

/// Builds a QUIC Initial packet with proper encryption.
///
/// This constructs a valid QUIC v1 Initial packet with:
/// - Long Header with Initial type
/// - Version 1
/// - Destination and Source Connection IDs
/// - CRYPTO frame with fake ClientHello
/// - Proper padding to 1200 bytes minimum
/// - AEAD AES-128-GCM encryption
pub fn build_quic_initial_with_crypto(dcid: &[u8], scid: &[u8], fake_sni: &str) -> Option<Vec<u8>> {
    // Build SNI extension
    let sni_bytes = fake_sni.as_bytes();
    let sni_ext = {
        let mut ext = Vec::new();
        // Extension type: server_name (0x0000)
        ext.extend_from_slice(&[0x00, 0x00]);
        // Extension data length placeholder
        let ext_data_len_pos = ext.len();
        ext.extend_from_slice(&[0x00, 0x00]);
        // Server name list length
        let sni_list_len = 1 + 2 + sni_bytes.len();
        ext.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
        // Server name type: host_name (0x00)
        ext.push(0x00);
        // Server name length
        ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        ext.extend_from_slice(sni_bytes);
        // Fill extension data length
        let ext_data_len = sni_list_len + 2;
        let len16 = ext_data_len as u16;
        ext[ext_data_len_pos..ext_data_len_pos + 2].copy_from_slice(&len16.to_be_bytes());
        ext
    };

    // Build the CRYPTO frame with fake ClientHello
    let mut crypto_frame = Vec::with_capacity(512);

    // CRYPTO frame type (0x06)
    crypto_frame.push(0x06);

    // Offset (varint) = 0
    crypto_frame.push(0x00);

    // Length (varint) - will be filled later
    let length_offset = crypto_frame.len();
    crypto_frame.push(0x00); // placeholder

    // ----- TLS ClientHello (RFC 8446 §4.1.2) -----
    // Handshake type: ClientHello (0x01)
    crypto_frame.push(0x01);

    // Length (3 bytes) — placeholder, filled after CH is built
    let ch_len_pos = crypto_frame.len();
    crypto_frame.extend_from_slice(&[0x00, 0x00, 0x00]);

    // Client version: TLS 1.2 (0x0303) per spec
    crypto_frame.extend_from_slice(&[0x03, 0x03]);

    // Random (32 bytes) — deterministic
    for i in 0..32 {
        crypto_frame.push(i as u8);
    }

    // Session ID length (0 = no session ID)
    crypto_frame.push(0x00);

    // Cipher suites
    crypto_frame.extend_from_slice(&[0x00, 0x04]); // length
    crypto_frame.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    crypto_frame.extend_from_slice(&[0x13, 0x02]); // TLS_AES_256_GCM_SHA384

    // Compression methods: null only
    crypto_frame.extend_from_slice(&[0x01, 0x00]);

    // Extensions: SNI only
    let ext_start = crypto_frame.len();
    crypto_frame.extend_from_slice(&sni_ext);
    let ext_total_len = crypto_frame.len() - ext_start;
    let extensions_len_pos = ext_start - 2;
    let ext_len16 = ext_total_len as u16;
    crypto_frame[extensions_len_pos..extensions_len_pos + 2]
        .copy_from_slice(&ext_len16.to_be_bytes());

    // Fill ClientHello length (everything after handshake type and length)
    let ch_len = crypto_frame.len() - ch_len_pos - 3;
    let ch_len24 = ch_len as u32;
    crypto_frame[ch_len_pos..ch_len_pos + 3].copy_from_slice(&ch_len24.to_be_bytes()[1..]);

    // Fill the CRYPTO frame length (everything after the length varint)
    let crypto_len = crypto_frame.len() - length_offset - 1;
    crypto_frame[length_offset] = crypto_len as u8;

    // Build the Initial packet header
    let mut packet = Vec::with_capacity(512);

    // Long Header: Header Form(1) + Fixed Bit(1) + Type(2) = 0xC0
    // Reserved Bits(2) = 0 + Packet Number Length(2) = 0
    packet.push(0xC0);

    // Version: 0x00000001 (QUIC v1)
    packet.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());

    // Destination Connection ID Length + CID
    packet.push(dcid.len() as u8);
    packet.extend_from_slice(dcid);

    // Source Connection ID Length + CID
    packet.push(scid.len() as u8);
    packet.extend_from_slice(scid);

    // Token Length = 0 (no token)
    packet.push(0);

    // Length field placeholder (will be filled after padding)
    let length_field_offset = packet.len();
    packet.extend_from_slice(&[0u8; 2]);

    // Packet Number: 0
    packet.push(0x00);

    // Add CRYPTO frame
    packet.extend_from_slice(&crypto_frame);

    // Pad to 1200 bytes minimum (RFC 9000 §14.1)
    const QUIC_MIN_INITIAL_SIZE: usize = 1200;
    if packet.len() < QUIC_MIN_INITIAL_SIZE {
        packet.resize(QUIC_MIN_INITIAL_SIZE, 0);
    }

    // Fill the length field (remaining bytes after length field)
    let remaining = packet.len() - length_field_offset - 2;
    packet[length_field_offset..length_field_offset + 2]
        .copy_from_slice(&(remaining as u16).to_be_bytes());

    // Encrypt using QUIC v1 Initial protection
    // header = everything before PN (length_field_offset + 2 bytes length)
    // PN is at header_len = length_field_offset + 2, PN length = 1 byte
    let pn_offset = length_field_offset + 2;
    let pn_len = 1; // PN length encoding in header byte 0 = 0 means 1 byte
    let pn_val = packet[pn_offset] as u64;
    let header = &packet[..pn_offset];
    let payload = &packet[pn_offset + pn_len..];

    if let Some(encrypted) = quic_v1_initial_encrypt(header, pn_val, pn_len, payload, dcid) {
        Some(encrypted)
    } else {
        // Fallback: return unencrypted (will be detected by DPI)
        Some(packet)
    }
}

/// Строит UDP пакет с IP header.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_udp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    ttl: u8,
    identification: u16,
) -> bytes::Bytes {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;

    let mut buf = bytes::BytesMut::with_capacity(total_len);
    buf.resize(total_len, 0);

    // IP Header
    {
        let mut ip = MutableIpv4Packet::new(&mut buf).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(total_len as u16);
        ip.set_identification(identification);
        ip.set_flags(0);
        ip.set_fragment_offset(0);
        ip.set_ttl(ttl);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip.set_source(src_ip);
        ip.set_destination(dst_ip);
    }

    // IP checksum
    let ip_csum = ipv4_checksum(&buf[..20]);
    buf[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // UDP Header
    {
        let mut udp = MutableUdpPacket::new(&mut buf[20..]).unwrap();
        udp.set_source(src_port);
        udp.set_destination(dst_port);
        udp.set_length(udp_len as u16);
        udp.set_checksum(0);
    }

    // UDP payload
    buf[28..28 + payload.len()].copy_from_slice(payload);

    // UDP checksum (optional for IPv4, but set for correctness)
    let udp_csum = crate::desync::tcp_checksum_v4(src_ip, dst_ip, &buf[20..20 + udp_len]);
    buf[26..28].copy_from_slice(&udp_csum.to_be_bytes());

    buf.freeze()
}

// ============================================================================
// QUIC packet parsing helpers (T41: PN extraction, DCID extraction)
// ============================================================================

/// QUIC Variable-Length Integer (RFC 9000 §16).
///
/// Два старших бита первого байта кодируют размер:
/// - 00: 1 байт (6 бит данных)
/// - 01: 2 байта (14 бит данных)
/// - 10: 4 байта (30 бит данных)
/// - 11: 8 байт (62 бита данных)
///
/// Возвращает `(value, bytes_consumed)` или `None` при недостатке данных.
pub fn parse_quic_varint(data: &[u8]) -> Option<(u64, usize)> {
    if data.is_empty() {
        return None;
    }
    let first = data[0];
    let prefix = first >> 6;
    let consumed = 1usize << prefix; // 1, 2, 4, 8

    if data.len() < consumed {
        return None;
    }

    let value = match prefix {
        0 => u64::from(first & 0x3F),
        1 => u64::from(u16::from_be_bytes([data[0], data[1]]) & 0x3FFF),
        2 => {
            let buf: [u8; 4] = data[..4].try_into().unwrap();
            u64::from(u32::from_be_bytes(buf) & 0x3FFF_FFFF)
        }
        3 => {
            let buf: [u8; 8] = data[..8].try_into().unwrap();
            u64::from_be_bytes(buf) & 0x3FFF_FFFF_FFFF_FFFF
        }
        _ => unreachable!(),
    };

    Some((value, consumed))
}

/// Извлечение QUIC Packet Number и Destination Connection ID.
///
/// Поддерживает Long Header (Initial, Handshake, 0-RTT, Retry)
/// и Short Header (1-RTT) пакеты.
///
/// Возвращает `(packet_number, dcid_bytes)` или `None`, если
/// пакет не является корректным QUIC.
pub fn extract_quic_pn_and_dcid(packet: &[u8]) -> Option<(u64, Vec<u8>)> {
    // Минимальная длина: 1 байт флагов
    if packet.is_empty() {
        return None;
    }

    let first = packet[0];
    let is_long_header = (first & 0x80) != 0;

    if is_long_header {
        extract_long_header_pn_dcid(packet)
    } else {
        extract_short_header_pn_dcid(packet)
    }
}

/// Long Header: версия (4), DCID len (1), DCID (N), SCID len (1), ...
/// PN находится после всех полей заголовка, в последних 1-4 байтах
/// (зависит от PN Length из флагов).
fn extract_long_header_pn_dcid(packet: &[u8]) -> Option<(u64, Vec<u8>)> {
    if packet.len() < 6 {
        return None;
    }

    let first = packet[0];
    let _version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);

    let dcid_len = packet[5] as usize;
    let dcid_end = 6 + dcid_len;

    if packet.len() < dcid_end + 1 {
        return None;
    }
    let dcid = packet[6..dcid_end].to_vec();

    // SCID length
    let scid_len = packet[dcid_end] as usize;
    let scid_end = dcid_end + 1 + scid_len;

    if packet.len() < scid_end {
        return None;
    }

    // Для Initial: есть Token Length (varint) + Token
    // Для всех Long Header: Length (varint) + PN
    let after_scid = &packet[scid_end..];

    // Определяем тип Long Header по битам 4-5 флагов
    let long_type = (first >> 4) & 0x03;
    let mut offset = 0;

    // Initial (type=0) и Retry (type=3) имеют Token
    if long_type == 0 || long_type == 3 {
        let (token_len, consumed) = parse_quic_varint(after_scid)?;
        offset += consumed;
        let token_end = offset + token_len as usize;
        if after_scid.len() < token_end {
            return None;
        }
        offset = token_end;
    }

    // Length (varint)
    let (_, consumed) = parse_quic_varint(&after_scid[offset..])?;
    offset += consumed;

    // Packet Number: 1-4 байта (PN Length = (flags & 0x03) + 1)
    let pn_len = (first as usize & 0x03) + 1;
    if after_scid.len() < offset + pn_len {
        return None;
    }

    let pn = match pn_len {
        1 => u64::from(after_scid[offset]),
        2 => u64::from(u16::from_be_bytes([
            after_scid[offset],
            after_scid[offset + 1],
        ])),
        3 => {
            let buf: [u8; 4] = [
                0,
                after_scid[offset],
                after_scid[offset + 1],
                after_scid[offset + 2],
            ];
            u64::from(u32::from_be_bytes(buf))
        }
        4 => {
            let buf: [u8; 8] = [
                0,
                0,
                0,
                0,
                after_scid[offset],
                after_scid[offset + 1],
                after_scid[offset + 2],
                after_scid[offset + 3],
            ];
            u64::from_be_bytes(buf)
        }
        _ => unreachable!(),
    };

    Some((pn, dcid))
}

/// Short Header: DCID (до 8 байт, negotiated), затем PN (1-4 байта).
/// Для short header мы не знаем длину DCID, если нет контекста.
/// По умолчанию пробуем все возможные длины DCID (8 байт,
/// как самое частое значение для Initial-установленных соединений).
fn extract_short_header_pn_dcid(packet: &[u8]) -> Option<(u64, Vec<u8>)> {
    if packet.len() < 2 {
        return None;
    }

    // Short Header: флаги + DCID + PN
    // DCID длина — по умолчанию 8 байт (наиболее распространённая)
    // PN Length = (flags & 0x03) + 1, но для short header биты 0-1
    // могут быть зарезервированы (RFC 9000).
    // Используем фиксированное предположение: PN = последние 4 байта заголовка,
    // всё что между flags и PN — DCID.
    let first = packet[0];
    let pn_len = ((first >> 2) & 0x03) as usize + 1; // Spin bit + Reserved + Key Phase + PN Length

    // Минимум: flags + 1 байт DCID + PN
    let min_len = 1 + 1 + pn_len;
    if packet.len() < min_len {
        return None;
    }

    let dcid_len = packet.len() - 1 - pn_len;
    if dcid_len > 20 || dcid_len == 0 {
        return None;
    }

    let dcid = packet[1..1 + dcid_len].to_vec();
    let pn_offset = 1 + dcid_len;

    let pn = match pn_len {
        1 => u64::from(packet[pn_offset]),
        2 => u64::from(u16::from_be_bytes([
            packet[pn_offset],
            packet[pn_offset + 1],
        ])),
        3 => {
            let buf: [u8; 4] = [
                0,
                packet[pn_offset],
                packet[pn_offset + 1],
                packet[pn_offset + 2],
            ];
            u64::from(u32::from_be_bytes(buf))
        }
        4 => {
            let buf: [u8; 8] = [
                0,
                0,
                0,
                0,
                packet[pn_offset],
                packet[pn_offset + 1],
                packet[pn_offset + 2],
                packet[pn_offset + 3],
            ];
            u64::from_be_bytes(buf)
        }
        _ => unreachable!(),
    };

    Some((pn, dcid))
}

// ============================================================================
// T44.3: Test helpers — build_test_quic_initial_packet, encode_quic_varint
// ============================================================================

/// Encode integer as QUIC variable-length integer (RFC 9000 §16).
///
/// Два старших бита первого байта кодируют размер varint:
/// - 00: 1 байт (6 бит данных, диапазон 0..63)
/// - 01: 2 байта (14 бит данных, диапазон 0..16383)
/// - 10: 4 байта (30 бит данных, диапазон 0..1073741823)
/// - 11: 8 байт (62 бита данных)
#[cfg(test)]
pub fn encode_quic_varint(value: u64) -> Vec<u8> {
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

/// Build minimal valid QUIC Initial packet with given PN, for testing.
///
/// Собирает full IP + UDP + QUIC Initial:
/// 1. Минимальный CRYPTO frame (type=0x06, offset=0, length=0)
/// 2. Padding до 1200 байт (QUIC minimum)
/// 3. Шифрование через `quic_v1_initial_encrypt` с RFC 9001 test DCID
/// 4. Обёртка в UDP + IP
#[cfg(test)]
fn build_test_quic_initial_packet(pn: u32) -> Vec<u8> {
    use crate::desync::build_ip_packet;

    let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]; // RFC 9001 test DCID

    let pn_bytes = pn.to_be_bytes(); // 4 bytes

    // Minimal CRYPTO frame: type=0x06, offset=0 (varint), length=0 (varint)
    let crypto_frame = [0x06, 0x00, 0x00];

    // Pad to 1200 bytes minimum (QUIC requirement), minus PN(4) and AEAD tag(16)
    let mut payload = Vec::new();
    payload.extend_from_slice(&crypto_frame);
    while payload.len() < 1200 - 4 - 16 {
        payload.push(0x00); // PADDING frame (type=0x00)
    }

    // Build header (without PN, before encryption)
    let mut header = Vec::new();
    header.push(0xC3); // Long + Initial + PN=4 bytes
    header.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // QUIC v1
    header.push(dcid.len() as u8);
    header.extend_from_slice(&dcid);
    header.push(0x00); // SCID length
    header.push(0x00); // Token length (varint)
                       // Length field: PN(4) + encrypted_payload_len (which includes AEAD tag 16)
    let total_remaining = 4 + payload.len() + 16; // PN + payload + AEAD tag
    let length_varint = encode_quic_varint(total_remaining as u64);
    header.extend_from_slice(&length_varint);

    // Encrypt using QUIC v1 Initial protection
    let encrypted = quic_v1_initial_encrypt(
        &header, pn as u64, 4, // pn_len
        &payload, &dcid,
    )
    .expect("QUIC encryption failed in test helper");

    // Wrap in UDP packet
    let src_ip = Ipv4Addr::new(192, 168, 1, 2);
    let dst_ip = Ipv4Addr::new(142, 250, 185, 46);
    let src_port: u16 = 54321;
    let dst_port: u16 = 443;

    let udp_len = 8 + encrypted.len();
    let mut udp_packet = Vec::with_capacity(udp_len);
    udp_packet.extend_from_slice(&src_port.to_be_bytes());
    udp_packet.extend_from_slice(&dst_port.to_be_bytes());
    udp_packet.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp_packet.extend_from_slice(&[0x00, 0x00]); // checksum = 0 (optional)
    udp_packet.extend_from_slice(&encrypted);

    // Wrap in IP packet
    build_ip_packet(
        src_ip,
        dst_ip,
        pnet_packet::ip::IpNextHeaderProtocols::Udp,
        64,
        0x1234,
        &udp_packet,
    )
    .to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_quic_initial() {
        let dcid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let payload = build_quic_initial(&dcid, "example.com");
        assert!(!payload.is_empty());
        // Long Header flag
        assert!(payload[0] & 0x80 != 0);
        // Version
        assert_eq!(
            u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]),
            QUIC_VERSION_1
        );
    }

    #[test]
    fn test_build_udp_packet() {
        let pkt = build_udp_packet(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(8, 8, 8, 8),
            crate::desync::rand::random_range(1024, 65535) as u16,
            443,
            &[0x01, 0x02],
            64,
            1,
        );
        assert_eq!(pkt.len(), 20 + 8 + 2); // IP + UDP + payload
        assert_eq!(pkt[0] >> 4, 4); // IPv4
        assert_eq!(pkt[9], 17); // UDP protocol
    }

    #[test]
    fn test_quic_long_header_detection() {
        let long_header = vec![
            0xC0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        assert!(long_header[0] & 0x80 != 0); // Long Header

        let short_header = vec![0x40, 0x00, 0x00, 0x01];
        assert!(short_header[0] & 0x80 == 0); // Short Header
    }

    fn make_quic_packet() -> Vec<u8> {
        // IP(20) + UDP(8) + QUIC Initial(20+)
        let quic_payload = vec![
            0xC0, // Long Header + Initial
            0x00, 0x00, 0x00, 0x01, // Version 1
            0x08, // DCID len
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
            0x00, // SCID len
        ];
        let udp_len = 8 + quic_payload.len();
        let total = 20 + udp_len;
        let mut pkt = vec![0u8; total];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&[192, 168, 1, 1]);
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);
        // UDP header
        pkt[20..22].copy_from_slice(
            &(crate::desync::rand::random_range(1024, 65535) as u16).to_be_bytes(),
        );
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        // QUIC payload
        let data_start = 28;
        pkt[data_start..data_start + quic_payload.len()].copy_from_slice(&quic_payload);
        let csum = ipv4_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&csum.to_be_bytes());
        pkt
    }

    #[test]
    fn test_quic_blocking() {
        let pkt = make_quic_packet();
        let result = quic_blocking(&pkt);
        assert!(result.drop);
    }

    #[test]
    fn test_quic_version_downgrade() {
        let pkt = make_quic_packet();
        let result = quic_version_downgrade(&pkt, 0xFF00_001D, 1);
        assert_eq!(result.inject.len(), 1);
    }

    #[test]
    fn test_quic_retry_inject() {
        let pkt = make_quic_packet();
        let result = quic_retry_inject(&pkt, 1);
        assert_eq!(result.inject.len(), 1);
    }

    #[test]
    fn test_quic_connection_close() {
        let pkt = make_quic_packet();
        let result = quic_connection_close(&pkt, 0x01, 1);
        assert_eq!(result.inject.len(), 1);
    }

    #[test]
    fn test_quic_stream_reset() {
        let pkt = make_quic_packet();
        let result = quic_stream_reset(&pkt, 1);
        assert_eq!(result.inject.len(), 1);
    }

    #[test]
    fn test_quic_max_streams() {
        let pkt = make_quic_packet();
        let result = quic_max_streams(&pkt, 100, 1);
        assert_eq!(result.inject.len(), 1);
    }

    #[test]
    fn test_quic_new_connection_id() {
        let pkt = make_quic_packet();
        let result = quic_new_connection_id(&pkt, 1);
        assert_eq!(result.inject.len(), 1);
    }

    #[test]
    fn test_non_quic_passthrough() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6; // TCP, not UDP
        pkt[12..16].copy_from_slice(&[192, 168, 1, 1]);
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);
        let csum = ipv4_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&csum.to_be_bytes());
        assert!(quic_blocking(&pkt).inject.is_empty());
        assert!(!quic_blocking(&pkt).drop);
    }

    /// RFC 9001 Appendix A.1 test vector — key derivation.
    #[test]
    fn test_quic_initial_key_derivation_rfc9001_vector() {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let keys = derive_quic_initial_keys(&dcid).expect("key derivation failed");

        let expected_key = [
            0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1,
            0xa2, 0x2d,
        ];
        let expected_iv = [
            0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c,
        ];
        let expected_hp = [
            0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad,
            0xed, 0xd2,
        ];

        assert_eq!(keys.key, expected_key, "client_key mismatch");
        assert_eq!(keys.iv, expected_iv, "client_iv mismatch");
        assert_eq!(keys.hp, expected_hp, "client_hp mismatch");
    }

    /// RFC 5869 §4.1 HKDF test vector.
    #[test]
    fn test_hkdf_extract_rfc5869_test1() {
        let ikm = [0x0b; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let prk = hkdf_extract(&salt, &ikm);
        let expected = [
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5,
        ];
        assert_eq!(prk, expected);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let header = vec![
            0xC3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
            0x00, 0x00, 0x41, 0x18,
        ];
        let pn: u64 = 0;
        let pn_len = 4;
        let payload = vec![
            0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, b'h', b'e', b'l', b'l', b'o',
        ];

        let encrypted = quic_v1_initial_encrypt(&header, pn, pn_len, &payload, &dcid)
            .expect("encryption failed");
        let decrypted = quic_v1_initial_decrypt(&encrypted, header.len(), pn_len, &dcid)
            .expect("decryption failed");

        assert_eq!(decrypted, payload, "roundtrip failed");
    }

    #[test]
    fn test_build_quic_initial_with_crypto() {
        let dcid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let scid = [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18];

        let result = build_quic_initial_with_crypto(&dcid, &scid, "example.com");
        assert!(result.is_some());

        let packet = result.unwrap();
        // Should be at least 1200 bytes
        assert!(packet.len() >= 1200);
        // Long Header flag
        assert!(packet[0] & 0x80 != 0);
        // Version
        assert_eq!(
            u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]),
            QUIC_VERSION_1
        );
        // DCID length
        assert_eq!(packet[5], 8);
        // SCID length (at byte 14: version[1..5] + dcid_len[5] + dcid[6..13])
        let scid_len_offset = 6 + 8; // after DCID bytes
        assert_eq!(packet[scid_len_offset], 8);
    }

    // ========================================================================
    // T44.3: build_test_quic_initial_packet + encode_quic_varint tests
    // ========================================================================

    #[test]
    fn test_build_test_quic_initial_packet_not_empty() {
        let packet = build_test_quic_initial_packet(0);
        assert!(!packet.is_empty(), "test packet must not be empty");
        assert!(
            packet.len() > 1200,
            "QUIC Initial should be >= 1200 bytes, got {}",
            packet.len()
        );
    }

    #[test]
    fn test_build_test_quic_initial_packet_parses() {
        let packet = build_test_quic_initial_packet(42);
        // extract_quic_pn_and_dcid expects raw QUIC, not IP+UDP+QUIC
        // Skip IP header (20 bytes for IPv4) + UDP header (8 bytes)
        if packet.len() > 28 {
            let quic_layer = &packet[28..];
            let (pn, dcid) = extract_quic_pn_and_dcid(quic_layer).expect("parse failed");
            assert!(!dcid.is_empty(), "DCID must be extracted");
            assert!(pn <= 0xFFFFFFFF, "PN should fit in 32 bits, got 0x{:X}", pn);
        }
    }

    #[test]
    fn test_encode_quic_varint_1byte() {
        assert_eq!(encode_quic_varint(37), vec![0x25]);
    }

    #[test]
    fn test_encode_quic_varint_2byte() {
        assert_eq!(encode_quic_varint(15293), vec![0x7B, 0xBD]);
    }

    #[test]
    fn test_encode_quic_varint_4byte_roundtrip() {
        let v = 15293000u64;
        let encoded = encode_quic_varint(v);
        assert_eq!(encoded.len(), 4);
        let (decoded, _) = parse_quic_varint(&encoded).expect("parse failed");
        assert_eq!(decoded, v);
    }

    #[test]
    fn test_encode_quic_varint_8byte_roundtrip() {
        // Max 62-bit value (QUIC varint max: 2^62 - 1)
        let v = (1u64 << 62) - 1; // 0x3FFF_FFFF_FFFF_FFFF
        let encoded = encode_quic_varint(v);
        assert_eq!(encoded.len(), 8);
        let (decoded, _) = parse_quic_varint(&encoded).expect("parse failed");
        assert_eq!(decoded, v);
    }

    #[test]
    fn test_encode_quic_varint_roundtrip_boundaries() {
        // Test boundary conditions for each varint length
        let cases = [0u64, 63, 64, 16383, 16384, 1073741823, 1073741824];
        for v in cases {
            let encoded = encode_quic_varint(v);
            let (decoded, _) =
                parse_quic_varint(&encoded).unwrap_or_else(|| panic!("parse failed for {}", v));
            assert_eq!(decoded, v, "roundtrip failed for {}", v);
        }
    }
}
