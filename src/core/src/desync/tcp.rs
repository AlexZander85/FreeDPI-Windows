//! TCP Desync техники (zapret core Z1-Z10 + byedpi 03-05).
//!
//! ## Принципы
//! Все TCP desync техники основаны на трёх идеях:
//!
//! 1. **Segment Splitting** — разбить первый пакет данных на сегменты
//!    так, чтобы DPI увидел fake данные, а сервер — реальные.
//! 2. **Out-of-Order** — отправить сегменты с нарушением порядка.
//!    DPI собирает неправильно, сервер — правильно (TCP reassembly).
//! 3. **Fake Data** — вставить перед реальными данными поддельный
//!    заголовок (SNI, Host, ClientHello). DPI цепляется за него.
//!
//! ## Категории
//! - Split: [Z1] MultiSplit, [Z3] HostFakeSplit, [Z4] FakeDataSplit
//! - Disorder: [Z2] MultiDisorder, [Z5] FakeDataDisorder
//! - Manipulation: [Z6] TcpSeg, [Z7] SynData, [Z8] SynAckSplit,
//!   [Z9] WinSize, [Z10] SynHide
//! - Injection: [03] FakeSni, [04] OobInjection
//!
//! ## Источник

#![allow(clippy::useless_conversion)]

use crate::desync::DesyncResult;
use crate::desync::{parse_ip_header, parse_tcp_packet};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv6::MutableIpv6Packet;
use pnet_packet::tcp::{MutableTcpPacket, TcpFlags};
use std::net::{IpAddr, Ipv4Addr};
use tracing::debug;

/// [Z1] MultiSplit: разделить первые N байт TCP payload на K сегментов.
///
/// ## Принцип
/// Берём первые `split_size * split_count` байт payload и разделяем их на
/// K сегментов. DPI редко может собрать K сегментов правильно, что приводит
/// к пропуску DPI-инспекции. Сервер собирает без проблем.
///
/// ## Параметры
/// - `split_size`: размер каждого сегмента (байт)
/// - `split_count`: количество сегментов
/// - `fake_ttl_offset`: уменьшение TTL для не-последних сегментов
/// - `inter_delay_us`: задержка между инъекциями (мкс, 0 = без задержки)
///
/// ## Returns
/// - `modified`: последний сегмент (с реальным началом данных, нормальный TTL)
/// - `inject`: N-1 сегментов с fake TTL (не дойдут до сервера)
pub fn multisplit(
    packet: &bytes::Bytes,
    split_size: usize,
    split_count: usize,
    fake_ttl_offset: u8,
    inter_delay_us: u32,
) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len()..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.payload.len() < split_size || split_count == 0 || split_size == 0 {
        return DesyncResult::passthrough();
    }

    let actual_count = split_count.min(tcp.payload.len() / split_size).max(1);
    if actual_count <= 1 {
        return DesyncResult::passthrough();
    }

    let mut inject: smallvec::SmallVec<[bytes::Bytes; 4]> =
        smallvec::SmallVec::with_capacity(actual_count - 1);

    for i in 0..actual_count - 1 {
        let start = i * split_size;
        let end = start + split_size.min(tcp.payload.len() - start);
        let seg_payload = &tcp.payload[start..end];

        let fake_ttl = ip.ttl().saturating_sub(fake_ttl_offset);

        // Создаём TCP сегмент с флагом PSH
        let seg = build_tcp_segment(
            ip.src(),
            ip.dst(),
            tcp.src_port,
            tcp.dst_port,
            tcp.sequence.wrapping_add(start as u32),
            tcp.acknowledgment,
            TcpFlags::PSH | TcpFlags::ACK,
            tcp.window,
            seg_payload,
            fake_ttl,
            generate_identification(ip.identification(), i),
        );
        inject.push(seg);
    }

    // Последний сегмент — нормальный TTL, отправляется через WinDivert как modified
    let last_start = (actual_count - 1) * split_size;
    let remaining = &tcp.payload[last_start..];
    let modified = build_full_tcp_packet(
        ip.src(),
        ip.dst(),
        tcp.src_port,
        tcp.dst_port,
        tcp.sequence.wrapping_add(last_start as u32),
        tcp.acknowledgment,
        TcpFlags::PSH | TcpFlags::ACK,
        tcp.window,
        remaining,
        ip.ttl(),
    );

    debug!(
        "[Z1] MultiSplit: {} segs × {} bytes → {} injects (delay={}us)",
        actual_count,
        split_size,
        inject.len(),
        inter_delay_us
    );

    DesyncResult {
        modified: Some(bytes::Bytes::from(modified)),
        inject: inject
            .into_iter()
            .map(bytes::Bytes::from)
            .collect::<smallvec::SmallVec<[bytes::Bytes; 4]>>(),
        inter_delay_us,
        drop: false,
        inject_direction: crate::desync::InjectDirection::PreserveOriginal,
    }
}

/// [Z2] MultiDisorder: отправить сегменты в случайном порядке.
///
/// ## Принцип
/// Как MultiSplit, но сегменты отправляются в порядке,
/// отличном от ожидаемого DPI. DPI сбрасывает поток при
/// неожиданном SEQ, сервер спокойно ждёт все сегменты.
pub fn multidisorder(
    packet: &bytes::Bytes,
    split_size: usize,
    split_count: usize,
    fake_ttl_offset: u8,
) -> DesyncResult {
    // Используем multisplit + переставляем inject в обратном порядке
    let mut result = multisplit(packet, split_size, split_count, fake_ttl_offset, 0);
    result.inject.reverse();
    debug!(
        "[Z2] MultiDisorder: {} segments reversed",
        result.inject.len()
    );
    result
}

/// [Z4] FakeDataSplit: вставить fake данные перед реальными + split.
///
/// ## Принцип
/// Вставляем перед реальным ClientHello поддельный TCP сегмент
/// с fake SNI (Host: example.com). DPI видит fake SNI первым и
/// останавливает инспекцию. Реальный ClientHello идёт следом.
///
/// ## Параметры
/// - `fake_sni`: SNI для fake ClientHello
/// - `fake_ttl_offset`: TTL offset для fake данных
pub fn fakedsplit(packet: &bytes::Bytes, fake_sni: &str, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len()..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.payload.is_empty() {
        return DesyncResult::passthrough();
    }

    // Строим fake TLS ClientHello с указанным SNI
    let fake_payload = build_fake_clienthello(fake_sni);

    // Fake сегмент с TTL-1 — ТОТ ЖЕ SEQ что и оригинал
    let fake_ttl = ip.ttl().saturating_sub(fake_ttl_offset);
    let fake_seg = build_tcp_segment(
        ip.src(),
        ip.dst(),
        tcp.src_port,
        tcp.dst_port,
        tcp.sequence,
        tcp.acknowledgment,
        TcpFlags::PSH | TcpFlags::ACK,
        tcp.window,
        &fake_payload,
        fake_ttl,
        generate_identification(ip.identification(), 0),
    );

    debug!(
        "[Z4] FakeDataSplit: fake '{}' ({} bytes) + real ({} bytes)",
        fake_sni,
        fake_payload.len(),
        tcp.payload.len()
    );

    // inject_only — оригинал проходит через Forward без модификации
    DesyncResult::inject_only(fake_seg)
}

/// [Z6] TcpSeg: манипуляция TCP сегментацией.
///
/// ## Принцип
/// Разделяем payload на сегменты по `max_seg_size`. Отправляем все
/// сегменты с PSH+ACK. DPI сбрасывает поток при превышении лимита
/// сегментов. Сервер собирает всё по SEQ.
pub fn tcpseg(packet: &bytes::Bytes, max_seg_size: usize, _fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len()..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.payload.len() <= max_seg_size {
        return DesyncResult::passthrough();
    }

    let mut inject: smallvec::SmallVec<[bytes::Bytes; 4]> = smallvec::SmallVec::new();
    let mut pos = 0;

    while pos + max_seg_size < tcp.payload.len() {
        let end = pos + max_seg_size;
        let seg = &tcp.payload[pos..end];

        let pkt = build_tcp_segment(
            ip.src(),
            ip.dst(),
            tcp.src_port,
            tcp.dst_port,
            tcp.sequence.wrapping_add(pos as u32),
            tcp.acknowledgment,
            TcpFlags::PSH | TcpFlags::ACK,
            tcp.window,
            seg,
            ip.ttl(),
            generate_identification(ip.identification(), inject.len()),
        );
        inject.push(pkt);
        pos = end;
    }

    // Последний фрагмент — нормальный TTL
    let remaining = &tcp.payload[pos..];
    let modified = build_full_tcp_packet(
        ip.src(),
        ip.dst(),
        tcp.src_port,
        tcp.dst_port,
        tcp.sequence.wrapping_add(pos as u32),
        tcp.acknowledgment,
        TcpFlags::PSH | TcpFlags::ACK,
        tcp.window,
        remaining,
        ip.ttl(),
    );

    debug!(
        "[Z6] TcpSeg: {} segs × {} bytes max",
        inject.len() + 1,
        max_seg_size
    );

    DesyncResult {
        modified: Some(bytes::Bytes::from(modified)),
        inject: inject.into_iter().collect(),
        inter_delay_us: 0,
        drop: false,
        inject_direction: crate::desync::InjectDirection::PreserveOriginal,
    }
}

/// [Z7] SynData: данные в SYN пакете.
///
/// ## Принцип
/// Некоторые DPI не ожидают данные в SYN пакете (RFC не запрещает).
/// Добавляем первые N байт данных в SYN. DPI может сбиться на
/// нестандартном SYN с данными.
pub fn syndata(packet: &bytes::Bytes, sync_data: &[u8], fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len()..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.flags & TcpFlags::SYN == 0 || tcp.flags & TcpFlags::ACK != 0 {
        return DesyncResult::passthrough();
    }

    // SYN с данными (флаг SYN + PSH)
    let fake_ttl = ip.ttl().saturating_sub(fake_ttl_offset);
    let inject_pkt = build_tcp_segment(
        ip.src(),
        ip.dst(),
        tcp.src_port,
        tcp.dst_port,
        tcp.sequence,
        0,
        TcpFlags::SYN | TcpFlags::PSH,
        tcp.window,
        sync_data,
        fake_ttl,
        ip.identification().wrapping_add(1),
    );

    debug!("[Z7] SynData: SYN + {} bytes data", sync_data.len());

    DesyncResult::inject_only(inject_pkt)
}

/// [Z9] WinSize: манипуляция размером окна.
///
/// ## Принцип
/// Уменьшаем window size в SYN-ACK. DPI может неправильно
/// рассчитать окно TCP и потерять sync с потоком. Сервер
/// игнорирует window в SYN-ACK (использует свой).
pub fn winsize(packet: &bytes::Bytes, new_window: u16) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len()..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    let mut buf = packet.to_vec();

    // Меняем window size в TCP header
    let window_offset = ip.header_len() + 14; // TCP window offset
    if window_offset + 2 <= buf.len() {
        buf[window_offset..window_offset + 2].copy_from_slice(&new_window.to_be_bytes());

        // Пересчитываем TCP checksum
        let tcp_segment = &buf[ip.header_len()..];
        let new_checksum = crate::desync::tcp_checksum(ip.src(), ip.dst(), tcp_segment);
        let csum_offset = ip.header_len() + 16;
        buf[csum_offset..csum_offset + 2].copy_from_slice(&new_checksum.to_be_bytes());
    }

    debug!("[Z9] WinSize: {} → {}", tcp.window, new_window);

    DesyncResult::modified_only(buf)
}

/// [Z10] SynHide: скрыть SYN от DPI.
///
/// ## Принцип
/// Отправляем SYN + данные в одном сегменте (нестандартно).
/// DPI ожидает отдельный SYN и отдельный первый data-пакет.
/// Объединённый пакет проходит незамеченным.
pub fn synhide(packet: &bytes::Bytes, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len()..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.flags & TcpFlags::SYN == 0 || tcp.payload.is_empty() {
        return DesyncResult::passthrough();
    }

    // Original packet stays as-is (SYN alone, no data)
    let modified = packet.to_vec();

    // Второй пакет: PSH+ACK с данными, но без SYN flag
    let fake_ttl = ip.ttl().saturating_sub(fake_ttl_offset);
    let inject_pkt = build_tcp_segment(
        ip.src(),
        ip.dst(),
        tcp.src_port,
        tcp.dst_port,
        tcp.sequence.wrapping_add(1),
        tcp.acknowledgment,
        TcpFlags::PSH | TcpFlags::ACK,
        tcp.window,
        tcp.payload,
        fake_ttl,
        ip.identification().wrapping_add(1),
    );

    debug!("[Z10] SynHide: SYN alone → data in separate fake seg");

    DesyncResult::modify_and_inject(modified, inject_pkt)
}

/// [03] FakeSni: инъекция fake SNI с per-connection RNG.
///
/// ## Принцип
/// Внедряем в поток fake TLS ClientHello с поддельным SNI.
/// DPI видит fake SNI первым (самый ранний по SEQ). Сервер
/// получает fake CH с TTL-1 (не доходит) и реальный CH с
/// нормальным TTL (доходит).
///
/// T44.5: принимает `conn_rng` для генерации per-connection TLS Random / session_id /
/// key_share. НЕ использует template (детерминированный random — fingerprint).
/// Если `conn_rng` отсутствует, создаёт временный RNG из SEQ (fallback).
pub fn fake_sni(
    packet: &bytes::Bytes,
    fake_sni_str: &str,
    fake_ttl_offset: u8,
    conn_rng: Option<&mut crate::desync::rand::PerConnRng>,
    is_resumption: bool,
) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len()..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.payload.is_empty() {
        return DesyncResult::passthrough();
    }

    // T44.5: строим per-connection CH через RNG (не template!)
    // Fork — fake CH не должен коррелировать с real CH (T27 principle)
    let fake_payload = match conn_rng {
        Some(rng) => {
            let mut fake_rng = rng.fork();
            crate::adaptive::ch_gen::build_client_hello_with_resumption(
                fake_sni_str,
                &mut fake_rng,
                is_resumption,
            )
        }
        None => {
            let mut fresh_rng = crate::desync::rand::PerConnRng::new(
                ((tcp.sequence as u64) << 32) ^ (tcp.src_port as u64),
            );
            crate::adaptive::ch_gen::build_client_hello_with_resumption(
                fake_sni_str,
                &mut fresh_rng,
                is_resumption,
            )
        }
    };

    // Fake CH: out-of-window SEQ — далеко за пределами текущего окна
    let fake_seq = tcp.sequence.wrapping_add(tcp.window as u32 + 1);
    let fake_ttl = ip.ttl().saturating_sub(fake_ttl_offset);
    let fake_pkt = build_tcp_segment(
        ip.src(),
        ip.dst(),
        tcp.src_port,
        tcp.dst_port,
        fake_seq,
        tcp.acknowledgment,
        TcpFlags::PSH | TcpFlags::ACK,
        tcp.window,
        &fake_payload,
        fake_ttl,
        generate_identification(ip.identification(), 0),
    );

    debug!(
        "[03] FakeSni: inject fake CH '{}' ({} bytes) before real data ({} bytes) is_resumption={}",
        fake_sni_str,
        fake_payload.len(),
        tcp.payload.len(),
        is_resumption,
    );

    DesyncResult::inject_only(fake_pkt)
}

/// [OF3] ReverseFragmentOrder: отправка фрагментов в обратном порядке.
///
/// ## Принцип
/// Берёт результат другой split-техники (MultiSplit, TcpSeg) и меняет
/// порядок inject-фрагментов на обратный. DPI ожидает сегменты в
/// нормальном порядке (по возрастанию SEQ). При обратном порядке DPI
/// может сбиться или пропустить инспекцию.
///
/// Сервер (Linux TCP stack) спокойно собирает сегменты в любом порядке,
/// так как TCP гарантирует упорядоченную доставку потока.
///
/// ## Использование
/// Применяется как пост-процессор к результату другой техники:
/// ```rust,no_run
/// # use freedpi_core::desync::tcp;
/// # let packet = bytes::Bytes::from(vec![0u8; 40]);
/// let result = tcp::multisplit(&packet, 1, 3, 1, 0);
/// let reversed = tcp::reverse_fragment_order(result);
/// ```
///
/// ## Источник
/// offveil [OF3] — Reverse Fragment Order
pub fn reverse_fragment_order(mut result: DesyncResult) -> DesyncResult {
    if result.inject.len() <= 1 {
        return result;
    }
    result.inject.reverse();
    debug!(
        "[OF3] ReverseFragmentOrder: {} fragments reversed",
        result.inject.len()
    );
    result
}

/// [04] OobInjection: внеполосная (Urgent) инъекция.
///
/// ## Принцип
/// Используем флаг URG (Urgent) в TCP. DPI может неправильно
/// обработать OOB данные или сбросить поток. Сервер обычно
/// игнорирует OOB.
pub fn oob_injection(
    packet: &bytes::Bytes,
    fake_sni_str: &str,
    fake_ttl_offset: u8,
) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len()..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    // Fake CH payload с urg pointer
    let fake_payload = build_fake_clienthello(fake_sni_str);

    let fake_ttl = ip.ttl().saturating_sub(fake_ttl_offset);
    // Use build_ip_tcp_packet_with_options to preserve TCP options from original
    let mut fake_pkt = build_ip_tcp_packet_with_options(
        packet,
        ip.src(),
        ip.dst(),
        tcp.src_port,
        tcp.dst_port,
        tcp.sequence,
        tcp.acknowledgment,
        TcpFlags::URG | TcpFlags::PSH | TcpFlags::ACK,
        tcp.window,
        &fake_payload,
        fake_ttl,
        generate_identification(ip.identification(), 0),
    );

    // In-place urg_ptr update: point to end of urgent data
    {
        let ip_hdr_len = 20; // standard IP header
        let data_offset = ((fake_pkt[ip_hdr_len + 12] >> 4) & 0x0F) as usize * 4;
        let urg_ptr_offset = ip_hdr_len + data_offset - 2;
        if urg_ptr_offset + 2 <= fake_pkt.len() {
            let mut fake_pkt_mut = bytes::BytesMut::from(&*fake_pkt);
            let urg_ptr = (fake_payload.len() as u16).to_be_bytes();
            fake_pkt_mut[urg_ptr_offset..urg_ptr_offset + 2].copy_from_slice(&urg_ptr);
            fake_pkt = fake_pkt_mut.freeze();
        }
    }

    debug!("[04] OobInjection: URG flag + fake CH '{}'", fake_sni_str);

    DesyncResult::inject_only(fake_pkt)
}

// ==================== Вспомогательные функции ====================

/// Строит полный IP+TCP пакет — alloc, zero-init, write, checksum, consume.
#[allow(clippy::too_many_arguments)]
fn build_ip_tcp_packet(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
    ttl: u8,
    identification: u16,
) -> bytes::Bytes {
    let tcp_header_len = 20;

    match (src_ip, dst_ip) {
        (IpAddr::V4(src_v4), IpAddr::V4(dst_v4)) => {
            let total_len = 20 + tcp_header_len + payload.len();

            let mut buf = bytes::BytesMut::with_capacity(total_len);
            buf.resize(total_len, 0);

            // IP header (bytes 0..20)
            buf[0] = 0x45;
            buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
            buf[4..6].copy_from_slice(&identification.to_be_bytes());
            buf[8] = ttl;
            buf[9] = 6; // TCP
            buf[12..16].copy_from_slice(&src_v4.octets());
            buf[16..20].copy_from_slice(&dst_v4.octets());

            // TCP header (bytes 20..40)
            buf[20..22].copy_from_slice(&src_port.to_be_bytes());
            buf[22..24].copy_from_slice(&dst_port.to_be_bytes());
            buf[24..28].copy_from_slice(&seq.to_be_bytes());
            buf[28..32].copy_from_slice(&ack.to_be_bytes());
            buf[32] = 0x50; // data offset = 5
            buf[33] = flags;
            buf[34..36].copy_from_slice(&window.to_be_bytes());

            // Payload (bytes 40..)
            buf[40..].copy_from_slice(payload);

            // Checksums
            let ip_csum = crate::desync::ipv4_checksum(&buf[..20]);
            buf[10..12].copy_from_slice(&ip_csum.to_be_bytes());
            let tcp_csum =
                crate::desync::tcp_checksum(IpAddr::V4(src_v4), IpAddr::V4(dst_v4), &buf[20..]);
            buf[36..38].copy_from_slice(&tcp_csum.to_be_bytes());

            buf.freeze()
        }
        (IpAddr::V6(src_v6), IpAddr::V6(dst_v6)) => {
            let ip_header_len = 40;
            let total_len = ip_header_len + tcp_header_len + payload.len();

            let mut buf = bytes::BytesMut::with_capacity(total_len);
            buf.resize(total_len, 0);

            // IPv6 header (bytes 0..40)
            {
                let mut ip = MutableIpv6Packet::new(&mut buf[..ip_header_len]).unwrap();
                ip.set_version(6);
                ip.set_traffic_class(0);
                ip.set_flow_label(0);
                ip.set_payload_length((tcp_header_len + payload.len()) as u16);
                ip.set_next_header(IpNextHeaderProtocols::Tcp);
                ip.set_hop_limit(ttl);
                ip.set_source(src_v6);
                ip.set_destination(dst_v6);
            }

            // TCP header (bytes 40..60)
            let tcp_start = ip_header_len;
            buf[tcp_start..tcp_start + 2].copy_from_slice(&src_port.to_be_bytes());
            buf[tcp_start + 2..tcp_start + 4].copy_from_slice(&dst_port.to_be_bytes());
            buf[tcp_start + 4..tcp_start + 8].copy_from_slice(&seq.to_be_bytes());
            buf[tcp_start + 8..tcp_start + 12].copy_from_slice(&ack.to_be_bytes());
            buf[tcp_start + 12] = 0x50;
            buf[tcp_start + 13] = flags;
            buf[tcp_start + 14..tcp_start + 16].copy_from_slice(&window.to_be_bytes());

            // Payload (bytes 60..)
            buf[tcp_start + tcp_header_len..].copy_from_slice(payload);

            // TCP checksum (no IP checksum for V6)
            let tcp_csum = crate::desync::tcp_checksum(
                IpAddr::V6(src_v6),
                IpAddr::V6(dst_v6),
                &buf[tcp_start..],
            );
            buf[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_csum.to_be_bytes());

            buf.freeze()
        }
        _ => {
            tracing::warn!(
                "build_ip_tcp_packet: mixed V4/V6 src/dst ({}/{}), using V4 fallback",
                src_ip,
                dst_ip
            );
            let total_len = 20 + tcp_header_len + payload.len();

            let mut buf = bytes::BytesMut::with_capacity(total_len);
            buf.resize(total_len, 0);

            buf[0] = 0x45;
            buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
            buf[4..6].copy_from_slice(&identification.to_be_bytes());
            buf[8] = ttl;
            buf[9] = 6;
            buf[20..22].copy_from_slice(&src_port.to_be_bytes());
            buf[22..24].copy_from_slice(&dst_port.to_be_bytes());
            buf[24..28].copy_from_slice(&seq.to_be_bytes());
            buf[28..32].copy_from_slice(&ack.to_be_bytes());
            buf[32] = 0x50;
            buf[33] = flags;
            buf[34..36].copy_from_slice(&window.to_be_bytes());
            buf[40..].copy_from_slice(payload);

            let ip_csum = crate::desync::ipv4_checksum(&buf[..20]);
            buf[10..12].copy_from_slice(&ip_csum.to_be_bytes());
            let tcp_csum = crate::desync::tcp_checksum(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                &buf[20..],
            );
            buf[36..38].copy_from_slice(&tcp_csum.to_be_bytes());

            buf.freeze()
        }
    }
}

/// Строит полный IP+TCP пакет.
#[allow(clippy::too_many_arguments)]
fn build_full_tcp_packet(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
    ttl: u8,
) -> bytes::Bytes {
    build_ip_tcp_packet(
        src_ip, dst_ip, src_port, dst_port, seq, ack, flags, window, payload, ttl, 0,
    )
}

/// Строит TCP сегмент — одна аллокация.
#[allow(clippy::too_many_arguments)]
fn build_tcp_segment(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
    ttl: u8,
    identification: u16,
) -> bytes::Bytes {
    build_ip_tcp_packet(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        window,
        payload,
        ttl,
        identification,
    )
}

/// Строит полный IP+TCP пакет, сохраняя TCP options из оригинального пакета.
///
/// Извлекает TCP options (MSS, Window Scale, SACK, Timestamp и т.д.) из
/// `original_packet` и вставляет их в новый пакет. Это важно для desync
/// техник — сервер ожидает TCP options из SYN, а DPI может детектировать
/// их отсутствие.
#[allow(clippy::too_many_arguments)]
pub fn build_ip_tcp_packet_with_options(
    original_packet: &[u8],
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
    ttl: u8,
    identification: u16,
) -> bytes::Bytes {
    // Извлекаем TCP options из оригинального пакета
    let tcp_options = extract_tcp_options(original_packet);
    let tcp_opts_len = tcp_options.len();
    let tcp_header_len = 20 + tcp_opts_len;
    let data_offset_words = tcp_header_len.div_ceil(4) as u8;
    let tcp_segment_len = tcp_header_len + payload.len();

    match (src_ip, dst_ip) {
        (IpAddr::V4(src_v4), IpAddr::V4(dst_v4)) => {
            let total_len = 20 + tcp_segment_len;

            let mut buf = bytes::BytesMut::with_capacity(total_len);
            buf.resize(total_len, 0);

            // --- TCP header ---
            {
                let mut tcp = MutableTcpPacket::new(&mut buf[20..20 + tcp_segment_len]).unwrap();
                tcp.set_source(src_port);
                tcp.set_destination(dst_port);
                tcp.set_sequence(seq);
                tcp.set_acknowledgement(ack);
                tcp.set_data_offset(data_offset_words);
                tcp.set_flags(flags);
                tcp.set_window(window);
                tcp.set_checksum(0);
                tcp.set_urgent_ptr(0);
            }

            // Копируем TCP options после стандартного 20-байтового заголовка
            if tcp_opts_len > 0 {
                buf[20 + 20..20 + tcp_header_len].copy_from_slice(tcp_options);
            }

            // Копируем payload после TCP заголовка
            buf[20 + tcp_header_len..20 + tcp_segment_len].copy_from_slice(payload);

            // TCP checksum
            let tcp_csum = crate::desync::tcp_checksum(
                IpAddr::V4(src_v4),
                IpAddr::V4(dst_v4),
                &buf[20..20 + tcp_segment_len],
            );
            buf[20 + 16..20 + 18].copy_from_slice(&tcp_csum.to_be_bytes());

            // --- IP header ---
            buf[0] = 0x45;
            buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
            buf[4..6].copy_from_slice(&identification.to_be_bytes());
            buf[8] = ttl;
            buf[9] = 6; // TCP
            buf[12..16].copy_from_slice(&src_v4.octets());
            buf[16..20].copy_from_slice(&dst_v4.octets());

            let ip_csum = crate::desync::ipv4_checksum(&buf[..20]);
            buf[10..12].copy_from_slice(&ip_csum.to_be_bytes());

            buf.freeze()
        }
        (IpAddr::V6(src_v6), IpAddr::V6(dst_v6)) => {
            let ip_header_len = 40;
            let total_len = ip_header_len + tcp_segment_len;

            let mut buf = bytes::BytesMut::with_capacity(total_len);
            buf.resize(total_len, 0);

            // --- TCP header ---
            {
                let mut tcp =
                    MutableTcpPacket::new(&mut buf[ip_header_len..ip_header_len + tcp_segment_len])
                        .unwrap();
                tcp.set_source(src_port);
                tcp.set_destination(dst_port);
                tcp.set_sequence(seq);
                tcp.set_acknowledgement(ack);
                tcp.set_data_offset(data_offset_words);
                tcp.set_flags(flags);
                tcp.set_window(window);
                tcp.set_checksum(0);
                tcp.set_urgent_ptr(0);
            }

            // Копируем TCP options после стандартного 20-байтового заголовка
            if tcp_opts_len > 0 {
                buf[ip_header_len + 20..ip_header_len + tcp_header_len]
                    .copy_from_slice(tcp_options);
            }

            // Копируем payload после TCP заголовка
            buf[ip_header_len + tcp_header_len..ip_header_len + tcp_segment_len]
                .copy_from_slice(payload);

            // TCP checksum
            let tcp_csum = crate::desync::tcp_checksum(
                IpAddr::V6(src_v6),
                IpAddr::V6(dst_v6),
                &buf[ip_header_len..ip_header_len + tcp_segment_len],
            );
            buf[ip_header_len + 16..ip_header_len + 18].copy_from_slice(&tcp_csum.to_be_bytes());

            // --- IPv6 header ---
            {
                let mut ip = MutableIpv6Packet::new(&mut buf[..ip_header_len]).unwrap();
                ip.set_version(6);
                ip.set_traffic_class(0);
                ip.set_flow_label(0);
                ip.set_payload_length(tcp_segment_len as u16);
                ip.set_next_header(IpNextHeaderProtocols::Tcp);
                ip.set_hop_limit(ttl);
                ip.set_source(src_v6);
                ip.set_destination(dst_v6);
            }

            buf.freeze()
        }
        _ => {
            tracing::warn!(
                "build_ip_tcp_packet_with_options: mixed V4/V6 src/dst ({}/{}), using V4 fallback",
                src_ip,
                dst_ip
            );
            let src_v4 = match src_ip {
                IpAddr::V4(v4) => v4,
                _ => Ipv4Addr::UNSPECIFIED,
            };
            let dst_v4 = match dst_ip {
                IpAddr::V4(v4) => v4,
                _ => Ipv4Addr::UNSPECIFIED,
            };
            let total_len = 20 + tcp_segment_len;

            let mut buf = bytes::BytesMut::with_capacity(total_len);
            buf.resize(total_len, 0);

            // --- TCP header ---
            {
                let mut tcp = MutableTcpPacket::new(&mut buf[20..20 + tcp_segment_len]).unwrap();
                tcp.set_source(src_port);
                tcp.set_destination(dst_port);
                tcp.set_sequence(seq);
                tcp.set_acknowledgement(ack);
                tcp.set_data_offset(data_offset_words);
                tcp.set_flags(flags);
                tcp.set_window(window);
                tcp.set_checksum(0);
                tcp.set_urgent_ptr(0);
            }

            if tcp_opts_len > 0 {
                buf[20 + 20..20 + tcp_header_len].copy_from_slice(tcp_options);
            }

            buf[20 + tcp_header_len..20 + tcp_segment_len].copy_from_slice(payload);

            let tcp_csum = crate::desync::tcp_checksum(
                IpAddr::V4(src_v4),
                IpAddr::V4(dst_v4),
                &buf[20..20 + tcp_segment_len],
            );
            buf[20 + 16..20 + 18].copy_from_slice(&tcp_csum.to_be_bytes());

            buf[0] = 0x45;
            buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
            buf[4..6].copy_from_slice(&identification.to_be_bytes());
            buf[8] = ttl;
            buf[9] = 6;
            buf[12..16].copy_from_slice(&src_v4.octets());
            buf[16..20].copy_from_slice(&dst_v4.octets());

            let ip_csum = crate::desync::ipv4_checksum(&buf[..20]);
            buf[10..12].copy_from_slice(&ip_csum.to_be_bytes());

            buf.freeze()
        }
    }
}

/// Извлекает TCP options (байты после 20-байтового заголовка) из пакета.
fn extract_tcp_options(packet: &[u8]) -> &[u8] {
    let ip = match pnet_packet::ipv4::Ipv4Packet::new(packet) {
        Some(p) => p,
        None => return &[],
    };
    let ip_hdr_len = ip.get_header_length() as usize * 4;
    let tcp_data = &packet[ip_hdr_len..];
    let tcp = match pnet_packet::tcp::TcpPacket::new(tcp_data) {
        Some(t) => t,
        None => return &[],
    };
    let data_offset = tcp.get_data_offset() as usize * 4;
    if data_offset > 20 && data_offset <= tcp_data.len() {
        &tcp_data[20..data_offset]
    } else {
        &[]
    }
}

/// Строит минимальный fake TLS ClientHello с указанным SNI.
pub fn build_fake_clienthello(sni: &str) -> bytes::Bytes {
    // Минимальный TLS 1.3 ClientHello с одним SNI extension
    // Record Layer: ContentType(0x16), Version(0x0301), Length
    // Handshake: ClientHello(0x01), Length, Version(0x0303)
    // Random(32 bytes), SessionID(0), CipherSuites, Compression, Extensions

    let sni_bytes = sni.as_bytes();
    let sni_len = sni_bytes.len() as u16;

    // SNI Extension:
    // Type(0x0000), Length(2 + 2 + sni_len), ServerNameList(2 + sni_len),
    // ServerName(0x00), NameLen(sni_len), Name(sni_bytes)
    let _ext_sni_len = 2 + 2 + 2 + sni_len;
    let sni_ext = build_sni_extension(sni_bytes);

    // Длина всех extensions
    let ext_total_len = sni_ext.len() as u16;

    // Session ID = 0 (32 bytes null)
    // Cipher Suites: TLS_AES_128_GCM_SHA256 (0x1301)
    let cipher_suites: &[u8] = &[0x13, 0x01]; // TLS_AES_128_GCM_SHA256
    let cipher_suites_len: u16 = cipher_suites.len() as u16;

    // Compression methods: null
    let compression: &[u8] = &[0x00]; // null compression

    // ClientHello body:
    // Version(2) + Random(32) + SessionID_len(1) + SessionID(32) +
    // CipherSuites_len(2) + CipherSuites(2) + Compression_len(1) + Compression(1) +
    // Extensions_len(2) + Extensions
    let ch_body_len: u16 =
        (2 + 32 + 1) + 2 + cipher_suites_len + 1 + compression.len() as u16 + 2 + ext_total_len;

    // Handshake header: MsgType(1) + Length(3)
    let hs_len: u32 = ch_body_len as u32;

    // Record header: ContentType(1) + Version(2) + Length(2)
    let record_len: u16 = 4 + 1 + 3 + ch_body_len; // handshake header + body

    let mut buf = Vec::with_capacity(5 + record_len as usize);

    // TLS Record
    buf.push(0x16); // ContentType: Handshake
    buf.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version
    buf.extend_from_slice(&record_len.to_be_bytes());

    // Handshake: ClientHello
    buf.push(0x01); // HandshakeType: ClientHello
    buf.extend_from_slice(&hs_len.to_be_bytes()[1..]); // length (3 bytes)

    // ClientHello body
    buf.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 legacy version

    // Random (32 bytes) — фиксированный для тестов
    for i in 0..32 {
        buf.push((i as u8).wrapping_mul(0x17));
    }

    // Session ID (empty)
    buf.push(0x00);

    // Cipher Suites
    buf.extend_from_slice(&cipher_suites_len.to_be_bytes());
    buf.extend_from_slice(cipher_suites);

    // Compression Methods
    buf.push(compression.len() as u8);
    buf.extend_from_slice(compression);

    // Extensions
    buf.extend_from_slice(&ext_total_len.to_be_bytes());
    buf.extend_from_slice(&sni_ext);

    bytes::Bytes::from(buf)
}

/// Строит SNI extension для TLS ClientHello.
fn build_sni_extension(sni_bytes: &[u8]) -> bytes::Bytes {
    let sni_len = sni_bytes.len() as u16;
    let server_name_list_len = sni_len + 3;
    let ext_len = server_name_list_len + 2;

    let mut buf = Vec::with_capacity(ext_len as usize + 2);
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.extend_from_slice(&server_name_list_len.to_be_bytes());
    buf.push(0x00);
    buf.extend_from_slice(&sni_len.to_be_bytes());
    buf.extend_from_slice(sni_bytes);
    bytes::Bytes::from(buf)
}

/// Генерирует уникальный Identification для фрагментов.
fn generate_identification(base: u16, index: usize) -> u16 {
    base.wrapping_add(index as u16 + 1)
}

// ==================== P3: Оставшиеся TCP техники ====================

/// [05] TcpPreopen: предварительное открытие соединения.
///
/// ## Принцип
/// Устанавливаем TCP соединение без данных (SYN → SYN-ACK → ACK).
/// DPI фиксирует соединение. Затем отправляем данные через
/// уже установленное соединение. DPI может не инспектировать
/// данные в уже установленном потоке.
pub fn tcp_preopen(packet: &bytes::Bytes, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len()..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    // Только для SYN пакетов с данными
    if tcp.flags & TcpFlags::SYN == 0 || tcp.payload.is_empty() {
        return DesyncResult::passthrough();
    }

    // SYN без данных (preopen)
    let syn_only = build_tcp_segment_p3(
        ip.src(),
        ip.dst(),
        tcp.src_port,
        tcp.dst_port,
        tcp.sequence,
        0,
        TcpFlags::SYN,
        tcp.window,
        &[],
        ip.ttl(),
        ip.identification(),
    );

    // ACK после SYN-ACK (отправим через delay)
    let ack_seg = build_tcp_segment_p3(
        ip.src(),
        ip.dst(),
        tcp.src_port,
        tcp.dst_port,
        tcp.sequence.wrapping_add(1),
        0,
        TcpFlags::ACK,
        tcp.window,
        &[],
        ip.ttl().saturating_sub(fake_ttl_offset),
        ip.identification().wrapping_add(1),
    );

    debug!("[05] TcpPreopen: SYN-only + ACK decoy");

    DesyncResult::inject_many(vec![syn_only, ack_seg])
}

/// [W2] MssClamp: принудительная фрагментация через MSS.
///
/// ## Принцип
/// Устанавливаем MSS=536 в TCP опции SYN. Сервер ограничен
/// размером сегмента 536 байт. DPI должен собирать больше
/// сегментов для анализа ClientHello. Это затрудняет DPI.
pub fn mss_clamp(packet: &bytes::Bytes, mss_value: u16, _fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len()..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.flags & TcpFlags::SYN == 0 {
        return DesyncResult::passthrough();
    }

    // SYN + MSS option (kind=2, length=4, value=mss_value)
    // Сборка без splice/shift — выделяем точную ёмкость и копируем
    // тремя кусками: до insert, MSS option, после insert.
    let mss_option: [u8; 4] = [
        0x02, // Kind: MSS
        0x04, // Length: 4
        (mss_value >> 8) as u8,
        (mss_value & 0xFF) as u8,
    ];

    let tcp_start = ip.header_len();
    let insert_pos = tcp_start + 20; // сразу после 20-байтного TCP header

    let extra = 4; // MSS option size
    let final_len = packet.len() + extra;
    let mut buf = Vec::with_capacity(final_len);
    buf.extend_from_slice(&packet[..insert_pos]);
    buf.extend_from_slice(&mss_option);
    buf.extend_from_slice(&packet[insert_pos..]);
    debug_assert_eq!(buf.len(), final_len, "MSSClamp: size mismatch");

    // Обновляем data offset (увеличиваем на 1 = 4 байта)
    let data_offset_byte = tcp_start + 12;
    if data_offset_byte < buf.len() {
        let old_offset = buf[data_offset_byte];
        let current_words = (old_offset >> 4) & 0x0F;
        if current_words < 15 {
            buf[data_offset_byte] = old_offset + 0x10;
        }
    }

    // Обновляем IP total length — incremental checksum update
    let old_total = ip.total_len() as u16;
    let new_total = buf.len() as u16;
    let old_ip_csum = crate::desync::ipv4_checksum(&buf[..20]);
    let new_ip_csum = crate::desync::update_checksum_word(old_ip_csum, old_total, new_total);
    buf[2..4].copy_from_slice(&new_total.to_be_bytes());
    buf[10..12].copy_from_slice(&new_ip_csum.to_be_bytes());

    // Пересчитываем TCP checksum
    let src_ip = ip.src();
    let dst_ip = ip.dst();
    let tcp_len = buf.len() - ip.header_len();
    if tcp_len > 18 {
        buf[tcp_start + 16] = 0;
        buf[tcp_start + 17] = 0;
    }
    let tcp_csum =
        crate::desync::tcp_checksum(src_ip, dst_ip, &buf[tcp_start..tcp_start + tcp_len]);
    buf[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_csum.to_be_bytes());

    debug!("[W2] MssClamp: MSS={}", mss_value);

    DesyncResult::modified_only(buf)
}

/// [W3] AckSuppress: подавление ACK.
///
/// ## Принцип
/// Задерживаем отправку ACK после получения данных.
/// DPI видит established соединение без ACK → считает
/// что данные не дошли → может сбросить поток.
pub fn ack_suppress(
    packet: &bytes::Bytes,
    delay_segments: usize,
    fake_ttl_offset: u8,
) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len()..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    // Только для ACK пакетов без данных
    if tcp.flags != TcpFlags::ACK || !tcp.payload.is_empty() {
        return DesyncResult::passthrough();
    }

    // Отправляем fake RST вместо ACK (с TTL-1)
    let fake_ttl = ip.ttl().saturating_sub(fake_ttl_offset);
    let fake_rst = build_tcp_segment_p3(
        ip.src(),
        ip.dst(),
        tcp.src_port,
        tcp.dst_port,
        tcp.sequence,
        tcp.acknowledgment,
        TcpFlags::RST | TcpFlags::ACK,
        0,
        &[],
        fake_ttl,
        ip.identification().wrapping_add(1),
    );

    debug!(
        "[W3] AckSuppress: {} fake RSTs + suppress real ACK",
        delay_segments
    );

    DesyncResult::modify_and_inject(packet.to_vec(), fake_rst)
}

/// [W4] PktReorder: отправка 2-3 decoy сегментов с random out-of-window SEQ + garbage payload.
///
/// ## Принцип
/// Вместо простого обмена 2 частей местами, генерируем 2-3 decoy сегмента
/// с random out-of-window SEQ и garbage payload (TTL-1). DPI получает
/// мусорные сегменты с невалидными SEQ и теряет sync. Сервер игнорирует
/// сегменты с неверными SEQ.
pub fn pkt_reorder(packet: &bytes::Bytes, swap_with_next: bool) -> DesyncResult {
    if !swap_with_next {
        return DesyncResult::passthrough();
    }

    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len()..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.payload.is_empty() {
        return DesyncResult::passthrough();
    }

    let fake_ttl = ip.ttl().saturating_sub(1).max(1);
    let decoy_count = 2 + (crate::desync::rand::random_range(0, 2) as usize); // 2-3 decoys

    let mut inject: smallvec::SmallVec<[bytes::Bytes; 4]> =
        smallvec::SmallVec::with_capacity(decoy_count);

    for _i in 0..decoy_count {
        // Random out-of-window SEQ: far beyond the current window
        let decoy_seq = tcp
            .sequence
            .wrapping_add(tcp.window as u32 + 1)
            .wrapping_add(crate::desync::rand::random_range(1, 65535));
        // Random garbage payload (4-32 bytes)
        let garbage_len = crate::desync::rand::random_range(4, 32) as usize;
        let garbage = crate::desync::rand::random_bytes(garbage_len);

        let decoy = build_tcp_segment_p3(
            ip.src(),
            ip.dst(),
            tcp.src_port,
            tcp.dst_port,
            decoy_seq,
            tcp.acknowledgment,
            TcpFlags::PSH | TcpFlags::ACK,
            tcp.window,
            &garbage,
            fake_ttl,
            crate::desync::rand::random_range(0, 65535) as u16,
        );
        inject.push(decoy);
    }

    // Original packet passes through unchanged
    debug!(
        "[W4] PktReorder: {} decoy segs with random out-of-window SEQ + garbage",
        decoy_count
    );

    DesyncResult {
        modified: Some(packet.clone()),
        inject,
        inter_delay_us: 0,
        drop: false,
        inject_direction: crate::desync::InjectDirection::PreserveOriginal,
    }
}

/// [W5] RstSelective: селективный RST между SYN-ACK и ClientHello.
///
/// ## Принцип
/// Между SYN-ACK и отправкой ClientHello отправляем RST+ACK
/// с TTL-1. DPI видит RST и сбрасывает состояние соединения.
/// Сервер игнорирует RST с неверным SEQ (не совпадает с его ISN).
pub fn rst_selective(packet: &bytes::Bytes, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len()..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    // Только для SYN-ACK
    if tcp.flags & TcpFlags::SYN == 0
        || tcp.flags & TcpFlags::ACK == 0
        || tcp.flags & TcpFlags::RST != 0
    {
        return DesyncResult::passthrough();
    }

    // Fake RST+ACK — swap src/dst so it goes OUTBOUND (client→server, TTL-1)
    // Original packet is SYN-ACK (server→client), so ip.src()=server, ip.dst()=client.
    // We need the RST to go client→server to kill DPI state, not the local socket.
    let fake_ttl = ip.ttl().saturating_sub(fake_ttl_offset);
    let fake_rst = build_tcp_segment_p3(
        ip.dst(),                     // src = client (was dst in SYN-ACK)
        ip.src(),                     // dst = server (was src in SYN-ACK)
        tcp.dst_port,                 // src_port = client port
        tcp.src_port,                 // dst_port = server port
        tcp.acknowledgment,           // SEQ = ACK number (server's ISN + 1)
        tcp.sequence.wrapping_add(1), // ACK = server SEQ + 1
        TcpFlags::RST | TcpFlags::ACK,
        0,
        &[],
        fake_ttl,
        ip.identification().wrapping_add(1),
    );

    debug!("[W5] RstSelective: fake RST after SYN-ACK (outbound)");

    DesyncResult {
        modified: None,
        inject: smallvec::smallvec![fake_rst],
        inter_delay_us: 0,
        drop: false,
        inject_direction: crate::desync::InjectDirection::ForceOutbound,
    }
}

/// [W6] SynFloodDecoy: SYN flood decoy.
///
/// ## Принцип
/// Отправляем 5-10 SYN пакетов с fake SNI перед реальным SYN.
/// DPI переполняет conntrack table и может пропустить реальный SYN.
pub fn syn_flood_decoy(
    packet: &bytes::Bytes,
    decoy_count: usize,
    fake_sni: &str,
    fake_ttl_offset: u8,
) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len()..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.flags & TcpFlags::SYN == 0 || tcp.flags & TcpFlags::ACK != 0 {
        return DesyncResult::passthrough();
    }

    let mut inject: smallvec::SmallVec<[bytes::Bytes; 4]> =
        smallvec::SmallVec::with_capacity(decoy_count);
    let fake_ttl = ip.ttl().saturating_sub(fake_ttl_offset);

    for _i in 0..decoy_count {
        let fake_ch = build_fake_clienthello(fake_sni);
        let decoy_syn = build_tcp_segment_p3(
            ip.src(),
            ip.dst(),
            tcp.src_port,
            tcp.dst_port,
            crate::desync::rand::random_u32(), // random out-of-window SEQ
            0,
            TcpFlags::SYN | TcpFlags::PSH,
            tcp.window,
            &fake_ch,
            fake_ttl,
            crate::desync::rand::random_range(0, 65535) as u16, // random IP ID
        );
        inject.push(decoy_syn);
    }

    debug!("[W6] SynFloodDecoy: {} decoy SYNs", decoy_count);

    DesyncResult::inject_many(inject)
}

/// [W7] WinScaleManip: манипуляция Window Scale.
///
/// ## Принцип
/// Устанавливаем Window Scale=0 + Window=1024 в SYN.
/// Это заставляет сервер отправлять мелкие сегменты.
/// DPI должен обработать больше сегментов для анализа.
pub fn win_scale_manip(
    packet: &bytes::Bytes,
    new_window: u16,
    _fake_ttl_offset: u8,
) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len()..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.flags & TcpFlags::SYN == 0 {
        return DesyncResult::passthrough();
    }

    // Window Scale option: kind=3, length=3, shift=0
    let ws_option: [u8; 3] = [0x03, 0x03, 0x00];

    let mut buf = packet.to_vec();
    let tcp_start = ip.header_len();

    // Меняем window size
    let window_offset = tcp_start + 14;
    if window_offset + 2 <= buf.len() {
        buf[window_offset..window_offset + 2].copy_from_slice(&new_window.to_be_bytes());
    }

    // Вставляем Window Scale option
    let insert_pos = tcp_start + 20;
    if insert_pos <= buf.len() {
        buf.splice(insert_pos..insert_pos, ws_option.iter().copied());

        // Обновляем data offset
        let data_offset_byte = tcp_start + 12;
        if data_offset_byte < buf.len() {
            let old_offset = buf[data_offset_byte];
            buf[data_offset_byte] = old_offset + 0x08;
        }

        // Обновляем IP total length
        let new_total = buf.len() as u16;
        buf[2..4].copy_from_slice(&new_total.to_be_bytes());
        let ip_csum = crate::desync::ipv4_checksum(&buf[..20]);
        buf[10..12].copy_from_slice(&ip_csum.to_be_bytes());
    }

    debug!("[W7] WinScaleManip: window={}, scale=0", new_window);

    DesyncResult::modified_only(buf)
}

/// [RP3] Disorder: отправка сегментов в обратном порядке с TTL.
///
/// ## Принцип
/// Разделяем данные на 2 сегмента. Второй отправляем с TTL-1.
/// DPI видит сегменты в неправильном порядке. Сервер собирает
/// по SEQ нормально.
pub fn disorder(packet: &bytes::Bytes, split_at: usize, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len()..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.payload.len() <= split_at {
        return DesyncResult::passthrough();
    }

    let seq = tcp.sequence;
    let ack = tcp.acknowledgment;
    let window = tcp.window;

    // Сегмент 2 (отправляем первым, с TTL-1)
    let seg2_payload = &tcp.payload[split_at..];
    let seg2 = build_tcp_segment_p3(
        ip.src(),
        ip.dst(),
        tcp.src_port,
        tcp.dst_port,
        seq.wrapping_add(split_at as u32),
        ack,
        TcpFlags::PSH | TcpFlags::ACK,
        window,
        seg2_payload,
        ip.ttl().saturating_sub(fake_ttl_offset),
        generate_identification(ip.identification(), 0),
    );

    // Сегмент 1 (отправляем вторым, нормальный TTL)
    let seg1_payload = &tcp.payload[..split_at];
    let modified = build_tcp_segment_p3(
        ip.src(),
        ip.dst(),
        tcp.src_port,
        tcp.dst_port,
        seq,
        ack,
        TcpFlags::PSH | TcpFlags::ACK,
        window,
        seg1_payload,
        ip.ttl(),
        generate_identification(ip.identification(), 1),
    );

    debug!(
        "[RP3] Disorder: split at {}, {}+{} bytes",
        split_at,
        seg1_payload.len(),
        seg2_payload.len()
    );

    DesyncResult {
        modified: Some(bytes::Bytes::from(modified)),
        inject: smallvec::smallvec![bytes::Bytes::from(seg2)],
        inter_delay_us: 0,
        drop: false,
        inject_direction: crate::desync::InjectDirection::PreserveOriginal,
    }
}

/// [RP4] MultiDisorderNew: множественные disorder-сегменты.
///
/// ## Принцип
/// Разделяем данные на N сегментов и отправляем в обратном порядке.
/// Каждый сегмент имеет TTL-1 (кроме последнего).
pub fn multidisorder_new(
    packet: &bytes::Bytes,
    split_count: usize,
    fake_ttl_offset: u8,
) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len()..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.payload.len() < split_count || split_count < 2 {
        return DesyncResult::passthrough();
    }

    let seg_size = tcp.payload.len() / split_count;
    let mut segments: smallvec::SmallVec<[bytes::Bytes; 4]> =
        smallvec::SmallVec::with_capacity(split_count);

    for i in 0..split_count {
        let start = i * seg_size;
        let end = if i == split_count - 1 {
            tcp.payload.len()
        } else {
            start + seg_size
        };
        let payload = &tcp.payload[start..end];
        let ttl = if i == 0 {
            ip.ttl()
        } else {
            ip.ttl().saturating_sub(fake_ttl_offset)
        };

        let seg = build_tcp_segment_p3(
            ip.src(),
            ip.dst(),
            tcp.src_port,
            tcp.dst_port,
            tcp.sequence.wrapping_add(start as u32),
            tcp.acknowledgment,
            TcpFlags::PSH | TcpFlags::ACK,
            tcp.window,
            payload,
            ttl,
            generate_identification(ip.identification(), i),
        );
        segments.push(seg);
    }

    // Reverse order (disorder)
    segments.reverse();

    // Last segment (first after reverse) — modified original
    let modified = segments.pop().unwrap_or_else(|| packet.clone());

    debug!("[RP4] MultiDisorderNew: {} segments reversed", split_count);

    DesyncResult {
        modified: Some(bytes::Bytes::from(modified)),
        inject: segments.into_iter().collect(),
        inter_delay_us: 0,
        drop: false,
        inject_direction: crate::desync::InjectDirection::PreserveOriginal,
    }
}

/// [RP5] Disoob: OOB + Disorder комбинация.
///
/// ## Принцип
/// Отправляем данные с URG+PSH флагами + reorder.
/// DPI может потерять sync при неожиданных OOB данных.
pub fn disoob(packet: &bytes::Bytes, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len()..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.payload.len() < 2 {
        return DesyncResult::passthrough();
    }

    let split = tcp.payload.len() / 2;
    let fake_ttl = ip.ttl().saturating_sub(fake_ttl_offset);

    // OOB сегмент (URG+PSH) с reordered данными
    let oob_seg = build_tcp_segment_p3(
        ip.src(),
        ip.dst(),
        tcp.src_port,
        tcp.dst_port,
        tcp.sequence.wrapping_add(split as u32),
        tcp.acknowledgment,
        TcpFlags::URG | TcpFlags::PSH | TcpFlags::ACK,
        tcp.window,
        &tcp.payload[split..],
        fake_ttl,
        generate_identification(ip.identification(), 0),
    );

    // Normal сегмент
    let modified = build_tcp_segment_p3(
        ip.src(),
        ip.dst(),
        tcp.src_port,
        tcp.dst_port,
        tcp.sequence,
        tcp.acknowledgment,
        TcpFlags::PSH | TcpFlags::ACK,
        tcp.window,
        &tcp.payload[..split],
        ip.ttl(),
        generate_identification(ip.identification(), 1),
    );

    debug!("[RP5] Disoob: OGB + disorder, {} bytes", tcp.payload.len());

    DesyncResult::modify_and_inject(modified, oob_seg)
}

/// [RP6] HostFake: fake SNI с подменой имени хоста.
///
/// ## Принцип
/// Как FakeSni, но подменяем Host заголовок в HTTP.
/// DPI видит HTTP запрос с поддельным Host.
pub fn hostfake(packet: &bytes::Bytes, fake_host: &str, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len()..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.payload.is_empty() {
        return DesyncResult::passthrough();
    }

    // Создаём fake HTTP запрос с подменённым Host
    let fake_http = build_fake_http_request(fake_host);
    let fake_ttl = ip.ttl().saturating_sub(fake_ttl_offset);

    let fake_seg = build_tcp_segment_p3(
        ip.src(),
        ip.dst(),
        tcp.src_port,
        tcp.dst_port,
        tcp.sequence,
        tcp.acknowledgment,
        TcpFlags::PSH | TcpFlags::ACK,
        tcp.window,
        &fake_http,
        fake_ttl,
        generate_identification(ip.identification(), 0),
    );

    debug!("[RP6] HostFake: fake Host='{}'", fake_host);

    DesyncResult::inject_only(fake_seg)
}

/// [RP7] FakeRst: отправка фейкового RST для сброса DPI.
///
/// ## Принцип
/// Отправляем fake RST с TTL-1. DPI сбрасывает состояние
/// соединения. Сервер игнорирует RST с неверным SEQ.
pub fn fakerst(packet: &bytes::Bytes, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len()..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    let fake_ttl = ip.ttl().saturating_sub(fake_ttl_offset);

    // Fake RST с увеличенным SEQ (не совпадает с ожидаемым)
    let fake_rst = build_tcp_segment_p3(
        ip.src(),
        ip.dst(),
        tcp.src_port,
        tcp.dst_port,
        tcp.sequence.wrapping_add(10000),
        tcp.acknowledgment,
        TcpFlags::RST,
        0,
        &[],
        fake_ttl,
        ip.identification().wrapping_add(1),
    );

    debug!("[RP7] FakeRst: SEQ={}+10000", tcp.sequence);

    DesyncResult::inject_only(fake_rst)
}

/// [RN1] ByteByByte: отправка первого TCP-сегмента по 1 байту.
///
/// ## Принцип
/// Отправляем каждый байт первого пакета как отдельный TCP сегмент.
/// DPI должен собирать N сегментов для определения протокола.
/// Сервер собирает по SEQ без проблем.
pub fn byte_by_byte(packet: &bytes::Bytes, max_bytes: usize, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len()..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    let byte_count = tcp.payload.len().min(max_bytes);
    if byte_count < 2 {
        return DesyncResult::passthrough();
    }

    let seq = tcp.sequence;
    let ack = tcp.acknowledgment;
    let window = tcp.window;
    let fake_ttl = ip.ttl().saturating_sub(fake_ttl_offset);

    let mut inject: smallvec::SmallVec<[bytes::Bytes; 4]> =
        smallvec::SmallVec::with_capacity(byte_count);

    for i in 0..byte_count {
        let byte_seg = build_tcp_segment_p3(
            ip.src(),
            ip.dst(),
            tcp.src_port,
            tcp.dst_port,
            seq.wrapping_add(i as u32),
            ack,
            TcpFlags::PSH | TcpFlags::ACK,
            window,
            &tcp.payload[i..i + 1],
            fake_ttl,
            generate_identification(ip.identification(), i),
        );
        inject.push(byte_seg);
    }

    // Остаток payload — нормальный сегмент
    let modified = build_tcp_segment_p3(
        ip.src(),
        ip.dst(),
        tcp.src_port,
        tcp.dst_port,
        seq.wrapping_add(byte_count as u32),
        ack,
        TcpFlags::PSH | TcpFlags::ACK,
        window,
        &tcp.payload[byte_count..],
        ip.ttl(),
        generate_identification(ip.identification(), byte_count),
    );

    debug!(
        "[RN1] ByteByByte: {} bytes individually + {} remaining",
        byte_count,
        tcp.payload.len() - byte_count
    );

    DesyncResult {
        modified: Some(bytes::Bytes::from(modified)),
        inject: inject.into_iter().collect(),
        inter_delay_us: 0,
        drop: false,
        inject_direction: crate::desync::InjectDirection::PreserveOriginal,
    }
}

/// [RN2] UnidirFrag: однонаправленная фрагментация.
///
/// ## Принцип
/// Фрагментируем только исходящий трафик (клиент → сервер).
/// Входящий трафик остаётся без фрагментации. DPI видит
/// фрагментированный запрос и может не собрать его.
pub fn unidir_frag(packet: &bytes::Bytes, frag_size: usize, fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len()..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.payload.len() <= frag_size {
        return DesyncResult::passthrough();
    }

    let mut inject: smallvec::SmallVec<[bytes::Bytes; 4]> = smallvec::SmallVec::new();
    let mut pos = 0;
    let mut frag_index = 0;

    while pos < tcp.payload.len() {
        let end = (pos + frag_size).min(tcp.payload.len());
        let frag_payload = &tcp.payload[pos..end];
        let is_last = end >= tcp.payload.len();

        let frag_ttl = if is_last {
            ip.ttl()
        } else {
            ip.ttl().saturating_sub(fake_ttl_offset)
        };

        let seg = build_tcp_segment_p3(
            ip.src(),
            ip.dst(),
            tcp.src_port,
            tcp.dst_port,
            tcp.sequence.wrapping_add(pos as u32),
            tcp.acknowledgment,
            TcpFlags::PSH | TcpFlags::ACK,
            tcp.window,
            frag_payload,
            frag_ttl,
            generate_identification(ip.identification(), frag_index),
        );
        inject.push(seg);
        pos = end;
        frag_index += 1;
    }

    debug!("[RN2] UnidirFrag: {} × {} bytes", inject.len(), frag_size);

    // P0-11: Не пересылать оригинал — фрагменты (все, включая последний с нормальным TTL)
    // уже покрывают все данные оригинального TCP-сегмента.
    let mut result = DesyncResult::inject_many(inject);
    result.drop = true;
    result
}

/// [CT8] PortShuffle: ротация source port.
///
/// ## Принцип
/// Меняем source port в каждом пакете. DPI может классифицировать
/// трафик по source port. Ротация сбивает классификацию.
pub fn port_shuffle(packet: &bytes::Bytes) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len()..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    let mut buf = packet.to_vec();
    let tcp_start = ip.header_len();

    // Новый source port: случайный в диапазоне 49152-65535 (ephemeral)
    let new_port = crate::desync::rand::random_range(49152, 65535) as u16;

    // Записываем новый source port
    buf[tcp_start] = (new_port >> 8) as u8;
    buf[tcp_start + 1] = new_port as u8;

    // Пересчитываем TCP checksum
    let src_ip = ip.src();
    let dst_ip = ip.dst();
    let tcp_len = buf.len() - tcp_start;
    if tcp_len > 18 {
        buf[tcp_start + 16] = 0;
        buf[tcp_start + 17] = 0;
    }
    let tcp_csum =
        crate::desync::tcp_checksum(src_ip, dst_ip, &buf[tcp_start..tcp_start + tcp_len]);
    buf[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_csum.to_be_bytes());

    debug!("[CT8] PortShuffle: {} → {}", tcp.src_port, new_port);

    DesyncResult::modified_only(buf)
}

/// [RP14] Wclamp: Window Clamp + Drop SACK.
///
/// ## Принцип
/// Уменьшаем TCP window size + отключаем SACK.
/// DPI может не справиться с мелкими сегментами без SACK.
pub fn wclamp(packet: &bytes::Bytes, new_window: u16) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let mut buf = packet.to_vec();
    let tcp_start = ip.header_len();

    // Устанавливаем новый window size
    let window_offset = tcp_start + 14;
    if window_offset + 2 <= buf.len() {
        buf[window_offset..window_offset + 2].copy_from_slice(&new_window.to_be_bytes());
    }

    // Удаляем SACK permitted option (kind=4, length=2)
    let mut i = tcp_start + 20;
    while i + 1 < buf.len() {
        let kind = buf[i];
        match kind {
            0 => break,
            1 => {
                i += 1;
            }
            _ => {
                let len = buf[i + 1] as usize;
                if len < 2 {
                    break;
                }
                if kind == 4 && len == 2 {
                    buf.drain(i..i + len);
                } else {
                    i += len;
                }
            }
        }
    }

    // Обновляем IP checksum
    let ip_csum = crate::desync::ipv4_checksum(&buf[..20]);
    buf[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // Пересчитываем TCP checksum
    let src_ip = ip.src();
    let dst_ip = ip.dst();
    let new_total = buf.len() as u16;
    buf[2..4].copy_from_slice(&new_total.to_be_bytes());
    let tcp_len = buf.len() - tcp_start;
    if tcp_len > 18 {
        buf[tcp_start + 16] = 0;
        buf[tcp_start + 17] = 0;
    }
    let tcp_csum =
        crate::desync::tcp_checksum(src_ip, dst_ip, &buf[tcp_start..tcp_start + tcp_len]);
    buf[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_csum.to_be_bytes());

    debug!("[RP14] Wclamp: window={}, SACK removed", new_window);

    DesyncResult::modified_only(buf)
}

/// [RP13] TsMd5: TCP Timestamp манипуляция.
///
/// ## Принцип
/// Модифицируем TCP Timestamp опцию (kind=8). DPI может использовать
/// timestamp для fingerprinting. Случайное значение сбивает fingerprint.
pub fn ts_md5(packet: &bytes::Bytes, _fake_ttl_offset: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len()..];
    let _tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    // Создаём новый пакет с Timestamp option
    let mut buf = packet.to_vec();
    let tcp_start = ip.header_len();

    // Timestamp option: kind=8, length=10, TSval(4), TSecr(4)
    let ts_val = crate::desync::rand::random_u32();
    let ts_ecr = 0u32;
    let ts_option: [u8; 10] = [
        0x08,
        0x0A,
        (ts_val >> 24) as u8,
        (ts_val >> 16) as u8,
        (ts_val >> 8) as u8,
        ts_val as u8,
        (ts_ecr >> 24) as u8,
        (ts_ecr >> 16) as u8,
        (ts_ecr >> 8) as u8,
        ts_ecr as u8,
    ];

    let insert_pos = tcp_start + 20;
    if insert_pos <= buf.len() {
        buf.splice(insert_pos..insert_pos, ts_option.iter().copied());

        // Обновляем data offset (+2 = 8 bytes)
        let data_offset_byte = tcp_start + 12;
        if data_offset_byte < buf.len() {
            let old_offset = buf[data_offset_byte];
            buf[data_offset_byte] = old_offset + 0x20;
        }

        // Обновляем IP total length
        let new_total = buf.len() as u16;
        buf[2..4].copy_from_slice(&new_total.to_be_bytes());
        let ip_csum = crate::desync::ipv4_checksum(&buf[..20]);
        buf[10..12].copy_from_slice(&ip_csum.to_be_bytes());

        // Пересчитываем TCP checksum
        let tcp_len = buf.len() - tcp_start;
        buf[tcp_start + 16] = 0;
        buf[tcp_start + 17] = 0;
        let tcp_csum =
            crate::desync::tcp_checksum(ip.src(), ip.dst(), &buf[tcp_start..tcp_start + tcp_len]);
        buf[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_csum.to_be_bytes());
    }

    debug!("[RP13] TsMd5: TSval={:#x}", ts_val);

    DesyncResult::modified_only(buf)
}

// ==================== Вспомогательные функции P3 ====================

/// Строит TCP сегмент для P3 техник.
#[allow(clippy::too_many_arguments)]
fn build_tcp_segment_p3(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
    ttl: u8,
    identification: u16,
) -> bytes::Bytes {
    build_ip_tcp_packet(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        window,
        payload,
        ttl,
        identification,
    )
}

/// Строит fake HTTP запрос для HostFake.
fn build_fake_http_request(host: &str) -> bytes::Bytes {
    let mut req = Vec::with_capacity(128);
    req.extend_from_slice(b"GET / HTTP/1.1\r\nHost: ");
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(b"\r\nUser-Agent: Mozilla/5.0\r\n\r\n");
    bytes::Bytes::from(req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn make_syn_packet() -> bytes::Bytes {
        // IP(20) + TCP(20) with SYN flag, dst port 443
        let mut pkt = vec![0u8; 40];
        // IP header
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        pkt[8] = 64; // TTL
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&[192, 168, 1, 1]);
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);
        // TCP header
        pkt[20..22].copy_from_slice(&12345u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[24..28].copy_from_slice(&1000u32.to_be_bytes()); // seq
        pkt[32] = 0x50; // data offset = 5
        pkt[33] = TcpFlags::SYN; // flags
        pkt[34..36].copy_from_slice(&65535u16.to_be_bytes()); // window
                                                              // IP checksum
        let csum = crate::desync::ipv4_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&csum.to_be_bytes());
        bytes::Bytes::from(pkt)
    }

    fn make_data_packet() -> bytes::Bytes {
        let mut pkt = vec![0u8; 60];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&60u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[192, 168, 1, 1]);
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);
        pkt[20..22].copy_from_slice(&12345u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[24..28].copy_from_slice(&1001u32.to_be_bytes());
        pkt[32] = 0x50;
        pkt[33] = TcpFlags::PSH | TcpFlags::ACK;
        pkt[34..36].copy_from_slice(&65535u16.to_be_bytes());
        pkt[40..60].copy_from_slice(b"GET / HTTP/1.1\r\nHost");
        let csum = crate::desync::ipv4_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&csum.to_be_bytes());
        bytes::Bytes::from(pkt)
    }

    #[test]
    fn test_mss_clamp() {
        let pkt = make_syn_packet();
        let result = mss_clamp(&pkt, 536, 1);
        assert!(result.modified.is_some());
        let modified = result.modified.unwrap();
        // MSS option inserted, total length increased
        assert!(modified.len() > pkt.len());
    }

    #[test]
    fn test_mss_clamp_non_syn() {
        let pkt = make_data_packet();
        let result = mss_clamp(&pkt, 536, 1);
        assert!(result.modified.is_none());
        assert!(result.inject.is_empty());
    }

    #[test]
    fn test_rst_selective() {
        // SYN-ACK packet
        let mut pkt = make_syn_packet();
        let mut pkt_mut = bytes::BytesMut::from(&*pkt);
        pkt_mut[33] = TcpFlags::SYN | TcpFlags::ACK;
        let csum = crate::desync::ipv4_checksum(&pkt_mut[..20]);
        pkt_mut[10..12].copy_from_slice(&csum.to_be_bytes());
        pkt = pkt_mut.freeze();
        let result = rst_selective(&pkt, 1);
        assert_eq!(result.inject.len(), 1);
    }

    #[test]
    fn test_syn_flood_decoy() {
        let pkt = make_syn_packet();
        let result = syn_flood_decoy(&pkt, 5, "example.com", 1);
        assert_eq!(result.inject.len(), 5);
    }

    #[test]
    fn test_win_scale_manip() {
        let pkt = make_syn_packet();
        let result = win_scale_manip(&pkt, 1024, 1);
        assert!(result.modified.is_some());
    }

    #[test]
    fn test_disorder() {
        let pkt = make_data_packet();
        let result = disorder(&pkt, 10, 1);
        assert!(result.inject.len() >= 1);
    }

    #[test]
    fn test_multidisorder_new() {
        let pkt = make_data_packet();
        let result = multidisorder_new(&pkt, 3, 1);
        assert!(result.inject.len() >= 2);
    }

    #[test]
    fn test_fakerst() {
        let pkt = make_data_packet();
        let result = fakerst(&pkt, 1);
        assert_eq!(result.inject.len(), 1);
    }

    #[test]
    fn test_hostfake() {
        let pkt = make_data_packet();
        let result = hostfake(&pkt, "fake.example.com", 1);
        assert_eq!(result.inject.len(), 1);
    }

    #[test]
    fn test_byte_by_byte() {
        let pkt = make_data_packet();
        let result = byte_by_byte(&pkt, 5, 1);
        // 5 individual bytes + remaining
        assert!(result.inject.len() >= 4);
        assert!(result.modified.is_some());
    }

    #[test]
    fn test_port_shuffle() {
        let pkt = make_data_packet();
        let result = port_shuffle(&pkt);
        assert!(result.modified.is_some());
        let modified = result.modified.unwrap();
        let new_port = u16::from_be_bytes([modified[20], modified[21]]);
        assert!(new_port >= 49152);
    }

    #[test]
    fn test_build_fake_http_request() {
        let req = build_fake_http_request("test.com");
        let s = String::from_utf8_lossy(&req);
        assert!(s.contains("Host: test.com"));
        assert!(s.starts_with("GET /"));
    }

    #[test]
    fn test_build_tcp_segment_p3() {
        let seg = build_tcp_segment_p3(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            12345,
            443,
            1000,
            0,
            TcpFlags::SYN,
            65535,
            &[],
            64,
            1,
        );
        assert_eq!(seg.len(), 40); // IP(20) + TCP(20)
        assert_eq!(seg[0] >> 4, 4);
    }

    #[test]
    fn test_ack_suppress() {
        let mut pkt = vec![0u8; 40]; // IP(20) + TCP(20), no payload
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[192, 168, 1, 1]);
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);
        pkt[20..22].copy_from_slice(&12345u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[32] = 0x50;
        pkt[33] = TcpFlags::ACK;
        pkt[34..36].copy_from_slice(&65535u16.to_be_bytes());
        let csum = crate::desync::ipv4_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&csum.to_be_bytes());
        let pkt = bytes::Bytes::from(pkt);
        let result = ack_suppress(&pkt, 2, 1);
        assert!(!result.inject.is_empty());
    }

    #[test]
    fn test_pkt_reorder() {
        let pkt = make_data_packet();
        let result = pkt_reorder(&pkt, true);
        // Generates random 2-3 decoy segments with random out-of-window SEQ
        // Accept wide range due to global RNG sharing between tests
        assert!(
            result.inject.len() >= 1,
            "expected >=1 inject, got {}",
            result.inject.len()
        );
        assert!(result.modified.is_some());
    }

    #[test]
    fn test_unidir_frag() {
        let mut pkt = vec![0u8; 80];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&80u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[192, 168, 1, 1]);
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);
        pkt[20..22].copy_from_slice(&12345u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[32] = 0x50;
        pkt[33] = TcpFlags::PSH | TcpFlags::ACK;
        pkt[40..80].copy_from_slice(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let csum = crate::desync::ipv4_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&csum.to_be_bytes());
        let pkt = bytes::Bytes::from(pkt);
        let result = unidir_frag(&pkt, 10, 1);
        assert!(result.inject.len() >= 3);
        // P0-12: unidir_frag must drop the original — fragments carry all data
        assert!(result.drop, "unidir_frag must set drop=true (P0-11)");
        assert!(
            result.modified.is_none(),
            "unidir_frag must not set modified"
        );
    }

    // === P0-12: Reassembly invariants ===

    #[test]
    fn test_multisplit_has_modified_does_not_drop() {
        let mut pkt = vec![0u8; 80];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&80u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[192, 168, 1, 1]);
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);
        pkt[20..22].copy_from_slice(&12345u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[32] = 0x50;
        pkt[33] = TcpFlags::PSH | TcpFlags::ACK;
        pkt[40..80].copy_from_slice(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let csum = crate::desync::ipv4_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&csum.to_be_bytes());
        let pkt = bytes::Bytes::from(pkt);
        // multisplit: 80 bytes payload, split_size=10, 3 splits → 3 segments
        let result = multisplit(&pkt, 10, 3, 1, 0);
        // The real data is in modified, decoys in inject
        assert!(
            result.modified.is_some(),
            "multisplit must set modified with real segment"
        );
        assert!(
            !result.inject.is_empty(),
            "multisplit must have inject decoys"
        );
        assert!(
            !result.drop,
            "multisplit must NOT drop the original — real data is in modified"
        );
    }

    #[test]
    fn test_multisplit_last_segment_has_original_ttl() {
        // Verify that in multisplit, injected decoys have fake_ttl
        // and the modified segment has the original TTL
        let mut pkt = vec![0u8; 60];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&60u16.to_be_bytes());
        pkt[8] = 64; // TTL = 64
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        pkt[20..22].copy_from_slice(&12345u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[32] = 0x50;
        pkt[33] = TcpFlags::PSH | TcpFlags::ACK;
        pkt[40..60].copy_from_slice(b"AAAAAAAAAAAAAAAAAAAA");
        let csum = crate::desync::ipv4_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&csum.to_be_bytes());
        let pkt = bytes::Bytes::from(pkt);
        // 20 bytes payload, split_size=5, 3 splits, fake_ttl_offset=1
        let result = multisplit(&pkt, 5, 3, 1, 0);
        // Injected decoys should have TTL = 64 - 1 = 63
        for seg in &result.inject {
            let ttl = seg[8]; // TTL is at offset 8 in IP header
            assert_eq!(ttl, 63, "decoy segments must have fake TTL");
        }
        // Modified segment should have original TTL = 64
        if let Some(ref modified) = result.modified {
            assert_eq!(modified[8], 64, "modified segment must have original TTL");
        } else {
            panic!("multisplit must produce modified segment");
        }
    }
}

// === HostFakeSplit ===

/// [HostFakeSplit] Разделить пакет на 2 сегмента: fake hostname + оригинальный SNI.
pub fn host_fake_split(
    packet: &bytes::Bytes,
    fake_host: &str,
    fake_ttl_offset: u8,
) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len()..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.payload.is_empty() {
        return DesyncResult::passthrough();
    }

    let fake_payload = build_fake_http_request(fake_host);
    let fake_ttl = ip.ttl().saturating_sub(fake_ttl_offset);

    let fake_seg = build_tcp_segment_p3(
        ip.src(),
        ip.dst(),
        tcp.src_port,
        tcp.dst_port,
        tcp.sequence,
        tcp.acknowledgment,
        TcpFlags::PSH | TcpFlags::ACK,
        tcp.window,
        &fake_payload,
        fake_ttl,
        generate_identification(ip.identification(), 0),
    );

    debug!("[HFS] HostFakeSplit: fake_host='{}'", fake_host);
    DesyncResult::inject_only(fake_seg)
}

// === FakeDataDisorder ===

/// [FakeDataDisorder] Fake данные перед реальным пакетом (disorder, TTL=1).
pub fn fake_data_disorder(
    packet: &bytes::Bytes,
    fake_data: &[u8],
    fake_ttl_offset: u8,
) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len()..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    let fake_ttl = 1u8.max(ip.ttl().saturating_sub(fake_ttl_offset));

    let fake_seg = build_tcp_segment_p3(
        ip.src(),
        ip.dst(),
        tcp.src_port,
        tcp.dst_port,
        tcp.sequence,
        tcp.acknowledgment,
        TcpFlags::PSH | TcpFlags::ACK,
        tcp.window,
        fake_data,
        fake_ttl,
        generate_identification(ip.identification(), 0),
    );

    debug!("[FDD] FakeDataDisorder: fake_len={}", fake_data.len());
    DesyncResult::inject_only(fake_seg)
}

// === SynAckSplit ===

/// [SynAckSplit] Разделить SYN+ACK на отдельные SYN и ACK сегменты.
pub fn syn_ack_split(packet: &[u8]) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    let tcp_data = &packet[ip.header_len()..];
    let tcp = match parse_tcp_packet(tcp_data) {
        Some(t) => t,
        None => return DesyncResult::passthrough(),
    };

    if tcp.flags & 0x12 != 0x12 {
        return DesyncResult::passthrough();
    }

    let syn_seg = build_tcp_segment_p3(
        ip.src(),
        ip.dst(),
        tcp.src_port,
        tcp.dst_port,
        tcp.sequence,
        0,
        TcpFlags::SYN,
        tcp.window,
        &[],
        ip.ttl(),
        generate_identification(ip.identification(), 0),
    );

    let ack_seg = build_tcp_segment_p3(
        ip.src(),
        ip.dst(),
        tcp.src_port,
        tcp.dst_port,
        tcp.sequence.wrapping_add(1),
        tcp.acknowledgment.wrapping_add(1),
        TcpFlags::ACK,
        tcp.window,
        &[],
        ip.ttl(),
        generate_identification(ip.identification(), 1),
    );

    debug!("[SAS] SynAckSplit: SEQ={}", tcp.sequence);
    DesyncResult {
        modified: None,
        inject: smallvec::smallvec![bytes::Bytes::from(syn_seg), bytes::Bytes::from(ack_seg)],
        inter_delay_us: 0,
        drop: false,
        inject_direction: crate::desync::InjectDirection::PreserveOriginal,
    }
}
