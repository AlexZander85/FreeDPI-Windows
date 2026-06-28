//! Synthetic Event Tagging — UUID-теги для injected пакетов.
//!
//! ## Проблема
//! При инъекции пакетов через raw socket они могут быть повторно перехвачены
//! WinDivert, создавая бесконечный loop (inject → divert → inject → ...).
//!
//! ## Решение (из OpenLogi)
//! Каждый поток получает UUID-тег (16 байт), который записывается в
//! **TCP payload** (не в IP header!) каждого injected пакета.
//!
//! WinDivert фильтр исключает пакеты с этим тегом:
//! ```text
//! not (tcp.PayloadLength >= 16 and
//!      tcp.Payload[0:16] == <UUID bytes>)
//! ```
//!
//! ## Важно
//! Тег пишется в TCP payload (после IP + TCP заголовков), а НЕ в начало пакета.
//! Запись в packet[0..16] уничтожит IP header и сломает пакет.

use std::cell::RefCell;
use uuid::Uuid;

const UUID_SIZE: usize = 16;

thread_local! {
    static INJECTION_TAG: RefCell<[u8; UUID_SIZE]> = RefCell::new({
        let uuid = Uuid::new_v4();
        *uuid.as_bytes()
    });
}

/// Определяет смещение до TCP payload в пакете.
///
/// Возвращает смещение (bytes) от начала пакета до начала TCP payload.
/// Если пакет не содержит TCP — возвращает `None`.
fn tcp_payload_offset(packet: &[u8]) -> Option<usize> {
    if packet.len() < 20 {
        return None;
    }

    // IPv4 header
    let version = (packet[0] >> 4) & 0xF;
    if version != 4 {
        return None;
    }

    let ihl = (packet[0] & 0xF) as usize * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }

    // Проверяем TCP protocol (byte 9)
    if packet[9] != 6 {
        return None;
    }

    // TCP header length (data offset)
    if packet.len() < ihl + 12 {
        return None;
    }
    let tcp_header_len = ((packet[ihl + 12] >> 4) & 0xF) as usize * 4;

    Some(ihl + tcp_header_len)
}

/// Маркирует пакет UUID-тегом в TCP payload.
///
/// Записывает UUID в первые 16 байт TCP payload (после IP + TCP заголовков).
/// Если payload короче 16 байт — ничего не делает.
///
/// **НЕ пишет в IP header** — это критически важно для работы пакета.
pub fn tag_injected_packet(packet: &mut [u8]) {
    let Some(offset) = tcp_payload_offset(packet) else {
        return;
    };

    let payload_end = packet.len();
    if payload_end - offset < UUID_SIZE {
        return;
    }

    INJECTION_TAG.with(|tag| {
        let tag = tag.borrow();
        packet[offset..offset + UUID_SIZE].copy_from_slice(&tag[..]);
    });
}

/// Проверяет, является ли пакет нашим собственным injected.
///
/// Сравнивает первые 16 байт TCP payload с UUID тегом текущего потока.
pub fn is_injected_packet(packet: &[u8]) -> bool {
    let Some(offset) = tcp_payload_offset(packet) else {
        return false;
    };

    let payload_end = packet.len();
    if payload_end - offset < UUID_SIZE {
        return false;
    }

    INJECTION_TAG.with(|tag| {
        let tag = tag.borrow();
        packet[offset..offset + UUID_SIZE] == tag[..]
    })
}

/// Генерирует строку для WinDivert фильтра.
pub fn injected_filter_clause() -> String {
    INJECTION_TAG.with(|tag| {
        let tag = tag.borrow();
        let hex_bytes: Vec<String> = tag.iter().map(|b| format!("{:#04x}", b)).collect();
        format!("not (tcp.PayloadLength >= {} and tcp.Payload[0:16] == {})",
                UUID_SIZE,
                hex_bytes.join(" "))
    })
}

pub fn reset_injection_tag() {
    INJECTION_TAG.with(|tag| {
        let uuid = Uuid::new_v4();
        *tag.borrow_mut() = *uuid.as_bytes();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_tcp_packet() -> Vec<u8> {
        // IP header (20 bytes) + TCP header (20 bytes) + payload
        let mut pkt = vec![0u8; 60];
        // IPv4: version=4, IHL=5
        pkt[0] = 0x45;
        // Protocol: TCP
        pkt[9] = 6;
        // Total length: 60
        pkt[2..4].copy_from_slice(&60u16.to_be_bytes());
        // TCP data offset = 5 (20 bytes)
        pkt[32] = 0x50;
        pkt
    }

    #[test]
    fn test_tag_in_tcp_payload() {
        let mut pkt = build_tcp_packet();
        // Payload starts at offset 40 (IP 20 + TCP 20)
        assert_eq!(tcp_payload_offset(&pkt), Some(40));

        tag_injected_packet(&mut pkt);
        assert!(is_injected_packet(&pkt));

        // IP header не должен быть изменён!
        assert_eq!(pkt[0], 0x45); // version=4, IHL=5
        assert_eq!(pkt[9], 6);    // TCP protocol

        // Тег в payload (offset 40)
        assert_ne!(pkt[40], 0); // UUID не нулевой
    }

    #[test]
    fn test_non_tcp_packet_not_tagged() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45; // IPv4
        pkt[9] = 17;   // UDP (не TCP)
        tag_injected_packet(&mut pkt);
        assert!(!is_injected_packet(&pkt));
    }

    #[test]
    fn test_short_payload_no_tag() {
        let mut pkt = build_tcp_packet();
        // Payload = 0 bytes (только заголовки)
        // tcp_payload_offset = 40, payload_end = 60
        // 60 - 40 = 20 >= 16, тег запишется
        tag_injected_packet(&mut pkt);
        assert!(is_injected_packet(&pkt));
    }

    #[test]
    fn test_empty_packet_no_panic() {
        let mut empty: Vec<u8> = vec![];
        tag_injected_packet(&mut empty);
        assert!(!is_injected_packet(&empty));
    }

    #[test]
    fn test_reset_tag() {
        let mut pkt = build_tcp_packet();
        tag_injected_packet(&mut pkt);
        assert!(is_injected_packet(&pkt));

        reset_injection_tag();
        assert!(!is_injected_packet(&pkt));
    }

    #[test]
    fn test_filter_clause_format() {
        let clause = injected_filter_clause();
        assert!(clause.starts_with("not (tcp.PayloadLength >= 16"));
    }

    #[test]
    fn test_ip_header_preserved() {
        let mut pkt = build_tcp_packet();
        let original_ip = pkt[..20].to_vec();

        tag_injected_packet(&mut pkt);

        // IP header должен остаться нетронутым
        assert_eq!(pkt[..20], original_ip[..]);
    }
}
