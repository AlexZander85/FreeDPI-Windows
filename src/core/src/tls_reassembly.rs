use crate::conntrack::ConnKey;
use bytes::BytesMut;
use dashmap::DashMap;
use std::time::{Duration, Instant};

const MAX_CLIENT_HELLO_BUF: usize = 8192;
const ENTRY_TTL: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct Entry {
    buf: BytesMut,
    last: Instant,
}

#[derive(Debug, Default)]
pub struct TlsReassembler {
    entries: DashMap<ConnKey, Entry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReassemblyState {
    NeedMore,
    Complete,
    NotTls,
    TooLarge,
}

impl TlsReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&self, key: ConnKey, payload: &[u8]) -> (ReassemblyState, Option<Vec<u8>>) {
        if payload.is_empty() {
            return (ReassemblyState::NeedMore, None);
        }

        // If it does not start with handshake record type (0x16) and we don't have an entry yet,
        // it cannot be TLS ClientHello.
        if !payload.starts_with(&[0x16]) && self.entries.get(&key).is_none() {
            return (ReassemblyState::NotTls, None);
        }

        let mut entry = self.entries.entry(key).or_insert_with(|| Entry {
            buf: BytesMut::with_capacity(2048),
            last: Instant::now(),
        });
        entry.last = Instant::now();

        if entry.buf.len() + payload.len() > MAX_CLIENT_HELLO_BUF {
            drop(entry);
            self.entries.remove(&key);
            return (ReassemblyState::TooLarge, None);
        }
        entry.buf.extend_from_slice(payload);

        let state = classify_tls_client_hello_buffer(&entry.buf);
        match state {
            ReassemblyState::Complete => {
                let data = entry.buf.to_vec();
                drop(entry);
                self.entries.remove(&key);
                (ReassemblyState::Complete, Some(data))
            }
            ReassemblyState::NotTls | ReassemblyState::TooLarge => {
                drop(entry);
                self.entries.remove(&key);
                (state, None)
            }
            ReassemblyState::NeedMore => (ReassemblyState::NeedMore, None),
        }
    }

    pub fn gc(&self) {
        let now = Instant::now();
        self.entries
            .retain(|_, v| now.duration_since(v.last) <= ENTRY_TTL);
    }
}

fn classify_tls_client_hello_buffer(buf: &[u8]) -> ReassemblyState {
    if buf.len() < 5 {
        return ReassemblyState::NeedMore;
    }
    if buf[0] != 0x16 || buf[1] != 0x03 {
        return ReassemblyState::NotTls;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let record_end = 5usize.saturating_add(record_len);
    if record_end > MAX_CLIENT_HELLO_BUF {
        return ReassemblyState::TooLarge;
    }
    if buf.len() < record_end {
        return ReassemblyState::NeedMore;
    }
    if buf.len() < 9 || buf[5] != 0x01 {
        return ReassemblyState::NotTls;
    }
    let hs_len = ((buf[6] as usize) << 16) | ((buf[7] as usize) << 8) | buf[8] as usize;
    if 9 + hs_len > record_end {
        return ReassemblyState::NeedMore;
    }
    ReassemblyState::Complete
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_key() -> ConnKey {
        ConnKey::new(
            std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            12345,
            443,
            6,
        )
    }

    #[test]
    fn test_reassembler_complete_one_packet() {
        let reassembler = TlsReassembler::new();
        let key = test_key();

        // Valid TLS ClientHello record prefix
        let payload = vec![
            0x16, 0x03, 0x01, 0x00, 0x05, // Record header (length = 5)
            0x01, 0x00, 0x00, 0x01, // Handshake header (length = 1)
            0xAA, // Handshake payload (1 byte)
        ];

        let (state, data) = reassembler.observe(key, &payload);
        assert_eq!(state, ReassemblyState::Complete);
        assert_eq!(data.unwrap(), payload);
    }

    #[test]
    fn test_reassembler_fragmented() {
        let reassembler = TlsReassembler::new();
        let key = test_key();

        let part1 = vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01];
        let part2 = vec![0x00, 0x00, 0x01, 0xAA];

        let (state1, data1) = reassembler.observe(key, &part1);
        assert_eq!(state1, ReassemblyState::NeedMore);
        assert!(data1.is_none());

        let (state2, data2) = reassembler.observe(key, &part2);
        assert_eq!(state2, ReassemblyState::Complete);
        let expected = vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0xAA];
        assert_eq!(data2.unwrap(), expected);
    }

    #[test]
    fn test_reassembler_not_tls() {
        let reassembler = TlsReassembler::new();
        let key = test_key();
        let payload = vec![0x00, 0x01, 0x02, 0x03, 0x04];
        let (state, data) = reassembler.observe(key, &payload);
        assert_eq!(state, ReassemblyState::NotTls);
        assert!(data.is_none());
    }
}
