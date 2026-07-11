//! Flow-affinity routing for packet shard dispatch.
//!
//! Provides fast flow classification and worker shard assignment
//! so all packets of one bidirectional flow go to the same shard worker.
//! Unknown / non-classifiable flows are hashed from first bytes.

use crate::classifier::{Classification, Classifier};
use crate::conntrack::{ConnKey, FlowKey};
use std::hash::{Hash, Hasher};

/// Classify a raw packet into an optional `FlowKey` for shard routing.
///
/// Returns `None` for `Classification::Unknown` (truncated / unrecognisable).
#[inline]
pub fn classify_flow_key(packet: &[u8]) -> Option<FlowKey> {
    match Classifier::classify(packet) {
        Classification::Tls(cp)
        | Classification::Quic(cp)
        | Classification::Dns(cp)
        | Classification::Http(cp)
        | Classification::Other(cp) => Some(FlowKey::new_bidirectional(
            cp.src_ip,
            cp.dst_ip,
            cp.src_port,
            cp.dst_port,
            cp.protocol,
        )),
        Classification::Unknown => None,
    }
}

/// Determine shard index for a flow.
///
/// Known flows → hash canonical `FlowKey` with `FxHasher`.
/// Unknown flows → hash packet length + first 16 bytes (stable fallback).
#[inline]
pub fn shard_for_flow(key: Option<FlowKey>, packet: &[u8], shards: usize) -> usize {
    let shards = shards.max(1);
    let mut h = rustc_hash::FxHasher::default();
    match key {
        Some(k) => k.hash(&mut h),
        None => {
            packet.len().hash(&mut h);
            packet.get(..16).unwrap_or(packet).hash(&mut h);
        }
    }
    (h.finish() as usize) % shards
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conntrack::ConnKey;
    use std::net::IpAddr;

    #[test]
    fn flow_key_is_bidirectional() {
        let a = ConnKey::new(
            "10.0.0.1".parse::<IpAddr>().unwrap(),
            "1.1.1.1".parse::<IpAddr>().unwrap(),
            50000,
            443,
            6,
        );
        let b = ConnKey::new(
            "1.1.1.1".parse::<IpAddr>().unwrap(),
            "10.0.0.1".parse::<IpAddr>().unwrap(),
            443,
            50000,
            6,
        );
        let fa = FlowKey::new_bidirectional(a.src_ip, a.dst_ip, a.src_port, a.dst_port, a.proto);
        let fb = FlowKey::new_bidirectional(b.src_ip, b.dst_ip, b.src_port, b.dst_port, b.proto);
        assert_eq!(fa, fb);
    }

    #[test]
    fn same_flow_same_shard() {
        let key = Some(FlowKey::new_bidirectional(
            "10.0.0.1".parse::<IpAddr>().unwrap(),
            "1.1.1.1".parse::<IpAddr>().unwrap(),
            50000,
            443,
            6,
        ));
        let s1 = shard_for_flow(key, &[], 16);
        let s2 = shard_for_flow(key, &[1, 2, 3], 16);
        assert_eq!(s1, s2);
    }

    #[test]
    fn unknown_flow_fallback_is_stable() {
        let s1 = shard_for_flow(None, &[0x45, 0x00, 0x00, 0x3c], 8);
        let s2 = shard_for_flow(None, &[0x45, 0x00, 0x00, 0x3c], 8);
        assert_eq!(s1, s2);
    }

    #[test]
    fn classify_ipv4_tls_returns_flow_key() {
        // Minimal IPv4 + TCP + TLS ClientHello
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0a, 0x00,
            0x00, 0x01, // src 10.0.0.1
            0x01, 0x01, 0x01, 0x01, // dst 1.1.1.1
        ]);
        // TCP header + TLS CH
        pkt.extend_from_slice(&[
            0xc3, 0x50, // src port 50000
            0x01, 0xbb, // dst port 443
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x18, 0xff, 0xff, // data offset=5, flags
            0x00, 0x00, 0x00, 0x00, // checksum, urgent
            0x16, 0x03, 0x01, 0x00, 0x05, // TLS record
            0x01, 0x00, 0x00, 0x00, 0x00,
        ]);
        let key = classify_flow_key(&pkt);
        assert!(key.is_some());
        let fk = key.unwrap();
        assert_eq!(fk.proto, 6);
        // Bidirectional: ip_a <= ip_b
        assert!(fk.ip_a.to_string() == "1.1.1.1" || fk.ip_a.to_string() == "10.0.0.1");
    }
}
