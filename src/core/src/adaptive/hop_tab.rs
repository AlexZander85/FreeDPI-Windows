//! HopTab — Auto-TTL Cache for fake ClientHello.
//!
//! 4-way set-associative hash table (1024 sets × 4 ways) для O(1) lookup.

use std::sync::atomic::{AtomicU64, Ordering};

const NUM_SETS: usize = 1024;
const NUM_WAYS: usize = 4;
const SET_MASK: usize = NUM_SETS - 1;

/// Pack entry: [ip:32][hops:8][gen:8] = 48 bits in u64.
fn pack_entry(ip: u32, hops: u8, gen: u8) -> u64 {
    (ip as u64) | ((hops as u64) << 32) | ((gen as u64) << 40)
}

fn unpack_entry(val: u64) -> (u32, u8, u8) {
    let ip = val as u32;
    let hops = (val >> 32) as u8;
    let gen = (val >> 40) as u8;
    (ip, hops, gen)
}

/// Known CDN initial TTL values (used in estimate ranges).
#[allow(dead_code)]
const CLOUDFLARE_TTL: u8 = 60;
#[allow(dead_code)]
const AWS_TTL: u8 = 57;
#[allow(dead_code)]
const AKAMAI_TTL: u8 = 54;

pub struct HopTab {
    /// 1024 sets × 4 ways = 4096 entries.
    cache: [[AtomicU64; NUM_WAYS]; NUM_SETS],
    /// Per-set generation counter for LRU replacement.
    gen_counters: [AtomicU64; NUM_SETS],
}

impl std::fmt::Debug for HopTab {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HopTab").field("len", &self.len()).finish()
    }
}

impl HopTab {
    pub fn new() -> Self {
        Self {
            cache: [const { [const { AtomicU64::new(0) }; NUM_WAYS] }; NUM_SETS],
            gen_counters: [const { AtomicU64::new(0) }; NUM_SETS],
        }
    }

    /// Estimate hops from recv_ttl, recognizing known CDN init TTLs.
    pub fn estimate(recv_ttl: u8) -> u8 {
        let init_ttl: u8 = match recv_ttl {
            0..=54 => 54,    // Akamai
            55..=57 => 57,   // AWS
            58..=60 => 60,   // Cloudflare
            61..=64 => 64,   // Linux/macOS
            65..=128 => 128, // Windows
            _ => 255,        // Cisco/other
        };
        init_ttl.saturating_sub(recv_ttl)
    }

    pub fn ip_to_u32(ip: &std::net::Ipv4Addr) -> u32 {
        ip.to_bits()
    }

    fn hash(ip: u32) -> usize {
        let mut h = ip;
        h ^= h >> 16;
        h = h.wrapping_mul(0x45d9f3b);
        h ^= h >> 16;
        h = h.wrapping_mul(0x45d9f3b);
        h ^= h >> 16;
        (h as usize) & SET_MASK
    }

    /// Insert into set-associative cache: find empty way or replace oldest gen.
    pub fn insert(&self, dst_ip: u32, hops: u8) {
        let set = Self::hash(dst_ip);
        let gen = self.gen_counters[set].fetch_add(1, Ordering::Relaxed) as u8;

        // Look for empty way
        for way in 0..NUM_WAYS {
            let (ip, _, _) = unpack_entry(self.cache[set][way].load(Ordering::Relaxed));
            if ip == 0 {
                self.cache[set][way].store(pack_entry(dst_ip, hops, gen), Ordering::Relaxed);
                return;
            }
        }

        // All ways occupied: replace entry with smallest generation (oldest)
        let mut min_gen = u8::MAX;
        let mut min_way = 0;
        for way in 0..NUM_WAYS {
            let (_, _, g) = unpack_entry(self.cache[set][way].load(Ordering::Relaxed));
            if g < min_gen || g == u8::MAX {
                min_gen = g;
                min_way = way;
            }
        }
        self.cache[set][min_way].store(pack_entry(dst_ip, hops, gen), Ordering::Relaxed);
    }

    /// Lookup in set-associative cache: check all 4 ways in the set.
    pub fn get(&self, dst_ip: u32) -> Option<u8> {
        let set = Self::hash(dst_ip);
        for way in 0..NUM_WAYS {
            let (ip, hops, _) = unpack_entry(self.cache[set][way].load(Ordering::Relaxed));
            if ip == dst_ip {
                return Some(hops);
            }
        }
        None
    }

    pub fn fake_ttl(&self, dst_ip: u32) -> Option<u8> {
        self.get(dst_ip).map(|hops| {
            if hops <= 2 {
                return 1;
            }
            (hops - 1).clamp(2, 64)
        })
    }

    pub fn fake_ttl_for_ip(&self, ip: &std::net::Ipv4Addr) -> Option<u8> {
        self.fake_ttl(Self::ip_to_u32(ip))
    }

    pub fn observe(&self, ip: u32, recv_ttl: u8) {
        let hops = Self::estimate(recv_ttl);
        self.insert(ip, hops);
    }

    /// Robust observation with outlier rejection and EMA smoothing.
    ///
    /// - Outlier rejection: ignores observation if differs by >5 hops from existing.
    /// - EMA smoothing: blends new observation with existing value (alpha=0.3).
    pub fn observe_robust(&self, ip: u32, recv_ttl: u8) {
        let new_hops = Self::estimate(recv_ttl);

        if let Some(existing) = self.get(ip) {
            let diff = (new_hops as i16 - existing as i16).abs();
            // Outlier rejection: >5 hops difference = ignore
            if diff > 5 {
                return;
            }
            // EMA smoothing: new = alpha * observed + (1-alpha) * existing
            let alpha = 0.3_f64;
            let smoothed =
                (alpha * new_hops as f64 + (1.0 - alpha) * existing as f64).round() as u8;
            self.insert(ip, smoothed);
        } else {
            // No existing entry — just insert
            self.insert(ip, new_hops);
        }
    }

    pub fn estimate_udp(recv_ttl: u8, src_port: u16) -> (u32, u8) {
        let hops = Self::estimate(recv_ttl);
        let key = (src_port as u32) << 16 | (recv_ttl as u32);
        (key, hops)
    }

    pub fn len(&self) -> usize {
        let mut count = 0;
        for set in 0..NUM_SETS {
            for way in 0..NUM_WAYS {
                let (ip, _, _) = unpack_entry(self.cache[set][way].load(Ordering::Relaxed));
                if ip != 0 {
                    count += 1;
                }
            }
        }
        count
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn snapshot(&self) -> Vec<(u32, u8)> {
        let mut result = Vec::new();
        for set in 0..NUM_SETS {
            for way in 0..NUM_WAYS {
                let (ip, hops, _) = unpack_entry(self.cache[set][way].load(Ordering::Relaxed));
                if ip != 0 {
                    result.push((ip, hops));
                }
            }
        }
        result
    }
}

impl Default for HopTab {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_estimate_cloudflare() {
        // Cloudflare uses init_ttl=60
        assert_eq!(HopTab::estimate(58), 2); // 60 - 58 = 2
        assert_eq!(HopTab::estimate(60), 0);
    }

    #[test]
    fn test_estimate_aws() {
        // AWS uses init_ttl=57
        assert_eq!(HopTab::estimate(55), 2); // 57 - 55 = 2
        assert_eq!(HopTab::estimate(57), 0);
    }

    #[test]
    fn test_estimate_akamai() {
        // Akamai uses init_ttl=54
        assert_eq!(HopTab::estimate(44), 10); // 54 - 44 = 10
        assert_eq!(HopTab::estimate(54), 0);
    }

    #[test]
    fn test_estimate_linux() {
        assert_eq!(HopTab::estimate(61), 3); // 64 - 61 = 3
        assert_eq!(HopTab::estimate(64), 0);
    }

    #[test]
    fn test_estimate_windows() {
        assert_eq!(HopTab::estimate(119), 9); // 128 - 119 = 9
        assert_eq!(HopTab::estimate(128), 0);
    }

    #[test]
    fn test_insert_get() {
        let tab = HopTab::new();
        let ip = HopTab::ip_to_u32(&Ipv4Addr::new(8, 8, 8, 8));
        tab.insert(ip, 13);
        assert_eq!(tab.get(ip), Some(13));
    }

    #[test]
    fn test_fake_ttl() {
        let tab = HopTab::new();
        let ip = HopTab::ip_to_u32(&Ipv4Addr::new(8, 8, 8, 8));
        tab.insert(ip, 13);
        assert_eq!(tab.fake_ttl(ip), Some(12));
    }

    #[test]
    fn test_set_associative_eviction() {
        let tab = HopTab::new();
        // Fill all 4 ways of set 0 with different IPs that hash to same set
        // We'll just insert many IPs and verify lookup works
        for i in 0..100u32 {
            let ip = i | (i << 8) | (i << 16) | (1 << 24); // force different IPs
            tab.insert(ip, (i % 60) as u8 + 1);
        }
        // Verify some entries are still accessible
        let ip = HopTab::ip_to_u32(&Ipv4Addr::new(1, 0, 0, 0));
        assert!(tab.get(ip).is_some());
    }

    #[test]
    fn test_observe_robust_no_outlier() {
        let tab = HopTab::new();
        let ip = HopTab::ip_to_u32(&Ipv4Addr::new(8, 8, 8, 8));
        tab.observe_robust(ip, 58); // estimate=2 (Cloudflare: 60-58)
        tab.observe_robust(ip, 59); // estimate=1, diff=1, accepted
        let hops = tab.get(ip).unwrap();
        // EMA: 0.3*1 + 0.7*2 = 1.7 → 2
        assert_eq!(hops, 2);
    }

    #[test]
    fn test_observe_robust_outlier_rejected() {
        let tab = HopTab::new();
        let ip = HopTab::ip_to_u32(&Ipv4Addr::new(8, 8, 8, 8));
        tab.observe_robust(ip, 58); // estimate=2 (Cloudflare: 60-58)
        tab.observe_robust(ip, 10); // estimate=44 (Windows: 128-10), diff=42 > 5, rejected
        assert_eq!(tab.get(ip), Some(2));
    }
}
