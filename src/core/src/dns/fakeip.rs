//! FakeIP DNS — аллокация fake IP адресов для доменов (из sing-box).

use dashmap::DashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use tracing::debug;

const FAKEIP_BASE: u32 = 0x0A00_0000;
const FAKEIP_MASK: u32 = 0x00FF_FFFF;

pub struct FakeIpEntry {
    pub domain: String,
    pub last_used: AtomicU64,
}

/// FakeIP DNS Manager.
pub struct FakeIpManager {
    domain_to_ip: Arc<DashMap<String, Ipv4Addr>>,
    ip_to_domain: Arc<DashMap<Ipv4Addr, FakeIpEntry>>,
    next_ip: Arc<AtomicU32>,
    max_entries: usize,
    evictions: Arc<AtomicU64>,
    access_counter: Arc<AtomicU64>,
}

impl FakeIpManager {
    pub fn new(max_entries: usize) -> Self {
        Self {
            domain_to_ip: Arc::new(DashMap::new()),
            ip_to_domain: Arc::new(DashMap::new()),
            next_ip: Arc::new(AtomicU32::new(1)),
            max_entries,
            evictions: Arc::new(AtomicU64::new(0)),
            access_counter: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn allocate(&self, domain: &str) -> Option<Ipv4Addr> {
        let now = self.access_counter.fetch_add(1, Ordering::Relaxed);

        // 1. Проверяем существующий маппинг
        if let Some(ip) = self.domain_to_ip.get(domain) {
            let ip_addr = *ip;
            if let Some(entry) = self.ip_to_domain.get(&ip_addr) {
                entry.last_used.store(now, Ordering::Relaxed);
            }
            return Some(ip_addr);
        }

        // 2. Если достигнут лимит, вытесняем старейшую запись (LRU)
        if self.domain_to_ip.len() >= self.max_entries {
            let mut oldest_ip: Option<Ipv4Addr> = None;
            let mut oldest_time = u64::MAX;

            for entry in self.ip_to_domain.iter() {
                let t = entry.value().last_used.load(Ordering::Relaxed);
                if t < oldest_time {
                    oldest_time = t;
                    oldest_ip = Some(*entry.key());
                }
            }

            if let Some(ip_to_evict) = oldest_ip {
                if let Some((_, entry)) = self.ip_to_domain.remove(&ip_to_evict) {
                    self.domain_to_ip.remove(&entry.domain);
                    self.evictions.fetch_add(1, Ordering::Relaxed);
                    debug!(
                        "FakeIP Cache full. Evicted domain '{}' (IP {}) with last use logical tick {}",
                        entry.domain,
                        ip_to_evict,
                        oldest_time
                    );

                    // Реиспользуем освобождённый IP!
                    self.domain_to_ip.insert(domain.to_string(), ip_to_evict);
                    self.ip_to_domain.insert(
                        ip_to_evict,
                        FakeIpEntry {
                            domain: domain.to_string(),
                            last_used: AtomicU64::new(now),
                        },
                    );
                    return Some(ip_to_evict);
                }
            }
        }

        // 3. Выделяем новый IP (если лимит не превышен или не удалось вытеснить)
        let offset = self.next_ip.fetch_add(1, Ordering::Relaxed);
        if offset > FAKEIP_MASK {
            tracing::warn!("FakeIP pool exhausted (16M addresses)");
            return None;
        }
        let ip_val = FAKEIP_BASE | (offset & FAKEIP_MASK);
        let ip = Ipv4Addr::from_bits(ip_val);

        debug!("FakeIP allocated: {} → {}", domain, ip);
        self.domain_to_ip.insert(domain.to_string(), ip);
        self.ip_to_domain.insert(
            ip,
            FakeIpEntry {
                domain: domain.to_string(),
                last_used: AtomicU64::new(now),
            },
        );

        Some(ip)
    }

    pub fn lookup(&self, fake_ip: &IpAddr) -> Option<String> {
        match fake_ip {
            IpAddr::V4(v4) => {
                if let Some(entry) = self.ip_to_domain.get(v4) {
                    let now = self.access_counter.fetch_add(1, Ordering::Relaxed);
                    entry.last_used.store(now, Ordering::Relaxed);
                    Some(entry.domain.clone())
                } else {
                    None
                }
            }
            IpAddr::V6(_) => None,
        }
    }

    pub fn remove(&self, domain: &str) {
        if let Some((_, ip)) = self.domain_to_ip.remove(domain) {
            self.ip_to_domain.remove(&ip);
            debug!("FakeIP removed: {} → {}", domain, ip);
        }
    }

    pub fn clear(&self) {
        self.domain_to_ip.clear();
        self.ip_to_domain.clear();
        self.next_ip.store(1, Ordering::Relaxed);
        self.evictions.store(0, Ordering::Relaxed);
        self.access_counter.store(0, Ordering::Relaxed);
    }

    pub fn len(&self) -> usize {
        self.domain_to_ip.len()
    }

    pub fn is_empty(&self) -> bool {
        self.domain_to_ip.is_empty()
    }

    pub fn evictions(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }

    pub fn is_fake_ip(ip: &Ipv4Addr) -> bool {
        ip.octets()[0] == 10
    }

    pub fn snapshot(&self) -> Vec<(String, Ipv4Addr)> {
        self.domain_to_ip
            .iter()
            .map(|entry| (entry.key().clone(), *entry.value()))
            .collect()
    }
}

impl Default for FakeIpManager {
    fn default() -> Self {
        Self::new(10_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate_and_lookup() {
        let manager = FakeIpManager::new(100);
        let ip = manager.allocate("example.com").unwrap();

        assert!(FakeIpManager::is_fake_ip(&ip));
        assert!(ip.octets()[0] == 10);

        let domain = manager.lookup(&IpAddr::V4(ip));
        assert_eq!(domain, Some("example.com".to_string()));
    }

    #[test]
    fn test_same_domain_returns_same_ip() {
        let manager = FakeIpManager::new(100);
        let ip1 = manager.allocate("example.com").unwrap();
        let ip2 = manager.allocate("example.com").unwrap();
        assert_eq!(ip1, ip2);
    }

    #[test]
    fn test_different_domains_different_ips() {
        let manager = FakeIpManager::new(100);
        let ip1 = manager.allocate("example.com").unwrap();
        let ip2 = manager.allocate("google.com").unwrap();
        assert_ne!(ip1, ip2);
    }

    #[test]
    fn test_remove() {
        let manager = FakeIpManager::new(100);
        let ip = manager.allocate("example.com").unwrap();

        manager.remove("example.com");
        assert!(manager.lookup(&IpAddr::V4(ip)).is_none());
        assert_eq!(manager.len(), 0);
    }

    #[test]
    fn test_clear() {
        let manager = FakeIpManager::new(100);
        manager.allocate("a.com");
        manager.allocate("b.com");
        assert_eq!(manager.len(), 2);

        manager.clear();
        assert_eq!(manager.len(), 0);
    }

    #[test]
    fn test_is_fake_ip() {
        assert!(FakeIpManager::is_fake_ip(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(FakeIpManager::is_fake_ip(&Ipv4Addr::new(10, 255, 255, 255)));
        assert!(!FakeIpManager::is_fake_ip(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!FakeIpManager::is_fake_ip(&Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_snapshot() {
        let manager = FakeIpManager::new(100);
        manager.allocate("a.com");
        manager.allocate("b.com");

        let snap = manager.snapshot();
        assert_eq!(snap.len(), 2);
        assert!(snap.iter().any(|(d, _)| d == "a.com"));
        assert!(snap.iter().any(|(d, _)| d == "b.com"));
    }

    #[test]
    fn test_fake_ip_manager_ttl_eviction() {
        let manager = FakeIpManager::new(3);
        let ip1 = manager.allocate("a.com").unwrap();
        let ip2 = manager.allocate("b.com").unwrap();
        let ip3 = manager.allocate("c.com").unwrap();

        // Access ip1, making it most recently used
        assert_eq!(manager.lookup(&IpAddr::V4(ip1)), Some("a.com".to_string()));

        // Allocate 4th domain, should trigger eviction of "b.com" (oldest unused)
        let ip4 = manager.allocate("d.com").unwrap();
        assert_eq!(ip4, ip2); // Recycled the IP of b.com
        assert_eq!(manager.lookup(&IpAddr::V4(ip2)), Some("d.com".to_string()));
        assert_eq!(manager.lookup(&IpAddr::V4(ip3)), Some("c.com".to_string()));
        assert_eq!(manager.lookup(&IpAddr::V4(ip1)), Some("a.com".to_string()));
        assert_eq!(manager.evictions(), 1);
    }
}
