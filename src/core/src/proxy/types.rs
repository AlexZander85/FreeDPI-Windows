use dashmap::DashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

pub const REDIRECTOR_PORT_RANGE: std::ops::Range<u16> = 17650..17660;

/// Запись соответствия локального src_port клиента → оригинальный адрес назначения.
#[derive(Clone, Debug)]
pub struct RedirectEntry {
    pub orig_dst_ip: IpAddr,
    pub orig_dst_port: u16,
    pub domain: Option<String>,
    pub created_at: Instant,
}

/// Таблица активных редиректов клиент→прокси.
pub struct RedirectTable {
    pub map: DashMap<u16, RedirectEntry>,
}

impl RedirectTable {
    pub fn new() -> Self {
        Self {
            map: DashMap::new(),
        }
    }

    pub fn insert(&self, src_port: u16, entry: RedirectEntry) {
        self.map.insert(src_port, entry);
    }

    pub fn get(&self, src_port: u16) -> Option<RedirectEntry> {
        self.map.get(&src_port).map(|e| e.clone())
    }

    pub fn remove(&self, src_port: u16) -> Option<RedirectEntry> {
        self.map.remove(&src_port).map(|(_, e)| e)
    }

    pub fn sweep_stale(&self, max_age: Duration) {
        self.map.retain(|_, e| e.created_at.elapsed() < max_age);
    }
}

impl Default for RedirectTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Один SOCKS5-прокси Opera с состоянием здоровья.
#[derive(Clone, Debug)]
pub struct OperaProxyEntry {
    pub addr: std::net::SocketAddr,
    pub healthy: bool,
    pub last_check: Instant,
    pub consecutive_failures: u32,
}

/// Пул из публичных SOCKS5-адресов Opera с health-check и ротацией.
pub struct OperaProxyPool {
    pub proxies: std::sync::RwLock<Vec<OperaProxyEntry>>,
}

impl OperaProxyPool {
    pub fn new(addrs: Vec<std::net::SocketAddr>) -> Self {
        let proxies = addrs
            .into_iter()
            .map(|addr| OperaProxyEntry {
                addr,
                healthy: true,
                last_check: Instant::now(),
                consecutive_failures: 0,
            })
            .collect();
        Self {
            proxies: std::sync::RwLock::new(proxies),
        }
    }

    pub fn select_best(&self) -> Option<std::net::SocketAddr> {
        self.proxies
            .read()
            .unwrap()
            .iter()
            .find(|p| p.healthy)
            .map(|p| p.addr)
    }

    pub fn is_known_ip(&self, ip: &IpAddr) -> bool {
        self.proxies
            .read()
            .unwrap()
            .iter()
            .any(|p| &p.addr.ip() == ip)
    }

    pub fn mark_result(&self, addr: std::net::SocketAddr, success: bool) {
        let mut proxies = self.proxies.write().unwrap();
        if let Some(p) = proxies.iter_mut().find(|p| p.addr == addr) {
            if success {
                p.consecutive_failures = 0;
                p.healthy = true;
            } else {
                p.consecutive_failures += 1;
                if p.consecutive_failures >= 3 {
                    p.healthy = false;
                }
            }
            p.last_check = Instant::now();
        }
    }
}

/// Домены, идущие через Opera-прокси.
pub struct DomainBlocklist {
    pub static_domains: std::collections::HashSet<String>,
    pub user_domains: std::sync::RwLock<std::collections::HashSet<String>>,
    pub probed_domains: DashMap<String, Instant>,
    pub probed_ttl: Duration,
}

impl DomainBlocklist {
    pub fn new(static_domains: Vec<String>) -> Self {
        Self {
            static_domains: static_domains
                .into_iter()
                .map(|d| d.to_lowercase())
                .collect(),
            user_domains: std::sync::RwLock::new(std::collections::HashSet::new()),
            probed_domains: DashMap::new(),
            probed_ttl: Duration::from_secs(6 * 3600),
        }
    }

    pub fn should_tunnel(&self, domain: &str) -> bool {
        let domain = domain.to_lowercase();
        if self.static_domains.contains(&domain)
            || self.user_domains.read().unwrap().contains(&domain)
        {
            return true;
        }
        if let Some(entry) = self.probed_domains.get(&domain) {
            return entry.elapsed() < self.probed_ttl;
        }
        false
    }

    pub fn mark_probed_blocked(&self, domain: &str) {
        self.probed_domains
            .insert(domain.to_lowercase(), Instant::now());
    }

    pub fn set_user_domains(&self, domains: Vec<String>) {
        *self.user_domains.write().unwrap() =
            domains.into_iter().map(|d| d.to_lowercase()).collect();
    }
}

/// Fake IP: домен ↔ выделенный синтетический IPv4 из диапазона 10.0.0.0/8
pub struct FakeIpManager {
    pub domain_to_ip: DashMap<String, Ipv4Addr>,
    pub ip_to_domain: DashMap<Ipv4Addr, String>,
    pub next_ip: std::sync::atomic::AtomicU32,
    pub max_entries: usize,
}

impl FakeIpManager {
    pub fn new(max_entries: usize) -> Self {
        Self {
            domain_to_ip: DashMap::new(),
            ip_to_domain: DashMap::new(),
            next_ip: std::sync::atomic::AtomicU32::new(1),
            max_entries,
        }
    }

    pub fn allocate(&self, domain: &str) -> Option<Ipv4Addr> {
        let domain = domain.to_lowercase();
        if let Some(ip) = self.domain_to_ip.get(&domain) {
            return Some(*ip);
        }
        if self.domain_to_ip.len() >= self.max_entries {
            return None;
        }
        // 10.0.0.0/8 allocation (starting with 10.0.0.1)
        let offset = self
            .next_ip
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if offset > 0x00FF_FFFF {
            return None;
        }
        let ip_val = 0x0A00_0000 | (offset & 0x00FF_FFFF);
        let ip = Ipv4Addr::from(ip_val);
        self.domain_to_ip.insert(domain.clone(), ip);
        self.ip_to_domain.insert(ip, domain);
        Some(ip)
    }

    pub fn lookup(&self, ip: &IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(v4) => self.ip_to_domain.get(v4).map(|d| d.clone()),
            _ => None,
        }
    }

    pub fn is_fake_ip(&self, ip: &Ipv4Addr) -> bool {
        ip.octets()[0] == 10
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redirect_table() {
        let table = RedirectTable::new();
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));
        let entry = RedirectEntry {
            orig_dst_ip: ip,
            orig_dst_port: 443,
            domain: Some("netflix.com".to_string()),
            created_at: Instant::now(),
        };

        table.insert(12345, entry);
        let fetched = table.get(12345).unwrap();
        assert_eq!(fetched.orig_dst_port, 443);
        assert_eq!(fetched.domain.as_deref(), Some("netflix.com"));

        let removed = table.remove(12345).unwrap();
        assert_eq!(removed.orig_dst_port, 443);
        assert!(table.get(12345).is_none());
    }

    #[test]
    fn test_opera_proxy_pool() {
        let addr1 = "127.0.0.1:1080".parse().unwrap();
        let addr2 = "127.0.0.1:1081".parse().unwrap();
        let pool = OperaProxyPool::new(vec![addr1, addr2]);

        assert_eq!(pool.select_best(), Some(addr1));

        // Mark unhealthy after 3 failures
        pool.mark_result(addr1, false);
        pool.mark_result(addr1, false);
        pool.mark_result(addr1, false);
        assert_eq!(pool.select_best(), Some(addr2));

        // Mark healthy again
        pool.mark_result(addr1, true);
        assert_eq!(pool.select_best(), Some(addr1));
    }

    #[test]
    fn test_domain_blocklist() {
        let blocklist = DomainBlocklist::new(vec!["netflix.com".to_string()]);
        assert!(blocklist.should_tunnel("netflix.com"));
        assert!(!blocklist.should_tunnel("google.com"));

        blocklist.mark_probed_blocked("google.com");
        assert!(blocklist.should_tunnel("google.com"));
    }

    #[test]
    fn test_fake_ip_manager_idempotency() {
        let manager = FakeIpManager::new(10);
        let ip1 = manager.allocate("netflix.com").unwrap();
        let ip2 = manager.allocate("netflix.com").unwrap();
        assert_eq!(ip1, ip2); // Idempotency
    }
}
