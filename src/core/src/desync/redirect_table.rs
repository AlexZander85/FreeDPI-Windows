use dashmap::DashMap;
use std::net::IpAddr;
use std::time::Instant;

/// T59: Таблица соответствия локального src_port -> (оригинальный dst, домен, время).
/// Ключ — src_port клиента (уникален в пределах TCP соединений клиента на loopback).
#[derive(Clone, Debug)]
pub struct RedirectEntry {
    pub orig_dst_ip: IpAddr,
    pub orig_dst_port: u16,
    pub domain: Option<String>,
    pub created_at: Instant,
}

pub struct RedirectTable {
    map: DashMap<u16, RedirectEntry>,
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

    /// Периодическая очистка устаревших записей (SYN тайм-аут).
    pub fn sweep_stale(&self, max_age: std::time::Duration) -> usize {
        let before = self.map.len();
        self.map.retain(|_, e| e.created_at.elapsed() < max_age);
        before.saturating_sub(self.map.len())
    }

    pub fn is_ip_active(&self, ip: &IpAddr) -> bool {
        self.map.iter().any(|entry| entry.value().orig_dst_ip == *ip)
    }
}

impl Default for RedirectTable {
    fn default() -> Self {
        Self::new()
    }
}
