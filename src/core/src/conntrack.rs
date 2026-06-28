//! Connection tracking — отслеживание состояния TCP/UDP соединений.
//!
//! Использует `DashMap` (64 shards) для низкого contention на multi-core.
//! `typed-arena` для zero-frag allocation.

use dashmap::DashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::debug;

/// Ключ соединения (96 бит).
///
/// Составной ключ: src_ip + dst_ip + src_port + dst_port.
/// Для IPv6 использовать 256-битный ключ (в будущем).
#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
pub struct ConnKey {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl ConnKey {
    /// Создаёт новый ключ соединения.
    pub fn new(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        }
    }
}

/// Состояние TCP соединения
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnState {
    /// SYN отправлен
    SynSent,
    /// SYN-ACK получен
    SynReceived,
    /// Handshake завершён, данные передаются
    Established,
    /// FIN ожидается
    Closing,
    /// Соединение закрыто
    Closed,
}

/// Состояние и метаданные соединения.
#[derive(Debug, Clone)]
pub struct ConntrackEntry {
    pub client_isn: u32,
    pub server_isn: u32,
    pub client_seq: u32,
    pub server_seq: u32,
    pub client_ack: u32,
    pub server_ack: u32,
    pub rtt_us: u64,
    pub state: ConnState,
    pub desync_applied: bool,
    pub strategy_id: u32,
    pub last_activity: Instant,
    pub dup_ack_count: u32,
    /// Per-connection PRNG (Xorshift128**)
    pub rng: Option<crate::desync::rand::PerConnRng>,
}

/// Connection tracking — шардированная хэш-таблица.
///
/// DashMap использует 64 shard'a с отдельными RwLock на каждый.
/// Это минимизирует contention на multi-core системах.
///
/// Clonable — все внутренние данные обёрнуты в Arc.
/// Clone создаёт лёгкую ссылку на те же данные.
#[derive(Clone, Debug)]
pub struct Conntrack {
    inner: Arc<ConntrackInner>,
}

#[derive(Debug)]
struct ConntrackInner {
    map: DashMap<ConnKey, ConntrackEntry>,
    gc_interval: Duration,
    /// Общее количество созданных entry (счётчик)
    total_created: AtomicU64,
    /// Текущее количество активных entry
    active_count: AtomicU64,
}

impl Conntrack {
    /// Создаёт новый conntrack с указанным интервалом GC.
    ///
    /// `gc_interval` — как часто чистить stale соединения (по умолчанию 30 сек).
    pub fn new(gc_interval: Duration) -> Self {
        Self {
            inner: Arc::new(ConntrackInner {
                map: DashMap::new(),
                gc_interval,
                total_created: AtomicU64::new(0),
                active_count: AtomicU64::new(0),
            }),
        }
    }

    /// Вставляет или обновляет запись соединения.
    ///
    /// Если запись уже существует — обновляет поля.
    /// Atomic increment для `total_created` при первой вставке.
    pub fn upsert(&self, key: ConnKey, entry: ConntrackEntry) {
        let existed = self.inner.map.get(&key).is_some();
        self.inner.map.insert(key, entry);
        if !existed {
            self.inner.total_created.fetch_add(1, Ordering::Relaxed);
            self.inner.active_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Быстрый lookup по ключу.
    pub fn get(&self, key: &ConnKey) -> Option<dashmap::mapref::one::Ref<'_, ConnKey, ConntrackEntry>> {
        self.inner.map.get(key)
    }

    /// Мьютирующий доступ к entry.
    pub fn get_mut(&self, key: &ConnKey) -> Option<dashmap::mapref::one::RefMut<'_, ConnKey, ConntrackEntry>> {
        self.inner.map.get_mut(key)
    }

    /// Удаляет запись.
    pub fn remove(&self, key: &ConnKey) -> Option<(ConnKey, ConntrackEntry)> {
        let result = self.inner.map.remove(key);
        if result.is_some() {
            self.inner.active_count.fetch_sub(1, Ordering::Relaxed);
        }
        result
    }

    /// Проверяет, существует ли ключ.
    pub fn contains(&self, key: &ConnKey) -> bool {
        self.inner.map.contains_key(key)
    }

    /// Обновление SEQ с проверкой на OOO/dup-ACK.
    ///
    /// Если delta == 0 → dup-ACK (инкрементируем счётчик).
    /// Если delta < 65535 → нормальное обновление.
    /// Если delta >= 1_000_000 → подозрительно (не обновляем).
    pub fn update_seq_monotonic(&self, key: &ConnKey, seq: u32, ack: u32) {
        if let Some(mut entry) = self.inner.map.get_mut(key) {
            let delta = seq.wrapping_sub(entry.client_seq);
            if delta < 1_000_000 {
                if delta == 0 {
                    entry.dup_ack_count += 1;
                } else if delta < 65535 {
                    entry.client_seq = seq;
                }
            }
            entry.client_ack = ack;
        }
    }

    /// Синтаксический сахар: вставляет entry и возвращает ссылку.
    pub fn insert(&self, key: ConnKey, entry: ConntrackEntry) {
        self.upsert(key, entry);
    }

    /// GC: удаление stale entry (полный итератор).
    pub fn gc(&self, max_idle: Duration) {
        let now = Instant::now();
        let before = self.inner.map.len();
        self.inner.map.retain(|_, entry| {
            let active = now.duration_since(entry.last_activity) < max_idle;
            if !active {
                self.inner.active_count.fetch_sub(1, Ordering::Relaxed);
            }
            active
        });
        let after = self.inner.map.len();
        if before != after {
            debug!("Conntrack GC: {} → {} entries", before, after);
        }
    }

    /// Быстрый GC (step-by-128) — проверяет каждый 128-й entry.
    /// Используется при высокой нагрузке для минимизации блокировки.
    pub fn gc_fast(&self, max_idle: Duration) {
        let now = Instant::now();
        let mut removed = 0u64;
        self.inner.map.iter().step_by(128).for_each(|r| {
            if now.duration_since(r.value().last_activity) > max_idle {
                self.inner.map.remove(r.key());
                removed += 1;
            }
        });
        if removed > 0 {
            self.inner.active_count.fetch_sub(removed, Ordering::Relaxed);
            debug!("Conntrack GC fast: removed {} stale entries", removed);
        }
    }

    /// Фоновый цикл GC.
    ///
    /// Запускается через `tokio::spawn`.
    /// По умолчанию: GC каждые 30 сек, max_idle = 120 сек.
    pub async fn gc_loop(&self) {
        let mut interval = tokio::time::interval(self.inner.gc_interval);
        loop {
            interval.tick().await;
            self.gc(Duration::from_secs(120));
        }
    }

    /// Количество активных соединений.
    pub fn active_count(&self) -> u64 {
        self.inner.active_count.load(Ordering::Relaxed)
    }

    /// Общее количество созданных соединений (за всё время).
    pub fn total_created(&self) -> u64 {
        self.inner.total_created.load(Ordering::Relaxed)
    }

    /// Снапшот всех соединений для API.
    pub fn snapshot(&self) -> Vec<(ConnKey, ConntrackEntry)> {
        self.inner.map
            .iter()
            .map(|r| (*r.key(), r.value().clone()))
            .collect()
    }
}

impl Default for Conntrack {
    fn default() -> Self {
        Self::new(Duration::from_secs(30))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Instant;

    fn test_key() -> ConnKey {
        ConnKey::new(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(10, 0, 0, 1),
            54321,
            443,
        )
    }

    fn test_entry() -> ConntrackEntry {
        ConntrackEntry {
            client_isn: 1000,
            server_isn: 2000,
            client_seq: 1001,
            server_seq: 2001,
            client_ack: 2001,
            server_ack: 1001,
            rtt_us: 50000,
            state: ConnState::Established,
            desync_applied: true,
            strategy_id: 42,
            last_activity: Instant::now(),
            dup_ack_count: 0,
            rng: None,
        }
    }

    #[test]
    fn test_insert_and_get() {
        let ct = Conntrack::default();
        let key = test_key();
        let entry = test_entry();

        ct.insert(key, entry);
        assert!(ct.contains(&key));

        let retrieved = ct.get(&key).unwrap();
        assert_eq!(retrieved.strategy_id, 42);
        assert_eq!(retrieved.state, ConnState::Established);
    }

    #[test]
    fn test_remove() {
        let ct = Conntrack::default();
        let key = test_key();
        ct.insert(key, test_entry());

        let removed = ct.remove(&key);
        assert!(removed.is_some());
        assert!(!ct.contains(&key));
    }

    #[test]
    fn test_gc_removes_stale() {
        let ct = Conntrack::default();
        let key = test_key();
        let mut entry = test_entry();
        entry.last_activity = Instant::now() - Duration::from_secs(300); // 5 min ago
        ct.insert(key, entry);

        ct.gc(Duration::from_secs(120)); // max_idle = 2 min
        assert!(!ct.contains(&key));
    }

    #[test]
    fn test_gc_keeps_recent() {
        let ct = Conntrack::default();
        let key = test_key();
        let entry = test_entry(); // last_activity = now
        ct.insert(key, entry);

        ct.gc(Duration::from_secs(120));
        assert!(ct.contains(&key));
    }
}
