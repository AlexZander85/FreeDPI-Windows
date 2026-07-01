//! Connection tracking — отслеживание состояния TCP/UDP соединений.

use dashmap::DashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::debug;

#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
pub struct ConnKey {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

impl ConnKey {
    pub fn new(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        proto: u8,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnState {
    SynSent,
    SynReceived,
    Established,
    Closing,
    Closed,
}

#[derive(Debug)]
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
    /// DSCP per-connection: фиксированное значение для всех пакетов соединения
    pub dscp_spoof: u8,
    pub strategy_id: u32,
    pub last_activity: Instant,
    pub dup_ack_count: u32,
    pub rng: Option<crate::desync::rand::PerConnRng>,
    /// Флаг TLS 1.3 session resumption.
    /// true если ClientHello содержал non-empty session_ticket extension.
    /// Используется для генерации fake CH с early_data extension (0-RTT defense).
    pub is_resumption: bool,
    /// QUIC: последний наблюдаемый packet number (для PN gap detection).
    pub quic_pn: u64,
    /// QUIC: destination connection ID (первые 8 байт, для идентификации потока).
    pub quic_dcid: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Conntrack {
    inner: Arc<ConntrackInner>,
}

#[derive(Debug)]
struct ConntrackInner {
    map: DashMap<ConnKey, ConntrackEntry>,
    gc_interval: Duration,
    total_created: AtomicU64,
    active_count: AtomicU64,
    gc_cursor: AtomicUsize,
}

impl Conntrack {
    pub fn new(gc_interval: Duration) -> Self {
        Self {
            inner: Arc::new(ConntrackInner {
                map: DashMap::new(),
                gc_interval,
                total_created: AtomicU64::new(0),
                active_count: AtomicU64::new(0),
                gc_cursor: AtomicUsize::new(0),
            }),
        }
    }

    /// Вставляет или обновляет запись — использует Entry API (один shard lock).
    /// Не перезаписывает существующий entry — только обновляет last_activity.
    pub fn upsert(&self, key: ConnKey, entry: ConntrackEntry) {
        use dashmap::mapref::entry::Entry;
        match self.inner.map.entry(key) {
            Entry::Vacant(e) => {
                e.insert(entry);
                self.inner.total_created.fetch_add(1, Ordering::Relaxed);
                self.inner.active_count.fetch_add(1, Ordering::Relaxed);
            }
            Entry::Occupied(mut e) => {
                e.get_mut().last_activity = Instant::now();
            }
        }
    }

    pub fn get(
        &self,
        key: &ConnKey,
    ) -> Option<dashmap::mapref::one::Ref<'_, ConnKey, ConntrackEntry>> {
        self.inner.map.get(key)
    }

    pub fn get_mut(
        &self,
        key: &ConnKey,
    ) -> Option<dashmap::mapref::one::RefMut<'_, ConnKey, ConntrackEntry>> {
        self.inner.map.get_mut(key)
    }

    pub fn remove(&self, key: &ConnKey) -> Option<(ConnKey, ConntrackEntry)> {
        let result = self.inner.map.remove(key);
        if result.is_some() {
            self.inner.active_count.fetch_sub(1, Ordering::Relaxed);
        }
        result
    }

    pub fn contains(&self, key: &ConnKey) -> bool {
        self.inner.map.contains_key(key)
    }

    /// Обновление SEQ — signed delta for proper SEQ wrap handling.
    ///
    /// Uses i32 delta to correctly handle wrap-around at 2^31 boundaries.
    /// Accepts delta in range [-2^30, 2^30] to allow for both forward and backward movement.
    pub fn update_seq_monotonic(&self, key: &ConnKey, seq: u32, ack: u32) {
        if let Some(mut entry) = self.inner.map.get_mut(key) {
            let delta = (seq as i32).wrapping_sub(entry.client_seq as i32);
            if delta == 0 {
                entry.dup_ack_count = entry.dup_ack_count.saturating_add(1);
            } else if delta > 0 && delta <= (1i32 << 30) {
                // Forward movement within acceptable range
                entry.client_seq = seq;
                entry.dup_ack_count = 0;
            } else if (-(1i32 << 30)..0).contains(&delta) {
                // Backward movement (retransmit) — still valid
                entry.client_seq = seq;
                entry.dup_ack_count = 0;
            }
            // delta outside [-2^30, 2^30] is treated as outlier and ignored
            entry.client_ack = ack;
            entry.last_activity = Instant::now();
        }
    }

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

    /// Incremental GC — round-robin across shards using gc_cursor.
    /// Processes entries from a subset of shards each tick to amortize work.
    pub fn gc_incremental(&self, max_idle: Duration) {
        let deadline = Instant::now() + Duration::from_millis(1);
        let mut evicted = 0u64;

        // Round-robin: start from current cursor position
        // Use a fixed shard count estimate (DashMap default is num_cpus, typically 8-64)
        let estimated_shards = 16; // reasonable default
        let start = self.inner.gc_cursor.fetch_add(1, Ordering::Relaxed) % estimated_shards;

        // Collect keys to remove from this shard subset
        let to_remove: Vec<ConnKey> = self
            .inner
            .map
            .iter()
            .skip(start)
            .take_while(|_| Instant::now() <= deadline)
            .filter(|r| r.value().last_activity.elapsed() > max_idle)
            .map(|r| *r.key())
            .collect();

        for key in to_remove {
            self.inner.map.remove(&key);
            evicted += 1;
        }

        if evicted > 0 {
            self.inner
                .active_count
                .fetch_sub(evicted, Ordering::Relaxed);
            debug!("Conntrack GC incremental: evicted {} entries", evicted);
        }
    }

    /// GC loop — uses configured gc_interval from inner, not hardcoded value.
    pub async fn gc_loop(&self) {
        let mut interval = tokio::time::interval(self.inner.gc_interval);
        loop {
            interval.tick().await;
            self.gc_incremental(self.inner.gc_interval);
        }
    }

    pub fn active_count(&self) -> u64 {
        self.inner.active_count.load(Ordering::Relaxed)
    }

    pub fn total_created(&self) -> u64 {
        self.inner.total_created.load(Ordering::Relaxed)
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
            6, // TCP
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
            dscp_spoof: 0,
            strategy_id: 42,
            last_activity: Instant::now(),
            dup_ack_count: 0,
            rng: None,
            quic_pn: 0,
            quic_dcid: vec![],
            is_resumption: false,
        }
    }

    #[test]
    fn test_insert_and_get() {
        let ct = Conntrack::default();
        let key = test_key();
        ct.insert(key, test_entry());
        assert!(ct.contains(&key));
        assert_eq!(ct.get(&key).unwrap().strategy_id, 42);
    }

    #[test]
    fn test_remove() {
        let ct = Conntrack::default();
        let key = test_key();
        ct.insert(key, test_entry());
        assert!(ct.remove(&key).is_some());
        assert!(!ct.contains(&key));
    }

    #[test]
    fn test_gc_removes_stale() {
        let ct = Conntrack::default();
        let key = test_key();
        let mut entry = test_entry();
        entry.last_activity = Instant::now() - Duration::from_secs(300);
        ct.insert(key, entry);
        ct.gc(Duration::from_secs(120));
        assert!(!ct.contains(&key));
    }

    #[test]
    fn test_gc_keeps_recent() {
        let ct = Conntrack::default();
        let key = test_key();
        ct.insert(key, test_entry());
        ct.gc(Duration::from_secs(120));
        assert!(ct.contains(&key));
    }

    #[test]
    fn test_update_seq_monotonic_forward() {
        let ct = Conntrack::default();
        let key = test_key();
        ct.insert(key, test_entry());
        ct.update_seq_monotonic(&key, 2000, 1001);
        assert_eq!(ct.get(&key).unwrap().client_seq, 2000);
    }

    #[test]
    fn test_update_seq_monotonic_wrap() {
        let ct = Conntrack::default();
        let key = test_key();
        let mut entry = test_entry();
        entry.client_seq = u32::MAX - 100;
        ct.insert(key, entry);
        // Wrap around: MAX-100 + 200 = wraps to ~100
        ct.update_seq_monotonic(&key, 100, 1001);
        assert_eq!(ct.get(&key).unwrap().client_seq, 100);
    }

    #[test]
    fn test_update_seq_monotonic_outlier_ignored() {
        let ct = Conntrack::default();
        let key = test_key();
        let mut entry = test_entry();
        entry.client_seq = 1000;
        ct.insert(key, entry);
        // Huge jump (>2^30) should be ignored
        ct.update_seq_monotonic(&key, 1000 + (1u32 << 30) + 1, 1001);
        assert_eq!(ct.get(&key).unwrap().client_seq, 1000);
    }

    #[test]
    fn test_key_includes_proto() {
        let k1 = ConnKey::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12345,
            443,
            6,
        );
        let k2 = ConnKey::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12345,
            443,
            17,
        );
        assert_ne!(k1, k2); // Different proto → different key
    }
}
