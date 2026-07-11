//! Connection tracking — отслеживание состояния TCP/UDP соединений.

use dashmap::DashMap;
use std::hash::{BuildHasher, Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::debug;

/// P0-09: Канонический ключ соединения (направленно-независимый).
/// Всегда сортирует (src, dst) и (sport, dport) так, что
/// потоки client→server и server→client дают один и тот же FlowKey.
#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
pub struct FlowKey {
    pub ip_a: IpAddr,
    pub ip_b: IpAddr,
    pub port_a: u16,
    pub port_b: u16,
    pub proto: u8,
}

impl FlowKey {
    /// Создаёт канонический FlowKey, где ip_a ≤ ip_b (лексикографически),
    /// а порты соответствуют порядку IP.
    pub fn new_bidirectional(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        proto: u8,
    ) -> Self {
        let (ip_a, ip_b, port_a, port_b) = if canonical_less(src_ip, dst_ip) {
            (src_ip, dst_ip, src_port, dst_port)
        } else {
            (dst_ip, src_ip, dst_port, src_port)
        };
        Self {
            ip_a,
            ip_b,
            port_a,
            port_b,
            proto,
        }
    }
}

/// P0-09: Сравнение IP-адресов для канонического порядка.
/// IPv4 < IPv6 (по длине), затем лексикографически по октетам.
fn canonical_less(a: IpAddr, b: IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(a4), IpAddr::V4(b4)) => u32::from(a4) < u32::from(b4),
        (IpAddr::V6(a6), IpAddr::V6(b6)) => u128::from(a6) < u128::from(b6),
        (IpAddr::V4(_), IpAddr::V6(_)) => true, // v4 < v6
        (IpAddr::V6(_), IpAddr::V4(_)) => false,
    }
}

/// P0-09: Connection ID hasher, использует SipHash-1-3 с
/// процесс-локальным случайным ключом. Заменяет XOR-folding ip_to_u64.
pub struct ConnIdHasher {
    key0: u64,
    key1: u64,
}

impl ConnIdHasher {
    /// Создаёт hasher со случайными ключами (вызывается один раз при старте процесса).
    pub const fn new(key0: u64, key1: u64) -> Self {
        Self { key0, key1 }
    }

    /// P0-09: Хеширует FlowKey в u64 conn_id для PerConnRng.
    /// Использует SipHash-1-3 (безопаснее XOR-folding, без коллизий IPv6 /64).
    pub fn hash_flow_key(&self, fk: &FlowKey) -> u64 {
        let mut hasher = siphasher::sip::SipHasher13::new_with_keys(self.key0, self.key1);
        fk.hash(&mut hasher);
        hasher.finish()
    }
}

/// P0-09: Процесс-локальный ConnIdHasher (инициализируется со случайными ключами при старте).
static CONN_ID_HASHER: std::sync::OnceLock<ConnIdHasher> = std::sync::OnceLock::new();

/// P0-09: Инициализирует глобальный ConnIdHasher. Должна быть вызвана при старте процесса.
pub fn init_conn_id_hasher() {
    CONN_ID_HASHER.get_or_init(|| {
        ConnIdHasher::new(
            crate::desync::rand::random_u64(),
            crate::desync::rand::random_u64(),
        )
    });
}

/// P0-09: Вычисляет conn_id для заданного FlowKey.
/// Замена XOR-folding ip_to_u64.
pub fn compute_conn_id(fk: &FlowKey) -> u64 {
    CONN_ID_HASHER
        .get_or_init(|| {
            ConnIdHasher::new(
                crate::desync::rand::random_u64(),
                crate::desync::rand::random_u64(),
            )
        })
        .hash_flow_key(fk)
}

#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
pub struct ConnKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

impl ConnKey {
    pub fn new(
        src_ip: impl Into<IpAddr>,
        dst_ip: impl Into<IpAddr>,
        src_port: u16,
        dst_port: u16,
        proto: u8,
    ) -> Self {
        Self {
            src_ip: src_ip.into(),
            dst_ip: dst_ip.into(),
            src_port,
            dst_port,
            proto,
        }
    }

    /// Возвращает true если оба IP — IPv4.
    pub fn is_ipv4(&self) -> bool {
        self.src_ip.is_ipv4() && self.dst_ip.is_ipv4()
    }

    /// Возвращает true если оба IP — IPv6.
    pub fn is_ipv6(&self) -> bool {
        self.src_ip.is_ipv6() && self.dst_ip.is_ipv6()
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
    /// P0-07: имя стратегии, которая была применена к соединению.
    /// Заполняется при первой десинхронизации. Используется для
    /// record_outcome: RST → fail, SYN-ACK/Established → success.
    pub applied_strategy: Option<String>,
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
    pub route_key: Option<String>,
    pub quic_dropped_initials: u8,
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
    gc_tick: std::sync::atomic::AtomicUsize,
    gc_wheel: Vec<crossbeam::queue::SegQueue<ConnKey>>,
}

impl Conntrack {
    pub fn new(gc_interval: Duration) -> Self {
        let mut gc_wheel = Vec::with_capacity(256);
        for _ in 0..256 {
            gc_wheel.push(crossbeam::queue::SegQueue::new());
        }
        Self {
            inner: Arc::new(ConntrackInner {
                map: DashMap::new(),
                gc_interval,
                total_created: AtomicU64::new(0),
                active_count: AtomicU64::new(0),
                gc_tick: std::sync::atomic::AtomicUsize::new(0),
                gc_wheel,
            }),
        }
    }

    fn schedule_gc_key(&self, key: ConnKey) {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        let hash_val = hasher.finish();
        let slot = (hash_val % 256) as usize;
        self.inner.gc_wheel[slot].push(key);
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
                self.schedule_gc_key(key);
            }
            Entry::Occupied(mut e) => {
                e.get_mut().last_activity = Instant::now();
                self.schedule_gc_key(key);
            }
        }
    }

    /// Проверяет и устанавливает флаг desync_applied атомарно.
    /// Возвращает true, если флаг был успешно установлен с false на true (или создана новая запись с true).
    /// Возвращает false, если флаг уже был true.
    pub fn check_and_apply_desync(
        &self,
        key: ConnKey,
        conn_id_generator: impl FnOnce() -> u64,
    ) -> bool {
        use dashmap::mapref::entry::Entry;
        match self.inner.map.entry(key) {
            Entry::Occupied(mut e) => {
                let entry = e.get_mut();
                if entry.desync_applied {
                    false
                } else {
                    entry.desync_applied = true;
                    entry.last_activity = Instant::now();
                    self.schedule_gc_key(key);
                    true
                }
            }
            Entry::Vacant(e) => {
                let conn_id = conn_id_generator();
                let entry = ConntrackEntry {
                    client_isn: 0,
                    server_isn: 0,
                    client_seq: 0,
                    server_seq: 0,
                    client_ack: 0,
                    server_ack: 0,
                    rtt_us: 0,
                    state: ConnState::SynSent,
                    desync_applied: true,
                    dscp_spoof: crate::desync::rand::random_range(0, 48) as u8,
                    strategy_id: 0,
                    last_activity: Instant::now(),
                    dup_ack_count: 0,
                    rng: Some(crate::desync::rand::PerConnRng::new(conn_id)),
                    quic_pn: 0,
                    quic_dcid: vec![],
                    is_resumption: false,
                    applied_strategy: None,
                    route_key: None,
                    quic_dropped_initials: 0,
                };
                e.insert(entry);
                self.inner.total_created.fetch_add(1, Ordering::Relaxed);
                self.inner.active_count.fetch_add(1, Ordering::Relaxed);
                self.schedule_gc_key(key);
                true
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
            drop(entry);
            self.schedule_gc_key(*key);
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

    /// Bucketed timing-wheel GC using crossbeam SegQueue.
    pub fn gc_incremental(&self, max_idle: Duration) {
        let slot = self.inner.gc_tick.fetch_add(1, Ordering::Relaxed) % 256;
        let queue = &self.inner.gc_wheel[slot];
        let mut evicted = 0u64;

        let mut count = 0;
        while let Some(key) = queue.pop() {
            count += 1;
            if count > 1000 {
                queue.push(key);
                break;
            }

            if let Some(entry) = self.inner.map.get(&key) {
                if entry.last_activity.elapsed() > max_idle {
                    drop(entry);
                    self.inner.map.remove(&key);
                    evicted += 1;
                } else {
                    drop(entry);
                    // Reschedule since it is still active
                    let next_slot = (slot + 128) % 256;
                    self.inner.gc_wheel[next_slot].push(key);
                }
            }
        }

        if evicted > 0 {
            self.inner
                .active_count
                .fetch_sub(evicted, Ordering::Relaxed);
            debug!("Conntrack GC timing-wheel: evicted {} entries", evicted);
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
            applied_strategy: None,
            route_key: None,
            quic_dropped_initials: 0,
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
    fn test_observe_tcp_syn_updates_existing_zero_isn() {
        let ct = Conntrack::default();
        let key = test_key();
        let mut entry = test_entry();
        entry.client_isn = 0;
        ct.insert(key, entry);

        // Simulate SYN observation
        if let Some(mut e) = ct.get_mut(&key) {
            e.client_isn = 777;
        }

        assert_eq!(ct.get(&key).unwrap().client_isn, 777);
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

    #[test]
    fn test_gc_incremental_removes_stale() {
        let ct = Conntrack::default();
        let key = test_key();
        let mut entry = test_entry();
        entry.last_activity = Instant::now() - Duration::from_secs(300);
        ct.insert(key, entry);

        for _ in 0..256 {
            ct.gc_incremental(Duration::from_secs(120));
        }
        assert!(!ct.contains(&key));
    }

    #[test]
    fn test_gc_incremental_keeps_recent() {
        let ct = Conntrack::default();
        let key = test_key();
        ct.insert(key, test_entry());

        for _ in 0..256 {
            ct.gc_incremental(Duration::from_secs(120));
        }
        assert!(ct.contains(&key));
    }
}
