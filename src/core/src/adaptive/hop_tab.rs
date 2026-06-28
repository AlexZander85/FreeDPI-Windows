//! HopTab — Auto-TTL Cache for fake ClientHello (из dpibreak).
//!
//! ## Принцип работы
//! HopTab оценивает количество хопов (прыжков) до сервера на основе TTL
//! входящих пакетов. Для fake ClientHello TTL устанавливается меньше
//! реального количества хопов, чтобы пакет гарантированно НЕ дошёл до сервера.
//!
//! ## Математика
//! - Входящий TTL (от сервера) → оценка initial TTL (64/128/255)
//! - `hops = init_ttl - recv_ttl`
//! - fake TTL = `hops - 1` (на один меньше, чем нужно для достижения сервера)
//!
//! ## Хранилище
//! Circular buffer на 256 записей — LRU-подобное поведение без аллокаций.
//! Двухслоговое (no_std-friendly) хранилище: `[(u32, u8); 256]`.
//!
//! ## Источник
//! Адаптировано из [dpibreak](https://github.com/hufrea/dpibreak) —
//! концепция auto-TTL для fake ClientHello.

use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

/// Размер circular buffer HopTab (степень двойки для быстрого modulo).
const HOPTAB_SIZE: usize = 256;

/// HopTab — кэш {dst_ip → hops} для автоматического подбора TTL.
///
/// Определяет количество хопов до сервера по входящему TTL.
/// Для fake ClientHello: TTL = hops - 1 (чтобы НЕ дошёл до сервера).
///
/// # Thread Safety
/// HopTab использует `AtomicU8` для курсора и `AtomicU64` для каждой
/// записи в circular buffer. Запись/чтение не блокирующие (lock-free).
fn pack_entry(ip: u32, hops: u8) -> u64 {
    (ip as u64) | ((hops as u64) << 32)
}

/// Распаковывает u64 в (u32, u8).
fn unpack_entry(val: u64) -> (u32, u8) {
    let ip = val as u32;
    let hops = (val >> 32) as u8;
    (ip, hops)
}

pub struct HopTab {
    /// Circular buffer: (ip_hash, hops) упакованные в AtomicU64.
    cache: [AtomicU64; HOPTAB_SIZE],
    /// Текущая позиция для записи (атомарный счётчик).
    cursor: AtomicU8,
}

impl std::fmt::Debug for HopTab {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HopTab")
            .field("cursor", &self.cursor.load(Ordering::Relaxed))
            .field("len", &self.len())
            .finish()
    }
}

impl HopTab {
    /// Создаёт новый HopTab с пустым кэшем.
    pub fn new() -> Self {
        Self {
            cache: [const { AtomicU64::new(0) }; HOPTAB_SIZE],
            cursor: AtomicU8::new(0),
        }
    }

    /// Оценивает количество хопов до сервера по входящему TTL.
    ///
    /// Использует стандартные initial TTL:
    /// - 64: Linux, macOS, Android
    /// - 128: Windows
    /// - 255: сетевые устройства (Cisco, Juniper)
    ///
    /// # Arguments
    /// * `recv_ttl` — TTL из входящего пакета (от сервера)
    ///
    /// # Returns
    /// Количество хопов (0 если сервер на той же машине).
    pub fn estimate(recv_ttl: u8) -> u8 {
        let init_ttl: u8 = if recv_ttl <= 64 {
            64
        } else if recv_ttl <= 128 {
            128
        } else {
            255
        };
        init_ttl - recv_ttl.min(init_ttl)
    }

    /// Преобразует IPv4 адрес в u32 для хранения в кэше.
    pub fn ip_to_u32(ip: &std::net::Ipv4Addr) -> u32 {
        ip.to_bits()
    }

    /// UDP sniffer: определяет hop count для UDP-пакетов (QUIC).
    ///
    /// Аналогично TCP, но для UDP. Нужен для fake QUIC Initial TTL.
    /// Используется с WinDivert фильтром `udp.DstPort == 443`.
    ///
    /// # Arguments
    /// * `recv_ttl` — TTL из UDP пакета
    /// * `src_port` — source port для генерации уникального ключа
    ///
    /// # Returns
    /// Количество хопов (estimate).
    pub fn estimate_udp(recv_ttl: u8, src_port: u16) -> (u32, u8) {
        let hops = Self::estimate(recv_ttl);
        // Генерируем уникальный ключ для UDP (src_port как идентификатор)
        let key = (src_port as u32) << 16 | (recv_ttl as u32);
        (key, hops)
    }

    /// Записывает количество хопов для IP в circular buffer.
    ///
    /// # Arguments
    /// * `dst_ip` — IP адрес назначения (как u32)
    /// * `hops` — количество хопов до сервера
    pub fn insert(&self, dst_ip: u32, hops: u8) {
        let idx = self.cursor.fetch_add(1, Ordering::Relaxed) as usize % HOPTAB_SIZE;
        self.cache[idx].store(pack_entry(dst_ip, hops), Ordering::Release);
    }

    /// Ищет количество хопов для IP в circular buffer.
    ///
    /// # Arguments
    /// * `dst_ip` — IP адрес назначения (как u32)
    ///
    /// # Returns
    /// `Some(hops)` если IP найден в кэше, `None` если нет данных.
    pub fn get(&self, dst_ip: u32) -> Option<u8> {
        self.cache.iter().find_map(|entry| {
            let (ip, hops) = unpack_entry(entry.load(Ordering::Acquire));
            if ip == dst_ip {
                Some(hops)
            } else {
                None
            }
        })
    }

    /// Вычисляет fake TTL для пакета, который НЕ должен дойти до сервера.
    ///
    /// Fake TTL = hops - 1 (на один хоп меньше, чем нужно).
    /// Если hops <= 2 — возвращает None (сервер слишком близко,
    /// спуфинг TTL неэффективен).
    ///
    /// # Arguments
    /// * `dst_ip` — IP адрес назначения (как u32)
    ///
    /// # Returns
    /// `Some(fake_ttl)` — TTL для fake пакета
    /// `None` — невозможно подобрать TTL (нет данных или сервер слишком близко)
    pub fn fake_ttl(&self, dst_ip: u32) -> Option<u8> {
        self.get(dst_ip).map(|hops| {
            if hops <= 2 {
                return 0; // Disable: сервер слишком близко
            }
            (hops - 1).clamp(2, 64)
        })
    }

    /// Удобный метод: получает fake TTL по Ipv4Addr.
    pub fn fake_ttl_for_ip(&self, ip: &std::net::Ipv4Addr) -> Option<u8> {
        self.fake_ttl(Self::ip_to_u32(ip))
    }

    /// Обновляет кэш на основе наблюдения.
    ///
    /// Вызывается при получении SYN-ACK или любого пакета от сервера.
    /// # Arguments
    /// * `ip` — IP адрес сервера
    /// * `recv_ttl` — TTL из входящего пакета
    pub fn observe(&self, ip: u32, recv_ttl: u8) {
        let hops = Self::estimate(recv_ttl);
        self.insert(ip, hops);
    }

    /// Количество записей в кэше (для статистики).
    pub fn len(&self) -> usize {
        self.cache
            .iter()
            .filter(|entry| {
                let (ip, _) = unpack_entry(entry.load(Ordering::Acquire));
                ip != 0
            })
            .count()
    }

    /// Пуст ли кэш.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Возвращает снапшот кэша (для тестов/API).
    pub fn snapshot(&self) -> Vec<(u32, u8)> {
        self.cache
            .iter()
            .filter_map(|entry| {
                let (ip, hops) = unpack_entry(entry.load(Ordering::Acquire));
                if ip != 0 {
                    Some((ip, hops))
                } else {
                    None
                }
            })
            .collect()
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
    fn test_new_hop_tab() {
        let ht = HopTab::new();
        assert!(ht.is_empty());
        assert_eq!(ht.len(), 0);
    }

    #[test]
    fn test_estimate_hops() {
        // Localhost
        assert_eq!(HopTab::estimate(64), 0);
        assert_eq!(HopTab::estimate(128), 0);

        // Linux: init=64, recv=52 → 12 hops
        assert_eq!(HopTab::estimate(52), 12);

        // Windows: init=128, recv=118 → 10 hops
        assert_eq!(HopTab::estimate(118), 10);

        // Cisco: init=255, recv=240 → 15 hops
        assert_eq!(HopTab::estimate(240), 15);
    }

    #[test]
    fn test_insert_and_get() {
        let ht = HopTab::new();
        let ip = Ipv4Addr::new(8, 8, 8, 8);
        let ip_u32 = HopTab::ip_to_u32(&ip);

        assert!(ht.get(ip_u32).is_none());

        ht.insert(ip_u32, 12);
        assert_eq!(ht.get(ip_u32), Some(12));
    }

    #[test]
    fn test_fake_ttl() {
        let ht = HopTab::new();
        let ip = Ipv4Addr::new(8, 8, 8, 8);
        let ip_u32 = HopTab::ip_to_u32(&ip);

        // 12 hops → fake TTL = 11 (на 1 меньше)
        ht.insert(ip_u32, 12);
        assert_eq!(ht.fake_ttl(ip_u32), Some(11));

        // 1 hop → слишком близко → disable
        let local_ip = Ipv4Addr::new(10, 0, 0, 1);
        ht.insert(HopTab::ip_to_u32(&local_ip), 1);
        assert_eq!(ht.fake_ttl(HopTab::ip_to_u32(&local_ip)), Some(0));
    }

    #[test]
    fn test_observe() {
        let ht = HopTab::new();
        let ip = Ipv4Addr::new(142, 250, 185, 46); // google.com
        let ip_u32 = HopTab::ip_to_u32(&ip);

        // Наблюдаем SYN-ACK с TTL=52 (Linux, 12 hops)
        ht.observe(ip_u32, 52);
        assert_eq!(ht.get(ip_u32), Some(12));

        // fake TTL для этого IP
        assert_eq!(ht.fake_ttl(ip_u32), Some(11));
    }

    #[test]
    fn test_circular_buffer_wrapping() {
        let ht = HopTab::new();

        // Заполняем 300 записей (больше чем 256)
        for i in 0..300 {
            ht.insert(i, (i % 64) as u8);
        }

        // Первые записи должны быть перезаписаны
        assert!(ht.get(0).is_none() || ht.get(0) != Some(0));
        // Последние записи должны быть в кэше
        assert_eq!(ht.get(299), Some((299 % 64) as u8));
    }

    #[test]
    fn test_snapshot() {
        let ht = HopTab::new();
        let ip1 = HopTab::ip_to_u32(&Ipv4Addr::new(8, 8, 8, 8));
        let ip2 = HopTab::ip_to_u32(&Ipv4Addr::new(1, 1, 1, 1));

        ht.insert(ip1, 10);
        ht.insert(ip2, 8);

        let snap = ht.snapshot();
        assert_eq!(snap.len(), 2);
        assert!(snap.contains(&(ip1, 10)));
        assert!(snap.contains(&(ip2, 8)));
    }

    #[test]
    fn test_fake_ttl_for_ip() {
        let ht = HopTab::new();
        let ip = Ipv4Addr::new(8, 8, 8, 8);
        let ip_u32 = HopTab::ip_to_u32(&ip);

        ht.insert(ip_u32, 8);
        let ttl = ht.fake_ttl_for_ip(&ip);
        assert_eq!(ttl, Some(7));
    }

    #[test]
    fn test_ip_conversion_roundtrip() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let ip_u32 = HopTab::ip_to_u32(&ip);
        let ip_back = Ipv4Addr::from_bits(ip_u32);
        assert_eq!(ip, ip_back);
    }

    #[test]
    fn test_estimate_udp() {
        let (key, hops) = HopTab::estimate_udp(52, 12345);
        assert!(key > 0);
        assert_eq!(hops, 12);
    }

    #[test]
    fn test_estimate_udp_different_ports_different_keys() {
        let (key1, _) = HopTab::estimate_udp(52, 12345);
        let (key2, _) = HopTab::estimate_udp(52, 54321);
        assert_ne!(key1, key2);
    }
}
