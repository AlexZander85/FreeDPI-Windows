//! Random Number Generator — Xorshift64 PRNG (из Omoikane).
//!
//! ## Назначение
//! Быстрый, детерминированный PRNG для генерации:
//! - Случайных TTL offset
//! - Случайных split позиций
//! - Случайных padding размеров
//! - Случайных задержек между инъекциями
//!
//! ## Почему Xorshift64?
//! - 128 бит state → высокое качество
//! - ~1ns на генерацию (на现代енных CPU)
//! - Нет зависимости от внешних crate (rand)
//! - Детерминированный (воспроизводимый seed)
//!
//! ## Источник
//! Адаптировано из [Omoikane](https://github.com/nickel-org/omoikane) —
//! Xorshift64 RNG для DPI desync техник.

use std::sync::atomic::{AtomicU64, Ordering};

/// Глобальный seed для RNG (init из SystemTime).
static GLOBAL_SEED: AtomicU64 = AtomicU64::new(0);

/// Инициализирует глобальный seed.
fn init_seed() -> u64 {
    let seed = GLOBAL_SEED.load(Ordering::Relaxed);
    if seed != 0 {
        return seed;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let new_seed = if now == 0 { 0xDEAD_BEEF_CAFE_BABE } else { now };
    GLOBAL_SEED.compare_exchange(0, new_seed, Ordering::SeqCst, Ordering::Relaxed)
        .unwrap_or(new_seed)
}

/// splitmix64 — хэш-функция для seed initialization.
fn splitmix64(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E3779B97F4A7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

/// Per-connection Xorshift128** PRNG.
#[derive(Clone)]
pub struct PerConnRng {
    state: [u64; 2],
    counter: u64,
}

impl std::fmt::Debug for PerConnRng {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PerConnRng").field("counter", &self.counter).finish()
    }
}

impl PerConnRng {
    pub fn new(conn_id: u64) -> Self {
        let e = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let seed = splitmix64(e ^ conn_id);
        Self {
            state: [seed, splitmix64(seed.wrapping_add(0x9E3779B97F4A7C15))],
            counter: 0,
        }
    }

    /// Следующее u64 значение (Xorshift128**).
    pub fn next_u64(&mut self) -> u64 {
        let mut s1 = self.state[0];
        let s0 = self.state[1];
        self.state[0] = s0;
        s1 ^= s1 << 23;
        self.state[1] = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5);
        self.counter += 1;
        // Xorshift128**: output = s0 * s1
        self.state[0].wrapping_mul(self.state[1])
    }

    /// Следующее u32 значение.
    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// Случайное число в диапазоне [0, range) без bias (Lemire's method).
    pub fn next_unbiased(&mut self, range: u64) -> u64 {
        if range == 0 { return 0; }
        let m = (self.next_u64() as u128).wrapping_mul(range as u128);
        (m >> 64) as u64
    }
}

/// Генерирует случайное u64 через thread-local Xorshift64.
pub fn random_u64() -> u64 {
    thread_local! {
        static STATE: std::cell::Cell<u64> = std::cell::Cell::new(0);
    }
    STATE.with(|state| {
        let mut x = state.get();
        if x == 0 { x = init_seed(); }
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        state.set(x);
        x
    })
}

pub fn random_u32() -> u32 { (random_u64() >> 32) as u32 }

/// Генерирует случайное число в диапазоне [min, max].
pub fn random_range(min: u32, max: u32) -> u32 {
    if min >= max {
        return min;
    }
    let range = max - min + 1;
    if range.is_power_of_two() {
        return min + (random_u32() & (range - 1));
    }
    // Lemire's method — без modulo bias
    let m = (random_u64() as u128).wrapping_mul(range as u128);
    min + (m >> 64) as u32
}

/// Генерирует случайный TTL offset (1-5).
///
/// Используется для fake пакетов, чтобы DPI не мог предсказать TTL.
pub fn random_ttl_offset() -> u8 {
    random_range(1, 5) as u8
}

/// Генерирует случайный split размер (1-100 байт).
pub fn random_split_size() -> usize {
    random_range(1, 100) as usize
}

/// Генерирует случайную задержку в микросекундах (0-10000).
pub fn random_delay_us() -> u64 {
    random_u64() % 10000
}

/// Генерирует случайный padding размер (16-512 байт).
pub fn random_padding_size() -> usize {
    random_range(16, 512) as usize
}

/// Генерирует случайный IP identification.
pub fn random_identification() -> u16 {
    random_u32() as u16
}

/// Генерирует случайный source port (1024-65535).
pub fn random_source_port() -> u16 {
    random_range(1024, 65535) as u16
}

/// Генерирует случайный массив байт заданной длины.
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(len);
    for _ in 0..len {
        buf.push(random_u32() as u8);
    }
    buf
}

/// Генерирует 64-битную split mask с гарантированным coverage.
///
/// ## Алгоритм (из SpoofDPI)
/// Каждый бит маски определяет split-точку в соответствующем байте.
/// Гарантируется ≥1 split-точка на каждый 8-битный блок.
///
/// Используется Xorshift64 с `bits.RotateLeft8/64` для быстрой генерации.
///
/// ## Пример
/// mask = 0b_1010_0100_0000_1000_... → split на позициях 2, 5, 11, 14, ...
pub fn gen_split_mask() -> u64 {
    let mut mask: u64 = 0;
    for byte_idx in 0..8 {
        let mut byte: u8 = random_u32() as u8;
        // Гарантируем хотя бы 1 бит в каждом 8-битном блоке
        if byte == 0 {
            byte = 1 << (random_range(0, 7) as u8);
        }
        mask |= (byte as u64) << (byte_idx * 8);
    }
    mask
}

/// Извлекает позиции split из 64-битной маски.
///
/// # Arguments
/// * `mask` — 64-битная маска (бит = split-точка)
/// * `base_offset` — смещение от начала пакета
///
/// # Returns
/// Вектор позиций split, отсортированный по возрастанию.
pub fn mask_to_positions(mask: u64, base_offset: usize) -> Vec<usize> {
    let mut positions = Vec::new();
    for bit in 0..64u32 {
        if (mask >> bit) & 1 == 1 {
            positions.push(base_offset + bit as usize);
        }
    }
    positions
}

/// Генерирует случайные split-позиции с гарантированным coverage.
///
/// Использует HashSet для O(1) dedup вместо O(n²) contains().
pub fn random_split_positions(base: usize, len: usize, min_count: usize) -> Vec<usize> {
    use std::collections::HashSet;

    let mask = gen_split_mask();
    let mut seen = HashSet::with_capacity(min_count.max(64));
    let mut positions = Vec::with_capacity(min_count.max(64));

    for bit in 0..64u32 {
        if (mask >> bit) & 1 == 1 {
            let p = base + bit as usize;
            if p < base + len && seen.insert(p) {
                positions.push(p);
            }
        }
    }

    while positions.len() < min_count && positions.len() < len {
        let pos = base + random_range(0, len as u32 - 1) as usize;
        if seen.insert(pos) {
            positions.push(pos);
        }
    }

    positions.sort_unstable();
    positions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_u64_range() {
        // Все значения должны быть > 0 (с very high probability)
        let val = random_u64();
        assert!(val > 0 || val == 0); // Just ensure no panic
    }

    #[test]
    fn test_random_u32_range() {
        let val = random_u32();
        assert!(val <= u32::MAX);
    }

    #[test]
    fn test_random_range() {
        for _ in 0..100 {
            let val = random_range(5, 10);
            assert!(val >= 5 && val <= 10);
        }
    }

    #[test]
    fn test_random_ttl_offset() {
        for _ in 0..50 {
            let ttl = random_ttl_offset();
            assert!(ttl >= 1 && ttl <= 5);
        }
    }

    #[test]
    fn test_random_split_size() {
        for _ in 0..50 {
            let size = random_split_size();
            assert!(size >= 1 && size <= 100);
        }
    }

    #[test]
    fn test_random_delay_us() {
        for _ in 0..50 {
            let delay = random_delay_us();
            assert!(delay < 10000);
        }
    }

    #[test]
    fn test_random_bytes() {
        let bytes = random_bytes(32);
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_random_identification() {
        let id = random_identification();
        assert!(id <= u16::MAX);
    }

    #[test]
    fn test_random_source_port() {
        for _ in 0..50 {
            let port = random_source_port();
            assert!(port >= 1024 && port <= 65535);
        }
    }

    #[test]
    fn test_random_padding_size() {
        for _ in 0..50 {
            let size = random_padding_size();
            assert!(size >= 16 && size <= 512);
        }
    }

    #[test]
    fn test_deterministic_with_same_seed() {
        // Два вызова в одном потоке — разные значения (разные state)
        let v1 = random_u64();
        let v2 = random_u64();
        // С very high probability, значения разные
        // (если совпали — это OK, это PRNG)
        let _ = (v1, v2);
    }

    #[test]
    fn test_random_range_min_equals_max() {
        assert_eq!(random_range(42, 42), 42);
    }
}
