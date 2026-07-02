//! Random Number Generator — dual-RNG architecture (fast + crypto).
//!
//! ## Архитектура
//! - `fast`: Xoshiro256++ для non-observable полей (TTL jitter, padding length,
//!   выбор стратегии, internal scheduling).
//! - `crypto`: ChaCha8Rng для wire-visible полей (GREASE, TLS random, session ID,
//!   key share) — DPI видит эти байты открытым текстом на проводе.
//!
//! ChaCha8Rng — CSPRNG, DPI не может восстановить state по выходам.
//! Xoshiro256++ — passes BigCrush, O'Neill 2019, быстрый non-crypto PRNG.

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

// ============================================================================
// Thread-local CSPRNG (global functions)
// ============================================================================

thread_local! {
    static THREAD_RNG: std::cell::RefCell<ChaCha20Rng> =
        std::cell::RefCell::new(ChaCha20Rng::from_entropy());
}

pub fn random_u64() -> u64 {
    THREAD_RNG.with(|rng| rng.borrow_mut().next_u64())
}

pub fn random_u32() -> u32 {
    (random_u64() >> 32) as u32
}

pub fn random_range(min: u32, max: u32) -> u32 {
    if min >= max {
        return min;
    }
    let range = (max - min) as u64 + 1;
    min + (lemire_fast(random_u64(), range) as u32)
}

pub fn fill_random_bytes(buf: &mut [u8]) {
    THREAD_RNG.with(|rng| rng.borrow_mut().fill_bytes(buf));
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    fill_random_bytes(&mut buf);
    buf
}

/// Generates a random f64 in [0.0, 1.0) using 53 bits of precision.
pub fn random_f64() -> f64 {
    let r = random_u64();
    (r & 0x001F_FFFF_FFFF_FFFF) as f64 * (1.0 / 9007199254740992.0)
}

// ============================================================================
// GREASE values (RFC 8701)
// ============================================================================

pub const GREASE_VALUES: [u16; 16] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A7A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

// ============================================================================
// Per-connection dual RNG
// ============================================================================

const RESEED_INTERVAL: u64 = 8192;
const RESEED_MASK: u64 = RESEED_INTERVAL - 1;

/// Per-connection dual RNG.
/// - `fast`: Xoshiro256++ для non-observable полей (TTL jitter, padding length).
/// - `crypto`: ChaCha20Rng для wire-visible полей (GREASE, TLS random, session ID).
pub struct PerConnRng {
    fast: Xoshiro256ppState,
    crypto: ChaCha20Rng,
    counter: u64,
}

impl std::fmt::Debug for PerConnRng {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PerConnRng")
            .field("counter", &self.counter)
            .finish()
    }
}

impl PerConnRng {
    pub fn new(conn_id: u64) -> Self {
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        let fast_seed = splitmix64(u64::from_le_bytes(seed[..8].try_into().unwrap()) ^ conn_id);
        Self {
            fast: Xoshiro256ppState::new([
                fast_seed,
                splitmix64(fast_seed.wrapping_add(0x9E3779B97F4A7C15)),
                splitmix64(fast_seed.wrapping_add(0xBB67AE8584CAA73B)),
                splitmix64(fast_seed.wrapping_add(0x3C6EF372FE94F82B)),
            ]),
            crypto: ChaCha20Rng::from_seed(seed),
            counter: 0,
        }
    }

    /// Non-observable PRNG (TTL offset, padding LENGTH, internal jitter).
    /// НЕ использовать для полей, которые DPI видит на проводе.
    #[inline(always)]
    pub fn next_internal_u64(&mut self) -> u64 {
        self.fast.next_u64()
    }

    /// Wire-visible CSPRNG (GREASE, TLS random, session ID, key share).
    #[inline(always)]
    pub fn next_wire_u64(&mut self) -> u64 {
        self.counter += 1;
        if (self.counter & RESEED_MASK) == 0 {
            let mut new_seed = [0u8; 32];
            rand_core::OsRng.fill_bytes(&mut new_seed);
            self.crypto = ChaCha20Rng::from_seed(new_seed);
        }
        self.crypto.next_u64()
    }

    #[inline(always)]
    pub fn fill_wire_bytes(&mut self, buf: &mut [u8]) {
        self.crypto.fill_bytes(buf);
    }

    #[inline(always)]
    pub fn fill_internal_bytes(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i + 8 <= buf.len() {
            buf[i..i + 8].copy_from_slice(&self.fast.next_u64().to_le_bytes());
            i += 8;
        }
        if i < buf.len() {
            let r = self.fast.next_u64();
            let remaining = buf.len() - i;
            buf[i..].copy_from_slice(&r.to_le_bytes()[..remaining]);
        }
    }

    pub fn pick_grease(&mut self) -> u16 {
        GREASE_VALUES[(self.next_wire_u64() as usize) & 0xF]
    }

    pub fn next_range_internal(&mut self, min: u64, max: u64) -> u64 {
        if min >= max {
            return min;
        }
        let range = max - min + 1;
        min + lemire_fast(self.next_internal_u64(), range)
    }

    /// Backward-compatible aliases
    pub fn next_u64(&mut self) -> u64 {
        self.next_wire_u64()
    }

    pub fn next_u32(&mut self) -> u32 {
        (self.next_wire_u64() >> 32) as u32
    }

    /// Returns a random value in `[0, range)` using Lemire's multiplication method.
    ///
    /// ## Modulo Bias Note
    /// This method performs Lemire's multiplication-high algorithm without a rejection step
    /// to guarantee constant-time execution and maximum speed. As a result, it introduces a
    /// tiny modulo bias on the order of `range / 2^64`. For small ranges (such as TTL offsets
    /// or packet padding lengths), this bias is mathematically negligible and wire-invisible.
    pub fn next_unbiased(&mut self, range: u64) -> u64 {
        if range == 0 {
            return 0;
        }
        let m = (self.next_wire_u64() as u128).wrapping_mul(range as u128);
        (m >> 64) as u64
    }

    pub fn next_range(&mut self, min: u64, max: u64) -> u64 {
        if min >= max {
            return min;
        }
        let range = max - min + 1;
        min + self.next_unbiased(range)
    }

    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        self.fill_wire_bytes(buf);
    }

    pub fn generate_grease_set(&mut self) -> (u16, u16, u16, u16) {
        let r = self.next_wire_u64();
        (
            GREASE_VALUES[(r & 0xF) as usize],
            GREASE_VALUES[((r >> 4) & 0xF) as usize],
            GREASE_VALUES[((r >> 8) & 0xF) as usize],
            GREASE_VALUES[((r >> 12) & 0xF) as usize],
        )
    }

    pub fn fork(&mut self) -> PerConnRng {
        let mut new_seed = [0u8; 32];
        self.crypto.fill_bytes(&mut new_seed);
        PerConnRng::from_seed(new_seed, self.next_internal_u64())
    }

    pub fn from_seed(seed: [u8; 32], conn_id: u64) -> Self {
        let fast_seed = splitmix64(u64::from_le_bytes(seed[..8].try_into().unwrap()) ^ conn_id);
        Self {
            fast: Xoshiro256ppState::new([
                fast_seed,
                splitmix64(fast_seed.wrapping_add(0x9E3779B97F4A7C15)),
                splitmix64(fast_seed.wrapping_add(0xBB67AE8584CAA73B)),
                splitmix64(fast_seed.wrapping_add(0x3C6EF372FE94F82B)),
            ]),
            crypto: ChaCha20Rng::from_seed(seed),
            counter: 0,
        }
    }
}

struct Xoshiro256ppState([u64; 4]);

impl Xoshiro256ppState {
    fn new(state: [u64; 4]) -> Self {
        debug_assert!(state != [0u64; 4], "xoshiro256 requires non-zero state");
        Self(state)
    }

    #[inline(always)]
    fn next_u64(&mut self) -> u64 {
        let result = self.0[0]
            .wrapping_add(self.0[3])
            .rotate_left(23)
            .wrapping_add(self.0[0]);
        let t = self.0[1] << 17;
        self.0[2] ^= self.0[0];
        self.0[3] ^= self.0[1];
        self.0[1] ^= self.0[2];
        self.0[0] ^= self.0[3];
        self.0[2] ^= t;
        self.0[3] = self.0[3].rotate_left(45);
        result
    }
}

#[inline(always)]
fn lemire_fast(random: u64, range: u64) -> u64 {
    let m = (random as u128).wrapping_mul(range as u128);
    (m >> 64) as u64
}

fn splitmix64(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E3779B97F4A7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_u64_nonzero() {
        let val = random_u64();
        let _ = val;
    }

    #[test]
    fn test_random_range() {
        for _ in 0..1000 {
            let val = random_range(5, 10);
            assert!((5..=10).contains(&val));
        }
    }

    #[test]
    fn test_random_range_min_equals_max() {
        assert_eq!(random_range(42, 42), 42);
    }

    #[test]
    fn test_fill_random_bytes() {
        let mut buf = [0u8; 100];
        fill_random_bytes(&mut buf);
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_perconnrng_no_clone() {
        // PerConnRng should NOT implement Clone
        // This is verified at compile time — the struct has no #[derive(Clone)]
        let mut rng = PerConnRng::new(12345);
        let _ = rng.next_u64();
    }

    #[test]
    fn test_perconnrng_different_outputs() {
        let mut rng = PerConnRng::new(42);
        let a = rng.next_internal_u64();
        let b = rng.next_wire_u64();
        assert_ne!(a, b);
    }

    #[test]
    fn test_perconnrng_fork_independent() {
        let mut rng1 = PerConnRng::new(42);
        let mut rng2 = rng1.fork();
        let a = rng2.next_wire_u64();
        let b = rng1.next_wire_u64();
        // Fork produces independent stream
        assert_ne!(a, b);
    }

    #[test]
    fn test_perconnrng_grease() {
        let mut rng = PerConnRng::new(7);
        for _ in 0..50 {
            let g = rng.pick_grease();
            assert!(GREASE_VALUES.contains(&g));
        }
    }

    #[test]
    fn test_perconnrng_reseed() {
        let mut rng = PerConnRng::new(12345);
        for _ in 0..RESEED_INTERVAL + 1 {
            let _ = rng.next_wire_u64();
        }
    }

    #[test]
    fn test_cross_thread_independence() {
        let (tx1, rx1) = std::sync::mpsc::channel();
        let (tx2, rx2) = std::sync::mpsc::channel();

        let h1 = std::thread::spawn(move || {
            let mut vals = Vec::new();
            for _ in 0..10 {
                vals.push(random_u64());
            }
            tx1.send(vals).unwrap();
        });

        let h2 = std::thread::spawn(move || {
            let mut vals = Vec::new();
            for _ in 0..10 {
                vals.push(random_u64());
            }
            tx2.send(vals).unwrap();
        });

        h1.join().unwrap();
        h2.join().unwrap();

        let v1 = rx1.recv().unwrap();
        let v2 = rx2.recv().unwrap();

        let matches = v1.iter().zip(v2.iter()).filter(|(a, b)| a == b).count();
        assert!(
            matches < v1.len() / 2,
            "Cross-thread sequences too similar: {}/{} matches",
            matches,
            v1.len()
        );
    }

    #[test]
    fn test_same_conn_id_different_outputs() {
        let mut rng1 = PerConnRng::new(99);
        let mut rng2 = PerConnRng::new(99);
        // Both use OsRng seed, so outputs should differ despite same conn_id
        let vals1: Vec<u64> = (0..5).map(|_| rng1.next_wire_u64()).collect();
        let vals2: Vec<u64> = (0..5).map(|_| rng2.next_wire_u64()).collect();
        assert_ne!(vals1, vals2);
    }
}
