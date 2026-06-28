//! Buffer Pool — кэш буферов для desync (уменьшает malloc/free).

use std::sync::Mutex;

const POOL_MAX_SIZE: usize = 1600;
const POOL_CAPACITY: usize = 32;

static POOL: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

/// Берёт буфер из пула или создаёт новый.
pub fn get_buf(size: usize) -> Vec<u8> {
    let mut pool = POOL.lock().unwrap_or_else(|e| e.into_inner());
    for i in 0..pool.len() {
        let len = pool[i].len();
        if len >= size && len <= size * 2 {
            let mut buf = pool.swap_remove(i);
            buf.clear();
            buf.resize(size, 0);
            return buf;
        }
    }
    vec![0u8; size]
}

/// Возвращает буфер в пул.
pub fn return_buf(buf: Vec<u8>) {
    if buf.capacity() <= POOL_MAX_SIZE {
        let mut b = buf;
        b.clear();
        let mut pool = POOL.lock().unwrap_or_else(|e| e.into_inner());
        if pool.len() < POOL_CAPACITY {
            pool.push(b);
        }
    }
}
