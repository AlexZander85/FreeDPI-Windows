//! Buffer Pool — кэш буферов для desync (уменьшает malloc/free).
//!
//! Thread-local pool без блокировок.
//! Каждый поток имеет собственный пул буферов — нулевой contention.

const POOL_MAX_CAPACITY: usize = 65535;
const POOL_MAX_BUFFERS: usize = 32;

thread_local! {
    static POOL: std::cell::RefCell<Vec<Vec<u8>>> =
        std::cell::RefCell::new(Vec::with_capacity(POOL_MAX_BUFFERS));
}

/// Берёт буфер из thread-local пула или создаёт новый.
pub fn get_buf(size: usize) -> Vec<u8> {
    POOL.with(|pool| {
        let mut p = pool.borrow_mut();
        if let Some(idx) = p.iter().position(|b| b.capacity() >= size) {
            let mut buf = p.swap_remove(idx);
            buf.clear();
            buf.resize(size, 0);
            return buf;
        }
        vec![0u8; size]
    })
}

/// Возвращает буфер в thread-local пул.
pub fn return_buf(buf: Vec<u8>) {
    if buf.capacity() > POOL_MAX_CAPACITY || buf.capacity() < 32 {
        return;
    }
    POOL.with(|pool| {
        let mut p = pool.borrow_mut();
        if p.len() < POOL_MAX_BUFFERS {
            let mut b = buf;
            b.clear();
            p.push(b);
        }
    });
}
