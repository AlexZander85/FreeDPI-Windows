//! FFI Bridge — связь Rust с C-ядром bye-dpi.
//!
//! ## Статус
//! bye-dpi C ядро (8 файлов: desync, packets, extend, proxy, conev, mpool, main)
//! использует Linux-specific API (epoll, POSIX sockets) и не компилируется на Windows.
//!
//! Полная Rust-реализация desync engine в `core/src/desync/` уже покрывает 50+ техник.
//! FFI bridge НЕ нужен до тех пор, пока не появится Windows-совместимая версия C кода.
//!
//! ## Паттерны (из RIPDPI + qeli)
//! - `catch_unwind` для containment паник на FFI boundary
//! - `ffi_boundary()` — sentinel-based error handling

use std::panic::{catch_unwind, AssertUnwindSafe};
use tracing::debug;

/// Panic boundary для FFI вызовов.
/// Если C код паникует (через catch_unwind), возвращается sentinel значение.
#[inline]
fn ffi_boundary<T, F>(default_on_panic: T, f: F) -> T
where
    F: FnOnce() -> T,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(value) => value,
        Err(_payload) => {
            debug!("FFI panic caught at boundary");
            default_on_panic
        }
    }
}

/// Результат FFI операции.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiResult {
    Ok,
    Error(i32),
    Panic,
}

impl FfiResult {
    pub fn is_ok(&self) -> bool {
        matches!(self, FfiResult::Ok)
    }
}

/// Конвертирует результат C вызова в FfiResult.
fn c_result_to_ffi(val: isize) -> FfiResult {
    if val >= 0 {
        FfiResult::Ok
    } else {
        FfiResult::Error(val as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ffi_boundary_panic_safety() {
        let result = ffi_boundary(FfiResult::Panic, || {
            panic!("test panic");
        });
        assert_eq!(result, FfiResult::Panic);
    }

    #[test]
    fn test_ffi_boundary_no_panic() {
        let result = ffi_boundary(FfiResult::Panic, || FfiResult::Ok);
        assert_eq!(result, FfiResult::Ok);
    }

    #[test]
    fn test_c_result_to_ffi() {
        assert_eq!(c_result_to_ffi(0), FfiResult::Ok);
        assert_eq!(c_result_to_ffi(5), FfiResult::Ok);
        assert_eq!(c_result_to_ffi(-1), FfiResult::Error(-1));
        assert_eq!(c_result_to_ffi(-42), FfiResult::Error(-42));
    }
}
