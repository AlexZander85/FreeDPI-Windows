//! Build script for C → Rust FFI bridge.
//!
//! ## Статус
//! bye-dpi C ядро использует Linux-specific API (epoll, POSIX sockets)
//! и не компилируется на Windows через MSVC.
//!
//! ## Рекомендация
//! Полная Rust-реализация desync engine в `core/src/desync/` уже покрывает
//! 50+ техник. FFI bridge НЕ нужен до тех пор, пока не появится
//! Windows-совместимая версия bye-dpi C кода.

fn main() {
    // Проверяем наличие C исходников
    let has_c_sources = std::path::Path::new("vendor/byedpi/src/desync.c").exists();

    if !has_c_sources {
        println!("cargo:warning=FFI bridge: C source files not found, skipping compilation");
        return;
    }

    // bye-dpi C код использует Linux-specific API (epoll, POSIX sockets)
    // и не компилируется на Windows через MSVC.
    // Полная Rust-реализация уже в core/src/desync/.
    println!("cargo:warning=FFI bridge: bye-dpi C code is Linux-only (epoll/POSIX), skipping on Windows");
    println!("cargo:warning=Use core::desync Rust implementation instead (50+ techniques)");
}
