//! Parallel Dial — race connection к нескольким IP (из SpoofDPI).
//!
//! DNS может возвращать несколько A/AAAA записей для одного домена.
//! Подключаемся ко всем параллельно, берём первый успешный.
//! Снижает latency на 40-60% при multi-homed доменах.

use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

/// Результат подключения.
pub struct DialResult {
    /// Адрес, к которому подключились.
    pub addr: SocketAddr,
    /// TCP stream.
    pub stream: TcpStream,
}

/// Максимальное количество параллельных подключений.
const MAX_PARALLEL: usize = 10;

/// Подключается ко всем IP параллельно, возвращает первый успешный.
///
/// # Arguments
/// * `addrs` — список адресов для подключения
/// * `port` — порт подключения
/// * `connect_timeout` — таймаут на одно подключение
///
/// # Returns
/// `Some(DialResult)` если хотя бы одно подключение успешно,
/// `None` если все упали.
pub async fn dial_fastest(
    addrs: &[std::net::IpAddr],
    port: u16,
    connect_timeout: Duration,
) -> Option<DialResult> {
    if addrs.is_empty() {
        return None;
    }

    let addrs: Vec<SocketAddr> = addrs
        .iter()
        .take(MAX_PARALLEL)
        .map(|ip| SocketAddr::new(*ip, port))
        .collect();

    let (tx, mut rx) = tokio::sync::mpsc::channel::<DialResult>(addrs.len());

    for addr in &addrs {
        let addr = *addr;
        let tx = tx.clone();
        let timeout_dur = connect_timeout;

        tokio::spawn(async move {
            if let Ok(Ok(stream)) = timeout(timeout_dur, TcpStream::connect(addr)).await {
                let _ = tx.send(DialResult { addr, stream }).await;
            }
        });
    }

    // Закрываем sender чтобы rx.recv() вернёт None когда все завершатся
    drop(tx);

    // Ждём первый успешный результат
    rx.recv().await
}

/// Подключается к одному адресу с таймаутом.
pub async fn dial_single(
    addr: std::net::IpAddr,
    port: u16,
    connect_timeout: Duration,
) -> Option<DialResult> {
    let sock = SocketAddr::new(addr, port);
    match timeout(connect_timeout, TcpStream::connect(sock)).await {
        Ok(Ok(stream)) => Some(DialResult { addr: sock, stream }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[tokio::test]
    async fn test_dial_fastest_empty() {
        let result = dial_fastest(&[], 443, Duration::from_secs(1)).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_dial_single_unreachable() {
        // 192.0.2.1 — TEST-NET, не должен отвечать
        let addr: IpAddr = "192.0.2.1".parse().unwrap();
        let result = dial_single(addr, 443, Duration::from_millis(100)).await;
        assert!(result.is_none());
    }
}
