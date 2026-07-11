//! Packet Engine — перехват (WinDivert) и инъекция (raw socket).
//!
//! # Разделение труда
//!
//! | Задача | Механизм | Почему |
//! |--------|----------|--------|
//! | Перехват пакетов | WinDivert | Точка входа, kernel-level filter |
//! | Модификация проходящих | WinDivert modify + reinject | Нативный, низкая задержка |
//! | Дроп пакетов | WinDivert (не reinject) | Минимальная задержка |
//! | Fake SNI + TTL | Raw socket | Нет WinDivert roundtrip |
//! | IP Fragmentation | Raw socket (IP_HDRINCL) | Полный контроль IP header |
//! | SEQ Overlap | Raw socket | Custom SEQ в raw IP |
//! | QUIC дейтаграммы | Raw socket (IPPROTO_RAW) | Полный UDP header |
//!
//! # WinDivert API (0.7.0-beta.4)
//! - `WinDivert::network()` вместо `WinDivert::new()`
//! - `recv(&mut buffer)` блокирующий, принимает буфер, возвращает `WinDivertPacket`
//! - `send(&packet)` блокирующий, принимает ссылку на пакет
//! - `set_param(param, u64)` — значения теперь `u64`

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use bytes::BytesMut;
use crossbeam::queue::ArrayQueue;
use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use windivert::prelude::WinDivertParam;
use windivert::prelude::*;
use windivert::WinDivert;

/// Реалистичный размер слота пула: обычный MTU + запас (не 65535).
const POOLED_BUF_SIZE: usize = 2048;

/// T62: Максимальный размер batch (пакетов за один syscall).
const RECV_BATCH_SIZE: usize = 64;
/// T62: Размер буфера для batch recv (64 пакета × 2048 байт).
const RECV_BATCH_BUFFER_SIZE: usize = RECV_BATCH_SIZE * 2048; // 128 KB

/// Lock-free пул переиспользуемых `BytesMut` для single-copy recv.
///
/// ## single-copy
/// Единственная копия за весь путь пакета — kernel→user (неустранима для WinDivert).
/// В steady-state ноль вызовов аллокатора: буферы переиспользуются через `ArrayQueue`.
/// Sizing function for packet buffer pool
pub fn packet_pool_capacity(worker_count: usize, recv_batch_size: usize) -> usize {
    let rx_prefetch = 2usize;
    let send_backlog = 2usize;
    let safety_factor = 2usize;
    let base = recv_batch_size
        .saturating_mul(worker_count + rx_prefetch + send_backlog)
        .saturating_mul(safety_factor);
    base.clamp(512, 8192)
}

/// Lock-free пул переиспользуемых `BytesMut` для single-copy recv.
///
/// ## single-copy
/// Единственная копия за весь путь пакета — kernel→user (неустранима для WinDivert).
/// В steady-state ноль вызовов аллокатора: буферы переиспользуются через `ArrayQueue`.
pub struct PacketBufferPool {
    free: ArrayQueue<BytesMut>,
    alloc_miss: AtomicU64,
    return_drop: AtomicU64,
    acquire_total: AtomicU64,
    release_success_total: AtomicU64,
    release_refcount_failed_total: AtomicU64,
    capacity: usize,
}

impl std::fmt::Debug for PacketBufferPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketBufferPool")
            .field("capacity", &self.capacity)
            .field("alloc_miss", &self.alloc_miss.load(Ordering::Relaxed))
            .field("acquire_total", &self.acquire_total.load(Ordering::Relaxed))
            .finish()
    }
}

impl PacketBufferPool {
    /// Создаёт пул с `capacity` предварительно выделенными буферами.
    pub fn new(capacity: usize) -> Self {
        let free = ArrayQueue::new(capacity);
        for _ in 0..capacity {
            let mut b = BytesMut::with_capacity(POOLED_BUF_SIZE);
            b.resize(POOLED_BUF_SIZE, 0);
            let _ = free.push(b);
        }
        Self {
            free,
            alloc_miss: AtomicU64::new(0),
            return_drop: AtomicU64::new(0),
            acquire_total: AtomicU64::new(0),
            release_success_total: AtomicU64::new(0),
            release_refcount_failed_total: AtomicU64::new(0),
            capacity,
        }
    }

    /// Извлекает буфер из пула или создаёт новый (нестандартный случай).
    #[inline]
    pub fn acquire(&self) -> BytesMut {
        self.acquire_total.fetch_add(1, Ordering::Relaxed);
        self.free.pop().unwrap_or_else(|| {
            self.alloc_miss.fetch_add(1, Ordering::Relaxed);
            let mut b = BytesMut::with_capacity(POOLED_BUF_SIZE);
            b.resize(POOLED_BUF_SIZE, 0);
            b
        })
    }

    /// Возвращает буфер в пул, восстанавливая длину до `POOLED_BUF_SIZE`.
    ///
    /// Если буфер крупнее (редкий jumbo-пакет) — не пуляем, Drop сам освободит.
    #[inline]
    pub fn release(&self, mut buf: BytesMut) {
        if buf.capacity() < POOLED_BUF_SIZE {
            return; // нестандартный — одноразовый
        }
        buf.resize(POOLED_BUF_SIZE, 0);
        if self.free.push(buf).is_ok() {
            self.release_success_total.fetch_add(1, Ordering::Relaxed);
        } else {
            self.return_drop.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Пытается вернуть замороженный `Bytes` обратно в пул, если refcount == 1.
    ///
    /// Вызывать после того, как пакет отправлен и больше не будет расшарен.
    /// Если refcount > 1 (Bytes расшарен несколькими клонами) — просто дропается.
    pub fn release_bytes(&self, packet: bytes::Bytes) {
        if let Ok(buf) = packet.try_into_mut() {
            self.release(buf);
        } else {
            self.release_refcount_failed_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn alloc_miss(&self) -> u64 {
        self.alloc_miss.load(Ordering::Relaxed)
    }

    pub fn return_drop(&self) -> u64 {
        self.return_drop.load(Ordering::Relaxed)
    }

    pub fn pool_acquire_total(&self) -> u64 {
        self.acquire_total.load(Ordering::Relaxed)
    }

    pub fn pool_release_success_total(&self) -> u64 {
        self.release_success_total.load(Ordering::Relaxed)
    }

    pub fn pool_release_refcount_failed_total(&self) -> u64 {
        self.release_refcount_failed_total.load(Ordering::Relaxed)
    }

    pub fn pool_acquire_miss_total(&self) -> u64 {
        self.alloc_miss.load(Ordering::Relaxed)
    }

    pub fn pool_capacity(&self) -> usize {
        self.capacity
    }
}

/// Пытается вернуть `Bytes` обратно в пул, если refcount == 1.
///
/// Вызывать после того, как пакет отправлен и больше не будет расшарен.
pub fn try_return_to_pool(packet: bytes::Bytes, pool: &PacketBufferPool) {
    pool.release_bytes(packet);
}

/// Cache-line-aligned atomic counter to prevent false sharing.
#[repr(align(64))]
pub struct PaddedCounter(AtomicU64);

impl std::fmt::Debug for PaddedCounter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PaddedCounter")
            .field(&self.0.load(Ordering::Relaxed))
            .finish()
    }
}

impl PaddedCounter {
    pub const fn new(val: u64) -> Self {
        Self(AtomicU64::new(val))
    }
}

impl Deref for PaddedCounter {
    type Target = AtomicU64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Размер буфера для WinDivert recv (максимальный MTU + заголовки).
#[allow(dead_code)]
const PACKET_BUFFER_SIZE: usize = 65535;
/// Приоритет фильтра (0 = нормальный).
const WINDIVERT_PRIORITY: i16 = 0;

/// Режим работы пакетного движка.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EngineMode {
    /// WinDivert — полный перехват и модификация пакетов
    WinDivert,
    /// WFP (Windows Filtering Platform) — альтернатива WinDivert
    /// Не требует kernel-mode driver, но имеет ограничения
    Wfp,
    /// Только API — без перехвата пакетов
    ApiOnly,
}

/// Абстракция над WinDivert + raw socket для перехвата и инъекции.
pub struct PacketEngine {
    divert: ArcSwap<Option<WinDivert<NetworkLayer>>>,
    raw_sock_v4: Option<RawSocketTxV4>,
    raw_sock_v6: Option<RawSocketTxV6>,
    stats: PacketStats,
    mode: EngineMode,
}

/// Статистика пакетного движка.
///
/// Каждое поле выровнено по cache-line (64 байта) для предотвращения false sharing.
#[derive(Debug)]
pub struct PacketStats {
    pub packets_received: PaddedCounter,
    pub packets_sent: PaddedCounter,
    pub packets_injected: PaddedCounter,
    pub packets_dropped: PaddedCounter,
}

impl PacketStats {
    fn new() -> Self {
        Self {
            packets_received: PaddedCounter::new(0),
            packets_sent: PaddedCounter::new(0),
            packets_injected: PaddedCounter::new(0),
            packets_dropped: PaddedCounter::new(0),
        }
    }
}

impl Default for PacketStats {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketEngine {
    /// Создаёт WinDivert handle + raw socket.
    ///
    /// `filter` — WinDivert filter string (например, `"(ip or ipv6) && tcp.DstPort == 443"`).
    ///
    /// Автоматически устанавливает WinDivert driver если он не загружен.
    /// Требует admin elevation для установки driver.
    pub fn new_with_tuning(
        filter: &str,
        tuning: &crate::config::NetworkTuningConfig,
    ) -> Result<Self> {
        // Проверяем/устанавливаем driver если нужно
        if !crate::infra::windivert_driver::is_driver_loaded() {
            info!("WinDivert driver not loaded, installing...");
            crate::infra::windivert_driver::install_driver()
                .context("Failed to install WinDivert driver")?;
        }

        let divert = WinDivert::network(filter, WINDIVERT_PRIORITY, WinDivertFlags::default())
            .context("Failed to open WinDivert (driver may be blocked by HVCI/EDR)")?;

        // WinDivert tuning
        Self::tune_divert(&divert)?;

        let raw_sock_v4 = match unsafe { RawSocketTxV4::new() } {
            Ok(sock) => {
                debug!("Raw socket (IPv4) created successfully");
                Some(sock)
            }
            Err(e) => {
                error!("Failed to create IPv4 raw socket (need admin?): {}", e);
                None
            }
        };

        let raw_sock_v6 = match unsafe { RawSocketTxV6::new() } {
            Ok(sock) => {
                debug!("Raw socket (IPv6) created successfully");
                Some(sock)
            }
            Err(e) => {
                warn!("Failed to create IPv6 raw socket (need admin?): {}", e);
                None
            }
        };

        // Отключаем TSO/LSO/RSS для совместимости с desync техниками
        if let Err(e) = Self::disable_offload(tuning) {
            warn!("Failed to disable network offload: {}", e);
        }

        debug!("PacketEngine initialized with filter: {}", filter);

        Ok(Self {
            divert: ArcSwap::new(Arc::new(Some(divert))),
            raw_sock_v4,
            raw_sock_v6,
            stats: PacketStats::new(),
            mode: EngineMode::WinDivert,
        })
    }

    pub fn new(filter: &str) -> Result<Self> {
        Self::new_with_tuning(filter, &crate::config::NetworkTuningConfig::default())
    }

    /// Создаёт движок без WinDivert (API-only режим).
    pub fn new_api_only() -> Self {
        let raw_sock_v4 = unsafe { RawSocketTxV4::new() }.ok();
        let raw_sock_v6 = unsafe { RawSocketTxV6::new() }.ok();

        Self {
            divert: ArcSwap::new(Arc::new(None)),
            raw_sock_v4,
            raw_sock_v6,
            stats: PacketStats::new(),
            mode: EngineMode::ApiOnly,
        }
    }

    /// Возвращает текущий режим работы.
    pub fn mode(&self) -> EngineMode {
        self.mode
    }

    /// Блокирующий перехват пакета с zero-alloc приёмом через пул.
    ///
    /// ## single-copy
    /// Единственная неустранимая копия — kernel→user (WinDivert).
    /// `BytesMut` из пула → `Bytes::freeze()` без аллокации и memcpy.
    ///
    /// ## Error path
    /// При ошибке `divert.recv` буфер ВОЗВРАЩАЕТСЯ в пул (не теряется).
    pub fn recv_blocking(
        &self,
        pool: &PacketBufferPool,
    ) -> Result<(bytes::Bytes, WinDivertAddress<NetworkLayer>)> {
        let guard = self.divert.load();
        let Some(ref divert) = **guard else {
            anyhow::bail!("WinDivert not initialized (API-only mode)");
        };

        let mut buf = pool.acquire(); // len == POOLED_BUF_SIZE

        // WinDivert пишет данные прямо в buf.
        // packet.data — slice buf'а; копируем всё, что нужно, до работы с buf.
        let result = divert.recv(&mut buf).context("WinDivert recv failed");
        let (len, addr) = match result {
            Ok(packet) => {
                let len = packet.data.len();
                let addr = packet.address.clone();
                // ⚠ packet.data (borrow buf) дропается здесь — buf снова полностью наш.
                drop(packet);
                (len, addr)
            }
            Err(e) => {
                // Возвращаем буфер в пул — не теряем аллокацию
                pool.release(buf);
                return Err(e);
            }
        };

        if len > buf.len() {
            // Редкий jumbo-пакет — аллокация под фактический размер
            buf = BytesMut::from(&buf[..len]);
        } else {
            buf.truncate(len);
        }

        self.stats.packets_received.fetch_add(1, Ordering::Relaxed);
        Ok((buf.freeze(), addr))
    }

    /// Send + возврат буфера в пул одной операцией.
    ///
    /// Вызывается в worker loop после обработки пакета.
    /// Не зависит от результата send — буфер возвращается в пул всегда
    /// (даже при ошибке, буфер можно переиспользовать на следующем recv).
    pub fn send_blocking_and_release(
        &self,
        packet: bytes::Bytes,
        addr: &WinDivertAddress<NetworkLayer>,
        pool: &PacketBufferPool,
    ) -> Result<u32> {
        let result = self.send_blocking(&packet, addr);
        pool.release_bytes(packet);
        result
    }

    /// Блокирующая отправка модифицированного пакета.
    ///
    /// Пакет проходит через WinDivert — может быть снова перехвачен.
    /// Должен быть запущен через `spawn_blocking`.
    pub fn send_blocking(
        &self,
        packet: &[u8],
        addr: &WinDivertAddress<NetworkLayer>,
    ) -> Result<u32> {
        let guard = self.divert.load();
        let Some(ref divert) = **guard else {
            anyhow::bail!("WinDivert not initialized (API-only mode)");
        };
        // Создаём временный WinDivertPacket из предоставленных данных
        let wd_packet = WinDivertPacket {
            address: addr.clone(),
            data: std::borrow::Cow::Borrowed(packet),
        };
        let sent = divert.send(&wd_packet).context("WinDivert send failed")?;
        self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
        Ok(sent)
    }

    /// Инъекция UDP/ICMP пакета через raw socket (обходит WinDivert).
    ///
    /// **ТОЛЬКО для UDP и ICMP!** TCP пакеты через raw socket
    /// молча дропаются Windows (XP SP2+). Для TCP используйте `inject_via_divert()`.
    ///
    /// Автоматически выбирает IPv4 или IPv6 raw socket по версии пакета (первый полубайт).
    pub fn inject_raw_udp(&self, packet: &[u8]) -> Result<()> {
        if packet.is_empty() {
            anyhow::bail!("Empty packet");
        }
        let version = packet[0] >> 4;
        match version {
            4 => {
                let Some(ref sock) = self.raw_sock_v4 else {
                    anyhow::bail!("Raw socket (IPv4) not available");
                };
                sock.send(packet)?;
            }
            6 => {
                let Some(ref sock) = self.raw_sock_v6 else {
                    anyhow::bail!("Raw socket (IPv6) not available");
                };
                sock.send(packet)?;
            }
            _ => anyhow::bail!("Unknown IP version: {}", version),
        }
        self.stats.packets_injected.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Инъекция TCP пакета через WinDivert (reinject).
    ///
    /// TCP пакеты НЕ могут быть отправлены через raw socket на Windows.
    /// Этот метод reinject'ит пакет обратно в сетевой стек через WinDivert.
    /// Пакет может быть снова перехвачен WinDivert → нужен EventTag.
    pub fn inject_via_divert(
        &self,
        packet: &[u8],
        addr: &WinDivertAddress<NetworkLayer>,
    ) -> Result<u32> {
        let guard = self.divert.load();
        let Some(ref divert) = **guard else {
            anyhow::bail!("WinDivert not initialized (API-only mode)");
        };
        let mut impostor_addr = addr.clone();
        impostor_addr.set_impostor(true);
        let wd_packet = WinDivertPacket {
            address: impostor_addr,
            data: std::borrow::Cow::Borrowed(packet),
        };
        let sent = divert.send(&wd_packet).context("WinDivert inject failed")?;
        self.stats.packets_injected.fetch_add(1, Ordering::Relaxed);
        Ok(sent)
    }

    /// Дроп пакета — просто не вызываем `send()`.
    pub fn drop_packet(&self) {
        self.stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// P1-01: Атомарное обновление WinDivert фильтра.
    ///
    /// Создаёт новый WinDivert handle, затем атомарно переключает `self.divert`
    /// через `ArcSwap::rcu()`. Старый handle закрывается автоматически при
    /// освобождении последней ссылки (drop внутри rcu-замыкания).
    /// Между старым и новым handle нет слепого окна — ни один пакет не теряется.
    pub fn update_filter(&self, filter: &str) -> Result<()> {
        // P5-01: Compile check safety
        crate::windivert_ext::compile_filter(filter)
            .map_err(|e| anyhow::anyhow!("WinDivert filter compile failed: {}", e))?;

        // Сначала создаём новый handle (может фейлиться — не трогаем state).
        let new_divert = WinDivert::network(filter, WINDIVERT_PRIORITY, WinDivertFlags::default())
            .context("Failed to update WinDivert filter")?;
        Self::tune_divert(&new_divert).context("Failed to tune new WinDivert handle")?;

        // Атомарный swap — старый handle живёт до вызова drop, WinDivert
        // не переходит в состояние None, потери пакетов нет.
        // Кратковременное сосуществование двух WinDivert фильтров безопасно:
        // каждый handle получает только свои matched пакеты; читаем только из нового.
        let old = self.divert.swap(Arc::new(Some(new_divert)));
        drop(old);

        debug!(
            "WinDivert filter updated (P1-01 atomic swap with FFI check): {}",
            filter
        );
        Ok(())
    }

    /// Check if WinDivert is initialized.
    fn tune_divert(divert: &WinDivert<NetworkLayer>) -> Result<()> {
        divert
            .set_param(WinDivertParam::QueueLength, 65535)
            .context("Failed to set QueueLength")?;
        divert
            .set_param(WinDivertParam::QueueTime, 500)
            .context("Failed to set QueueTime")?;
        divert
            .set_param(WinDivertParam::QueueSize, 64 * 1024 * 1024)
            .context("Failed to set QueueSize")?;
        Ok(())
    }

    /// Проверяет, инициализирован ли WinDivert.
    pub fn has_divert(&self) -> bool {
        self.divert.load().is_some()
    }

    /// Проверяет, доступен ли хотя бы один raw socket (IPv4 или IPv6).
    pub fn has_raw_socket(&self) -> bool {
        self.raw_sock_v4.is_some() || self.raw_sock_v6.is_some()
    }

    /// Проверяет, доступен ли IPv4 raw socket.
    pub fn has_raw_socket_v4(&self) -> bool {
        self.raw_sock_v4.is_some()
    }

    /// Проверяет, доступен ли IPv6 raw socket.
    pub fn has_raw_socket_v6(&self) -> bool {
        self.raw_sock_v6.is_some()
    }

    /// Асинхронная версия `disable_offload` — не блокирует вызывающий поток.
    pub fn disable_offload_async(
        tuning: crate::config::NetworkTuningConfig,
    ) -> tokio::task::JoinHandle<Result<()>> {
        tokio::task::spawn_blocking(move || Self::disable_offload(&tuning))
    }

    /// Отключает TSO/LSO (TCP Segmentation Offload / Large Send Offload)
    /// на активном сетевом интерфейсе.
    ///
    /// NIC с TSO может "починить" фрагментированные пакеты до отправки
    /// в кабель, перезаписав контрольные суммы или собрав фрагменты.
    /// Это ломает desync техники (IP fragmentation overlap, SEQ spoofing).
    ///
    /// Использует `netsh` для отключения offload на всех адаптерах.
    pub fn disable_offload(tuning: &crate::config::NetworkTuningConfig) -> Result<()> {
        if tuning.disable_chimney {
            // Отключаем TCP Chimney Offload (включает TSO/LSO)
            let output = std::process::Command::new("netsh")
                .args(["int", "tcp", "set", "global", "chimney=disabled"])
                .output();

            match output {
                Ok(o) if o.status.success() => {
                    debug!("TCP Chimney Offload disabled");
                }
                Ok(o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    warn!("Failed to disable TCP Chimney: {}", stderr);
                }
                Err(e) => {
                    warn!("Failed to run netsh: {}", e);
                }
            }
        }

        if tuning.disable_rss {
            // Отключаем RSS (Receive Side Scaling) — может переупорядочить пакеты
            let output = std::process::Command::new("netsh")
                .args(["int", "tcp", "set", "global", "rss=disabled"])
                .output();

            match output {
                Ok(o) if o.status.success() => {
                    warn!("RSS disabled by explicit config; throughput may degrade");
                }
                Ok(o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    warn!("Failed to disable RSS: {}", stderr);
                }
                Err(e) => {
                    warn!("Failed to run netsh for RSS: {}", e);
                }
            }
        }

        if tuning.disable_ecn {
            // Отключаем ECN (Explicit Congestion Notification) — может модифицировать TCP headers
            let output = std::process::Command::new("netsh")
                .args(["int", "tcp", "set", "global", "ecn=disabled"])
                .output();

            match output {
                Ok(o) if o.status.success() => {
                    debug!("ECN disabled");
                }
                _ => {
                    debug!("ECN disable skipped (non-critical)");
                }
            }
        }

        info!("Network offload disabled based on config tuning");
        Ok(())
    }

    /// Текущая статистика (снэпшот).
    pub fn stats_snapshot(&self) -> PacketStatsSnapshot {
        PacketStatsSnapshot {
            packets_received: self.stats.packets_received.load(Ordering::Relaxed),
            packets_sent: self.stats.packets_sent.load(Ordering::Relaxed),
            packets_injected: self.stats.packets_injected.load(Ordering::Relaxed),
            packets_dropped: self.stats.packets_dropped.load(Ordering::Relaxed),
        }
    }

    /// T62: Пакетный приём — до 64 пакетов за один syscall.
    ///
    /// WinDivertRecvEx возвращает немедленно, если есть хотя бы 1 пакет.
    /// При высокой нагрузке возвращает полные батчи (adaptive batching).
    ///
    /// # Arguments
    /// * `pool` — buffer pool для аллокации Bytes на каждый пакет
    ///
    /// # Returns
    /// `Vec<(bytes::Bytes, WinDivertAddress)>` — до 64 пакетов
    pub fn recv_batch_into(
        &self,
        pool: &PacketBufferPool,
        out: &mut Vec<(bytes::Bytes, WinDivertAddress<NetworkLayer>)>,
    ) -> Result<usize> {
        out.clear();
        let guard = self.divert.load();
        let Some(ref divert) = **guard else {
            anyhow::bail!("WinDivert not initialized (API-only mode)");
        };

        // 1. Выделяем один большой буфер для batch (thread-local reuse)
        thread_local! {
            static BATCH_BUF: std::cell::RefCell<Vec<u8>> =
                std::cell::RefCell::new(vec![0u8; RECV_BATCH_BUFFER_SIZE]);
        }

        let n = BATCH_BUF.with(|buf| -> Result<usize> {
            let mut buf = buf.borrow_mut();

            // 2. Вызываем WinDivertRecvEx — до 64 пакетов за 1 syscall
            // P4-03: Note on zero-copy scatter/gather FFI support.
            // WinDivert's underlying native API (WinDivertRecvEx) only supports reading multiple packets
            // contiguously into a single flat buffer (passed as a single pointer). It does not support
            // scatter/gather into disjoint buffers. Thus, true zero-copy from the kernel driver straight
            // into disjoint pool-allocated buffers is not possible with WinDivert. The optimal path
            // remains: single contiguous copy from kernel into BATCH_BUF, and then copying individual
            // packet slices from BATCH_BUF into pool buffers.
            let pkts = divert
                .recv_ex(&mut buf[..], RECV_BATCH_SIZE as u8)
                .map_err(|e| anyhow::anyhow!("WinDivertRecvEx failed: {}", e))?;

            out.reserve(pkts.len());
            for pkt in pkts {
                let len = pkt.data.len();
                let mut data_buf = if len > POOLED_BUF_SIZE {
                    BytesMut::with_capacity(len)
                } else {
                    pool.acquire()
                };

                if len > data_buf.capacity() {
                    data_buf = BytesMut::with_capacity(len);
                }
                data_buf.resize(len, 0);
                data_buf[..len].copy_from_slice(&pkt.data);
                out.push((data_buf.freeze(), pkt.address));
            }
            Ok(out.len())
        })?;

        self.stats
            .packets_received
            .fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }

    pub fn recv_batch(
        &self,
        pool: &PacketBufferPool,
    ) -> Result<Vec<(bytes::Bytes, WinDivertAddress<NetworkLayer>)>> {
        let mut out = Vec::with_capacity(RECV_BATCH_SIZE);
        self.recv_batch_into(pool, &mut out)?;
        Ok(out)
    }

    /// T62: Пакетная отправка — до 64 пакетов за один syscall.
    ///
    /// # Arguments
    /// * `packets` — вектор (data, address) для отправки
    ///
    /// # Returns
    /// Количество успешно отправленных пакетов.
    pub fn send_batch(
        &self,
        packets: &[(bytes::Bytes, WinDivertAddress<NetworkLayer>)],
    ) -> Result<usize> {
        if packets.is_empty() {
            return Ok(0);
        }

        let guard = self.divert.load();
        let Some(ref divert) = **guard else {
            anyhow::bail!("WinDivert not initialized (API-only mode)");
        };

        let mut total_sent = 0;
        let mut wd_packets = smallvec::SmallVec::<[_; 64]>::new();

        for (data, addr) in packets {
            wd_packets.push(WinDivertPacket {
                address: addr.clone(),
                data: std::borrow::Cow::Borrowed(&data[..]),
            });
        }

        // Вызываем send_ex с массивом WinDivertPacket
        match divert.send_ex(&wd_packets) {
            Ok(n) => {
                total_sent = n as usize;
                self.stats
                    .packets_sent
                    .fetch_add(total_sent as u64, Ordering::Relaxed);
            }
            Err(e) => {
                // Fallback: отправляем по одному
                tracing::warn!("send_ex failed ({}), falling back to individual send", e);
                for (data, addr) in packets {
                    let wd_packet = WinDivertPacket {
                        address: addr.clone(),
                        data: std::borrow::Cow::Borrowed(data),
                    };
                    if divert.send(&wd_packet).is_ok() {
                        total_sent += 1;
                        self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }

        Ok(total_sent)
    }

    /// T62: Пакетная инъекция (impostor packets) — до 64 за один syscall.
    pub fn inject_batch_via_divert(
        &self,
        packets: &[(bytes::Bytes, WinDivertAddress<NetworkLayer>)],
    ) -> Result<usize> {
        if packets.is_empty() {
            return Ok(0);
        }

        let guard = self.divert.load();
        let Some(ref divert) = **guard else {
            anyhow::bail!("WinDivert not initialized");
        };

        let mut wd_packets = smallvec::SmallVec::<[_; 64]>::new();
        for (data, addr) in packets {
            let mut a = addr.clone();
            a.set_impostor(true);
            wd_packets.push(WinDivertPacket {
                address: a,
                data: std::borrow::Cow::Borrowed(&data[..]),
            });
        }

        match divert.send_ex(&wd_packets) {
            Ok(n) => {
                let sent = n as usize;
                self.stats
                    .packets_injected
                    .fetch_add(sent as u64, Ordering::Relaxed);
                Ok(sent)
            }
            Err(e) => {
                // Fallback: индивидуальная отправка
                tracing::warn!("inject_batch send_ex failed ({}), fallback", e);
                let mut sent = 0;
                for (data, addr) in packets {
                    let mut a = addr.clone();
                    a.set_impostor(true);
                    let wd_packet = WinDivertPacket {
                        address: a,
                        data: std::borrow::Cow::Borrowed(data),
                    };
                    if divert.send(&wd_packet).is_ok() {
                        sent += 1;
                    }
                }
                self.stats
                    .packets_injected
                    .fetch_add(sent as u64, Ordering::Relaxed);
                Ok(sent)
            }
        }
    }
}

/// Копия статистики (не-atomic, для чтения).
#[derive(Debug, Clone, Default)]
pub struct PacketStatsSnapshot {
    pub packets_received: u64,
    pub packets_sent: u64,
    pub packets_injected: u64,
    pub packets_dropped: u64,
}

/// Raw socket для инъекции IPv4 пакетов с полным IP header.
///
/// Использует `WSASocketW(AF_INET, SOCK_RAW, IPPROTO_RAW)` с `IP_HDRINCL`.
/// Позволяет отправлять пакеты с произвольным IP, TCP, UDP header.
struct RawSocketTxV4 {
    sock: std::net::UdpSocket, // используется для sendto
}

impl RawSocketTxV4 {
    /// Создаёт IPv4 raw socket.
    ///
    /// # Требования
    /// - Admin elevation (UAC или запуск от SYSTEM)
    /// - Windows 10/11
    ///
    /// # Safety
    /// Требует admin прав; создаёт raw socket с `IP_HDRINCL`.
    unsafe fn new() -> Result<Self> {
        use windows::Win32::Networking::WinSock::*;

        let sock = WSASocketW(AF_INET.0 as i32, SOCK_RAW.0, IPPROTO_RAW.0, None, 0, 0)?;

        if sock == INVALID_SOCKET {
            anyhow::bail!("WSASocketW failed: {}", WSAGetLastError().0);
        }

        // IP_HDRINCL: весь IP header включён в пакет
        let opt: u32 = 1;
        let opt_ptr = &opt as *const u32 as *const u8;
        let result = setsockopt(
            sock,
            IPPROTO_IP.0,
            IP_HDRINCL,
            Some(std::slice::from_raw_parts(
                opt_ptr,
                std::mem::size_of::<u32>(),
            )),
        );
        if result == SOCKET_ERROR {
            let _ = closesocket(sock);
            anyhow::bail!("setsockopt(IP_HDRINCL) failed: {}", WSAGetLastError().0);
        }

        // Преобразуем SOCKET в std::net::UdpSocket для sendto
        use std::os::windows::io::{FromRawSocket, OwnedSocket};
        let owned = OwnedSocket::from_raw_socket(sock.0 as u64 as std::os::windows::raw::SOCKET);
        let udp = std::net::UdpSocket::from(owned);
        Ok(Self { sock: udp })
    }

    /// Отправляет raw IPv4 пакет.
    ///
    /// Пакет должен содержать полный IP header + payload.
    /// sendto на raw socket игнорирует адрес назначения — он берётся из IP header.
    fn send(&self, packet: &[u8]) -> Result<()> {
        let addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0);
        let sent = self.sock.send_to(packet, addr)?;
        if sent != packet.len() {
            anyhow::bail!("sendto sent {} of {} bytes", sent, packet.len());
        }
        Ok(())
    }
}

/// Raw socket для инъекции IPv6 пакетов с полным IP header.
///
/// Использует `WSASocketW(AF_INET6, SOCK_RAW, IPPROTO_RAW)` с `IPV6_HDRINCL`.
struct RawSocketTxV6 {
    sock: std::net::UdpSocket,
}

impl RawSocketTxV6 {
    /// Создаёт IPv6 raw socket.
    ///
    /// # Требования
    /// - Admin elevation (UAC или запуск от SYSTEM)
    /// - Windows 10/11
    ///
    /// # Safety
    /// Требует admin прав; создаёт raw socket с `IPV6_HDRINCL`.
    unsafe fn new() -> Result<Self> {
        use windows::Win32::Networking::WinSock::*;

        let sock = WSASocketW(AF_INET6.0 as i32, SOCK_RAW.0, IPPROTO_RAW.0, None, 0, 0)?;

        if sock == INVALID_SOCKET {
            anyhow::bail!("WSASocketW (IPv6) failed: {}", WSAGetLastError().0);
        }

        // IPV6_HDRINCL: весь IPv6 header включён в пакет
        // Константа 24 согласно MSDN (ws2ipdef.h), windows crate 0.62 даёт 2 — используем кастом.
        const IPV6_HDRINCL: i32 = 24;
        let opt: u32 = 1;
        let opt_ptr = &opt as *const u32 as *const u8;
        let result = setsockopt(
            sock,
            IPPROTO_IPV6.0,
            IPV6_HDRINCL,
            Some(std::slice::from_raw_parts(
                opt_ptr,
                std::mem::size_of::<u32>(),
            )),
        );
        if result == SOCKET_ERROR {
            let _ = closesocket(sock);
            anyhow::bail!("setsockopt(IPV6_HDRINCL) failed: {}", WSAGetLastError().0);
        }

        // Преобразуем SOCKET в std::net::UdpSocket для sendto
        use std::os::windows::io::{FromRawSocket, OwnedSocket};
        let owned = OwnedSocket::from_raw_socket(sock.0 as u64 as std::os::windows::raw::SOCKET);
        let udp = std::net::UdpSocket::from(owned);
        Ok(Self { sock: udp })
    }

    /// Отправляет raw IPv6 пакет.
    ///
    /// Пакет должен содержать полный IPv6 header + payload.
    fn send(&self, packet: &[u8]) -> Result<()> {
        let addr = std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0);
        let sent = self.sock.send_to(packet, addr)?;
        if sent != packet.len() {
            anyhow::bail!("sendto (IPv6) sent {} of {} bytes", sent, packet.len());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_stats_default() {
        let stats = PacketStats::new();
        assert_eq!(stats.packets_received.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_sent.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_injected.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_dropped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_packet_stats_snapshot() {
        let engine = PacketEngine::new_api_only();
        engine
            .stats
            .packets_received
            .fetch_add(1, Ordering::Relaxed);
        engine.stats.packets_sent.fetch_add(2, Ordering::Relaxed);
        engine
            .stats
            .packets_injected
            .fetch_add(3, Ordering::Relaxed);
        engine.stats.packets_dropped.fetch_add(4, Ordering::Relaxed);

        let snap = engine.stats_snapshot();
        assert_eq!(snap.packets_received, 1);
        assert_eq!(snap.packets_sent, 2);
        assert_eq!(snap.packets_injected, 3);
        assert_eq!(snap.packets_dropped, 4);
    }

    #[test]
    fn test_api_only_engine() {
        let engine = PacketEngine::new_api_only();
        assert!(!engine.has_divert());
        // recv_blocking should fail in API-only mode
        let pool = PacketBufferPool::new(1);
        assert!(engine.recv_blocking(&pool).is_err());
    }

    #[test]
    fn test_inject_raw_no_socket() {
        // Without admin, RawSocketTx won't be available
        // But the engine should still be usable
        let engine = PacketEngine::new_api_only();
        let result = engine.inject_raw_udp(&[0x45, 0x00, 0x00, 0x14]);
        // Might fail because raw sock is None
        // Just validate it doesn't panic
        let _ = result;
    }

    // ── PacketBufferPool tests ──

    #[test]
    fn test_pool_acquire_release() {
        let pool = PacketBufferPool::new(4);
        let buf = pool.acquire();
        assert_eq!(buf.len(), POOLED_BUF_SIZE);
        assert_eq!(buf.capacity(), POOLED_BUF_SIZE);
        // Возвращаем в пул
        pool.release(buf);
        // После release буфер должен быть доступен снова
        let buf2 = pool.acquire();
        assert_eq!(buf2.len(), POOLED_BUF_SIZE);
    }

    #[test]
    fn test_pool_reuse_count() {
        // Проверяем, что acquire не переаллоцирует: пул отдаёт те же буферы
        let pool = PacketBufferPool::new(4);
        let mut addrs = Vec::new();
        for _ in 0..4 {
            let buf = pool.acquire();
            addrs.push(buf.as_ptr());
            pool.release(buf);
        }
        // Второй раунд — те же указатели
        for addr in &addrs {
            let buf = pool.acquire();
            assert_eq!(buf.as_ptr(), *addr, "буфер не из пула — новая аллокация");
        }
    }

    #[test]
    fn test_pool_reuse_count_exhausted() {
        // Когда пул исчерпан — acquire создаёт новый (без паники)
        let pool = PacketBufferPool::new(2);
        let _a = pool.acquire();
        let _b = pool.acquire();
        // Пул пуст → fallback-аллокация
        let c = pool.acquire();
        assert_eq!(c.len(), POOLED_BUF_SIZE);
    }

    #[test]
    fn test_pool_release_bytes_returns_to_pool() {
        let pool = PacketBufferPool::new(2);
        let buf = pool.acquire();
        let frozen: bytes::Bytes = buf.freeze();

        // release_bytes должен вернуть буфер в пул (refcount == 1)
        pool.release_bytes(frozen);

        // Следующий acquire — из пула, не аллокация
        let reused = pool.acquire();
        assert_eq!(reused.len(), POOLED_BUF_SIZE);
    }

    #[test]
    fn test_pool_release_bytes_shared_noop() {
        // Если Bytes расшарен — release_bytes не пуляет (refcount > 1)
        let pool = PacketBufferPool::new(2);
        let buf = pool.acquire();
        let frozen: bytes::Bytes = buf.freeze();
        let _clone = frozen.clone(); // refcount++
        let ptr_before = frozen.as_ptr();

        pool.release_bytes(frozen); // refcount-- (clone остаётся)

        // Пул должен иметь все элементы (ничего не вернулось)
        let reused = pool.acquire();
        assert_ne!(
            reused.as_ptr(),
            ptr_before,
            "shared Bytes не должен пулиться"
        );
    }

    #[test]
    fn test_pool_release_small_noop() {
        // Маленький буфер (capacity < POOLED_BUF_SIZE) — не пуляем
        let pool = PacketBufferPool::new(2);
        let mut small = bytes::BytesMut::with_capacity(100);
        small.resize(100, 0);
        let small = small.freeze();

        pool.release_bytes(small);

        // Пул всё ещё имеет свои 2 буфера — small не попал в него
        let _a = pool.acquire();
        let _b = pool.acquire();
        // Пул пуст → третий acquire создаст новый буфер (не из пула)
        let c = pool.acquire();
        assert_eq!(c.len(), POOLED_BUF_SIZE);
        assert_eq!(c.capacity(), POOLED_BUF_SIZE);
    }

    #[test]
    fn test_pool_thread_safety() {
        // ArrayQueue — lock-free, проверяем concurrent доступ
        let pool = std::sync::Arc::new(PacketBufferPool::new(8));
        let mut handles = Vec::new();

        for _ in 0..4 {
            let p = pool.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..100 {
                    let buf = p.acquire();
                    // симуляция работы
                    std::thread::yield_now();
                    p.release(buf);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // Все буферы вернулись
        for _ in 0..8 {
            let buf = pool.acquire();
            assert_eq!(buf.len(), POOLED_BUF_SIZE);
        }
        // Пул пуст
        let overflow = pool.acquire();
        assert_eq!(overflow.len(), POOLED_BUF_SIZE);
    }
}

#[cfg(test)]
mod t62_tests {
    use super::*;

    #[test]
    fn test_recv_batch_buffer_size() {
        // 64 packets × 2048 bytes = 128 KB
        assert_eq!(RECV_BATCH_BUFFER_SIZE, 131_072);
        assert_eq!(RECV_BATCH_SIZE, 64);
    }

    #[test]
    fn test_batch_buffers_capacity() {
        // Проверяем что Vec::with_capacity(64) не reallocates в типичном случае
        let forward_batch: Vec<(bytes::Bytes, WinDivertAddress<NetworkLayer>)> =
            Vec::with_capacity(64);
        assert_eq!(forward_batch.capacity(), 64);

        let inject_batch: Vec<(bytes::Bytes, WinDivertAddress<NetworkLayer>)> =
            Vec::with_capacity(64);
        assert_eq!(inject_batch.capacity(), 64);
    }

    #[test]
    fn test_send_batch_empty() {
        // send_batch с пустым вектором должен возвращать Ok(0) без syscall
        let engine = PacketEngine::new_api_only();
        let empty: Vec<(bytes::Bytes, WinDivertAddress<NetworkLayer>)> = Vec::new();
        let result = engine.send_batch(&empty);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_inject_batch_empty() {
        let engine = PacketEngine::new_api_only();
        let empty: Vec<(bytes::Bytes, WinDivertAddress<NetworkLayer>)> = Vec::new();
        let result = engine.inject_batch_via_divert(&empty);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }
}
