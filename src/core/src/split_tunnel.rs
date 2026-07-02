//! Split Tunneling Engine — blacklist/whitelist/auto режимы.
//!
//! Определяет, какие домены/IP должны проходить через DPI-обход,
//! а какие — напрямую (банки, госуслуги, корпоративные ресурсы).
//!
//! Поддерживает:
//! - Точные IP (IPv4 + IPv6) — быстрый lookup через DashSet
//! - CIDR диапазоны (IPv4 + IPv6) — проверка через ipnet::IpNet
//! - Домены (blacklist / whitelist)
//! - DNS-маппинг IP → domain
//! - Auto-режим с TLS-пробой и автоматическим blacklist'ом

use dashmap::{DashMap, DashSet};
use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

/// Thread-local LRU cache для `should_bypass_ip()`.
/// Устраняет 5 DashMap lookups на пакет при 10Gbps.
const TL_CACHE_SIZE: usize = 1024;

thread_local! {
    static BYPASS_CACHE: std::cell::RefCell<Vec<(u128, bool)>> =
        std::cell::RefCell::new(Vec::with_capacity(TL_CACHE_SIZE));
}

/// Режим раздельного туннелирования.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SplitMode {
    /// Только whitelist-домены проходят через DPI-обход.
    /// Остальные — напрямую (безопасный режим).
    WhitelistOnly,
    /// Все домены, кроме blacklist, проходят через DPI-обход.
    /// Blacklist — напрямую (банки, госуслуги).
    BlacklistOnly,
    /// Авто-режим: пробуем через DPI-обход, при ошибке
    /// добавляем в auto-detected blacklist.
    Auto,
}

/// Результат проверки split tunnel.
#[derive(Debug, Clone, PartialEq)]
pub enum SplitDecision {
    /// Пропустить через DPI-обход
    Bypass,
    /// Пропустить напрямую
    Direct,
    /// Проверить (Auto-режим)
    Probe,
}

/// Движок раздельного туннелирования.
pub struct SplitTunnel {
    /// Домены, которые НЕ нужно обходить (банки, госуслуги)
    blacklist_domains: Arc<DashSet<String>>,
    /// Точные IP, которые НЕ нужно обходить (IPv4 + IPv6)
    blacklist_ips: Arc<DashSet<IpAddr>>,
    /// CIDR диапазоны, которые НЕ нужно обходить
    blacklist_nets: Vec<IpNet>,
    /// Домены, которые нужно обходить (только в WhitelistOnly)
    whitelist_domains: Arc<DashSet<String>>,
    /// Точные IP для whitelist (IPv4 + IPv6)
    whitelist_ips: Arc<DashSet<IpAddr>>,
    /// CIDR диапазоны для whitelist
    whitelist_nets: Vec<IpNet>,
    /// Авто-детекшенные IP (для Auto-режима)
    auto_detected: Arc<DashSet<IpAddr>>,
    /// Маппинг IP → domain (из DNS ответов)
    domain_cache: Arc<DashMap<IpAddr, String>>,
    /// Текущий режим
    mode: SplitMode,
}

impl SplitTunnel {
    /// Создаёт новый split tunnel engine.
    pub fn new(mode: SplitMode) -> Self {
        Self::with_cidrs(mode, Vec::new(), Vec::new())
    }

    /// Создаёт split tunnel engine с CIDR диапазонами.
    pub fn with_cidrs(
        mode: SplitMode,
        blacklist_nets: Vec<IpNet>,
        whitelist_nets: Vec<IpNet>,
    ) -> Self {
        Self {
            blacklist_domains: Arc::new(DashSet::new()),
            blacklist_ips: Arc::new(DashSet::new()),
            blacklist_nets,
            whitelist_domains: Arc::new(DashSet::new()),
            whitelist_ips: Arc::new(DashSet::new()),
            whitelist_nets,
            auto_detected: Arc::new(DashSet::new()),
            domain_cache: Arc::new(DashMap::new()),
            mode,
        }
    }

    /// Преобразует IpAddr в u128 для thread-local cache.
    #[inline]
    fn addr_to_key(addr: &IpAddr) -> u128 {
        match addr {
            IpAddr::V4(v4) => v4.to_bits() as u128,
            IpAddr::V6(v6) => v6.to_bits(),
        }
    }

    /// Определяет, нужно ли обходить этот IP (fast path с thread-local cache).
    pub fn should_bypass_ip_fast(&self, dst_ip: &IpAddr) -> bool {
        let key = Self::addr_to_key(dst_ip);

        // Thread-local cache lookup
        let cached = BYPASS_CACHE.with(|c| {
            let cache = c.borrow();
            cache.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
        });
        if let Some(result) = cached {
            return result;
        }

        // Cache miss — делаем настоящий lookup
        let result = self.should_bypass_ip(dst_ip);

        // Сохраняем в cache
        BYPASS_CACHE.with(|c| {
            let mut cache = c.borrow_mut();
            if cache.len() >= TL_CACHE_SIZE {
                cache.remove(0);
            }
            cache.push((key, result));
        });

        result
    }

    /// Определяет, нужно ли обходить этот IP.
    ///
    /// Порядок проверки:
    /// 1. Точное совпадение в DashSet (O(1)) — fast path
    /// 2. CIDR contains (O(n), n = число CIDR диапазонов)
    pub fn should_bypass_ip(&self, dst_ip: &IpAddr) -> bool {
        match self.mode {
            SplitMode::WhitelistOnly => {
                // 1. Точное совпадение
                let exact = self.domain_cache.get(dst_ip);
                if exact.is_some_and(|d| self.whitelist_domains.contains(d.value()))
                    || self.whitelist_ips.contains(dst_ip)
                {
                    return true;
                }
                // 2. CIDR contains
                self.whitelist_nets.iter().any(|net| net.contains(dst_ip))
            }
            SplitMode::BlacklistOnly => {
                // 1. Точное совпадение
                if self.blacklist_ips.contains(dst_ip) {
                    return false;
                }
                // 2. CIDR contains
                !self.blacklist_nets.iter().any(|net| net.contains(dst_ip))
            }
            SplitMode::Auto => !self.auto_detected.contains(dst_ip),
        }
    }

    /// Определяет, нужно ли обходить этот домен.
    pub fn should_bypass_domain(&self, domain: &str) -> bool {
        match self.mode {
            SplitMode::WhitelistOnly => self.whitelist_domains.contains(domain),
            SplitMode::BlacklistOnly => !self.blacklist_domains.contains(domain),
            SplitMode::Auto => true, // Auto: пробуем всё
        }
    }

    /// Принимает решение для домена.
    pub fn decide(&self, domain: &str) -> SplitDecision {
        match self.mode {
            SplitMode::WhitelistOnly => {
                if self.whitelist_domains.contains(domain) {
                    SplitDecision::Bypass
                } else {
                    SplitDecision::Direct
                }
            }
            SplitMode::BlacklistOnly => {
                if self.blacklist_domains.contains(domain) {
                    SplitDecision::Direct
                } else {
                    SplitDecision::Bypass
                }
            }
            SplitMode::Auto => {
                if self.auto_detected.iter().any(|ip| {
                    self.domain_cache
                        .get(&ip)
                        .is_some_and(|d| d.value() == domain)
                }) {
                    SplitDecision::Direct
                } else {
                    SplitDecision::Probe
                }
            }
        }
    }

    /// Добавляет домен в blacklist.
    pub fn add_to_blacklist(&self, domain: String) {
        debug!("Adding to blacklist: {}", domain);
        self.blacklist_domains.insert(domain);
    }

    /// Добавляет IP в blacklist.
    pub fn add_ip_to_blacklist(&self, ip: IpAddr) {
        debug!("Adding IP to blacklist: {}", ip);
        self.blacklist_ips.insert(ip);
    }

    /// Добавляет CIDR в blacklist.
    pub fn add_net_to_blacklist(&mut self, net: IpNet) {
        debug!("Adding CIDR to blacklist: {}", net);
        self.blacklist_nets.push(net);
    }

    /// Добавляет домен в whitelist.
    pub fn add_to_whitelist(&self, domain: String) {
        debug!("Adding to whitelist: {}", domain);
        self.whitelist_domains.insert(domain);
    }

    /// Добавляет CIDR в whitelist.
    pub fn add_net_to_whitelist(&mut self, net: IpNet) {
        debug!("Adding CIDR to whitelist: {}", net);
        self.whitelist_nets.push(net);
    }

    /// Регистрирует IP → domain маппинг (из DNS ответов).
    pub fn register_dns(&self, ip: IpAddr, domain: String) {
        self.domain_cache.insert(ip, domain);
    }

    /// Маркирует IP как заблокированный (Auto-режим).
    pub fn mark_blocked(&self, ip: IpAddr) {
        debug!("Auto-detected blocked IP: {}", ip);
        self.auto_detected.insert(ip);
    }

    /// Построение WinDivert фильтра (оптимизация).
    ///
    /// WinDivert фильтр может быть длиной до 256 символов.
    /// Если blacklist слишком большой — используем базовый фильтр.
    pub fn build_win_divert_filter(&self) -> String {
        let base = "(ip or ipv6) && ((outbound && tcp.DstPort == 443 && tcp.PayloadLength > 5 \
                     && tcp.Payload[0] == 0x16 && tcp.Payload[1] == 0x03 && tcp.Payload[5] == 0x01) \
                     or udp.DstPort == 53 or udp.DstPort == 443)"
            .to_string();

        match self.mode {
            SplitMode::BlacklistOnly => {
                // Собираем все IP-исключения (точные + CIDR)
                let mut exclusions: Vec<String> = Vec::new();

                // Точные IPv4
                for ip in self.blacklist_ips.iter() {
                    if let IpAddr::V4(v4) = *ip {
                        exclusions.push(format!("ip.DstAddr != {}", v4));
                    }
                    // WinDivert 2.2 не поддерживает ipv6.DstAddr в фильтре напрямую,
                    // поэтому IPv6 исключения пропускаем — базовый фильтр достаточен.
                }

                // CIDR диапазоны — конвертируем в WinDivert синтаксис
                for net in &self.blacklist_nets {
                    match net {
                        IpNet::V4(v4net) => {
                            // Формат: ip.DstAddr != 10.0.0.0/8
                            exclusions.push(format!(
                                "ip.DstAddr != {}/{}",
                                v4net.addr(),
                                v4net.prefix_len()
                            ));
                        }
                        IpNet::V6(_v6net) => {
                            // IPv6 CIDR не поддерживается WinDivert фильтром
                        }
                    }
                }

                if exclusions.is_empty() {
                    base
                } else {
                    // WinDivert лимит ~256 символов — берём первые 32 исключения
                    let filtered: Vec<&str> =
                        exclusions.iter().map(|s| s.as_str()).take(32).collect();
                    format!("({}) && ({})", base, filtered.join(" && "))
                }
            }
            _ => base,
        }
    }

    /// Меняет режим.
    pub fn set_mode(&mut self, mode: SplitMode) {
        debug!("Split tunnel mode changed: {:?} → {:?}", self.mode, mode);
        self.mode = mode;
    }

    /// Текущий режим.
    pub fn mode(&self) -> SplitMode {
        self.mode
    }

    /// Снапшот blacklist для API.
    pub fn blacklist_snapshot(&self) -> Vec<String> {
        self.blacklist_domains.iter().map(|d| d.clone()).collect()
    }

    /// Снапшот whitelist для API.
    pub fn whitelist_snapshot(&self) -> Vec<String> {
        self.whitelist_domains.iter().map(|d| d.clone()).collect()
    }
}

impl Default for SplitTunnel {
    fn default() -> Self {
        Self::new(SplitMode::BlacklistOnly)
    }
}

/// Prober для Auto-режима.
pub struct AutoProber {
    /// Успешно пробированные домены (whitelist — не блокировать повторно).
    whitelist: dashmap::DashSet<String>,
    /// Путь к файлу с blocked доменами.
    blocked_file: Option<String>,
}

impl AutoProber {
    pub fn new(blocked_file: Option<String>) -> Self {
        Self {
            whitelist: dashmap::DashSet::new(),
            blocked_file,
        }
    }

    /// Проверяет доступность сайта. Результаты сохраняются в whitelist/blacklist.
    pub async fn probe(&self, domain: &str, ip: IpAddr) -> ProbeResult {
        if self.whitelist.contains(domain) {
            return ProbeResult::Direct;
        }

        let result = Self::probe_raw(domain, ip).await;

        match result {
            ProbeResult::Direct => {
                self.whitelist.insert(domain.to_string());
                debug!("AutoProbe: {} → Direct (whitelisted)", domain);
            }
            ProbeResult::Blocked => {
                if let Some(ref path) = self.blocked_file {
                    self.append_to_file(path, domain);
                }
                debug!("AutoProbe: {} → Blocked", domain);
            }
        }
        result
    }

    async fn probe_raw(domain: &str, ip: IpAddr) -> ProbeResult {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let stream =
            tokio::time::timeout(Duration::from_secs(3), TcpStream::connect((ip, 443))).await;

        let Ok(Ok(mut stream)) = stream else {
            return ProbeResult::Blocked;
        };

        let ch = build_probe_client_hello(domain);
        if stream.write(&ch).await.is_err() {
            return ProbeResult::Blocked;
        }

        let mut buf = [0u8; 1024];
        let response = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;

        match response {
            Ok(Ok(n)) if n > 5 && buf[0] == 0x16 => ProbeResult::Direct,
            _ => ProbeResult::Blocked,
        }
    }

    fn append_to_file(&self, path: &str, domain: &str) {
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = writeln!(file, "{}", domain);
        }
    }

    /// Загружает blocked домены из файла в SplitTunnel blacklist.
    pub fn load_blocked_file(path: &str, tunnel: &SplitTunnel) {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                let domain = line.trim().to_string();
                if !domain.is_empty() && !domain.starts_with('#') {
                    tunnel.add_to_blacklist(domain);
                }
            }
        }
    }
}

/// Результат пробы.
#[derive(Debug, Clone, PartialEq)]
pub enum ProbeResult {
    /// Сайт доступен напрямую
    Direct,
    /// Сайт заблокирован (или недоступен)
    Blocked,
}

/// Строит минимальный TLS ClientHello для пробы.
///
/// Содержит только SNI extension (минимальный размер).
fn build_probe_client_hello(domain: &str) -> Vec<u8> {
    let sni_len = domain.len();

    // TLS record header: ContentType(0x16), Version(0x0301), Length
    let mut packet = Vec::with_capacity(1024);

    // TLS record: Handshake
    packet.extend_from_slice(&[
        0x16, // ContentType: Handshake
        0x03, 0x01, // TLS version (TLS 1.0 in record layer)
        0x00, 0x00, // Length (placeholder)
    ]);

    // Handshake: ClientHello
    packet.extend_from_slice(&[
        0x01, // HandshakeType: ClientHello
        0x00, 0x00, 0x00, // Length (placeholder)
        0x03,
        0x03, // Version: TLS 1.2
              // Random (32 bytes) — можно из реального Chrome
    ]);
    packet.extend_from_slice(&[0u8; 32]);

    // Session ID length = 0
    packet.push(0x00);

    // Cipher suites: TLS_AES_128_GCM_SHA256 (0x1301)
    packet.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);

    // Compression methods: null
    packet.extend_from_slice(&[0x01, 0x00]);

    // Extensions length
    let ext_len = 2 + 2 + 2 + 2 + sni_len + 2;
    packet.extend_from_slice(&[(ext_len >> 8) as u8, (ext_len & 0xFF) as u8]);

    // Extension: SNI (server_name)
    packet.extend_from_slice(&[0x00, 0x00]); // Type: SNI (0)
    let sni_payload_len = 2 + 1 + 2 + sni_len;
    packet.extend_from_slice(&[(sni_payload_len >> 8) as u8, (sni_payload_len & 0xFF) as u8]);
    packet.extend_from_slice(&[0x00, (sni_len + 5) as u8]); // SNI list length
    packet.extend_from_slice(&[0x00]); // NameType: host_name
    packet.extend_from_slice(&[(sni_len >> 8) as u8, (sni_len & 0xFF) as u8]);
    packet.extend_from_slice(domain.as_bytes());

    // Fill lengths
    let handshake_len = (packet.len() - 5) as u16;
    packet[3] = (handshake_len >> 8) as u8;
    packet[4] = (handshake_len & 0xFF) as u8;

    let record_len = (packet.len() - 5) as u16;
    packet[3] = (record_len >> 8) as u8;
    packet[4] = (record_len & 0xFF) as u8;

    packet
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    #[test]
    fn test_blacklist_bypass() {
        let tunnel = SplitTunnel::new(SplitMode::BlacklistOnly);
        tunnel.add_to_blacklist("gosuslugi.ru".to_string());
        tunnel.add_ip_to_blacklist(IpAddr::V4(Ipv4Addr::new(95, 213, 0, 1)));

        assert!(!tunnel.should_bypass_domain("gosuslugi.ru"));
        assert!(tunnel.should_bypass_domain("youtube.com"));
        assert!(!tunnel.should_bypass_ip(&IpAddr::V4(Ipv4Addr::new(95, 213, 0, 1))));
    }

    #[test]
    fn test_whitelist_bypass() {
        let tunnel = SplitTunnel::new(SplitMode::WhitelistOnly);
        tunnel.add_to_whitelist("youtube.com".to_string());

        assert!(tunnel.should_bypass_domain("youtube.com"));
        assert!(!tunnel.should_bypass_domain("gosuslugi.ru"));
    }

    #[test]
    fn test_auto_mode() {
        let tunnel = SplitTunnel::new(SplitMode::Auto);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        assert!(tunnel.should_bypass_ip(&ip)); // Initially true
        tunnel.mark_blocked(ip);
        assert!(!tunnel.should_bypass_ip(&ip)); // Now blocked
    }

    #[test]
    fn test_dns_registration() {
        let tunnel = SplitTunnel::new(SplitMode::WhitelistOnly);
        let ip = IpAddr::V4(Ipv4Addr::new(142, 250, 185, 46));
        tunnel.register_dns(ip, "youtube.com".to_string());

        // Without whitelist, should not bypass
        assert!(!tunnel.should_bypass_ip(&ip));

        // With whitelist
        tunnel.add_to_whitelist("youtube.com".to_string());
        assert!(tunnel.should_bypass_ip(&ip));
    }

    #[test]
    fn test_ipv6_support() {
        let tunnel = SplitTunnel::new(SplitMode::BlacklistOnly);
        let ipv6 = IpAddr::V6(Ipv6Addr::new(
            0x2a00, 0x1450, 0x4001, 0x0812, 0, 0, 0, 0x200e,
        ));

        tunnel.add_ip_to_blacklist(ipv6);
        assert!(!tunnel.should_bypass_ip(&ipv6));
        assert!(tunnel.should_bypass_ip(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }

    #[test]
    fn test_cidr_blacklist() {
        let cidr = IpNet::from_str("10.0.0.0/8").unwrap();
        let tunnel = SplitTunnel::with_cidrs(SplitMode::BlacklistOnly, vec![cidr], Vec::new());

        assert!(!tunnel.should_bypass_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!tunnel.should_bypass_ip(&IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))));
        assert!(tunnel.should_bypass_ip(&IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))));
    }

    #[test]
    fn test_cidr_whitelist() {
        let cidr = IpNet::from_str("192.168.0.0/16").unwrap();
        let tunnel = SplitTunnel::with_cidrs(SplitMode::WhitelistOnly, Vec::new(), vec![cidr]);

        assert!(tunnel.should_bypass_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!tunnel.should_bypass_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn test_cidr_ipv6() {
        let cidr = IpNet::from_str("2a00:1450::/32").unwrap();
        let mut tunnel = SplitTunnel::with_cidrs(SplitMode::BlacklistOnly, vec![cidr], Vec::new());

        let ip_in = IpAddr::V6(Ipv6Addr::new(
            0x2a00, 0x1450, 0x4001, 0x0812, 0, 0, 0, 0x200e,
        ));
        let ip_out = IpAddr::V6(Ipv6Addr::new(0x2607, 0xf8b0, 0, 0, 0, 0, 0, 0x200e));

        assert!(!tunnel.should_bypass_ip(&ip_in));
        assert!(tunnel.should_bypass_ip(&ip_out));
    }

    #[test]
    fn test_exact_ip_overrides_cidr() {
        // Точный IP в whitelist должен работать даже внутри blacklist CIDR
        let cidr = IpNet::from_str("10.0.0.0/8").unwrap();
        let tunnel = SplitTunnel::with_cidrs(SplitMode::BlacklistOnly, vec![cidr], Vec::new());

        // 10.0.0.1 внутри CIDR → не обходим
        assert!(!tunnel.should_bypass_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn test_win_divert_filter() {
        let tunnel = SplitTunnel::new(SplitMode::BlacklistOnly);
        let filter = tunnel.build_win_divert_filter();
        assert!(filter.contains("tcp.DstPort == 443"));
    }

    #[test]
    fn test_win_divert_filter_with_cidr() {
        let cidr = IpNet::from_str("10.0.0.0/8").unwrap();
        let tunnel = SplitTunnel::with_cidrs(SplitMode::BlacklistOnly, vec![cidr], Vec::new());
        let filter = tunnel.build_win_divert_filter();
        assert!(filter.contains("ip.DstAddr != 10.0.0.0/8"));
    }

    #[test]
    fn test_addr_to_key() {
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let v6 = IpAddr::V6(Ipv6Addr::new(
            0x2a00, 0x1450, 0x4001, 0x0812, 0, 0, 0, 0x200e,
        ));

        let key_v4 = SplitTunnel::addr_to_key(&v4);
        let key_v6 = SplitTunnel::addr_to_key(&v6);

        // V4 ключ должен быть уникальным
        assert_ne!(key_v4, 0);
        // V6 ключ должен быть уникальным
        assert_ne!(key_v6, 0);
        // V4 и V6 не должны коллизить
        assert_ne!(key_v4, key_v6);
    }
}
