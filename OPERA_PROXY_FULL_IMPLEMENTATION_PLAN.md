# Полная реализация: реальный SOCKS5-туннель через Opera + DNS/FakeIP + усиление

Самодостаточный документ. Все структуры данных, весь код и порядок интеграции описаны здесь
целиком — не требует чтения других файлов.

---

## Часть 0. Диагноз и архитектурное решение

**Проблема:** `Egress::OperaVpn` — вводящее в заблуждение название. Это SOCKS5-прокси Opera
(бесплатные, без аутентификации), не VPN. Текущий `process_socks5_fallback` при активации
только **дропает** TCP SYN европейских доменов (Netflix/Spotify/Telegram), в надежде что у
клиента настроен SOCKS5 вручную. Реального проксирования (`connect → SOCKS5 handshake →
CONNECT → bridge`) в рантайме нет.

**Архитектурное решение:** Перехват SYN через WinDivert → подмена адреса назначения на
`127.0.0.1:REDIRECTOR_PORT` → приложение довершает TCP-handshake через **настоящий стек ОС**
(не собственная реализация TCP) → локальный `tokio`-сервис делает реальный SOCKS5 CONNECT к
Opera → `copy_bidirectional`. ОС берёт на себя ретрансмиты, окна, MSS-негоциацию и
MTU-фрагментацию — то, что пришлось бы реализовывать вручную при альтернативном подходе
(перехват и ручная пересборка TCP-потока из сырых пакетов на уровне WinDivert), а такой ручной
TCP-стек — источник трудноуловимых багов (нет фрагментации по MTU, нет ретрансмитов, нет
управления окном) и блокирующего I/O внутри пакетного цикла, поэтому этот путь не используется.

**Технический риск, который нужно подтвердить PoC до полной интеграции:** редирект пакета на
`127.0.0.1` в WinDivert иногда даёт `ERROR_INVALID_PARAMETER`/потерю пакета в зависимости от
`IfIdx`/`SubIfIdx`. Рабочая комбинация по опыту сообщества: **локальный слушатель на
`0.0.0.0:PORT`**, а не строго `127.0.0.1`; WinDivert меняет `dst` пакета на `127.0.0.1:PORT`.
Отдельно: loopback-пакеты в WinDivert захватываются **только на outbound-пути** (задокументи-
ровано начиная с WinDivert 1.4: "WinDivert considers loopback packets to be outbound only, and
will not capture loopback packets on the inbound path") — то есть SYN (клиент→редиректор) и
SYN-ACK (редиректор→клиент) — это два разных пакета, оба с флагом `Outbound=1`, а не один и тот
же пакет, "увиденный дважды". Это важно для корректной ментальной модели при написании обработ-
чика обратного пути (часть 3).

Второй риск: повторный захват собственных реинжектированных пакетов (infinite loop через
`WinDivertSend()` → снова `WinDivertRecv()`). Официальная документация подтверждает, что это
реальный сценарий ("Impostor packets are problematic since they can cause infinite loops, where
a packet injected by WinDivertSend() is captured again by WinDivertRecv()"), но точная семантика
флага `Impostor` для пакетов, инжектированных **тем же самым** приложением, неоднозначна даже в
обсуждениях самого проекта WinDivert — поэтому ниже используется дополнительная защита через
собственную таблицу "уже обработанных" портов (`RedirectTable`), а не только флаг `Impostor`.

**Технический риск №3 (порт назначения проверить перед стартом):** локальный порт `17650`
должен быть свободен на машине пользователя — проверка `bind` на старте, при занятости —
попытка следующего порта в диапазоне `17650..17660`, иначе явная ошибка запуска вместо
молчаливого падения SOCKS5-редиректора.

**Порядок работы (обязательный):**
1. Изолированный PoC (отдельный bin-target): голый WinDivert-редирект одного захардкоженного
   `dst:443` на `127.0.0.1:PORT` + `nc -l -p PORT`, проверить что curl к внешнему сайту реально
   долетает до `nc`. Закрыть риски loopback/impostor до того, как код появится в основном движке.
2. Часть 1-3 (транспорт) можно тестировать независимо от WinDivert через обычный
   `TcpStream::connect` на локальный порт вручную.
3. Часть 4 (WinDivert rewrite) — по результатам PoC.
4. Части 5-11 (домены, DNS, hardening) — после того как базовый мост стабилен на 1-2 доменах.

---

## Часть 1. Общие структуры данных

**Файл:** `core/src/proxy/types.rs` (новый)

```rust
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use dashmap::DashMap;

pub const REDIRECTOR_PORT_RANGE: std::ops::Range<u16> = 17650..17660;

/// Запись соответствия локального src_port клиента → оригинальный адрес назначения.
/// Ключ — src_port клиента: в пределах одного TCP-соединения он уникален, ОС не
/// переиспользует его, пока соединение не закрыто и не истёк TIME_WAIT.
#[derive(Clone)]
pub struct RedirectEntry {
    pub orig_dst_ip: IpAddr,
    pub orig_dst_port: u16,
    pub domain: Option<String>,
    pub created_at: Instant,
}

/// Таблица активных редиректов клиент→прокси. Общая для обычного SOCKS5-fallback
/// трафика (Часть 4) и для трафика к Fake IP (Часть 8) — оба случая неотличимы
/// на уровне транспорта после того, как домен резолвлен.
pub struct RedirectTable {
    map: DashMap<u16, RedirectEntry>,
}

impl RedirectTable {
    pub fn new() -> Self {
        Self { map: DashMap::new() }
    }

    pub fn insert(&self, src_port: u16, entry: RedirectEntry) {
        self.map.insert(src_port, entry);
    }

    pub fn get(&self, src_port: u16) -> Option<RedirectEntry> {
        self.map.get(&src_port).map(|e| e.clone())
    }

    pub fn remove(&self, src_port: u16) {
        self.map.remove(&src_port);
    }

    /// Периодическая уборка зависших записей (клиент так и не подключился к
    /// редиректору — например исходный SYN потерялся). Вызывать раз в 30-60 сек
    /// из фонового tokio-таска.
    pub fn sweep_stale(&self, max_age: Duration) {
        self.map.retain(|_, e| e.created_at.elapsed() < max_age);
    }
}

/// Один SOCKS5-прокси Opera с состоянием здоровья.
#[derive(Clone)]
pub struct OperaProxyEntry {
    pub addr: std::net::SocketAddr,
    pub healthy: bool,
    pub last_check: Instant,
    pub consecutive_failures: u32,
}

/// Пул из пяти публичных SOCKS5-адресов Opera с health-check и ротацией.
pub struct OperaProxyPool {
    proxies: parking_lot::RwLock<Vec<OperaProxyEntry>>,
}

impl OperaProxyPool {
    pub fn new(addrs: Vec<std::net::SocketAddr>) -> Self {
        let proxies = addrs.into_iter().map(|addr| OperaProxyEntry {
            addr,
            healthy: true, // оптимистично до первого health-check
            last_check: Instant::now(),
            consecutive_failures: 0,
        }).collect();
        Self { proxies: parking_lot::RwLock::new(proxies) }
    }

    /// Возвращает первый живой прокси или None, если все считаются недоступными.
    /// None должен обрабатываться вызывающим кодом как fail-open (Forward direct),
    /// а не как основание для Drop — бесплатные прокси Opera регулярно ложатся,
    /// и полный отказ хуже, чем просто пропустить гео-разблокировку на этот раз.
    pub fn select_best(&self) -> Option<std::net::SocketAddr> {
        self.proxies.read().iter()
            .find(|p| p.healthy)
            .map(|p| p.addr)
    }

    pub fn is_known_ip(&self, ip: &IpAddr) -> bool {
        self.proxies.read().iter().any(|p| &p.addr.ip() == ip)
    }

    pub fn mark_result(&self, addr: std::net::SocketAddr, success: bool) {
        let mut proxies = self.proxies.write();
        if let Some(p) = proxies.iter_mut().find(|p| p.addr == addr) {
            if success {
                p.consecutive_failures = 0;
                p.healthy = true;
            } else {
                p.consecutive_failures += 1;
                if p.consecutive_failures >= 3 {
                    p.healthy = false;
                }
            }
            p.last_check = Instant::now();
        }
    }

    /// TCP-ping всех прокси раз в N секунд — восстанавливает healthy=true, если
    /// прокси снова стал доступен (иначе он никогда не вернётся в ротацию).
    pub async fn health_check_loop(self: std::sync::Arc<Self>) {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let addrs: Vec<_> = self.proxies.read().iter().map(|p| p.addr).collect();
            for addr in addrs {
                let ok = tokio::time::timeout(
                    Duration::from_secs(3),
                    tokio::net::TcpStream::connect(addr),
                ).await.map(|r| r.is_ok()).unwrap_or(false);
                self.mark_result(addr, ok);
            }
        }
    }
}

/// Домены, идущие через Opera-прокси: статические (built-in), пользовательские
/// (из TOML/файла) и авто-обнаруженные (probe). should_tunnel — единая точка входа.
pub struct DomainBlocklist {
    static_domains: std::collections::HashSet<String>,
    user_domains: parking_lot::RwLock<std::collections::HashSet<String>>,
    probed_domains: DashMap<String, Instant>,
    probed_ttl: Duration,
}

impl DomainBlocklist {
    pub fn new(static_domains: Vec<String>) -> Self {
        Self {
            static_domains: static_domains.into_iter().collect(),
            user_domains: parking_lot::RwLock::new(std::collections::HashSet::new()),
            probed_domains: DashMap::new(),
            probed_ttl: Duration::from_secs(6 * 3600), // 6 часов
        }
    }

    pub fn should_tunnel(&self, domain: &str) -> bool {
        let domain = domain.to_lowercase();
        if self.static_domains.contains(&domain) || self.user_domains.read().contains(&domain) {
            return true;
        }
        if let Some(entry) = self.probed_domains.get(&domain) {
            return entry.elapsed() < self.probed_ttl;
        }
        false
    }

    pub fn mark_probed_blocked(&self, domain: &str) {
        self.probed_domains.insert(domain.to_lowercase(), Instant::now());
    }

    pub fn set_user_domains(&self, domains: Vec<String>) {
        *self.user_domains.write() = domains.into_iter().collect();
    }
}

/// Fake IP: домен ↔ выделенный синтетический IPv4 из диапазона 198.18.0.0/15
/// (RFC 2544 benchmarking-диапазон, не маршрутизируется в реальном интернете).
pub struct FakeIpManager {
    domain_to_ip: DashMap<String, Ipv4Addr>,
    ip_to_domain: DashMap<Ipv4Addr, String>,
    geo_blocked: DashMap<String, Instant>,
    geo_blocked_ttl: Duration,
    next_octet: std::sync::atomic::AtomicU32,
}

impl FakeIpManager {
    pub fn new() -> Self {
        Self {
            domain_to_ip: DashMap::new(),
            ip_to_domain: DashMap::new(),
            geo_blocked: DashMap::new(),
            geo_blocked_ttl: Duration::from_secs(6 * 3600),
            next_octet: std::sync::atomic::AtomicU32::new(1),
        }
    }

    /// Возвращает существующий или выделяет новый fake IP из 198.18.0.0/15.
    pub fn assign_fake_ip(&self, domain: &str) -> Ipv4Addr {
        let domain = domain.to_lowercase();
        if let Some(ip) = self.domain_to_ip.get(&domain) {
            return *ip;
        }
        let n = self.next_octet.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // 198.18.0.0/15 = 198.18.0.0 - 198.19.255.255, ~130k адресов, достаточно с запасом
        let b2 = 18 + (n / 65536) as u8;
        let b3 = ((n / 256) % 256) as u8;
        let b4 = (n % 256) as u8;
        let ip = Ipv4Addr::new(198, b2, b3, b4);
        self.domain_to_ip.insert(domain.clone(), ip);
        self.ip_to_domain.insert(ip, domain);
        ip
    }

    pub fn lookup(&self, ip: &Ipv4Addr) -> Option<String> {
        self.ip_to_domain.get(ip).map(|d| d.clone())
    }

    pub fn is_fake_ip(&self, ip: &Ipv4Addr) -> bool {
        ip.octets()[0] == 198 && (ip.octets()[1] == 18 || ip.octets()[1] == 19)
    }

    /// TTL здесь — насколько долго держим домен геоблокированным в памяти,
    /// НЕ TTL DNS-ответа клиенту (тот задаётся отдельно, см. Часть 6).
    pub fn mark_geo_blocked(&self, domain: &str) {
        self.geo_blocked.insert(domain.to_lowercase(), Instant::now());
    }

    pub fn is_geo_blocked(&self, domain: &str) -> bool {
        self.geo_blocked.get(&domain.to_lowercase())
            .map(|e| e.elapsed() < self.geo_blocked_ttl)
            .unwrap_or(false)
    }
}
```

---

## Часть 2. Подмена адресов в пакете (checksum-корректная)

**Файл:** `core/src/proxy/rewrite.rs` (новый)

```rust
use std::net::IpAddr;
use anyhow::{anyhow, Result};
use pnet_packet::ipv4::MutableIpv4Packet;
use pnet_packet::ipv6::MutableIpv6Packet;
use pnet_packet::tcp::MutableTcpPacket;
use pnet_packet::ipv4::checksum as ipv4_checksum;
use pnet_packet::tcp::ipv4_checksum as tcp_checksum_v4;
use pnet_packet::tcp::ipv6_checksum as tcp_checksum_v6;

enum ParsedIpHeader {
    V4 { src: IpAddr, dst: IpAddr, header_len: usize },
    V6 { src: IpAddr, dst: IpAddr, header_len: usize },
}

impl ParsedIpHeader {
    fn header_len(&self) -> usize {
        match self { Self::V4 { header_len, .. } | Self::V6 { header_len, .. } => *header_len }
    }
    fn src(&self) -> IpAddr {
        match self { Self::V4 { src, .. } | Self::V6 { src, .. } => *src }
    }
    fn dst(&self) -> IpAddr {
        match self { Self::V4 { dst, .. } | Self::V6 { dst, .. } => *dst }
    }
}

fn parse_ip_header_local(buf: &[u8]) -> Option<ParsedIpHeader> {
    if buf.is_empty() { return None; }
    let version = buf[0] >> 4;
    if version == 4 {
        let pkt = pnet_packet::ipv4::Ipv4Packet::new(buf)?;
        let ihl = (pkt.get_header_length() as usize) * 4;
        Some(ParsedIpHeader::V4 {
            src: IpAddr::V4(pkt.get_source()),
            dst: IpAddr::V4(pkt.get_destination()),
            header_len: ihl,
        })
    } else if version == 6 {
        let pkt = pnet_packet::ipv6::Ipv6Packet::new(buf)?;
        Some(ParsedIpHeader::V6 {
            src: IpAddr::V6(pkt.get_source()),
            dst: IpAddr::V6(pkt.get_destination()),
            header_len: 40, // без extension headers — для SYN-пакетов этого достаточно
        })
    } else {
        None
    }
}

/// Переписывает IP-назначение и TCP-порт назначения, пересчитывает IP- и
/// TCP-чексуммы (включая pseudo-header, который меняется при смене IP).
pub fn rewrite_dst_addr(packet_data: &[u8], new_dst_ip: IpAddr, new_dst_port: u16) -> Result<bytes::Bytes> {
    let mut buf = bytes::BytesMut::from(packet_data);
    let ip_hdr = parse_ip_header_local(&buf).ok_or_else(|| anyhow!("invalid ip header"))?;
    let ip_hdr_len = ip_hdr.header_len();
    let orig_src = ip_hdr.src();

    match (&ip_hdr, new_dst_ip) {
        (ParsedIpHeader::V4 { .. }, IpAddr::V4(new_ip)) => {
            let mut ip_pkt = MutableIpv4Packet::new(&mut buf[..ip_hdr_len])
                .ok_or_else(|| anyhow!("bad ipv4 slice"))?;
            ip_pkt.set_destination(new_ip);
            ip_pkt.set_checksum(0);
            let csum = ipv4_checksum(&ip_pkt.to_immutable());
            ip_pkt.set_checksum(csum);
        }
        (ParsedIpHeader::V6 { .. }, IpAddr::V6(new_ip)) => {
            let mut ip_pkt = MutableIpv6Packet::new(&mut buf[..ip_hdr_len])
                .ok_or_else(|| anyhow!("bad ipv6 slice"))?;
            ip_pkt.set_destination(new_ip);
        }
        _ => return Err(anyhow!("ip version mismatch between packet and new_dst_ip")),
    }

    {
        let mut tcp_pkt = MutableTcpPacket::new(&mut buf[ip_hdr_len..])
            .ok_or_else(|| anyhow!("invalid tcp header"))?;
        tcp_pkt.set_destination(new_dst_port);
        tcp_pkt.set_checksum(0);
    }

    let new_csum = match (orig_src, new_dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let tcp_view = pnet_packet::tcp::TcpPacket::new(&buf[ip_hdr_len..]).unwrap();
            tcp_checksum_v4(&tcp_view, &s, &d)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let tcp_view = pnet_packet::tcp::TcpPacket::new(&buf[ip_hdr_len..]).unwrap();
            tcp_checksum_v6(&tcp_view, &s, &d)
        }
        _ => return Err(anyhow!("mixed ip versions in checksum calc")),
    };
    let mut tcp_pkt = MutableTcpPacket::new(&mut buf[ip_hdr_len..]).unwrap();
    tcp_pkt.set_checksum(new_csum);

    Ok(buf.freeze())
}

/// Переписывает IP-источник и TCP-порт источника (обратный путь: ответ
/// локального редиректора → клиенту, подмена под адрес оригинальной цели).
pub fn rewrite_src_addr(packet_data: &[u8], new_src_ip: IpAddr, new_src_port: u16) -> Result<bytes::Bytes> {
    let mut buf = bytes::BytesMut::from(packet_data);
    let ip_hdr = parse_ip_header_local(&buf).ok_or_else(|| anyhow!("invalid ip header"))?;
    let ip_hdr_len = ip_hdr.header_len();
    let orig_dst = ip_hdr.dst();

    match (&ip_hdr, new_src_ip) {
        (ParsedIpHeader::V4 { .. }, IpAddr::V4(new_ip)) => {
            let mut ip_pkt = MutableIpv4Packet::new(&mut buf[..ip_hdr_len])
                .ok_or_else(|| anyhow!("bad ipv4 slice"))?;
            ip_pkt.set_source(new_ip);
            ip_pkt.set_checksum(0);
            let csum = ipv4_checksum(&ip_pkt.to_immutable());
            ip_pkt.set_checksum(csum);
        }
        (ParsedIpHeader::V6 { .. }, IpAddr::V6(new_ip)) => {
            let mut ip_pkt = MutableIpv6Packet::new(&mut buf[..ip_hdr_len])
                .ok_or_else(|| anyhow!("bad ipv6 slice"))?;
            ip_pkt.set_source(new_ip);
        }
        _ => return Err(anyhow!("ip version mismatch between packet and new_src_ip")),
    }

    {
        let mut tcp_pkt = MutableTcpPacket::new(&mut buf[ip_hdr_len..])
            .ok_or_else(|| anyhow!("invalid tcp header"))?;
        tcp_pkt.set_source(new_src_port);
        tcp_pkt.set_checksum(0);
    }

    let new_csum = match (new_src_ip, orig_dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let tcp_view = pnet_packet::tcp::TcpPacket::new(&buf[ip_hdr_len..]).unwrap();
            tcp_checksum_v4(&tcp_view, &s, &d)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let tcp_view = pnet_packet::tcp::TcpPacket::new(&buf[ip_hdr_len..]).unwrap();
            tcp_checksum_v6(&tcp_view, &s, &d)
        }
        _ => return Err(anyhow!("mixed ip versions in checksum calc")),
    };
    let mut tcp_pkt = MutableTcpPacket::new(&mut buf[ip_hdr_len..]).unwrap();
    tcp_pkt.set_checksum(new_csum);

    Ok(buf.freeze())
}

/// UDP-чексумма — обязательна для IPv6 (RFC 8200 запрещает нулевую), опциональна
/// для IPv4. Используется при сборке DNS-ответов (Часть 6).
pub fn udp_checksum(src: IpAddr, dst: IpAddr, udp_packet: &[u8]) -> u16 {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let pkt = pnet_packet::udp::UdpPacket::new(udp_packet).unwrap();
            pnet_packet::udp::ipv4_checksum(&pkt, &s, &d)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let pkt = pnet_packet::udp::UdpPacket::new(udp_packet).unwrap();
            pnet_packet::udp::ipv6_checksum(&pkt, &s, &d)
        }
        _ => 0,
    }
}
```

---

## Часть 3. Реальный SOCKS5-клиент и мост

**Файл:** `core/src/proxy/socks5_client.rs` (новый)

```rust
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use anyhow::{bail, Result};

/// SOCKS5 handshake без аутентификации (RFC 1928, метод 0x00).
pub async fn socks5_handshake_noauth(s: &mut TcpStream) -> Result<()> {
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await?;
    if resp[0] != 0x05 || resp[1] != 0x00 {
        bail!("SOCKS5 handshake failed or authentication required (method={})", resp[1]);
    }
    Ok(())
}

/// SOCKS5 CONNECT. Если host — доменное имя, шлёт ATYP=0x03 (домен резолвится
/// НА СТОРОНЕ прокси — критично для геообхода: если резолвить локально и слать
/// IP, DNS-резолвинг останется на стороне ISP/локального DNS и вернёт не тот
/// edge-сервер, который отдаёт разблокированный контент для нужного региона).
pub async fn socks5_connect(s: &mut TcpStream, host: &str, port: u16) -> Result<()> {
    let mut req = Vec::new();
    req.extend_from_slice(&[0x05, 0x01, 0x00]);

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(ipv4) => {
                req.push(0x01);
                req.extend_from_slice(&ipv4.octets());
            }
            std::net::IpAddr::V6(ipv6) => {
                req.push(0x04);
                req.extend_from_slice(&ipv6.octets());
            }
        }
    } else {
        if host.len() > 255 {
            bail!("domain name too long for SOCKS5: {} bytes", host.len());
        }
        req.push(0x03);
        req.push(host.len() as u8);
        req.extend_from_slice(host.as_bytes());
    }
    req.extend_from_slice(&port.to_be_bytes());

    s.write_all(&req).await?;

    let mut resp_header = [0u8; 4];
    s.read_exact(&mut resp_header).await?;
    if resp_header[0] != 0x05 || resp_header[1] != 0x00 {
        bail!("SOCKS5 CONNECT failed, REP={}", resp_header[1]);
    }

    // Дочитываем BND.ADDR/BND.PORT по фактическому ATYP, чтобы не оставить
    // "хвост" в буфере (иначе следующее чтение получит эти байты вместо данных).
    let atyp = resp_header[3];
    let skip_len = match atyp {
        0x01 => 4 + 2,
        0x03 => {
            let mut len_byte = [0u8; 1];
            s.read_exact(&mut len_byte).await?;
            len_byte[0] as usize + 2
        }
        0x04 => 16 + 2,
        _ => bail!("unsupported SOCKS5 ATYP in response: {atyp}"),
    };
    let mut skip_buf = vec![0u8; skip_len];
    s.read_exact(&mut skip_buf).await?;

    Ok(())
}
```

**Файл:** `core/src/proxy/redirector.rs` (новый)

```rust
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::copy_bidirectional;
use tracing::{debug, warn, info};

use super::types::{RedirectTable, OperaProxyPool};
use super::socks5_client::{socks5_handshake_noauth, socks5_connect};

pub struct SocksRedirector {
    table: Arc<RedirectTable>,
    proxy_pool: Arc<OperaProxyPool>,
}

impl SocksRedirector {
    pub fn new(table: Arc<RedirectTable>, proxy_pool: Arc<OperaProxyPool>) -> Self {
        Self { table, proxy_pool }
    }

    /// Пытается забиндить порт из диапазона 17650-17659 (см. Часть 0, риск №3).
    /// Слушает на 0.0.0.0, не строго на 127.0.0.1 — см. обоснование в Части 0.
    pub async fn bind_and_run(self: Arc<Self>) -> anyhow::Result<u16> {
        let mut last_err = None;
        for port in super::types::REDIRECTOR_PORT_RANGE {
            match TcpListener::bind(("0.0.0.0", port)).await {
                Ok(listener) => {
                    info!("SocksRedirector listening on 0.0.0.0:{port}");
                    let this = self.clone();
                    tokio::spawn(async move { this.accept_loop(listener).await; });
                    return Ok(port);
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(anyhow::anyhow!(
            "failed to bind SocksRedirector on any port in 17650-17659: {:?}",
            last_err
        ))
    }

    async fn accept_loop(self: Arc<Self>, listener: TcpListener) {
        loop {
            match listener.accept().await {
                Ok((inbound, peer_addr)) => {
                    let this = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = this.handle(inbound, peer_addr.port()).await {
                            debug!("socks redirect session error: {e}");
                        }
                    });
                }
                Err(e) => {
                    warn!("SocksRedirector accept error: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    async fn handle(&self, mut inbound: TcpStream, client_src_port: u16) -> anyhow::Result<()> {
        let entry = self.table.get(client_src_port)
            .ok_or_else(|| anyhow::anyhow!("no redirect entry for port {client_src_port}"))?;

        let target_host = entry.domain.clone()
            .unwrap_or_else(|| entry.orig_dst_ip.to_string());

        let proxy_addr = self.proxy_pool.select_best()
            .ok_or_else(|| anyhow::anyhow!("no healthy opera proxy"))?;

        let connect_result = async {
            let mut outbound = TcpStream::connect(proxy_addr).await?;
            socks5_handshake_noauth(&mut outbound).await?;
            socks5_connect(&mut outbound, &target_host, entry.orig_dst_port).await?;
            Ok::<_, anyhow::Error>(outbound)
        }.await;

        let mut outbound = match connect_result {
            Ok(s) => {
                self.proxy_pool.mark_result(proxy_addr, true);
                s
            }
            Err(e) => {
                self.proxy_pool.mark_result(proxy_addr, false);
                self.table.remove(client_src_port);
                return Err(e);
            }
        };

        let bridge_result = copy_bidirectional(&mut inbound, &mut outbound).await;
        self.table.remove(client_src_port);

        match bridge_result {
            Ok((up, down)) => {
                debug!("bridge {target_host}:{} closed: {up}B up / {down}B down", entry.orig_dst_port);
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }
}
```

---

## Часть 4. Перехват SYN и обратного пути в WinDivert-цикле

**Интеграция в существующий цикл обработки пакетов** (метод, где сейчас происходит
классификация трафика и принятие решения Forward/Drop/Modify):

```rust
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

const REDIRECTOR_PORT: u16 = 17650; // фактический порт возвращается bind_and_run(), см. Часть 3

/// Заменяет прежнее поведение "дропнуть SYN, надеясь на ручной SOCKS5 в браузере".
/// Вызывается для TCP SYN-пакетов, чей домен/IP определён как подлежащий тунне-
/// лированию через Opera (обычный DomainBlocklist ИЛИ Fake IP — оба случая
/// сходятся в одну и ту же функцию, см. Часть 8).
fn process_socks5_redirect(
    &self,
    captured: &mut CapturedPacket,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    domain: Option<String>,
) -> anyhow::Result<PacketDecision> {
    // Fail-open: нет живого прокси — пропускаем direct, не дропаем (Часть 1, OperaProxyPool).
    if self.proxy_pool.select_best().is_none() {
        tracing::warn!("all opera proxies unhealthy, falling back to direct for {:?}", domain);
        return Ok(PacketDecision::Forward);
    }

    self.redirect_table.insert(src_port, crate::proxy::types::RedirectEntry {
        orig_dst_ip: dst_ip,
        orig_dst_port: dst_port,
        domain,
        created_at: Instant::now(),
    });

    let modified = crate::proxy::rewrite::rewrite_dst_addr(
        &captured.data,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        REDIRECTOR_PORT,
    )?;

    Ok(PacketDecision::Modify(modified.to_vec()))
}

/// Обратный путь: ответы нашего же локального SocksRedirector (src_port ==
/// REDIRECTOR_PORT) переписываются под оригинальный адрес назначения, чтобы TCP-
/// стек клиентского приложения увидел ожидаемый 4-tuple (иначе SYN-ACK будет
/// молча отброшен как несоответствующий открытому соединению).
fn process_redirect_return_path(
    &self,
    captured: &mut CapturedPacket,
    dst_port_of_packet: u16, // это src_port клиента (на обратном пути dst становится client's src)
) -> anyhow::Result<PacketDecision> {
    if let Some(entry) = self.redirect_table.get(dst_port_of_packet) {
        let modified = crate::proxy::rewrite::rewrite_src_addr(
            &captured.data,
            entry.orig_dst_ip,
            entry.orig_dst_port,
        )?;
        return Ok(PacketDecision::Modify(modified.to_vec()));
    }
    Ok(PacketDecision::Forward)
}
```

**Фильтр WinDivert** должен включать loopback-трафик до порта редиректора:

```rust
fn build_filter(existing_filter: &str) -> String {
    format!(
        "({existing_filter}) or (loopback and tcp.SrcPort == {REDIRECTOR_PORT}) or (loopback and tcp.DstPort == {REDIRECTOR_PORT})"
    )
}
```

`existing_filter` — то, что уже используется в проекте для остальных техник (TLS ClientHello
matching, generic TCP и т.д.) — эта строка добавляется поверх, не заменяет её целиком, чтобы не
потерять уже работающие условия.

---

## Часть 5. Список доменов: TOML + внешний файл + hot-reload

**Файл:** `core/src/proxy/domain_list.rs` (новый)

```rust
use anyhow::{Context, Result};
use std::time::{Duration, SystemTime};
use std::sync::Arc;
use parking_lot::RwLock;
use tracing::{info, warn};

/// Читает домены из файла, игнорируя пустые строки и комментарии (#...).
pub fn load_domains_from_file(path: &str) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read domains file: {path}"))?;

    let domains: Vec<String> = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_lowercase())
        .collect();

    info!("loaded {} domains from {path}", domains.len());
    Ok(domains)
}

/// Фоновый таск: пуллинг файла по mtime раз в 30 сек, без внешних зависимостей
/// от файловых уведомлений ОС (Windows не имеет SIGHUP; polling — самый простой
/// надёжный вариант для однопользовательского десктоп-приложения).
pub async fn watch_domains_file(
    blocklist: Arc<crate::proxy::types::DomainBlocklist>,
    path: String,
) {
    let mut last_mtime: Option<SystemTime> = std::fs::metadata(&path)
        .and_then(|m| m.modified()).ok();

    if let Ok(domains) = load_domains_from_file(&path) {
        blocklist.set_user_domains(domains);
    }

    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;
        let mtime = match std::fs::metadata(&path).and_then(|m| m.modified()) {
            Ok(m) => m,
            Err(e) => { warn!("domains file {path} unreadable: {e}"); continue; }
        };
        if Some(mtime) != last_mtime {
            last_mtime = Some(mtime);
            match load_domains_from_file(&path) {
                Ok(domains) => {
                    blocklist.set_user_domains(domains);
                    info!("domains file reloaded: {path}");
                }
                Err(e) => warn!("domains file reload failed: {e}"),
            }
        }
    }
}
```

**Файл:** `blocked_domains.txt.example`

```
# Домены, которые всегда идут через Opera SOCKS5 прокси.
# Один домен на строку. Поддомены НЕ разворачиваются автоматически —
# добавляй явно (netflix.com и www.netflix.com — разные строки).
netflix.com
www.netflix.com
nflxvideo.net
spotify.com
open.spotify.com
scdn.co
```

---

## Часть 6. DNS Proxy Engine (Split-DNS: adblock / system / DoH / Fake IP)

**Файл:** `core/src/dns/dns_utils.rs` (новый) — низкоуровневый парсинг/сборка

```rust
use std::net::IpAddr;
use anyhow::{anyhow, Result};

pub struct DnsQuery {
    pub transaction_id: u16,
    pub domain: String,
    pub query_type: u16, // 1 = A, 28 = AAAA
    pub raw_question: Vec<u8>,
}

/// Парсит DNS-запрос из сырого UDP-пакета (IP+UDP+DNS).
pub fn parse_dns_query(packet: &[u8]) -> Option<DnsQuery> {
    let ip_hdr = crate::desync::parse_ip_header(packet)?;
    if ip_hdr.protocol().0 != 17 { return None; } // не UDP

    let udp_start = ip_hdr.header_len();
    if packet.len() < udp_start + 8 { return None; }
    let udp_data = &packet[udp_start + 8..];

    if udp_data.len() < 12 { return None; }
    let transaction_id = u16::from_be_bytes([udp_data[0], udp_data[1]]);
    let qdcount = u16::from_be_bytes([udp_data[4], udp_data[5]]);
    if qdcount == 0 { return None; }

    let mut pos = 12;
    let mut labels = Vec::new();
    while pos < udp_data.len() {
        let label_len = udp_data[pos] as usize;
        if label_len == 0 { pos += 1; break; }
        if pos + 1 + label_len > udp_data.len() { return None; }
        let label = std::str::from_utf8(&udp_data[pos + 1..pos + 1 + label_len]).ok()?;
        labels.push(label);
        pos += 1 + label_len;
    }
    let domain = labels.join(".");

    if pos + 4 > udp_data.len() { return None; }
    let query_type = u16::from_be_bytes([udp_data[pos], udp_data[pos + 1]]);

    Some(DnsQuery {
        transaction_id,
        domain,
        query_type,
        raw_question: udp_data[12..pos + 4].to_vec(),
    })
}

/// Собирает полный IP+UDP+DNS пакет-ответ (swap src/dst из оригинального запроса).
/// answer: None → ANCOUNT=0 (пустой NOERROR-ответ, используется для AAAA-заглушки).
/// rcode: 0 = NOERROR, 3 = NXDOMAIN.
pub fn build_dns_response(
    original_packet: &[u8],
    query: &DnsQuery,
    answer: Option<IpAddr>,
    ttl: u32,
    rcode: u8,
) -> Result<Vec<u8>> {
    let mut dns_response = Vec::new();
    dns_response.extend_from_slice(&query.transaction_id.to_be_bytes());
    let flags: u16 = 0x8000 | 0x0080 | (rcode as u16 & 0x0F); // QR=1, RA=1, RCODE
    dns_response.extend_from_slice(&flags.to_be_bytes());
    dns_response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    dns_response.extend_from_slice(&(if answer.is_some() { 1u16 } else { 0u16 }).to_be_bytes());
    dns_response.extend_from_slice(&0u16.to_be_bytes());
    dns_response.extend_from_slice(&0u16.to_be_bytes());
    dns_response.extend_from_slice(&query.raw_question);

    if let Some(ip) = answer {
        dns_response.extend_from_slice(&[0xC0, 0x0C]); // указатель на имя в question
        dns_response.extend_from_slice(&query.query_type.to_be_bytes());
        dns_response.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        dns_response.extend_from_slice(&ttl.to_be_bytes());
        match ip {
            IpAddr::V4(v4) => {
                dns_response.extend_from_slice(&4u16.to_be_bytes());
                dns_response.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                dns_response.extend_from_slice(&16u16.to_be_bytes());
                dns_response.extend_from_slice(&v6.octets());
            }
        }
    }

    let ip_hdr = crate::desync::parse_ip_header(original_packet)
        .ok_or_else(|| anyhow!("invalid original ip header"))?;
    let src_ip = ip_hdr.dst(); // ответ идёт ОТ того адреса, на который слался запрос
    let dst_ip = ip_hdr.src(); // К клиенту

    let udp_start = ip_hdr.header_len();
    let orig_src_port = u16::from_be_bytes([original_packet[udp_start], original_packet[udp_start + 1]]);
    let orig_dst_port = u16::from_be_bytes([original_packet[udp_start + 2], original_packet[udp_start + 3]]);
    // ответ: src/dst портов меняются местами относительно запроса
    let (resp_src_port, resp_dst_port) = (orig_dst_port, orig_src_port);

    let udp_len = 8 + dns_response.len();
    let mut udp_packet = Vec::with_capacity(udp_len);
    udp_packet.extend_from_slice(&resp_src_port.to_be_bytes());
    udp_packet.extend_from_slice(&resp_dst_port.to_be_bytes());
    udp_packet.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp_packet.extend_from_slice(&[0, 0]); // checksum placeholder

    // UDP checksum обязателен для IPv6 (RFC 8200 запрещает 0), для IPv4 — опционален.
    if matches!(src_ip, IpAddr::V6(_)) {
        udp_packet.extend_from_slice(&dns_response);
        let csum = crate::proxy::rewrite::udp_checksum(src_ip, dst_ip, &udp_packet);
        udp_packet[6] = (csum >> 8) as u8;
        udp_packet[7] = (csum & 0xFF) as u8;
    } else {
        udp_packet.extend_from_slice(&dns_response);
    }

    Ok(crate::desync::build_ip_packet(
        src_ip, dst_ip, crate::desync::ip::IpNextHeaderProtocols::Udp, 64, 0, &udp_packet,
    ).to_vec())
}
```

**Файл:** `core/src/dns/dns_proxy.rs` (новый) — классификация и резолвинг

```rust
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use dashmap::DashMap;
use tracing::{debug, warn};
use serde::{Deserialize, Serialize};

use super::dns_utils::{DnsQuery, parse_dns_query, build_dns_response};
use crate::proxy::types::FakeIpManager;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsResolveMode {
    AdBlock,
    SystemDns,
    SecureDoh,
    FakeIp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsProxyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub adblock_enabled: bool,
    #[serde(default = "default_doh_servers")]
    pub doh_servers: Vec<String>,
    #[serde(default = "default_system_dns")]
    pub system_dns_servers: Vec<String>,
    /// Домены с известной/заподозренной DNS-цензурой (RKN-спуфинг) — ТОЛЬКО они
    /// идут через DoH. Всё остальное — через системный DNS, чтобы не терять ECS
    /// (client subnet) и получать оптимальный CDN-роутинг для незаблокированных
    /// сайтов, которых подавляющее большинство.
    #[serde(default)]
    pub censored_domains: Vec<String>,
    #[serde(default)]
    pub censored_domains_file: Option<String>,
    #[serde(default = "default_adblock_domains")]
    pub adblock_domains: Vec<String>,
    #[serde(default = "default_ttl")]
    pub ttl: u32,
}

fn default_true() -> bool { true }
fn default_ttl() -> u32 { 60 }
fn default_doh_servers() -> Vec<String> {
    vec!["https://cloudflare-dns.com/dns-query".into(), "https://dns.google/resolve".into()]
}
fn default_system_dns() -> Vec<String> {
    vec!["8.8.8.8".into()] // используется только как fallback, если системный резолвер недоступен
}
fn default_adblock_domains() -> Vec<String> {
    vec![
        "doubleclick.net".into(), "googlesyndication.com".into(),
        "googleadservices.com".into(), "google-analytics.com".into(),
        "adservice.google.com".into(), "adnxs.com".into(), "2mdn.net".into(),
    ]
}

impl Default for DnsProxyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            adblock_enabled: false,
            doh_servers: default_doh_servers(),
            system_dns_servers: default_system_dns(),
            censored_domains: Vec::new(),
            censored_domains_file: None,
            adblock_domains: default_adblock_domains(),
            ttl: default_ttl(),
        }
    }
}

pub struct DnsProxyEngine {
    config: parking_lot::RwLock<DnsProxyConfig>,
    fake_ip_manager: Arc<FakeIpManager>,
    cache: DashMap<String, (IpAddr, Instant)>,
    doh_resolvers: Vec<(String, trust_dns_resolver::TokioAsyncResolver)>,
    doh_health: DashMap<String, bool>,
    system_resolver: Option<trust_dns_resolver::TokioAsyncResolver>,
}

impl DnsProxyEngine {
    pub fn new(config: DnsProxyConfig, fake_ip_manager: Arc<FakeIpManager>) -> Self {
        let doh_resolvers = Self::create_doh_resolvers(&config.doh_servers);
        let system_resolver = Self::create_system_resolver();
        Self {
            config: parking_lot::RwLock::new(config),
            fake_ip_manager,
            cache: DashMap::new(),
            doh_resolvers,
            doh_health: DashMap::new(),
            system_resolver,
        }
    }

    /// ВАЖНО: crate `trust-dns-resolver` был переименован в `hickory-resolver`;
    /// перед реализацией свериться с docs.rs на закреплённую в Cargo.toml версию —
    /// точная сигнатура bootstrap для DoH (`NameServerConfig`/аналог) могла
    /// измениться. Ниже — сигнатура на основе publicly documented API на момент
    /// написания плана, требует верификации перед компиляцией.
    fn create_doh_resolvers(urls: &[String]) -> Vec<(String, trust_dns_resolver::TokioAsyncResolver)> {
        use trust_dns_resolver::config::{ResolverConfig, ResolverOpts, NameServerConfig, Protocol};
        use trust_dns_resolver::TokioAsyncResolver;

        let mut out = Vec::new();
        for url in urls {
            let mut cfg = ResolverConfig::new();
            if let Ok(ns) = NameServerConfig::from_url(url, Protocol::Https) {
                cfg.add_name_server(ns);
            } else {
                warn!("skipping unparseable DoH url: {url}");
                continue;
            }
            let mut opts = ResolverOpts::default();
            opts.timeout = Duration::from_secs(3);
            opts.attempts = 2;
            match TokioAsyncResolver::tokio(cfg, opts) {
                Ok(r) => out.push((url.clone(), r)),
                Err(e) => warn!("failed to create DoH resolver for {url}: {e}"),
            }
        }
        out
    }

    fn create_system_resolver() -> Option<trust_dns_resolver::TokioAsyncResolver> {
        use trust_dns_resolver::TokioAsyncResolver;
        use trust_dns_resolver::system_conf::read_system_conf;
        match read_system_conf() {
            Ok((cfg, opts)) => TokioAsyncResolver::tokio(cfg, opts).ok(),
            Err(e) => { warn!("failed to read system DNS config: {e}"); None }
        }
    }

    fn matches_suffix_list(domain: &str, list: &[String]) -> bool {
        list.iter().any(|d| domain == d || domain.ends_with(&format!(".{d}")))
    }

    /// Приоритет по умолчанию: system DNS. DoH — только явное исключение для
    /// доменов из censored_domains (известная/заподозренная DNS-цензура), не
    /// для всего подряд — иначе весь обычный некензурируемый трафик теряет ECS
    /// и получает худший CDN-роутинг без всякой необходимости.
    pub fn classify_domain(&self, domain: &str) -> DnsResolveMode {
        let lower = domain.to_lowercase();
        let lower = lower.trim_end_matches('.');
        let config = self.config.read();

        if config.adblock_enabled && Self::matches_suffix_list(lower, &config.adblock_domains) {
            return DnsResolveMode::AdBlock;
        }
        if self.fake_ip_manager.is_geo_blocked(domain) {
            return DnsResolveMode::FakeIp;
        }
        if Self::matches_suffix_list(lower, &config.censored_domains) {
            return DnsResolveMode::SecureDoh;
        }
        DnsResolveMode::SystemDns
    }

    pub async fn handle_dns_query(&self, query_packet: &[u8]) -> Option<Vec<u8>> {
        let dns_query = parse_dns_query(query_packet)?;
        debug!("DNS query: {} (type={})", dns_query.domain, dns_query.query_type);

        let mode = self.classify_domain(&dns_query.domain);

        // AAAA для AdBlock/FakeIp — НЕ подменяем поддельным IPv4 (это дало бы
        // невалидную запись TYPE=AAAA с 4-байтным RDATA). Отвечаем пустым
        // NOERROR — форсирует клиента на A-запрос/IPv4, без протокольной ошибки.
        if dns_query.query_type == 28 && matches!(mode, DnsResolveMode::AdBlock | DnsResolveMode::FakeIp) {
            let ttl = self.config.read().ttl;
            return build_dns_response(query_packet, &dns_query, None, ttl, 0).ok();
        }

        let ttl = self.config.read().ttl;
        match mode {
            DnsResolveMode::AdBlock => {
                debug!("DNS AdBlock: {} → NXDOMAIN", dns_query.domain);
                build_dns_response(query_packet, &dns_query, None, ttl, 3 /* NXDOMAIN */).ok()
            }
            DnsResolveMode::FakeIp => {
                let fake_ip = self.fake_ip_manager.assign_fake_ip(&dns_query.domain);
                debug!("DNS FakeIP: {} → {fake_ip}", dns_query.domain);
                build_dns_response(query_packet, &dns_query, Some(IpAddr::V4(fake_ip)), ttl, 0).ok()
            }
            DnsResolveMode::SystemDns => {
                match self.resolve_via_system(&dns_query.domain).await {
                    Some(ip) => build_dns_response(query_packet, &dns_query, Some(ip), ttl, 0).ok(),
                    None => None, // резолвер недоступен — форвардим запрос в интернет как есть
                }
            }
            DnsResolveMode::SecureDoh => {
                match self.resolve_via_doh(&dns_query.domain).await {
                    Some(ip) => build_dns_response(query_packet, &dns_query, Some(ip), ttl, 0).ok(),
                    None => None,
                }
            }
        }
    }

    async fn resolve_via_doh(&self, domain: &str) -> Option<IpAddr> {
        if let Some(entry) = self.cache.get(domain) {
            if entry.1 > Instant::now() { return Some(entry.0); }
        }
        for (label, resolver) in &self.doh_resolvers {
            if !self.doh_health.get(label).map(|h| *h).unwrap_or(true) { continue; }
            match resolver.lookup_ip(domain).await {
                Ok(lookup) => {
                    if let Some(ip) = lookup.iter().next() {
                        let ttl = self.config.read().ttl as u64;
                        self.cache.insert(domain.to_string(), (ip, Instant::now() + Duration::from_secs(ttl)));
                        return Some(ip);
                    }
                }
                Err(e) => {
                    warn!("DoH resolve failed via {label} for {domain}: {e}");
                    self.doh_health.insert(label.clone(), false);
                }
            }
        }
        None
    }

    async fn resolve_via_system(&self, domain: &str) -> Option<IpAddr> {
        if let Some(entry) = self.cache.get(domain) {
            if entry.1 > Instant::now() { return Some(entry.0); }
        }
        let resolver = self.system_resolver.as_ref()?;
        match resolver.lookup_ip(domain).await {
            Ok(lookup) => {
                let ip = lookup.iter().next()?;
                let ttl = self.config.read().ttl as u64;
                self.cache.insert(domain.to_string(), (ip, Instant::now() + Duration::from_secs(ttl)));
                Some(ip)
            }
            Err(e) => { warn!("system DNS resolve failed for {domain}: {e}"); None }
        }
    }

    /// Health-check DoH-резолверов раз в 2 минуты — восстанавливает их в
    /// ротации после временной недоступности (иначе пометка "мёртв" навсегда).
    pub async fn doh_health_check_loop(self: Arc<Self>) {
        let mut interval = tokio::time::interval(Duration::from_secs(120));
        loop {
            interval.tick().await;
            for (label, resolver) in &self.doh_resolvers {
                let ok = tokio::time::timeout(Duration::from_secs(3), resolver.lookup_ip("cloudflare.com"))
                    .await.is_ok();
                self.doh_health.insert(label.clone(), ok);
            }
        }
    }

    pub fn cleanup_cache(&self) {
        let now = Instant::now();
        self.cache.retain(|_, (_, expiry)| *expiry > now);
    }
}
```

---

## Часть 7. Интеграция DNS-перехвата и Fake-IP-трафика в основной цикл

```rust
/// Вызывается для UDP-пакетов с dst_port == 53.
async fn process_dns_query(&self, captured: &mut CapturedPacket) -> anyhow::Result<PacketDecision> {
    match self.dns_proxy.handle_dns_query(&captured.data).await {
        Some(dns_response_packet) => {
            let mut addr = captured.addr.clone();
            addr.set_outbound(false);
            let _ = self.packet_engine.inject_via_divert(&dns_response_packet, &addr);
            self.stats.dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(PacketDecision::Drop) // подавляем оригинальный запрос, клиент получил наш ответ
        }
        None => Ok(PacketDecision::Forward), // DNS proxy не смог обработать — форвардим как есть
    }
}

/// Вызывается для TCP/UDP-пакетов, чей dst_ip находится в диапазоне Fake IP
/// (198.18.0.0/15). Переиспользует ТОТ ЖЕ транспорт, что и обычный SOCKS5-редирект
/// (Часть 4) — единственная разница в том, откуда взялся домен (обратный lookup
/// по Fake IP вместо прямой проверки DomainBlocklist).
fn process_fake_ip_traffic(
    &self,
    captured: &mut CapturedPacket,
    fake_ip: &Ipv4Addr,
) -> anyhow::Result<PacketDecision> {
    let domain = match self.fake_ip.lookup(fake_ip) {
        Some(d) => d,
        None => return Ok(PacketDecision::Forward),
    };

    let ip_hdr = crate::desync::parse_ip_header(&captured.data)
        .ok_or_else(|| anyhow::anyhow!("invalid ip header"))?;

    match ip_hdr.protocol().0 {
        6 => {
            let tcp = crate::desync::parse_tcp_packet(&captured.data[ip_hdr.header_len()..])
                .ok_or_else(|| anyhow::anyhow!("invalid tcp header"))?;
            let is_syn = (tcp.flags & 0x02) != 0;
            let is_ack = (tcp.flags & 0x10) != 0;
            if is_syn && !is_ack {
                return self.process_socks5_redirect(
                    captured, tcp.src_port, IpAddr::V4(*fake_ip), tcp.dst_port, Some(domain),
                );
            }
            // не-SYN пакеты к Fake IP после установления редиректа больше не
            // приходят на этот путь — как только SYN переписан на 127.0.0.1,
            // всё соединение целиком проходит через loopback (Часть 4).
            Ok(PacketDecision::Forward)
        }
        17 => {
            // QUIC к Fake IP — дропаем, форсируем откат клиента на TCP (где
            // работает описанный выше SOCKS5-редирект).
            debug!("FakeIP: dropping QUIC to {fake_ip} (domain='{domain}') — forcing TCP fallback");
            self.stats.dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(PacketDecision::Drop)
        }
        _ => Ok(PacketDecision::Forward),
    }
}
```

**Финальная точка диспетчеризации** (единое место, где сходятся все ветки — заменяет
существующий `process_socks5_fallback`-дроп):

```rust
async fn process_one_sync_dispatch(&self, captured: &mut CapturedPacket) -> anyhow::Result<PacketDecision> {
    let ip_hdr = match crate::desync::parse_ip_header(&captured.data) {
        Some(h) => h,
        None => return Ok(PacketDecision::Forward),
    };

    // 1. DNS (UDP:53) — всегда первым, до любой другой классификации
    if ip_hdr.protocol().0 == 17 {
        if let Some(udp) = crate::desync::parse_udp_header(&captured.data[ip_hdr.header_len()..]) {
            if udp.dst_port == 53 {
                return self.process_dns_query(captured).await;
            }
        }
    }

    // 2. Обратный путь от собственного SocksRedirector (loopback, src_port==REDIRECTOR_PORT)
    if ip_hdr.protocol().0 == 6 {
        if let Some(tcp) = crate::desync::parse_tcp_packet(&captured.data[ip_hdr.header_len()..]) {
            if tcp.src_port == REDIRECTOR_PORT {
                return self.process_redirect_return_path(captured, tcp.dst_port);
            }

            // 3. Трафик к Fake IP (198.18.0.0/15)
            if let IpAddr::V4(dst) = ip_hdr.dst() {
                if self.fake_ip.is_fake_ip(&dst) {
                    return self.process_fake_ip_traffic(captured, &dst);
                }
            }

            // 4. Защита хендшейка к самим Opera-прокси — известные IP получают
            // ту же desync-обработку, что обычный generic TCP (см. Часть 9),
            // ДО generic-TCP fallback, иначе никогда не сработает.
            let is_syn = (tcp.flags & 0x02) != 0 && (tcp.flags & 0x10) == 0;
            if is_syn && self.proxy_pool.is_known_ip(&ip_hdr.dst()) {
                return self.process_generic_tcp_desync(captured, &tcp);
            }

            // 5. Обычный SOCKS5-редирект по домену/IP из DomainBlocklist (SNI/Host уже
            // извлечён выше по стеку классификации TLS/HTTP — здесь предполагается,
            // что домен передан вызывающим кодом; для краткости взят из fake_ip lookup
            // либо из отдельной SNI-классификации, которая уже существует в проекте)
            if is_syn {
                let domain_guess = self.sni_cache.get(&(ip_hdr.dst(), tcp.dst_port));
                let should_tunnel = domain_guess.as_ref()
                    .map(|d| self.domain_blocklist.should_tunnel(d))
                    .unwrap_or(false);
                if should_tunnel {
                    return self.process_socks5_redirect(
                        captured, tcp.src_port, ip_hdr.dst(), tcp.dst_port, domain_guess,
                    );
                }
            }
        }
    }

    Ok(PacketDecision::Forward)
}
```

---

## Часть 8. Auto-probe: автоматическое пополнение списка геоблокированных доменов

```rust
/// Активная проверка доступности прямого соединения. Обнаруживает только
/// СЕТЕВУЮ недоступность (TCP/TLS не устанавливается) — НЕ детектирует
/// контентную гео-блокировку внутри HTTPS (Netflix отдаёт 403 после успешного
/// TLS-хендшейка), поскольку это требует расшифровки трафика (MITM), чего этот
/// план сознательно не делает — MITM собственного трафика пользователя добавляет
/// отдельный класс рисков (доверие/сертификаты), которого стоит избегать здесь.
pub async fn auto_probe_and_tune(
    blocklist: Arc<crate::proxy::types::DomainBlocklist>,
    candidate_domains: &[String],
) {
    tracing::info!("auto-probe: {} candidate domains", candidate_domains.len());
    for domain in candidate_domains {
        let addr = format!("{domain}:443");
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(&addr),
        ).await;

        let blocked = match result {
            Ok(Ok(_)) => false,           // TCP connect удался — считаем доступным
            Ok(Err(_)) => true,           // явный connection refused/reset
            Err(_) => true,               // timeout — тоже считаем блокировкой
        };

        if blocked {
            tracing::info!("'{domain}' unreachable directly, routing via Opera proxy");
            blocklist.mark_probed_blocked(domain);
        }
    }
}
```

Запускается при старте пайплайна по списку из `DomainBlocklist` пользовательских доменов
(`proxy_domains`/`proxy_domains_file`) плюс небольшой built-in preset (Netflix/Spotify/Telegram),
и периодически (например раз в час) повторно — держать preset маленьким: каждая проверка это
реальное сетевое соединение при старте.

---

## Часть 9. Защита хендшейка к Opera-прокси десинк-техниками

Переиспользует уже существующий в движке механизм TCP-десинка (mss/window clamp и другие
техники, применяемые к generic TCP-трафику) — единственное новое здесь: классификация по
известным IP-адресам прокси, показанная выше в диспетчере (Часть 7, пункт 4). Функция
`process_generic_tcp_desync` — существующая в проекте функция обработки generic TCP; новых
структур для неё не требуется, только новая точка вызова из диспетчера.

---

## Часть 10. Резервный DNS через SOCKS5-туннель

```rust
/// Резервный резолвинг через уже реализованный SOCKS5-клиент (Часть 3), когда
/// все DoH-резолверы (Часть 6) недоступны. DNS-over-TCP поверх SOCKS5 CONNECT
/// (RFC 1035 §4.2.2 — 2-байтный префикс длины).
pub async fn resolve_via_socks5_dns(
    proxy_pool: &Arc<crate::proxy::types::OperaProxyPool>,
    dns_server_ip: std::net::IpAddr,
    query: &[u8],
) -> anyhow::Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let proxy_addr = proxy_pool.select_best()
        .ok_or_else(|| anyhow::anyhow!("no healthy opera proxy for dns fallback"))?;

    let mut stream = tokio::net::TcpStream::connect(proxy_addr).await?;
    crate::proxy::socks5_client::socks5_handshake_noauth(&mut stream).await?;
    crate::proxy::socks5_client::socks5_connect(&mut stream, &dns_server_ip.to_string(), 53).await?;

    let len_prefix = (query.len() as u16).to_be_bytes();
    stream.write_all(&len_prefix).await?;
    stream.write_all(query).await?;

    let mut resp_len_buf = [0u8; 2];
    stream.read_exact(&mut resp_len_buf).await?;
    let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await?;
    Ok(resp)
}
```

Встраивается в `resolve_via_doh` (Часть 6) как последний шаг перед возвратом `None`: если ни
один DoH-резолвер не ответил — пробуем `resolve_via_socks5_dns` к `1.1.1.1:53` через уже живой
Opera-прокси; если и это не удалось — только тогда `None` (запрос форвардится в интернет как
есть, деградированно, но без разрыва соединения).

---

## Часть 11. EDNS(0) Padding для защиты censored_domains-запросов от traffic analysis

Длина зашифрованного DoH-пакета коррелирует с длиной домена в запросе — DPI может это
использовать для анализа трафика даже без расшифровки. Применяется только к запросам режима
`SecureDoh` (censored_domains) — остальные режимы (system DNS, не приватные) в этом не нуждаются.

```rust
/// EDNS(0) Padding (RFC 7830) — добавляет OPT-псевдозапись с опцией padding
/// (code 12), выравнивая размер сообщения до ближайших 128 байт (рекомендация
/// RFC 8467 для DoH). Резолвер верхнего уровня (Часть 6) не даёт прямого
/// контроля над сырыми байтами сообщения — этот путь строит и шлёт DNS-запрос
/// вручную, в обход resolver-абстракции, только для censored_domains-трафика.
fn build_padded_dns_query(domain: &str, qtype: u16, txid: u16) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&txid.to_be_bytes());
    msg.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    msg.extend_from_slice(&1u16.to_be_bytes());      // QDCOUNT=1
    msg.extend_from_slice(&[0, 0, 0, 0, 0, 0]);      // ANCOUNT/NSCOUNT/ARCOUNT=0

    for label in domain.split('.') {
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0x00);
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN

    let opt_fixed_len = 1 + 2 + 2 + 4 + 2;
    let option_header_len = 4;
    let target_total = (msg.len() + opt_fixed_len + option_header_len).div_ceil(128) * 128;
    let padding_len = target_total - msg.len() - opt_fixed_len - option_header_len;

    msg.push(0x00);
    msg.extend_from_slice(&41u16.to_be_bytes());   // TYPE = OPT
    msg.extend_from_slice(&4096u16.to_be_bytes()); // UDP payload size
    msg.extend_from_slice(&[0, 0, 0, 0]);
    let rdata_len = (option_header_len + padding_len) as u16;
    msg.extend_from_slice(&rdata_len.to_be_bytes());
    msg.extend_from_slice(&12u16.to_be_bytes());   // OPTION-CODE = 12 (Padding, RFC 7830)
    msg.extend_from_slice(&(padding_len as u16).to_be_bytes());
    msg.extend(std::iter::repeat(0u8).take(padding_len));

    let arcount = 1u16;
    msg[10..12].copy_from_slice(&arcount.to_be_bytes());
    msg
}

/// RFC 8484 — POST сырого DNS-сообщения на DoH endpoint.
async fn send_doh_padded(client: &reqwest::Client, doh_url: &str, query: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    let resp = client.post(doh_url)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(query)
        .send().await?
        .error_for_status()?;
    Ok(resp.bytes().await?.to_vec())
}
```

**ECH для самого DoH-хендшейка (осознанно оставлено на уровне архитектуры, не финального
кода):** защита от определения самого факта "это DoH-хендшейк" по открытому SNI требует
поддержки Encrypted Client Hello в используемой версии `rustls`, а её API для ECH менялся между
версиями библиотеки. Прежде чем кодить — свериться с docs.rs на закреплённую в `Cargo.toml`
версию `rustls`, есть ли там стабильный `EchConfig`. Если на момент реализации ECH окажется
нестабильным — не блокер: padding (эта часть) и сам TLS 1.3 уже дают частичную защиту, ECH
можно добавить отдельной задачей позже без пересмотра остального.

---

## Часть 12. Конфигурация — полный TOML

**Файл:** `config.toml.example`

```toml
[proxy]
enabled = true
opera_proxies = [
    "185.167.238.201:1080",
    "185.167.238.202:1080",
    "185.167.238.203:1080",
    "185.167.238.204:1080",
    "185.167.238.205:1080",
]
# Ручной override прямо в TOML (необязательно, если используется файл ниже)
proxy_domains = []
# Основной способ — отдельный файл, удобно редактировать/пополнять без пересборки
proxy_domains_file = "blocked_domains.txt"
# Автоматически пробовать определять недоступные напрямую домены (уровень "сеть
# недоступна", НЕ "контент гео-заблокирован" — детектится только сетевой сбой)
auto_probe = true
max_connections = 1000
idle_timeout_secs = 300

[dns_proxy]
enabled = true
adblock_enabled = false
ttl = 60

doh_servers = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
]

# Домены с известной/заподозренной DNS-цензурой — ТОЛЬКО они идут через DoH.
# Всё остальное резолвится через системный DNS (лучший CDN-роутинг за счёт ECS).
censored_domains = []
censored_domains_file = "censored_domains.txt"

adblock_domains = [
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "google-analytics.com",
    "adnxs.com",
]
```

---

## Часть 13. Порядок реализации и критерии готовности

**Порядок (обязательный, см. также Часть 0):**
1. PoC WinDivert loopback-редирект (изолированно, вне основного движка).
2. Части 1-3 (структуры данных, checksum-rewrite, SOCKS5-клиент, redirector) — тестируются
   без WinDivert через ручной `TcpStream::connect` на локальный порт.
3. Часть 4 (WinDivert SYN/return-path rewrite) — по результатам PoC.
4. Часть 5 (список доменов) + Часть 6-7 (DNS proxy + Fake IP) — независимая пара веток,
   можно разрабатывать параллельно с Частью 4.
5. Части 8-11 (auto-probe, защита хендшейка Opera, DNS-fallback, EDNS padding) — после того,
   как базовый мост стабилен на 1-2 доменах в ручном тестировании.

**Критерии готовности:**
1. `RedirectTable`, `OperaProxyPool`, `DomainBlocklist`, `FakeIpManager` — реализованы и
   покрыты unit-тестами (insert/get/remove, health-check переключение healthy/unhealthy,
   assign_fake_ip идемпотентность на повторный вызов для одного домена).
2. `rewrite_dst_addr`/`rewrite_src_addr` — тест на реальных захваченных SYN-пакетах: после
   rewrite TCP checksum валиден (проверяется тем же `pnet_packet` парсером на чтение).
3. `SocksRedirector` — интеграционный тест: локальный TCP echo-сервер вместо реального Opera,
   проверка что данные проходят bridge в обе стороны.
4. `DnsProxyEngine::classify_domain` — тесты на все 4 режима + AAAA-заглушку для FakeIp/AdBlock.
5. `process_one_sync_dispatch` — покрывает все 5 веток (DNS, return-path, FakeIP, Opera-IP
   защита, обычный redirect) в правильном порядке (return-path и Opera-IP проверка — раньше
   generic fallback).
6. Fail-open проверен явно: если `OperaProxyPool::select_best()` возвращает `None` —
   `process_socks5_redirect` возвращает `Forward`, не `Drop`.
7. Конфиг парсится из `config.toml.example` без паники на дефолтных значениях.

## Верификация после реализации

```bash
grep -n "struct RedirectTable\|struct OperaProxyPool\|struct DomainBlocklist\|struct FakeIpManager" core/src/proxy/types.rs
grep -n "fn rewrite_dst_addr\|fn rewrite_src_addr\|fn udp_checksum" core/src/proxy/rewrite.rs
grep -n "fn socks5_handshake_noauth\|fn socks5_connect" core/src/proxy/socks5_client.rs
grep -n "struct SocksRedirector\|fn bind_and_run" core/src/proxy/redirector.rs
grep -n "struct DnsProxyEngine\|fn classify_domain\|fn handle_dns_query" core/src/dns/dns_proxy.rs
grep -n "fn process_one_sync_dispatch\|fn process_socks5_redirect\|fn process_fake_ip_traffic" core/src/engine/mod.rs
grep -n "hickory-resolver\|trust-dns-resolver" core/Cargo.toml
cargo test -p freedpi-core --lib proxy:: --nocapture
cargo test -p freedpi-core --lib dns:: --nocapture
```
