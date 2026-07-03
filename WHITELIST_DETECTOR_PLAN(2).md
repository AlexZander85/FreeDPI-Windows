# Детектор режима белых списков (Whitelist Drop-All Detection)

Самодостаточный документ — не требует чтения других файлов.

## Идея

Обычная точечная цензура (блокировка конкретных доменов/VPN) и drop-all whitelist-режим
("чебурнет") различаются статистически, а не по одному признаку. В whitelist-режиме
ТСПУ пропускает только заранее одобренные IP+SNI (порядка 63 тысяч IP из 46 миллионов),
всё остальное — дропается на 2-м хопе с инжектированным RST, независимо от того,
политический это домен, коммерческий или вообще случайный.

Детектор использует два независимых сигнала:

1. **Массовая сигнатура:** набор "нейтральных" доменов-канареек (не политика, не VPN,
   не порно — то, что обычная точечная цензура не трогает индивидуально), которые тем не
   менее точно не входят в куцый whitelist. Если большинство из них разом получает
   одинаковую RST/timeout-сигнатуру — это системный drop-all, а не точечная блокировка.
2. **RST-фингерпринтинг:** RST, инжектированный ТСПУ на 2-м хопе, приходит **быстрее**
   и с **другим TTL**, чем настоящий RST от реального удалённого сервера (потому что он
   генерируется ближним устройством, а не конечным хостом). Это стандартная техника,
   которую используют исследовательские инструменты вроде OONI/Censored Planet для
   детекции инжектированных RST.

---

## Часть 1. Структуры данных

**Файл:** `core/src/detector/types.rs` (новый)

```rust
use std::net::IpAddr;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};

/// Один домен-канарейка с ролью в детекции.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryDomain {
    pub domain: String,
    pub role: CanaryRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanaryRole {
    /// Точно входит в белый список (Госуслуги, VK, Sberbank и т.п.) —
    /// должен проходить ВСЕГДА, даже при активном drop-all. Если этот домен
    /// тоже не проходит — значит либо интернета нет вообще, либо список устарел
    /// (whitelist меняется в реальном времени, нужно обновлять периодически).
    Positive,
    /// Заведомо НЕ входит в белый список, но и не является целью обычной точечной
    /// цензуры (не VPN-сервис, не политика/СМИ-иноагент, не порно) — небольшие
    /// легитимные международные сайты/API, которые при обычной блокировке работали бы
    /// нормально. Если ОНИ массово не проходят — это системный сигнал, не точечный.
    Negative,
}

/// Результат одного пробного соединения.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub domain: String,
    pub ip: IpAddr,
    pub outcome: ProbeOutcome,
    pub rtt: Option<Duration>,
    pub observed_ttl: Option<u8>,
    pub timestamp: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// TCP-соединение и TLS-хендшейк с ожидаемым SNI прошли полностью.
    Success,
    /// Получен RST до завершения хендшейка.
    ResetByPeer,
    /// Нет ответа за отведённое время — ни SYN-ACK, ни RST (L3 blackhole
    /// или сервер действительно недоступен по независимым причинам).
    Timeout,
    /// Соединение установилось, но TLS-хендшейк не завершился штатно
    /// (не RST, а обрыв/ошибка на уровне TLS — отдельная категория,
    /// т.к. ТСПУ обычно работает через RST, а не через порчу TLS-данных).
    TlsFailure,
}

/// Итоговое состояние сети, выводимое из агрегации проб. Consumed остальным
/// движком (дальше — Часть 4).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WhitelistState {
    /// Ещё не набрали достаточно данных.
    Unknown,
    /// Обычный интернет, drop-all не обнаружен.
    Inactive,
    /// Обнаружен drop-all whitelist-режим, confidence — доля негативных
    /// канареек, давших RST/timeout-сигнатуру (0.0-1.0).
    Active { confidence: f32, l7_sni_based: bool },
}
```

---

## Часть 2. Список канареек — конфигурация

**Файл:** `core/src/detector/canary_list.rs` (новый)

Список нельзя жёстко зашивать надолго — состав whitelist меняется в реальном времени, а
подходящие "нейтральные" домены для негативного контроля со временем тоже могут случайно
попасть под точечную блокировку (тогда они перестанут быть чистым сигналом). Поэтому список
конфигурируемый и живёт в отдельном файле — тем же способом, что и остальные списки доменов
в проекте (парсинг строк, `#`-комментарии, без внешних зависимостей).

```rust
use std::path::Path;
use anyhow::{Context, Result};
use super::types::{CanaryDomain, CanaryRole};

pub fn load_canary_list(path: &Path) -> Result<Vec<CanaryDomain>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read canary list: {}", path.display()))?;

    let mut canaries = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        let mut parts = line.splitn(2, ',');
        let domain = parts.next().unwrap_or("").trim().to_string();
        let role_str = parts.next().unwrap_or("").trim();
        let role = match role_str {
            "positive" => CanaryRole::Positive,
            "negative" => CanaryRole::Negative,
            other => {
                tracing::warn!("unknown canary role '{other}' for {domain}, skipping");
                continue;
            }
        };
        if !domain.is_empty() {
            canaries.push(CanaryDomain { domain, role });
        }
    }
    Ok(canaries)
}
```

**Файл:** `canary_domains.txt.example`

```
# Формат: домен,роль (positive|negative)
#
# POSITIVE — точно в белом списке, должны проходить всегда при drop-all.
# Список Минцифры публично не раскрывается целиком, но известные крупные
# гос./банковские/социальные сервисы регулярно в него входят — сверяться
# с актуальными агрегированными списками (например, community-датасетами
# сканирования whitelist) и обновлять этот файл периодически, статика
# протухает.
gosuslugi.ru,positive
vk.com,positive
sberbank.ru,positive

# NEGATIVE — заведомо не в белом списке, но и не мишень точечной цензуры
# (не VPN/прокси-сервис, не заблокированные СМИ, не порно). Подбирать
# небольшие иностранные корпоративные/технические сайты без политической
# окраски — от этого зависит чистота сигнала. НЕ используй сюда VPN-провайдеров
# или известные обходные инструменты — их блокируют точечно и они дадут
# ложное срабатывание "похоже на drop-all", когда на деле это обычная
# точечная блокировка конкретно VPN-категории.
example.com,negative
```

---

## Часть 3. Активный пробинг с RST-фингерпринтингом

**Ключевая техническая деталь:** обычный `TcpStream::connect()` из tokio/std не даёт доступа
к TTL полученного RST-пакета — эта информация теряется на уровне сокет-API ОС. Чтобы получить
TTL и точный RTT именно RST-пакета (не просто факт ошибки соединения), нужно наблюдать за
пакетами на уровне WinDivert — той же инфраструктуры перехвата, что уже используется в проекте
для десинк-техник, только в режиме пассивного наблюдения (не модификации) за откликами на
собственные пробные SYN.

**Файл:** `core/src/detector/prober.rs` (новый)

```rust
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use dashmap::DashMap;
use tokio::sync::oneshot;
use tracing::{debug, warn};

use super::types::{ProbeOutcome, ProbeResult};

/// Ожидающие пробы: src_port нашего исходящего SYN → канал для доставки
/// результата, когда WinDivert-наблюдатель увидит ответ (RST/SYN-ACK) или
/// когда истечёт таймаут.
pub struct ActiveProbeTable {
    pending: DashMap<u16, (oneshot::Sender<(ProbeOutcome, Option<u8>)>, Instant)>,
}

impl ActiveProbeTable {
    pub fn new() -> Self {
        Self { pending: DashMap::new() }
    }

    /// Регистрирует ожидание ответа на пробный SYN с данным src_port.
    pub fn register(&self, src_port: u16) -> oneshot::Receiver<(ProbeOutcome, Option<u8>)> {
        let (tx, rx) = oneshot::channel();
        self.pending.insert(src_port, (tx, Instant::now()));
        rx
    }

    /// Вызывается из пассивного WinDivert-наблюдателя (Часть 3.1) при получении
    /// RST или SYN-ACK, адресованного одному из наших пробных src_port.
    pub fn deliver(&self, dst_port_of_response: u16, outcome: ProbeOutcome, ttl: Option<u8>) {
        if let Some((_, (tx, _))) = self.pending.remove(&dst_port_of_response) {
            let _ = tx.send((outcome, ttl));
        }
    }

    /// Периодическая уборка проб, не получивших ответа (Timeout будет
    /// обработан отдельно вызывающим кодом по истечении await-таймаута —
    /// эта функция просто чистит "протухшие" записи, которые никто не забрал).
    pub fn sweep_stale(&self, max_age: Duration) {
        self.pending.retain(|_, (_, ts)| ts.elapsed() < max_age);
    }
}
```

### 3.1 Пассивный наблюдатель в существующем цикле WinDivert

Встраивается как ветка НАБЛЮДЕНИЯ (не изменяет пакет, только читает и форвардит как есть) —
добавляется в диспетчер до остальной классификации:

```rust
use std::net::IpAddr;

/// Вызывается для каждого входящего TCP-пакета (RST или SYN-ACK), чей dst_port
/// совпадает с одним из наших активных проб. Возвращает Forward всегда —
/// это чисто наблюдательная ветка, пакет не модифицируется.
fn observe_probe_response(
    &self,
    captured: &CapturedPacket,
    ip_ttl: u8,
    tcp_flags: u8,
    tcp_dst_port: u16,
) -> anyhow::Result<()> {
    const RST: u8 = 0x04;
    const SYN: u8 = 0x02;
    const ACK: u8 = 0x10;

    if (tcp_flags & RST) != 0 {
        self.probe_table.deliver(tcp_dst_port, ProbeOutcome::ResetByPeer, Some(ip_ttl));
    } else if (tcp_flags & (SYN | ACK)) == (SYN | ACK) {
        self.probe_table.deliver(tcp_dst_port, ProbeOutcome::Success, Some(ip_ttl));
    }
    Ok(())
}
```

Точка вызова — в существующем диспетчере, для входящих (не исходящих) TCP-пакетов, отдельной
веткой перед остальной обработкой:

```rust
// В process_one_sync_dispatch, для inbound-направления (addr.outbound == false):
if ip_hdr.protocol().0 == 6 {
    if let Some(tcp) = crate::desync::parse_tcp_packet(&captured.data[ip_hdr.header_len()..]) {
        if self.probe_table.is_pending(tcp.dst_port) {
            self.observe_probe_response(captured, ip_hdr.ttl(), tcp.flags, tcp.dst_port)?;
        }
    }
}
```

### 3.2 Отправка пробного SYN и измерение RTT/TTL

```rust
use std::time::Duration;

/// RTT и TTL "чистого" RST/timeout для калибровки — берём известно закрытый
/// порт на локальном шлюзе (первый хоп), чтобы иметь baseline "как быстро
/// отвечает ближайшее устройство сети", независимо от того, ТСПУ это или нет.
/// Если TTL/RTT инжектированного RST от "дальнего" домена совпадает по
/// характеру с этим локальным baseline — это сильный сигнал, что RST пришёл
/// не от реального удалённого сервера, а от устройства где-то рядом (ТСПУ).
async fn calibrate_local_rst_baseline(&self, gateway_ip: IpAddr) -> Option<(Duration, u8)> {
    let start = Instant::now();
    // Порт, которого почти наверняка нет на шлюзе — быстрый закономерный RST.
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect((gateway_ip, 1)),
    ).await;
    match result {
        Ok(Err(_)) => Some((start.elapsed(), 1)), // TTL locahost-gateway обычно 1, не показателен как есть — используется как RTT-эталон
        _ => None,
    }
}

/// Одна проба: реальный TCP SYN к домену (обычным системным сокетом — ОС сама
/// сформирует и отправит SYN, а наш WinDivert-наблюдатель (3.1) увидит ответ
/// и доставит его через ActiveProbeTable, не вмешиваясь в сам процесс connect()).
pub async fn probe_domain(
    &self,
    domain: &str,
    resolved_ip: IpAddr,
) -> ProbeResult {
    let start = Instant::now();

    // Регистрируем src_port ДО фактического connect — используем bind на
    // конкретный локальный порт, чтобы знать заранее, что искать в ответах.
    let socket = match tokio::net::TcpSocket::new_v4() {
        Ok(s) => s,
        Err(e) => {
            warn!("probe socket creation failed for {domain}: {e}");
            return ProbeResult {
                domain: domain.to_string(), ip: resolved_ip,
                outcome: ProbeOutcome::Timeout, rtt: None, observed_ttl: None,
                timestamp: start,
            };
        }
    };
    let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let _ = socket.bind(local_addr);
    let src_port = socket.local_addr().map(|a| a.port()).unwrap_or(0);

    let rx = self.probe_table.register(src_port);

    let connect_fut = socket.connect(SocketAddr::new(resolved_ip, 443));
    let (connect_outcome, ttl_from_observer) = tokio::select! {
        result = connect_fut => {
            match result {
                Ok(_) => (ProbeOutcome::Success, None),
                Err(_) => (ProbeOutcome::ResetByPeer, None), // ОС уже интерпретировала как ошибку — TTL узнаем из observer ниже, если успеет
            }
        }
        observed = rx => {
            match observed {
                Ok((outcome, ttl)) => (outcome, ttl),
                Err(_) => (ProbeOutcome::Timeout, None),
            }
        }
        _ = tokio::time::sleep(Duration::from_secs(5)) => (ProbeOutcome::Timeout, None),
    };

    ProbeResult {
        domain: domain.to_string(),
        ip: resolved_ip,
        outcome: connect_outcome,
        rtt: Some(start.elapsed()),
        observed_ttl: ttl_from_observer,
        timestamp: start,
    }
}
```

**Оговорка по надёжности этой части:** гонка между стандартным `connect()` (который сам
интерпретирует RST как ошибку на уровне ОС) и наблюдателем WinDivert (который видит сырой
пакет с TTL) может отдать результат до того, как наблюдатель успеет доставить TTL. Для
надёжного TTL нужно тестировать на реальном трафике — возможно, придётся отказаться от
`tokio::net::TcpSocket::connect()` и вместо этого formировать SYN вручную через уже
существующий в проекте код сборки пакетов, чтобы полностью контролировать тайминг и не
полагаться на гонку между двумя независимыми путями получения одного и того же события.
Это стоит проверить эмпирически на первой итерации, прежде чем полагаться на точность TTL
как основной сигнал (RTT и массовая сигнатура по канарейкам — более надёжный резервный канал,
даже если TTL окажется недостижим без более глубокой переделки).

### 3.3 Второй этап: TLS ClientHello с SNI (критично — без этого детектор слеп к L7-блокировке)

**Важный пробел в первой версии плана:** голый TCP-коннект к порту 443 проверяет только
L3 (IP) фильтрацию. Если блокировка идёт по SNI на уже открытом IP (характерная ситуация для
доменов на shared/CDN-адресах — IP сам не заблокирован, потому что на нём висят и другие,
разрешённые домены, а режется именно ClientHello с конкретным SNI) — TCP SYN-ACK пройдёт
штатно, `probe_domain` вернёт `Success`, и детектор ошибочно решит, что домен не заблокирован.
Это системная слепая зона именно там, где whitelist работает через L7, а не L3. Нужен
второй этап: после успешного TCP-коннекта отправить минимальный TLS ClientHello с целевым SNI
и посмотреть на реакцию — ServerHello (не заблокировано) или RST/разрыв соединения
(заблокировано на уровне SNI).

```rust
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Собирает синтаксически валидный, но минимальный TLS ClientHello с SNI-
/// расширением. Не проходит полный TLS-стек — задача не установить настоящую
/// TLS-сессию, а спровоцировать реакцию DPI, которая парсит SNI из этого же
/// байтового потока. Реальный сервер (если не заблокирован) ответит ServerHello
/// на этот же запрос — этого достаточно, полное завершение хендшейка не нужно.
fn build_minimal_client_hello(sni: &str) -> Vec<u8> {
    let mut random = [0u8; 32];
    for (i, b) in random.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(37).wrapping_add(11);
    }

    let mut hello_body = Vec::new();
    hello_body.extend_from_slice(&[0x03, 0x03]); // legacy_version = TLS 1.2
    hello_body.extend_from_slice(&random);
    hello_body.push(0x00); // session_id length = 0

    let ciphers: &[u16] = &[0x1301, 0x1302, 0x1303, 0xc02f, 0xc030];
    hello_body.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
    for c in ciphers { hello_body.extend_from_slice(&c.to_be_bytes()); }

    hello_body.push(0x01); // compression methods length
    hello_body.push(0x00); // null compression

    let mut extensions = Vec::new();

    // SNI (server_name, extension type 0x0000)
    let sni_bytes = sni.as_bytes();
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&((sni_bytes.len() + 3) as u16).to_be_bytes());
    sni_ext.push(0x00); // name_type = host_name
    sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(sni_bytes);
    extensions.extend_from_slice(&0x0000u16.to_be_bytes());
    extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_ext);

    // supported_versions = TLS 1.3 — многие современные DPI-парсеры и серверы
    // ожидают это расширение для корректного разбора остальной ClientHello.
    let sv_ext: &[u8] = &[0x03, 0x04];
    extensions.extend_from_slice(&0x002bu16.to_be_bytes());
    extensions.extend_from_slice(&((1 + sv_ext.len()) as u16).to_be_bytes());
    extensions.push(sv_ext.len() as u8);
    extensions.extend_from_slice(sv_ext);

    hello_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello_body.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(0x01); // ClientHello
    let len = hello_body.len() as u32;
    handshake.extend_from_slice(&len.to_be_bytes()[1..]); // 3-байтная длина
    handshake.extend_from_slice(&hello_body);

    let mut record = Vec::new();
    record.push(0x16); // Content Type = Handshake
    record.extend_from_slice(&[0x03, 0x01]); // record version = TLS 1.0 (совместимость)
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// Второй этап пробы — вызывается ТОЛЬКО если TCP-коннект (Часть 3.2) успешен.
async fn probe_tls_sni(stream: &mut tokio::net::TcpStream, domain: &str) -> ProbeOutcome {
    let hello = build_minimal_client_hello(domain);
    if stream.write_all(&hello).await.is_err() {
        return ProbeOutcome::ResetByPeer;
    }

    let mut buf = [0u8; 5]; // TLS record header достаточно, чтобы отличить ServerHello от Alert
    match tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut buf)).await {
        Ok(Ok(_)) => {
            if buf[0] == 0x16 { ProbeOutcome::Success }      // Handshake (ServerHello)
            else { ProbeOutcome::TlsFailure }                 // Alert или мусор
        }
        Ok(Err(_)) => ProbeOutcome::ResetByPeer, // соединение разорвано в момент чтения — RST после ClientHello
        Err(_) => ProbeOutcome::Timeout,
    }
}
```

`probe_domain` (Часть 3.2) обновляется: при `ProbeOutcome::Success` на TCP-этапе — не возвращать
результат сразу, а передать открытый `TcpStream` в `probe_tls_sni` и вернуть уже ЕГО исход как
финальный. `ProbeOutcome::TlsFailure` из enum типов (Часть 1) был объявлен с самого начала, но
не использовался нигде в логике агрегации — это и есть тот пробел, который нужно закрыть в
Части 4 (см. ниже).

---

## Часть 4. Агрегация и интеграция в основной пайплайн

**Файл:** `core/src/detector/detector.rs` (новый)

```rust
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;
use tracing::info;

use super::types::{CanaryDomain, CanaryRole, ProbeOutcome, WhitelistState};
use super::prober::ActiveProbeTable;

/// Атомарно читаемое состояние — 0=Unknown, 1=Inactive, 2=Active.
/// Confidence и l7_sni_based хранятся отдельно (не атомарно, под RwLock),
/// т.к. это составное значение, читается редко относительно частоты обновления.
pub struct WhitelistDetector {
    canaries: Vec<CanaryDomain>,
    probe_table: Arc<ActiveProbeTable>,
    state_tag: AtomicU8,
    state_detail: parking_lot::RwLock<WhitelistState>,
}

impl WhitelistDetector {
    pub fn new(canaries: Vec<CanaryDomain>, probe_table: Arc<ActiveProbeTable>) -> Self {
        Self {
            canaries,
            probe_table,
            state_tag: AtomicU8::new(0),
            state_detail: parking_lot::RwLock::new(WhitelistState::Unknown),
        }
    }

    pub fn current_state(&self) -> WhitelistState {
        *self.state_detail.read()
    }

    /// Один полный проход по канарейкам + агрегация. Вызывается периодически
    /// фоновым тасков (Часть 4.1) и может быть вызван вручную (например, по
    /// команде пользователя "проверить сейчас" из UI/CLI).
    pub async fn run_detection_pass(&self, resolve_fn: impl Fn(&str) -> Option<std::net::IpAddr>) {
        let mut positive_ok = 0usize;
        let mut positive_total = 0usize;
        let mut negative_blocked = 0usize;
        let mut negative_total = 0usize;
        let mut l7_signal = 0usize; // RST специфически после отправки SNI, не на SYN

        for canary in &self.canaries {
            let Some(ip) = resolve_fn(&canary.domain) else { continue };
            let result = self.probe(&canary.domain, ip).await;

            match canary.role {
                CanaryRole::Positive => {
                    positive_total += 1;
                    if result.outcome == ProbeOutcome::Success { positive_ok += 1; }
                }
                CanaryRole::Negative => {
                    negative_total += 1;
                    if matches!(result.outcome, ProbeOutcome::ResetByPeer | ProbeOutcome::Timeout) {
                        negative_blocked += 1;
                        if result.outcome == ProbeOutcome::ResetByPeer {
                            l7_signal += 1;
                        }
                    }
                }
            }
        }

        let new_state = self.aggregate(positive_ok, positive_total, negative_blocked, negative_total, l7_signal);
        info!("whitelist detection pass: positive={positive_ok}/{positive_total} negative_blocked={negative_blocked}/{negative_total} -> {:?}", new_state);

        *self.state_detail.write() = new_state;
        self.state_tag.store(match new_state {
            WhitelistState::Unknown => 0,
            WhitelistState::Inactive => 1,
            WhitelistState::Active { .. } => 2,
        }, Ordering::Relaxed);
    }

    /// Пороговая логика. Требует данных по обеим ролям — одних негативных
    /// канареек недостаточно (могли легитимно упасть все разом по совпадению,
    /// например реальный сбой сети), а одних позитивных недостаточно (они и так
    /// почти всегда проходят, это не отличает whitelist-режим от обычного интернета).
    fn aggregate(
        &self,
        positive_ok: usize, positive_total: usize,
        negative_blocked: usize, negative_total: usize,
        l7_signal: usize,
    ) -> WhitelistState {
        if positive_total == 0 || negative_total < 3 {
            // Недостаточно канареек для статистически значимого вывода —
            // список слишком мал, нужно требовать минимум перед выводом.
            return WhitelistState::Unknown;
        }

        let positive_rate = positive_ok as f32 / positive_total as f32;
        let negative_block_rate = negative_blocked as f32 / negative_total as f32;

        // Позитивные канарейки почти все должны проходить — иначе либо сети нет
        // вообще (тогда это не "мы под whitelist", а "мы офлайн"), либо список
        // канареек устарел и не годится для вывода.
        if positive_rate < 0.7 {
            return WhitelistState::Unknown;
        }

        if negative_block_rate >= 0.7 {
            WhitelistState::Active {
                confidence: negative_block_rate,
                l7_sni_based: l7_signal as f32 / negative_blocked.max(1) as f32 > 0.5,
            }
        } else if negative_block_rate <= 0.2 {
            WhitelistState::Inactive
        } else {
            // Смешанная картина — похоже на обычную точечную цензуру
            // конкретных сайтов, а не на системный drop-all. Тоже полезный
            // вывод, но не Active — не стоит переключать поведение движка
            // так, будто активен полный whitelist-режим.
            WhitelistState::Inactive
        }
    }

    async fn probe(&self, domain: &str, ip: std::net::IpAddr) -> super::types::ProbeResult {
        // делегирует в Часть 3.2 (prober.rs) — метод probe_domain там
        todo!("вызов self.prober.probe_domain(domain, ip) — связывается при интеграции")
    }
}
```

### 4.1 Фоновый цикл переоценки

Состояние сети не статично — работает неравномерно по регионам, районам и провайдерам,
режим включают/выключают в реальном времени. Разовая проверка при старте бесполезна для
длительной сессии:

```rust
pub async fn detection_loop(detector: Arc<WhitelistDetector>, resolve_fn: impl Fn(&str) -> Option<std::net::IpAddr> + Clone + Send + 'static) {
    // Первая проверка сразу при старте, затем раз в 10 минут — не чаще, чтобы
    // не тратить впустую сетевые попытки и не давать лишний повод для
    // подозрительного паттерна трафика самому детектору.
    let mut interval = tokio::time::interval(Duration::from_secs(600));
    loop {
        interval.tick().await;
        detector.run_detection_pass(resolve_fn.clone()).await;
    }
}
```

### 4.2 Потребление результата остальным движком

```rust
// В диспетчере (или в модуле принятия решений по стратегиям) — проверка
// перед выбором транспорта:
match self.whitelist_detector.current_state() {
    WhitelistState::Active { confidence, l7_sni_based } => {
        tracing::debug!("whitelist drop-all active (confidence={confidence:.2}, l7={l7_sni_based})");
        // Форсировать TCP-only путь, отключить попытки QUIC/WireGuard-based
        // техник на этой сети — они гарантированно срежутся под UDP-фильтрацией.
        self.force_tcp_only.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    WhitelistState::Inactive => {
        self.force_tcp_only.store(false, std::sync::atomic::Ordering::Relaxed);
    }
    WhitelistState::Unknown => {
        // Ничего не меняем — недостаточно данных, чтобы что-то форсировать.
    }
}
```

---

## Часть 5. Ограничения — честно, до реализации

1. **Различает drop-all от точечной цензуры только статистически**, не абсолютно —
   при малом наборе канареек (меньше ~10-15 доменов каждой роли) возможны ложные срабатывания
   в обе стороны. Список нужно расширять и поддерживать в актуальном состоянии, статичный
   маленький список быстро потеряет ценность.
2. **TTL-фингерпринтинг RST — экспериментальная часть**, зависит от того, удастся ли надёжно
   получить сырой TTL ответа раньше, чем ОС интерпретирует его на уровне сокет-API (см. оговорку
   в конце Части 3.2). Если не получится сделать надёжно — детектор всё равно работает на
   массовой сигнатуре (Часть 4), просто без дополнительного L7-уточнения "это именно
   SNI-based блокировка, а не что-то ещё".
3. **Детектор сам создаёт диагностический трафик** — регулярные пробы к внешним доменам с
   локальной машины. Это не должно быть частым (раз в 10 минут — разумный компромисс) и не
   должно использовать чувствительные/подозрительные домены как канарейки (см. пометку в
   `canary_domains.txt.example` про исключение VPN/обходных сервисов из негативного списка —
   это не только про чистоту сигнала, но и снижает шанс, что сама активность детектора
   выглядит подозрительно).
4. Детектор **сообщает о наличии режима, но не решает проблему** — это диагностика для
   остального движка (форсировать TCP-only, не тратить время на заведомо обречённые UDP-пути),
   не замена рабочего fronting-решения, которое всё ещё зависит от результата PoC-теста Opera
   SOCKS5 IP на TLS (обсуждали ранее).

## Верификация

```bash
grep -n "struct WhitelistDetector\|fn run_detection_pass\|fn aggregate" core/src/detector/detector.rs
grep -n "struct ActiveProbeTable\|fn probe_domain" core/src/detector/prober.rs
grep -n "fn load_canary_list" core/src/detector/canary_list.rs
cargo test -p freedpi-core --lib detector:: --nocapture
```
