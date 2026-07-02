# T59 — Реальный SOCKS5-туннель через Opera-прокси (замена drop-заглушки)

## Диагноз (подтверждён)

`Egress::OperaVpn` — вводящее в заблуждение название: это SOCKS5-прокси Opera без аутентификации,
не VPN. Сейчас пайплайн умеет только:

1. `geo.rs` — классифицировать домен как EU (Netflix/Spotify/Telegram/…) → `[OperaProxy, Direct(desync)]`
2. `opera.rs` — health-check 5 хардкоженных SOCKS5 (`185.167.238.201-205:1080`)
3. `process_socks5_fallback` — **дропать** direct TCP SYN, в надежде что у клиента где-то настроен SOCKS5

Реального прокси-клиента (`connect() → SOCKS5 handshake → CONNECT → bridge`) в рантайме нет.
`proxy.rs` (`ProxyFallback`, `FreeProxyPool`) — несвязанные с движком библиотечные структуры.

## Архитектурная развилка

Есть два реалистичных варианта транспарентного проксирования на Windows без смены прокси-настроек
браузера вручную:

| Вариант | Суть | Оценка |
|---|---|---|
| **A. Полный userspace TCP/IP стек поверх WinDivert** | Пересобирать TCP stream из сырых пакетов, самому делать retransmit/ack/window, поверх этого — SOCKS5 | Технически возможно, но это переизобретение TCP-стека внутри DPI-движка. Огромная площадь для багов (задержки, ретрансмиты, окна) — не рекомендую |
| **B. WinDivert address-rewrite redirect → loopback → реальный `tokio` TCP-сокет** | SYN на geo-домен переадресуется на `127.0.0.1:PORT`, ОС сама завершает TCP handshake, локальный listener делает **настоящий** SOCKS5-CONNECT к Opera и `copy_bidirectional` | Стандартный паттерн ("poor man's TPROXY" на Windows — так делают VpnHood, Clash for Windows, sing-box tun-less режимы). Меньше кода, ОС-стек делает всю тяжёлую TCP-работу |

**Рекомендация: вариант B.** Ниже — план именно под него.

### Технический риск №1 (проверено через документацию/issue-трекер WinDivert)

- WinDivert официально поддерживает loopback, но **redirect строго на `127.0.0.1`** — не всегда
  надёжен из-за `IfIdx`/`SubIfIdx` (см. `basil00/WinDivert#82`): часть комбинаций даёт
  `ERROR_INVALID_PARAMETER` или пакет уходит в никуда без ошибки.
- Рабочий обходной путь по опыту сообщества: **редиректор слушает `0.0.0.0:PORT`** (не строго
  loopback-интерфейс), а WinDivert меняет `dst` пакета на `127.0.0.1:PORT`. Комбинация
  "dst=127.0.0.1, listener=0.0.0.0" работает стабильно.
- Обязательно нужен PoC на 20-30 строк (голый WinDivert redirect + `nc -l`) **до** того как
  встраивать это в основной пайплайн — не трать время сразу на интеграцию, если базовый механизм
  не подтверждён у тебя на конкретной версии Windows/WinDivert.

### Технический риск №2 — обратный путь (return path)

`Loopback`-флаг у WinDivert выставляется только на исходящих пакетах (в обе стороны — то, что
для приложения "входящее", ОС всё равно считает `Outbound`, т.к. пакет идёт от себя к себе).
Значит: ответ от локального SOCKS5-редиректора (`127.0.0.1:PORT → app`) тоже придёт в твой
WinDivert-хендл как outbound-loopback пакет, и его нужно поймать и подменить `src` обратно на
`(original_dst_ip, original_dst_port)` — иначе TCP-стек приложения увидит несовпадающий 4-tuple
и просто отбросит SYN-ACK как чужой. Это симметричная операция к прямой подмене, обе стороны
завязаны на одну connection table.

---

## T59.1 — Connection table (src_port → original dst)

**Файл:** `core/src/desync/redirect_table.rs` (новый)

```rust
use dashmap::DashMap;
use std::net::IpAddr;
use std::time::Instant;

/// T59: Таблица соответствия локального src_port → (оригинальный dst, домен, время).
/// Ключ — src_port клиента (уникален в пределах TCP, т.к. ОС не переиспользует
/// его, пока соединение не закрыто/не истёк TIME_WAIT).
#[derive(Clone)]
pub struct RedirectEntry {
    pub orig_dst_ip: IpAddr,
    pub orig_dst_port: u16,
    pub domain: Option<String>,
    pub created_at: Instant,
}

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

    /// T59: периодическая уборка зависших записей (клиент так и не подключился
    /// к редиректору — например SYN потерялся). Вызывать раз в 30-60 сек.
    pub fn sweep_stale(&self, max_age: std::time::Duration) {
        self.map.retain(|_, e| e.created_at.elapsed() < max_age);
    }
}
```

## T59.2 — WinDivert: подмена SYN на пути "туда"

**Файл:** `core/src/engine/redirect.rs` (новый), интеграция в `process_socks5_fallback`

Вместо `Drop` — переписываем адрес пакета и шлём его дальше через `WinDivertSend`:

```rust
const REDIRECTOR_PORT: u16 = 17650; // локальный, не пересекается с desync_port

/// T59: заменяет process_socks5_fallback. Вместо дропа — транспарентный редирект.
fn process_socks5_redirect(
    &self,
    captured: &mut CapturedPacket,
    cp: &ClassifiedPacket,
) -> Result<PacketDecision> {
    let socks5_active = self.is_profile_activated("socks5_fallback");
    if !socks5_active {
        return Ok(PacketDecision::Forward);
    }

    let domain = self.fake_ip.lookup(&cp.dst_ip);
    let should_tunnel = domain.as_ref()
        .map(|d| self.accumulator.should_tunnel(d))
        .unwrap_or(false);

    if !should_tunnel {
        return Ok(PacketDecision::Forward);
    }

    // Регистрируем оригинальный адрес назначения ДО подмены
    self.redirect_table.insert(cp.src_port, RedirectEntry {
        orig_dst_ip: cp.dst_ip,
        orig_dst_port: cp.dst_port,
        domain,
        created_at: Instant::now(),
    });

    // Переписываем dst в самом пакете (IP + TCP заголовки), пересчитываем checksum
    let modified = crate::desync::rewrite_dst_addr(
        &captured.data,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        REDIRECTOR_PORT,
    )?;

    Ok(PacketDecision::Modify(modified))
}
```

`rewrite_dst_addr` — узкая функция: парсит IP+TCP заголовок (уже есть `parse_ip_header`/
`parse_tcp_packet` в `desync/mod.rs`), меняет `dst_addr`/`dst_port`, обнуляет и пересчитывает
IP header checksum и TCP checksum (pseudo-header тоже меняется из-за смены dst IP — это частая
ошибка, если забыть пересчитать TCP checksum после смены IP, пакет молча дропнется стеком).

## T59.3 — WinDivert: подмена на обратном пути (return path)

Это **отдельный** WinDivert-хендл или отдельная ветка в существующем `process_one_sync`,
которая матчит пакеты `src_port == REDIRECTOR_PORT` (то есть ответы от нашего же локального
редиректора) и подменяет `src` обратно на значение из `redirect_table` по `dst_port` пакета
(для ответа `dst_port` пакета — это оригинальный `src_port` клиента):

```rust
Classification::Other(cp) if cp.src_port == REDIRECTOR_PORT => {
    if let Some(entry) = self.redirect_table.get(cp.dst_port) {
        let modified = crate::desync::rewrite_src_addr(
            &captured.data,
            entry.orig_dst_ip,
            entry.orig_dst_port,
        )?;
        return Ok(PacketDecision::Modify(modified));
    }
    Ok(PacketDecision::Forward)
}
```

**Важно:** фильтр WinDivert должен явно захватывать loopback-трафик для этого случая
(`... or loopback`), иначе обратный путь вообще не попадёт в хендл — это то место, где стоит
делать самый первый PoC (T59, риск №1/№2 из раздела выше).

## T59.4 — Реальный SOCKS5-клиент + bridge

**Файл:** `core/src/socks/redirector.rs` (новый), отдельный `tokio` рантайм/таск, поднимается
при старте пайплайна если `socks5_fallback` профиль присутствует в конфиге.

```rust
use tokio::net::{TcpListener, TcpStream};
use tokio::io::copy_bidirectional;

pub struct SocksRedirector {
    table: Arc<RedirectTable>,
    proxy_pool: Arc<OperaProxyPool>, // существующий opera.rs, добавить select_best()
}

impl SocksRedirector {
    pub async fn run(self: Arc<Self>, port: u16) -> std::io::Result<()> {
        // T59: слушаем 0.0.0.0, а не 127.0.0.1 (см. риск №1 выше)
        let listener = TcpListener::bind(("0.0.0.0", port)).await?;
        loop {
            let (inbound, peer_addr) = listener.accept().await?;
            let this = self.clone();
            tokio::spawn(async move {
                if let Err(e) = this.handle(inbound, peer_addr.port()).await {
                    tracing::debug!("socks redirect session error: {e}");
                }
            });
        }
    }

    async fn handle(&self, mut inbound: TcpStream, client_src_port: u16) -> anyhow::Result<()> {
        let entry = self.table.get(client_src_port)
            .ok_or_else(|| anyhow::anyhow!("no redirect entry for port {client_src_port}"))?;

        let target_host = entry.domain.clone()
            .unwrap_or_else(|| entry.orig_dst_ip.to_string());

        // T59: реальный SOCKS5-клиент к Opera-прокси (без аутентификации)
        let proxy_addr = self.proxy_pool.select_best()
            .ok_or_else(|| anyhow::anyhow!("no healthy opera proxy"))?;

        let mut outbound = TcpStream::connect(proxy_addr).await?;
        socks5_handshake_noauth(&mut outbound).await?;
        socks5_connect(&mut outbound, &target_host, entry.orig_dst_port).await?;

        let (from_client, from_proxy) = copy_bidirectional(&mut inbound, &mut outbound).await?;
        tracing::debug!(
            "socks5 bridge {target_host}:{} closed: {from_client}B up / {from_proxy}B down",
            entry.orig_dst_port
        );
        self.table.remove(client_src_port);
        Ok(())
    }
}

/// T59: SOCKS5 handshake без аутентификации (RFC 1928, метод 0x00).
async fn socks5_handshake_noauth(s: &mut TcpStream) -> anyhow::Result<()> { /* ... */ Ok(()) }

/// T59: SOCKS5 CONNECT по доменному имени (ATYP=0x03), не по IP —
/// важно: резолвить домен должен именно Opera-прокси на своей стороне,
/// иначе получим DNS-запрос локально и потеряем смысл гео-обхода.
async fn socks5_connect(s: &mut TcpStream, host: &str, port: u16) -> anyhow::Result<()> { /* ... */ Ok(()) }
```

**Ключевой момент, который легко упустить:** CONNECT в SOCKS5 нужно слать по **доменному имени**
(`ATYP=0x03`), а не по уже резолвленному IP клиента. Если слать IP — резолвинг Netflix/Spotify
останется на стороне ISP/локального DNS, что может вернуть не тот edge-сервер, который отдаёт
контент для европейского гео. У тебя уже есть `fake_ip.lookup()`, который восстанавливает домен
из fake-IP — им и нужно пользоваться здесь.

## T59.5 — Fail-open вместо fail-closed

Текущий дизайн (и Drop-заглушка, и мой скетч выше) **дропает** соединение, если прокси
недоступны. Это хуже, чем ничего не делать: если все 5 Opera SOCKS5 упали (они бесплатные —
это будет происходить регулярно), пользователь получает "сайт недоступен" вместо "работает
как обычный direct без гео-обхода".

```rust
// В process_socks5_redirect — прежде чем ставить redirect, проверяем наличие живого прокси:
if self.proxy_pool.select_best().is_none() {
    tracing::warn!("all opera proxies unhealthy, falling back to direct for {:?}", domain);
    return Ok(PacketDecision::Forward); // не Drop!
}
```

Дополнительно: если сам `SocksRedirector::handle` не смог законнектиться к прокси или к
таргету (`outbound.connect` упал), нужно **не просто закрыть `inbound`**, а поставить это
как сигнал health-check'у (уменьшить приоритет этого прокси в пуле), иначе застрявший мёртвый
прокси будет выбираться повторно.

## T59.6 — Auto-detect блокировки: честная оценка возможного

Ты просил "автоматически определять наличие блокировки". Здесь нужно разделить два разных
явления:

1. **Сетевая недоступность** (TCP/TLS не устанавливается вовсе) — детектируется легко:
   таймаут/RST на connect. Для этого можно использовать паттерн, который уже есть в проекте
   (`AutoTune` success/failure метрики) — считать fail rate прямых подключений к доменам из
   geo-списка и, если он выше порога, автоматически подключать `socks5_fallback` для этого
   домена без ручного список-only режима.

2. **Гео-блокировка на уровне контента** (TCP/TLS устанавливаются нормально, но
   Netflix/Spotify отдают HTTP 403 / "not available in your region") — это происходит **внутри**
   зашифрованного HTTPS. Определить это без MITM-терминации TLS **невозможно** — а MITM
   собственного трафика пользователя это отдельный (и гораздо более рискованный, с точки зрения
   доверия/сертификатов) уровень сложности, который я бы не советовал добавлять ради этой задачи.

**Практический вывод:** для сценария Netflix/Spotify/Telegram полноценный автодетект гео-блока
не реализуем без MITM. Реалистичный компромисс — то, что у тебя уже частично есть в `geo.rs`:
статический список доменов, известных как гео-заблокированные для RU. Автоматизировать можно
только уровень (1) — переключение profile на socks5_fallback по фактической недоступности,
а не по контент-уровню. Могу добавить эвристику "домен из geo-списка И direct-connect fail rate
> N% за последние M минут → активировать socks5_fallback" через существующий `AutoTune`, это
не требует новой инфраструктуры.

## T59.7 — Интеграция в `process_one_sync`

```rust
Classification::Tls(cp) | Classification::Http(cp) | Classification::Quic(cp) if /* dst в geo-списке */ => {
    // T59: сначала пробуем редирект на Opera (если активирован и есть живой прокси),
    // иначе — обычный process_with_profile как раньше
    let redirect_decision = self.process_socks5_redirect(captured, &cp)?;
    if !matches!(redirect_decision, PacketDecision::Forward) {
        return Ok(redirect_decision);
    }
    self.process_with_profile(captured, &cp, protocol)
}
```

## Порядок работы (рекомендуемый)

1. **PoC вне основного пайплайна** (отдельный bin-target `redirect_poc`): голый WinDivert +
   redirect одного захардкоженного `dst:443` на `127.0.0.1:PORT` + `nc -l -p PORT`, проверить
   что curl к внешнему сайту действительно долетает до `nc`. Это закроет риски №1 и №2 до того,
   как код появится в основном движке.
2. T59.1 (RedirectTable) + T59.4 (SocksRedirector, реальный SOCKS5-клиент) — их можно
   разрабатывать и тестировать независимо от WinDivert, через обычный `TcpStream::connect`
   на локальный порт вручную.
3. T59.2/T59.3 (WinDivert rewrite обеих сторон) — по результатам PoC.
4. T59.5 (fail-open) и T59.6 (auto fail-rate detection) — после того как базовый мост заработал
   стабильно на 1-2 доменах.

## Что нужно от тебя, чтобы сделать это точным патчем, а не скетчем

Пришли актуальные `opera.rs`, `geo.rs`, `proxy.rs`, `engine/mod.rs` (или хотя бы сигнатуры
`Classifier`, `ClassifiedPacket`, `PacketDecision`, `CapturedPacket`, существующий
`parse_ip_header`/`parse_tcp_packet`) — тогда перепишу T59.1-T59.4 как конкретный diff
под твой код, а не как архитектурный скетч.
