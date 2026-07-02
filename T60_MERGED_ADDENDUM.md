# T60 — Аддендум к T59: пользовательский список доменов + auto-probe

**База:** T59 (WinDivert redirect → loopback → реальный SOCKS5-клиент через tokio).
T58 (агент) отклонён как основа транспорта — см. обоснование в чате: отсутствие
фрагментации по MTU в `ProxyRelay::build_tcp_packet` и блокирующий I/O в hot path.
Из T58 забираем только конфиг доменного списка (T58.9) и auto-probe (T58.6-T58.8),
адаптированные под T59.

---

## T60.1 — Источник списка доменов: TOML + внешний файл

**Файл:** `core/src/config.rs`

Инлайн-список в TOML неудобен для большого личного списка — добавляем опциональный
путь к файлу (один домен на строку, `#` — комментарий), который мёржится со
статическим EU-списком из `geo.rs` и с инлайн-списком.

```rust
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ProxyConfig {
    /// Включить Opera SOCKS5 proxy routing вообще.
    #[serde(default)]
    pub enabled: bool,
    /// Домены прямо в TOML (маленький список / override).
    #[serde(default)]
    pub proxy_domains: Vec<String>,
    /// Путь к внешнему файлу со списком доменов (один домен на строку).
    /// Если задан — читается при старте и при получении SIGHUP/reload команды.
    #[serde(default)]
    pub proxy_domains_file: Option<String>,
    /// Автоматически определять заблокированные домены через probe (T60.4).
    #[serde(default = "default_true")]
    pub auto_probe: bool,
    pub max_connections: Option<usize>,
    pub idle_timeout_secs: Option<u64>,
}

fn default_true() -> bool { true }

/// T60: Читает домены из файла, игнорируя пустые строки и комментарии (#...).
pub fn load_domains_from_file(path: &str) -> anyhow::Result<Vec<String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read proxy domains file: {path}"))?;

    let domains: Vec<String> = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_lowercase())
        .collect();

    tracing::info!("T60: loaded {} domains from {path}", domains.len());
    Ok(domains)
}
```

**Файл:** `blocked_domains.txt.example` (новый, кладём рядом с `config.toml.example`)

```
# T60: домены, которые всегда идут через Opera SOCKS5 прокси.
# Один домен на строку. Поддомены НЕ разворачиваются автоматически —
# добавляй явно (netflix.com и www.netflix.com — разные строки).
netflix.com
www.netflix.com
nflxvideo.net
spotify.com
open.spotify.com
scdn.co
```

## T60.2 — `DomainBlocklist`: приоритет источников

**Файл:** `core/src/geo.rs`

Три источника доменов должны сочетаться предсказуемо:

1. Статический EU-список из `geo.rs` (как раньше — базовый "known EU-geoblocked").
2. Пользовательский список из `proxy_domains_file` / `proxy_domains` (T60.1) — **добавляется**
   к статическому, не заменяет его.
3. Auto-probe (T60.4) — домены, которые probe **сам** пометил как заблокированные — тоже
   добавляются, но живут отдельно (могут "остыть", если домен снова стал доступен — статический
   и пользовательский списки не "остывают" сами).

```rust
pub struct DomainBlocklist {
    /// T60: статический список из geo.rs (compile-time / built-in).
    static_domains: HashSet<String>,
    /// T60: из config.toml / внешнего файла — не меняется без рестарта/reload.
    user_domains: HashSet<String>,
    /// T60: из auto-probe — может обновляться в рантайме, есть TTL.
    probed_domains: DashMap<String, Instant>,
    probed_ttl: Duration,
}

impl DomainBlocklist {
    pub fn should_tunnel(&self, domain: &str) -> bool {
        let domain = domain.to_lowercase();
        if self.static_domains.contains(&domain) || self.user_domains.contains(&domain) {
            return true;
        }
        if let Some(entry) = self.probed_domains.get(&domain) {
            return entry.elapsed() < self.probed_ttl;
        }
        false
    }

    /// T60: вызывается из auto_probe при обнаружении блокировки.
    pub fn mark_probed_blocked(&self, domain: &str) {
        self.probed_domains.insert(domain.to_lowercase(), Instant::now());
    }

    /// T60: reload пользовательского списка без рестарта процесса.
    pub fn reload_user_domains(&mut self, path: &str) -> anyhow::Result<()> {
        let domains = crate::config::load_domains_from_file(path)?;
        self.user_domains = domains.into_iter().collect();
        tracing::info!("T60: reloaded {} user domains", self.user_domains.len());
        Ok(())
    }
}
```

Это заменяет `self.accumulator.should_tunnel(d)`, использовавшийся в T59.2 — сигнатура
вызова не меняется, меняется только то, что стоит за ней.

## T60.3 — Reload по сигналу (Windows: именованное событие, не SIGHUP)

Windows не имеет SIGHUP — для reload списка без рестарта сервиса нужен либо polling
файла по mtime (проще, надёжнее для одного пользователя), либо `named event`
(`CreateEvent`/`SetEvent`) если нужен reload по команде из трея/CLI. Для одиночного
пользователя рекомендую **polling по mtime раз в 30-60 сек** — проще и без гонок:

```rust
// В фоновом таске pipeline:
async fn watch_domains_file(blocklist: Arc<RwLock<DomainBlocklist>>, path: String) {
    let mut last_mtime = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;
        if let Ok(meta) = std::fs::metadata(&path) {
            if let Ok(mtime) = meta.modified() {
                if Some(mtime) != last_mtime {
                    last_mtime = Some(mtime);
                    if let Err(e) = blocklist.write().unwrap().reload_user_domains(&path) {
                        tracing::warn!("T60: domain list reload failed: {e}");
                    }
                }
            }
        }
    }
}
```

Практический плюс: можно просто редактировать `blocked_domains.txt` в блокноте на лету,
без перезапуска сервиса — изменения подхватятся в течение минуты.

## T60.4 — Auto-probe (адаптация T58.6-T58.8 под T59)

Логика из плана агента (T58.7) в целом годная как *эвристика уровня "сеть недоступна"*
(см. мою оговорку из прошлого ответа — контентный гео-блок внутри HTTPS так не поймать).
Переиспользуем идею, но результат не активирует голый `socks5_fallback`-профиль вручную —
кладём домен в `DomainBlocklist::mark_probed_blocked`, что автоматически подключает его
к T59-редиректору при следующем подключении:

```rust
pub async fn auto_probe_and_tune(
    probe: &ProbeModule,
    blocklist: Arc<RwLock<DomainBlocklist>>,
    candidate_domains: &[String],
) {
    tracing::info!("T60: auto-probe {} candidate domains", candidate_domains.len());
    for domain in candidate_domains {
        let result = probe.probe(domain).await;
        if result.verdict == crate::probe::classifier::ProbeVerdict::Blocked {
            tracing::info!("T60: '{domain}' detected as blocked, routing via Opera proxy");
            blocklist.write().unwrap().mark_probed_blocked(domain);
        }
    }
}
```

`candidate_domains` — не жёстко захардкоженные preset-списки как в T58.7, а: (домены из
`user_domains`, если они ещё не отмечены как гарантированно рабочие) + опционально
небольшой built-in preset (Netflix/Spotify/Telegram) для домена, которые пользователь ещё
не добавил вручную. Держи preset маленьким — каждый probe это реальный сетевой запрос при
старте, не нужно проверять сотни доменов.

## T60.5 — Итоговый конфиг

**Файл:** `config.toml.example`

```toml
[proxy]
enabled = true
# Маленький ручной override прямо в TOML (необязательно, если есть файл ниже)
proxy_domains = []
# Основной способ — отдельный файл, который удобно редактировать/пополнять
proxy_domains_file = "blocked_domains.txt"
# Автоматически пробовать определять заблокированные домены (уровень "сеть недоступна",
# НЕ "контент гео-заблокирован" — см. пояснение в T59.6)
auto_probe = true
max_connections = 1000
idle_timeout_secs = 300
```

## Итоговый список задач (что реально кодить)

1. Транспорт: **T59.1-T59.5** (RedirectTable, WinDivert rewrite туда/обратно, реальный
   SOCKS5-клиент на tokio, fail-open) — без изменений.
2. Домены: **T60.1-T60.3** (файл со списком + мёрж со статикой + polling-reload) — новое.
3. Auto-probe: **T60.4** — адаптация T58.6-T58.8 под `DomainBlocklist` вместо ручного
   `set_manual_override`.
4. Из T58 **не берём**: `ProxyRelay` (T58.2), `ProxyConnectionTable` (T58.3-T58.5, не
   показан целиком, но построен поверх того же `ProxyRelay`) — весь mini-TCP-stack.

## Верификация

```bash
grep -n "struct ProxyConfig\|fn load_domains_from_file" core/src/config.rs
grep -n "struct DomainBlocklist\|fn should_tunnel\|fn mark_probed_blocked\|fn reload_user_domains" core/src/geo.rs
grep -n "fn watch_domains_file" core/src/engine/mod.rs
grep -n "fn auto_probe_and_tune" core/src/probe/mod.rs
cargo test -p freedpi-core --lib geo::t60_tests --nocapture
```
