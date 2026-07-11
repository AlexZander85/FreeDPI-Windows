# GPT-5.5 Thinking — FreeDPI Windows patch plan v6, fully integrated + operational hardening + DeepSeek + Gemini verified merge

Дата: 2026-07-05. База: архив `FreeDPI-Windows-master(1).zip`, ревью `GPT-5.5_Thinking_review.md`, GLM-review `glm_review.md`, Claude-review `claude_review.md`, DeepSeek-review `deepseek.md`, Gemini-review `gemini_3.5_flash_review.md`, предыдущий файл `GPT-5.5_Thinking_patch_plan_v5_integrated_deepseek.md`.

Этот файл заменяет предыдущие patch plan. В нём нет добавочных override-разделов, delta-блоков и правил вида “поздняя находка важнее ранней задачи”. Все находки GPT/GLM/Claude/DeepSeek/Gemini, подтверждённые или требующие обязательной проверки по исходникам, встроены в единый линейный порядок. Кодинговый агент должен выполнять этот документ сверху вниз по фазам; не нужно сначала выполнять старые задачи, а потом исправлять их GLM/Claude-задачами.

Принцип мерджа:

1. Исправления, которые устраняют startup panic, packet corruption или неверный L3/L4 offset, стоят раньше performance/adaptive задач.
2. GLM/Claude/DeepSeek/Gemini-находки, которые уточняют уже существующую задачу, встроены внутрь этой задачи как обязательные подпункты, а не вынесены в конец.
3. Если компонент был найден как no-op/недособранный, задача не требует его удалить. Компонент должен либо быть полноценно подключён к data path, либо безопасно переведён в explicit quarantine без wire-visible мусора и без ложного success.
4. Любой код из плана должен сверяться с текущими сигнатурами архива перед применением. Если кодинговый агент меняет сигнатуру, он обязан обновить все вызывающие места в этом же PR.

## Внешние технические ограничения, которые нельзя нарушать

1. WinDivert — user-mode capture/modification/re-injection. Захваченные packets проходят через user/kernel boundary и очереди WinDivert, поэтому фильтр должен быть максимально узким, а packet worker не должен ждать DNS/сеть, спать или держать глобальный lock на hot path. Источник: `https://reqrypt.org/windivert-doc.html`.
2. QUIC Initial/Long Header и Version Negotiation должны соответствовать RFC 9000. Client Initial UDP datagram должен быть не меньше 1200 bytes до получения Handshake keys; packet number нельзя честно использовать для PN-gap logic без снятия header protection. Источник: `https://datatracker.ietf.org/doc/html/rfc9000`.
3. IPv6 header layout и extension headers должны соответствовать RFC 8200: Traffic Class не является IPv4-like byte 1, а upper-layer header не обязан начинаться на offset 40. Источник: `https://datatracker.ietf.org/doc/html/rfc8200`.
4. TLS 1.3 resumption/0-RTT нужно моделировать через `pre_shared_key`, `psk_key_exchange_modes`, binders и `early_data`, а не через TLS 1.2-style “random session_ticket fantasy”. Источник: `https://www.rfc-editor.org/rfc/rfc8446.html`.
5. Все изменения должны проходить `cargo fmt --all`, `cargo check --workspace --all-targets`, `cargo test --workspace`. Windows path дополнительно проверяется под admin с WinDivert.
6. `bytes::Bytes`/`BytesMut` pool semantics зависят от уникальности ownership. Любой clone `Bytes` на hot path должен иметь доказанный lifetime; иначе `try_into_mut()` не вернёт allocation в pool и zero-allocation будет иллюзией. Источник: `https://docs.rs/bytes/latest/bytes/`.
7. QUIC packet protection/header protection должны соответствовать RFC 9001. Любой код, который заявляет QUIC PN analysis или valid forged Initial, должен либо реально снимать header protection/валидировать AEAD, либо явно отключать эту ветку как quarantine. Источник: `https://www.rfc-editor.org/rfc/rfc9001.html`.
8. WinDivert performance tuning не должен быть статическим обещанием в конфиге: filter selectivity, batch I/O, queue parameters and thread topology должны контролироваться runtime-метриками. Источники: `https://reqrypt.org/windivert-doc.html`, `https://deepwiki.com/basil00/WinDivert/8.1-performance-optimization`.
9. PCAP regression harness должен читать формат как global header + packet records и валидировать linktype/header boundaries до анализа payload. Источник: `https://datatracker.ietf.org/doc/html/draft-ietf-opsawg-pcap`.
10. Fuzz targets должны быть частью CI для pure parser/desync слоёв; `cargo-fuzz` является стандартным wrapper вокруг libFuzzer для Rust fuzzing. Источник: `https://rust-fuzz.github.io/book/cargo-fuzz.html`.
11. `tokio::sync::broadcast::Receiver::try_recv()` — неблокирующая попытка чтения с ошибками `Empty/Closed/Lagged`, но control-plane polling не должен жить в packet hot loop. Shutdown должен распространяться через atomic/control token, проверяемый внутри RX/worker loop. Источник: `https://docs.rs/tokio/latest/tokio/sync/broadcast/struct.Receiver.html`.
12. Runtime идентификаторы flow/profile/strategy не должны строиться через строковые lookup на packet path. Rust `HashMap` сейчас использует SipHash 1-3 по умолчанию, но это implementation detail; для `conn_id`/RNG seed нужен явный keyed hasher над полным normalized 5-tuple. Источник: `https://doc.rust-lang.org/std/collections/struct.HashMap.html`.
13. QUIC `CONNECTION_CLOSE`, `Retry` и любой forged QUIC control packet нельзя генерировать как raw UDP payload. Если packet заявлен как valid QUIC, он обязан соответствовать RFC 9000/9001 packet protection/header protection; иначе техника должна быть marked invalid-desync и выключена по умолчанию. Источники: `https://datatracker.ietf.org/doc/html/rfc9000`, `https://www.rfc-editor.org/rfc/rfc9001.html`.
14. Direction metadata WinDivert является частью корректности packet injection. Если `pAddr->Outbound`/Direction неверен, fake packet может быть injected в локальный stack вместо outbound path. Любая desync-техника, генерирующая RST/fake control packet, обязана явно передавать injection direction до worker send path. Источник: `https://github.com/basil00/WinDivert/wiki/WinDivert-Documentation`.
15. OS RNG нельзя вызывать на per-packet/per-new-flow hot path без доказанного профиля. Системная entropy используется один раз для process secret, а per-connection seed выводится из canonical FlowKey через проверенный keyed KDF/hash.



---

# Канонический порядок внедрения

## Фаза 0 — correctness before speed

1. P0-01 AWG startup panic.
2. P0-02 `DesyncResult.modified`, `max_seg_size` и честная семантика local application.
3. P0-03 единая L3/L4 parsing foundation: IPv4 fragments, IPv6 extension headers, panics, classifier offsets.
4. P0-04 TLS/QUIC layer offsets: TCP `client_isn`, QUIC DCID/SCID только из UDP payload, PN-gap отключить до header-protection removal.
5. P0-05 IPv4/IPv6-safe `DscpRandom`.
6. P0-06 `tls_record_pad` checksum по реальному IPv4 IHL.
7. P0-07 outcome model: local generation не равно network success.
8. P0-08 buffer-pool ownership: убрать `CapturedPacket.data.clone()` lifetime bug до любых zero-copy/perf задач.
9. P0-09 заменить XOR-fold IPv6/tuple mixing на keyed full-5-tuple `FlowKey`/`conn_id`.
10. P0-10 direction-aware inject model: не терять `DesyncResult.is_outbound_inject`, RST/fake control packets не должны наследовать неверный inbound address.
11. P0-11 real-vs-decoy TCP fragment invariant: `tls_record_frag`, `multisplit`, `multidisorder_new` не пересылают original CH и не сжигают real bytes fake TTL'ом.

## Фаза 1 — hot path architecture and packet-capture surface

1. P1-00 flow-affinity architecture: один capture loop + bounded per-flow shard queues; не много workers, читающих один WinDivert handle.
2. P1-00A shutdown/control-plane correctness: no broadcast `try_recv()` polling around infinite worker loop; atomic shutdown inside RX/workers.
2. P1-01 сузить default WinDivert filter до outbound TLS CH, outbound DNS request, outbound QUIC Initial.
3. P1-16 feature-dependent SYN capture: SYN попадает в pipeline только когда включены SYN-dependent функции; не расширять filter до всего TCP/UDP.
3. P1-02 blind-window-free filter rotation и `QueueSize`.
4. P1-03 убрать per-batch allocation в recv/send/inject batches.
5. P1-04 delayed injector вместо `sleep()` в worker.
6. P1-05 DNS async queue вместо `block_on()`.
7. P1-06 AWG/UDP proxy worker pool вместо Tokio task per packet.
8. P1-07 убрать `DesyncGroup::clone()` на packet path.
9. P1-08 atomic `injected_seqs` check-and-mark.
10. P1-09 dependency-aware `BadChecksum`.
11. P1-10 безопасный параметризованный `TtlManipulation`.
12. P1-11 убрать hot-path allocations в TCP options и TLS padding.
13. P1-12 HopTab robust observe + `u16` generation.
14. P1-13 TLS 1.3 resumption-aware fake ClientHello shape.
15. P1-14 убрать `Mutex<AutoTune>` с hot path.
16. P1-15 заменить string-based active profiles на `ProfileId`/`AtomicU32` и ProfileId-indexed AutoTune metrics.

## Фаза 2 — замкнуть реально работающие adaptive/routing/lifecycle контуры

1. P2-01 уважать `StrategyProfileConfig.enabled` и активировать профиль при запуске.
2. P2-02 Probe -> StrategyProfile -> Pipeline contour.
3. P2-03 SplitTunnel decisions в live data path.
4. P2-04 AdaptiveRouter CircuitBreaker и ThroughputTracker.
5. P2-05 FallbackChain, TargetEscalator, ProbeTuneRun как единый adaptive contour с реальным network outcome.
6. P2-06 заменить ложный `Conntrack::gc_incremental` на timing-wheel/bucketed GC с доказуемым покрытием.
7. P2-07 lifecycle sweeper для `redirect_table`.
8. P2-08 NamedPipe IPC вместо заглушки.
9. P2-09 dead-code policy без потери намерения подсистем.
10. P2-10 harden/delete `DesyncGroup::apply_single_safe`: wildcard passthrough запрещён.
11. P2-11 DeepSeek dead-code triage: `has_non_empty_session_ticket`, `zero_config`, legacy sync send/forward/inject/execute functions.
12. P2-12 FakeIP eviction/TTL: переполнение fake IP cache не должно ломать DNS до рестарта службы.

## Фаза 3 — protocol correctness for DPI evasion

1. P3-01 QUIC Version Negotiation packet.
2. P3-02 QUIC Initial builder: varint, TLS extensions, random, no unencrypted fallback.
3. P3-02A QUIC Initial crypto fallback ban: crypto failure = skip injection + metric, не unprotected zero-padded packet.
3. P3-03 TLS first-record reassembly для fragmented ClientHello.
4. P3-04 подключить unreachable QUIC arsenal (`quic_initial_inject`, GREASE, normalizer, coalescing) через variants/dispatch/profile gates и protocol-validity tests.
5. P3-04A QUIC original port preservation: packet builders используют port из PacketContext, никаких hardcoded UDP/443.
5. P3-05 реализовать `SniMasking` dispatcher и провести audit HTTP/2/obfs helpers как intended techniques, а не dead helpers.
6. P3-06 QUIC fallback policy: запретить raw `CONNECTION_CLOSE`; разрешать только valid protected/profiled QUIC fallback или controlled drop/jitter.

## Фаза 4 — масштабирование 5–10 Gbps после correctness gates

1. P4-00 pool capacity sizing policy: не 64 buffers, а capacity от worker_count × batch_size × safety_factor с метриками starvation/release-failure.
2. P4-01 не отключать RSS глобально.
3. P4-02 perf gates: capture ratio, pool hit-rate, shard queue pressure, p99 latency.
4. P4-03 evaluate true pool-backed `RecvEx` only after verifying crate/FFI support; не обещать scatter/gather zero-copy без доказательства.
5. P4-04 per-connection RNG seeding: убрать `OsRng` с new-flow hot path, seed derive from process secret + FlowKey.
6. P4-05 proxy rewrite copy-on-write/in-place: no unconditional `packet_data.to_vec()` in rewrite paths.

## Фаза 5 — operational hardening before production-ready

1. P5-01 Capture Budget Governor: runtime-контроль capture surface и safe filter rotation.
2. P5-02 Runtime Packet Invariant Guard: не выпускать malformed generated packets на wire.
3. P5-03 PCAP Replay + Fuzz Regression Harness: воспроизводимые parser/desync regression tests.
4. P5-04 full validation matrix.

---

# P0-01. Устранить startup panic при включённом AWG: `Arc::try_unwrap(awg_tunnel_state).unwrap()`

## Проблема

В `core/src/engine/mod.rs` поле pipeline сейчас объявлено как:

```rust
awg_tunnel: ArcSwap<Option<Arc<crate::proxy::awg_tunnel::AwgTunnel>>>,
```

В `ProcessingPipeline::new()` создаётся `Arc<ArcSwap<...>>`, клон этого `Arc` уходит в `tokio::spawn`, после чего код делает:

```rust
awg_tunnel: Arc::try_unwrap(awg_tunnel_state).unwrap(),
```

Если `config.awg.enabled == true`, spawned future уже владеет клоном `Arc`, поэтому `try_unwrap()` получает `strong_count > 1` и паникует. Это не нагрузочный race, а детерминированный startup crash для AWG-enabled конфигурации.

## Решение и обоснование

`ArcSwap` уже предназначен для lock-free публикации новой `Arc<T>` между потоками. Его не нужно unwrap-ить из `Arc`: сам pointer container должен быть общим объектом pipeline и background task. Поэтому поле pipeline должно хранить `Arc<ArcSwap<Option<Arc<AwgTunnel>>>>`.

Это решение не переносит синхронизацию в hot path: `ArcSwap::load()` остаётся wait-free atomic load, а `store()` выполняется только из AWG lifecycle task.

## Реализация

В `core/src/engine/mod.rs` заменить поле:

```rust
// было
awg_tunnel: ArcSwap<Option<Arc<crate::proxy::awg_tunnel::AwgTunnel>>>,

// стало
awg_tunnel: Arc<ArcSwap<Option<Arc<crate::proxy::awg_tunnel::AwgTunnel>>>>,
```

В `ProcessingPipeline::new()` оставить создание как есть:

```rust
let awg_tunnel_state: Arc<ArcSwap<Option<Arc<crate::proxy::awg_tunnel::AwgTunnel>>>> =
    Arc::new(ArcSwap::from_pointee(None));
```

В `Ok(Self { ... })` заменить:

```rust
// было
awg_tunnel: Arc::try_unwrap(awg_tunnel_state).unwrap(),

// стало
awg_tunnel: awg_tunnel_state,
```

В `new_api_only()` заменить:

```rust
// было
awg_tunnel: ArcSwap::from_pointee(None),

// стало
awg_tunnel: Arc::new(ArcSwap::from_pointee(None)),
```

Все чтения вида:

```rust
let awg_guard = self.awg_tunnel.load();
```

оставить без изменений: autoderef у `Arc<ArcSwap<...>>` корректно вызывает `ArcSwap::load()`.

## Критерии готовности

- При `config.awg.enabled = true` `ProcessingPipeline::new()` не паникует.
- Background task может выполнить `state_clone.store(Some(Arc::new(tunnel)))`.
- Packet path читает опубликованный tunnel через `self.awg_tunnel.load()` без `Mutex`.
- В коде больше нет `Arc::try_unwrap(awg_tunnel_state)`.

## Верификация

Добавить unit/integration test в `engine/mod.rs` под `#[cfg(test)]`:

```rust
#[test]
fn awg_state_is_shared_not_unwrapped() {
    let state = std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(None::<std::sync::Arc<()>>));
    let cloned = state.clone();
    assert_eq!(std::sync::Arc::strong_count(&state), 2);
    drop(cloned);
    assert_eq!(std::sync::Arc::strong_count(&state), 1);
}
```

Этот тест не проверяет `AwgTunnel::start`, но фиксирует запрещённую модель владения: pipeline не должен требовать unique ownership у состояния, которое передаётся в async task.

Также выполнить ручной smoke-test на Windows:

```powershell
# config.toml: [awg] enabled = true
cargo test -p freedpi-core
cargo run -p freedpi-service -- --config .\config.toml
# Ожидание: нет panic в ProcessingPipeline::new; при ошибке старта AWG только tracing::error.
```

---

---

# P0-02. Исправить семантику `DesyncResult.modified`, доставку `max_seg_size` и честный local-application status

## Проблема

`core/src/desync/group.rs::PipelineState::into_result()` всегда возвращает `modified: Some(self.packet)`. Это ломает все downstream decisions: no-op техники выглядят успешными, AutoTune получает ложные success, оригинальные packets идут по ветке `Modify`, а dead techniques маскируются.

Отдельно `TuneParams.max_seg_size` существует, но теряется в `ConfigOverride`. В результате `TcpSeg` и `MssClamp` используют hardcode (`c.max_seg_size` и `536`) вместо профиля/AutoTune/config.

## Решение и обоснование

Вводим явный dirty bit `modified_dirty`. Только функция `merge_into_state()` выставляет его при реальном `result.modified`. Это сохраняет текущую pipeline-модель, не меняет владение `Bytes`, не добавляет locks и делает semantics проверяемой. `max_seg_size` добавляем в `ConfigOverride`, а `TcpSeg`/`MssClamp` читают единый resolved parameter.

## Реализация

Файл: `core/src/desync/group.rs`.

Заменить `ConfigOverride` и `impl From<TuneParams>` на:

```rust
#[derive(Debug, Clone, Copy, Default)]
pub struct ConfigOverride {
    pub split_size: Option<usize>,
    pub split_count: Option<usize>,
    pub fake_ttl_offset: Option<u8>,
    pub max_seg_size: Option<usize>,
}

impl From<TuneParams> for ConfigOverride {
    fn from(params: TuneParams) -> Self {
        Self {
            split_size: params.split_size,
            split_count: params.split_count,
            fake_ttl_offset: params.fake_ttl_offset,
            max_seg_size: params.max_seg_size,
        }
    }
}
```

В `PipelineState` добавить поле:

```rust
    /// true только если хотя бы одна техника реально вернула modified packet.
    modified_dirty: bool,
```

В `PipelineState::from_packet()` добавить инициализацию:

```rust
            modified_dirty: false,
```

Заменить `into_result()` на:

```rust
    pub fn into_result(self) -> DesyncResult {
        DesyncResult {
            modified: if self.modified_dirty { Some(self.packet) } else { None },
            inject: self.injects,
            inter_delay_us: 0,
            drop: self.drop,
            is_outbound_inject: self.is_outbound_inject,
        }
    }
```

Заменить `merge_into_state()` на:

```rust
impl DesyncGroup {
    fn merge_into_state(&self, state: &mut PipelineState, result: DesyncResult) {
        if let Some(modified) = result.modified {
            state.packet = modified;
            state.modified_dirty = true;
            state.invalidate_header_cache();
        }
        for inject in result.inject {
            state.injects.push(inject);
        }
        if result.drop {
            state.drop = true;
        }
        if result.is_outbound_inject {
            state.is_outbound_inject = true;
        }
    }
}
```

В `apply_to_state()` после вычисления `fake_ttl_offset` добавить:

```rust
        let max_seg_size = override_params
            .and_then(|p| p.max_seg_size)
            .unwrap_or(c.max_seg_size);
```

Заменить ветку `TcpSeg`:

```rust
            DesyncTechnique::TcpSeg => {
                let result = tcp::tcpseg(&state.packet, max_seg_size, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
```

Заменить ветку `MssClamp`:

```rust
            DesyncTechnique::MssClamp => {
                let mss = max_seg_size.clamp(68, u16::MAX as usize) as u16;
                let result = tcp::mss_clamp(&state.packet, mss, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
```

Заменить ветку `SniMasking`, чтобы существующая функция реально подключалась, а не была no-op:

```rust
            DesyncTechnique::SniMasking => {
                let result = tls::sni_masking(&state.packet, 0x2A);
                self.merge_into_state(state, result);
            }
```

В `apply_single_safe()` заменить `SniMasking => DesyncResult::passthrough()` на:

```rust
            DesyncTechnique::SniMasking => tls::sni_masking(packet, 0x2A),
```

## Критерии готовности

- Пакет, прошедший через пустую группу или через no-op технику, возвращает `modified == None`.
- `TcpSeg` и `MssClamp` используют `TuneParams.max_seg_size`, если он задан.
- `SniMasking` больше не является silent no-op.
- AutoTune success перестаёт быть почти всегда true после no-op pipeline.

## Верификация

Добавить тесты в `core/src/desync/group.rs`:

```rust
#[test]
fn test_pipeline_noop_does_not_mark_modified() {
    let group = DesyncGroup::new(DesyncConfig::default());
    let pkt = bytes::Bytes::from_static(b"not an ip packet");
    let result = group.apply(&pkt, None, None, None);
    assert!(result.modified.is_none());
    assert!(result.inject.is_empty());
    assert!(!result.drop);
}

#[test]
fn test_config_override_preserves_max_seg_size() {
    let params = crate::adaptive::auto_tune::TuneParams {
        split_size: Some(2),
        split_count: Some(3),
        fake_ttl_offset: Some(4),
        max_seg_size: Some(777),
    };
    let override_params: ConfigOverride = params.into();
    assert_eq!(override_params.max_seg_size, Some(777));
}
```

Команды:

```bash
cargo test -p freedpi-core desync::group::tests -- --nocapture
cargo check --workspace --all-targets
```

---

---

# P0-03. Сделать единую L3/L4 parsing foundation: IPv4 fragments, IPv6 extension headers, panics, classifier offsets

## Проблема

`core/src/classifier.rs` делает `&packet[header_len..]` и `&packet[payload_offset..]` без `get()`. Malformed/truncated packet может уронить worker. IPv4 non-first fragments интерпретируются как TCP/UDP header. IPv6 extension headers игнорируются, поэтому `payload_offset` для QUIC/TLS может указывать на неправильный слой.

## Решение и обоснование

Classifier обязан быть total function: любой byte slice -> `Classification`, без panic. IPv4 fragments не парсим как L4, а возвращаем `Other`. Для IPv6 добавляем bounded walk по extension headers, включая Fragment. Это дешёвый фикс: только несколько чтений header bytes на packet, без heap allocation.

## Реализация

Файл: `core/src/classifier.rs`.

Заменить `classify_ipv4`, `classify_ipv6`, `classify_transport` и добавить helpers внутри `impl Classifier`:

```rust
    fn classify_ipv4(packet: &[u8]) -> Classification {
        let ip = match Ipv4Packet::new(packet) {
            Some(ip) => ip,
            None => return Classification::Unknown,
        };

        let src_ip = IpAddr::V4(ip.get_source());
        let dst_ip = IpAddr::V4(ip.get_destination());
        let protocol = ip.get_next_level_protocol().0;
        let header_len = (ip.get_header_length() as usize) * 4;
        if header_len < 20 || packet.len() < header_len {
            return Classification::Unknown;
        }

        let flags = ip.get_flags();
        let fragment_offset = ip.get_fragment_offset();
        let more_fragments = (flags & 0x1) != 0;
        if fragment_offset != 0 || more_fragments {
            return Self::classify_other(src_ip, dst_ip, protocol, header_len.min(packet.len()), packet.len());
        }

        Self::classify_transport(packet, src_ip, dst_ip, protocol, header_len)
    }

    fn classify_ipv6(packet: &[u8]) -> Classification {
        let ip = match Ipv6Packet::new(packet) {
            Some(ip) => ip,
            None => return Classification::Unknown,
        };

        let src_ip = IpAddr::V6(ip.get_source());
        let dst_ip = IpAddr::V6(ip.get_destination());
        let Some((protocol, header_len, fragmented)) = Self::ipv6_l4_offset(packet, ip.get_next_header().0) else {
            return Classification::Unknown;
        };
        if fragmented {
            return Self::classify_other(src_ip, dst_ip, protocol, header_len.min(packet.len()), packet.len());
        }
        Self::classify_transport(packet, src_ip, dst_ip, protocol, header_len)
    }

    fn classify_other(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        protocol: u8,
        payload_offset: usize,
        packet_len: usize,
    ) -> Classification {
        Classification::Other(ClassifiedPacket {
            src_ip,
            dst_ip,
            src_port: 0,
            dst_port: 0,
            protocol,
            direction: PacketDirection::Outbound,
            conn_key: ConnKey::new(src_ip, dst_ip, 0, 0, protocol),
            payload_offset,
            payload_len: packet_len.saturating_sub(payload_offset),
        })
    }

    fn ipv6_l4_offset(packet: &[u8], first_next_header: u8) -> Option<(u8, usize, bool)> {
        let mut next = first_next_header;
        let mut offset = 40usize;
        let mut hops = 0usize;

        loop {
            hops += 1;
            if hops > 8 {
                return None;
            }
            match next {
                0 | 43 | 60 | 135 => {
                    let hdr = packet.get(offset..offset + 2)?;
                    next = hdr[0];
                    let len = (hdr[1] as usize + 1) * 8;
                    offset = offset.checked_add(len)?;
                    if offset > packet.len() {
                        return None;
                    }
                }
                44 => {
                    let hdr = packet.get(offset..offset + 8)?;
                    next = hdr[0];
                    return Some((next, offset + 8, true));
                }
                51 => {
                    let hdr = packet.get(offset..offset + 2)?;
                    next = hdr[0];
                    let len = (hdr[1] as usize + 2) * 4;
                    offset = offset.checked_add(len)?;
                    if offset > packet.len() {
                        return None;
                    }
                }
                50 | 59 => return Some((next, offset, false)),
                _ => return Some((next, offset, false)),
            }
        }
    }

    fn classify_transport(
        packet: &[u8],
        src_ip: IpAddr,
        dst_ip: IpAddr,
        protocol: u8,
        header_len: usize,
    ) -> Classification {
        match protocol {
            6 => {
                let l4 = match packet.get(header_len..) {
                    Some(s) => s,
                    None => return Classification::Unknown,
                };
                let tcp = match TcpPacket::new(l4) {
                    Some(tcp) => tcp,
                    None => return Classification::Unknown,
                };
                let src_port = tcp.get_source();
                let dst_port = tcp.get_destination();
                let tcp_header_len = (tcp.get_data_offset() as usize) * 4;
                if tcp_header_len < 20 || l4.len() < tcp_header_len {
                    return Classification::Unknown;
                }
                let payload_offset = match header_len.checked_add(tcp_header_len) {
                    Some(v) => v,
                    None => return Classification::Unknown,
                };
                let payload = match packet.get(payload_offset..) {
                    Some(p) => p,
                    None => return Classification::Unknown,
                };

                let cp = ClassifiedPacket {
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    protocol,
                    direction: PacketDirection::Outbound,
                    conn_key: ConnKey::new(src_ip, dst_ip, src_port, dst_port, protocol),
                    payload_offset,
                    payload_len: payload.len(),
                };

                if payload.len() >= 5 {
                    if payload[0] == 0x16 && payload[1] == 0x03 && payload[2] <= 0x03 {
                        return Classification::Tls(cp);
                    }
                    if payload.starts_with(b"GET ")
                        || payload.starts_with(b"POST ")
                        || payload.starts_with(b"PUT ")
                        || payload.starts_with(b"HEAD ")
                        || payload.starts_with(b"DELETE ")
                        || payload.starts_with(b"CONNECT ")
                        || payload.starts_with(b"OPTIONS ")
                    {
                        return Classification::Http(cp);
                    }
                    if payload.len() >= 24 && &payload[..24] == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
                        return Classification::Http(cp);
                    }
                }

                match dst_port {
                    443 => Classification::Tls(cp),
                    80 => Classification::Http(cp),
                    _ => Classification::Other(cp),
                }
            }
            17 => {
                let l4 = match packet.get(header_len..) {
                    Some(s) => s,
                    None => return Classification::Unknown,
                };
                let udp = match UdpPacket::new(l4) {
                    Some(udp) => udp,
                    None => return Classification::Unknown,
                };
                if l4.len() < 8 {
                    return Classification::Unknown;
                }
                let src_port = udp.get_source();
                let dst_port = udp.get_destination();
                let payload_offset = match header_len.checked_add(8) {
                    Some(v) => v,
                    None => return Classification::Unknown,
                };
                let payload = match packet.get(payload_offset..) {
                    Some(p) => p,
                    None => return Classification::Unknown,
                };

                let cp = ClassifiedPacket {
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    protocol,
                    direction: PacketDirection::Outbound,
                    conn_key: ConnKey::new(src_ip, dst_ip, src_port, dst_port, protocol),
                    payload_offset,
                    payload_len: payload.len(),
                };

                if dst_port == 53 {
                    return Classification::Dns(cp);
                }
                if !payload.is_empty() && (payload[0] & 0x80) != 0 {
                    return Classification::Quic(cp);
                }
                match dst_port {
                    443 => Classification::Quic(cp),
                    _ => Classification::Other(cp),
                }
            }
            _ => Self::classify_other(src_ip, dst_ip, protocol, header_len.min(packet.len()), packet.len()),
        }
    }
```

Также заменить `extract_sni()` preconditions, чтобы не читать `payload[43]` без длины:

```rust
        if !Self::is_client_hello(payload) || payload.len() < 44 {
            return None;
        }
```

## Критерии готовности

- Любой truncated packet возвращает `Unknown`/`Other`, но не panic.
- IPv4 non-first fragments не классифицируются как TLS/QUIC/HTTP.
- IPv6 с Destination Options перед TCP/UDP получает правильный `payload_offset`.

## Верификация

Добавить тесты в `core/src/classifier.rs`:

```rust
#[test]
fn test_classifier_truncated_tcp_no_panic() {
    let pkt = [0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0];
    let _ = Classifier::classify(&pkt);
}

#[test]
fn test_extract_sni_short_payload_no_panic() {
    assert_eq!(Classifier::extract_sni(&[0x16, 0x03, 0x03, 0, 1, 0x01]), None);
}
```

Запустить:

```bash
cargo test -p freedpi-core classifier -- --nocapture
```

---

## Обязательная встроенная конкретизация из GLM-review: IPv6 classifier должен использовать parser extension headers

## Проблема

`classifier.rs::classify_ipv6()` использует fixed `header_len = 40` и `ip.get_next_header()`, поэтому misclassifies IPv6 packets с Hop-by-Hop, Routing, Fragment, Destination Options headers. В проекте уже есть корректный `crate::desync::parse_ipv6_header()`, но classifier его не использует.

## Решение и обоснование

Использовать один source of truth для IPv6 header-chain parsing. RFC 8200 требует обрабатывать extension headers по порядку; upper-layer header может идти не сразу после 40-byte base header. Поэтому classifier обязан получать actual upper-layer protocol и offset из `parse_ipv6_header()`.

## Реализация

В `core/src/classifier.rs` заменить `classify_ipv6`:

```rust
fn classify_ipv6(packet: &[u8]) -> Classification {
    let parsed = match crate::desync::parse_ipv6_header(packet) {
        Some(h) => h,
        None => return Classification::Unknown,
    };

    // Не пытаемся классифицировать non-first fragments: TCP/UDP header может отсутствовать.
    if parsed.fragment_offset.unwrap_or(0) != 0 {
        return Classification::Other;
    }

    let src_ip = IpAddr::V6(parsed.src);
    let dst_ip = IpAddr::V6(parsed.dst);
    let protocol = parsed.protocol.0;
    let header_len = parsed.header_len;

    Self::classify_transport(packet, src_ip, dst_ip, protocol, header_len)
}
```

Также защитить `classify_transport` от slicing panic:

```rust
let transport = match packet.get(header_len..) {
    Some(s) => s,
    None => return Classification::Unknown,
};
```

и затем передавать `transport` в `TcpPacket::new`/`UdpPacket::new`, а не `&packet[header_len..]`.

## Критерии готовности

- IPv6 с no extension headers классифицируется как раньше.
- IPv6 с Hop-by-Hop/Destination Options перед TCP/UDP классифицируется правильно.
- Non-first fragments не парсятся как TCP/UDP garbage.
- `classifier.rs` больше не делает unchecked `packet[header_len..]`.

## Верификация

Добавить тесты:

```rust
#[test]
fn ipv6_hop_by_hop_tcp_uses_actual_transport_offset() {
    let pkt = build_ipv6_with_hop_by_hop_then_tcp_443_clienthello();
    match PacketClassifier::classify(&pkt) {
        Classification::Tls(cp) => assert_eq!(cp.dst_port, 443),
        other => panic!("expected TLS classification, got {other:?}"),
    }
}

#[test]
fn ipv6_non_first_fragment_is_not_classified_as_tcp() {
    let pkt = build_ipv6_fragment(offset_units = 1, more = true);
    assert!(matches!(PacketClassifier::classify(&pkt), Classification::Other));
}
```

---

---

# P0-04. Исправить TLS/QUIC layer offsets, TCP `client_isn` и QUIC DCID/SCID parsing

## Проблема

`has_non_empty_session_ticket()` и `extract_quic_pn_and_dcid()` вызываются на полном IP packet, хотя ожидают TLS record payload и raw QUIC payload. `client_isn` в conntrack остаётся `0`, поэтому `SeqSpoof` при включении строит SEQ от неправильной базы.

## Решение и обоснование

Все protocol parsers должны получать слой, для которого они написаны. Conntrack должен видеть TCP SYN до ClientHello. Реализация добавляет методы наблюдения в `Conntrack` и вызывает их из dispatch для любого TCP packet.

## Реализация

Файл: `core/src/conntrack.rs`.

Добавить методы в `impl Conntrack` после `insert()`:

```rust
    pub fn observe_tcp_syn(
        &self,
        key: ConnKey,
        client_isn: u32,
        client_ack: u32,
        conn_id: u64,
    ) {
        use dashmap::mapref::entry::Entry;
        match self.inner.map.entry(key) {
            Entry::Vacant(e) => {
                let entry = ConntrackEntry {
                    client_isn,
                    server_isn: 0,
                    client_seq: client_isn,
                    server_seq: 0,
                    client_ack,
                    server_ack: 0,
                    rtt_us: 0,
                    state: ConnState::SynSent,
                    desync_applied: false,
                    dscp_spoof: crate::desync::rand::random_range(0, 48) as u8,
                    strategy_id: 0,
                    last_activity: Instant::now(),
                    dup_ack_count: 0,
                    rng: Some(crate::desync::rand::PerConnRng::new(conn_id)),
                    is_resumption: false,
                    quic_pn: 0,
                    quic_dcid: Vec::new(),
                };
                e.insert(entry);
                self.inner.total_created.fetch_add(1, Ordering::Relaxed);
                self.inner.active_count.fetch_add(1, Ordering::Relaxed);
            }
            Entry::Occupied(mut e) => {
                let entry = e.get_mut();
                if entry.client_isn == 0 {
                    entry.client_isn = client_isn;
                }
                entry.client_seq = client_isn;
                entry.client_ack = client_ack;
                entry.state = ConnState::SynSent;
                entry.last_activity = Instant::now();
                if entry.rng.is_none() {
                    entry.rng = Some(crate::desync::rand::PerConnRng::new(conn_id));
                }
            }
        }
    }

    pub fn observe_tls_resumption(&self, key: &ConnKey, is_resumption: bool) {
        if let Some(mut entry) = self.inner.map.get_mut(key) {
            entry.is_resumption = is_resumption;
            entry.last_activity = Instant::now();
        }
    }

    pub fn observe_quic(&self, key: ConnKey, pn: u64, dcid: Vec<u8>, conn_id: u64) {
        use dashmap::mapref::entry::Entry;
        match self.inner.map.entry(key) {
            Entry::Vacant(e) => {
                let entry = ConntrackEntry {
                    client_isn: 0,
                    server_isn: 0,
                    client_seq: 0,
                    server_seq: 0,
                    client_ack: 0,
                    server_ack: 0,
                    rtt_us: 0,
                    state: ConnState::Established,
                    desync_applied: false,
                    dscp_spoof: crate::desync::rand::random_range(0, 48) as u8,
                    strategy_id: 0,
                    last_activity: Instant::now(),
                    dup_ack_count: 0,
                    rng: Some(crate::desync::rand::PerConnRng::new(conn_id)),
                    is_resumption: false,
                    quic_pn: pn,
                    quic_dcid: dcid,
                };
                e.insert(entry);
                self.inner.total_created.fetch_add(1, Ordering::Relaxed);
                self.inner.active_count.fetch_add(1, Ordering::Relaxed);
            }
            Entry::Occupied(mut e) => {
                let entry = e.get_mut();
                entry.quic_pn = pn;
                if !dcid.is_empty() {
                    entry.quic_dcid = dcid;
                }
                entry.last_activity = Instant::now();
                if entry.rng.is_none() {
                    entry.rng = Some(crate::desync::rand::PerConnRng::new(conn_id));
                }
            }
        }
    }
```

Файл: `core/src/engine/mod.rs`.

Добавить helper в `impl ProcessingPipeline` перед `process_one_sync_dispatch()`:

```rust
    fn conn_id_for(cp: &ClassifiedPacket) -> u64 {
        ip_to_u64(cp.src_ip)
            ^ (ip_to_u64(cp.dst_ip) << 32)
            ^ ((cp.src_port as u64) << 48)
            ^ (cp.dst_port as u64)
            ^ ((cp.protocol as u64) << 56)
    }

    fn observe_tcp_syn_state(&self, captured: &CapturedPacket, cp: &ClassifiedPacket) {
        if cp.protocol != 6 {
            return;
        }
        let Some(ip) = crate::desync::parse_ip_header(&captured.data) else {
            return;
        };
        let tcp_data = match captured.data.get(ip.header_len()..) {
            Some(s) => s,
            None => return,
        };
        let Some(tcp) = pnet_packet::tcp::TcpPacket::new(tcp_data) else {
            return;
        };
        let flags = tcp.get_flags();
        if (flags & pnet_packet::tcp::TcpFlags::SYN) != 0
            && (flags & pnet_packet::tcp::TcpFlags::ACK) == 0
        {
            self.conntrack.observe_tcp_syn(
                cp.conn_key,
                tcp.get_sequence(),
                tcp.get_acknowledgement(),
                Self::conn_id_for(cp),
            );
        }
    }

    fn observe_classified_tcp_state(&self, captured: &CapturedPacket, classification: &Classification) {
        match classification {
            Classification::Tls(cp)
            | Classification::Http(cp)
            | Classification::Other(cp) if cp.protocol == 6 => self.observe_tcp_syn_state(captured, cp),
            _ => {}
        }
    }
```

В начале `process_one_sync_dispatch()`, сразу после:

```rust
        let classification = Classifier::classify(&captured.data);
```

добавить:

```rust
        self.observe_classified_tcp_state(captured, &classification);
```

В TLS branch заменить небезопасный slice:

```rust
                let payload = match captured.data.get(cp.payload_offset..) {
                    Some(p) => p,
                    None => return Ok(PacketDecision::Forward),
                };
                let mut should_desync = false;
                if Classifier::is_client_hello(payload) && payload.len() >= 50 {
                    should_desync = self.conntrack.check_and_apply_desync(conn_key, || {
                        Self::conn_id_for(&cp)
                    });
                }
```

В `process_outbound_tls_sync()` заменить resumption block:

```rust
        let is_resumption = captured
            .data
            .get(cp.payload_offset..)
            .map(has_non_empty_session_ticket)
            .unwrap_or(false);
        self.conntrack.observe_tls_resumption(&conn_key, is_resumption);
```

В `process_quic_sync()` заменить весь conntrack block на:

```rust
        let quic_payload = match captured.data.get(cp.payload_offset..) {
            Some(p) => p,
            None => return Ok(PacketDecision::Forward),
        };
        if let Some((pn, dcid)) = crate::desync::quic::extract_quic_pn_and_dcid(quic_payload) {
            self.conntrack.observe_quic(cp.conn_key, pn, dcid, Self::conn_id_for(cp));
        }
```

## Критерии готовности

- TLS resumption detector получает payload, начинающийся с TLS record type `0x16`, а не `0x45/0x60`.
- QUIC PN/DCID extractor получает raw UDP payload.
- TCP SYN до ClientHello сохраняет `client_isn != 0` для flow.
- `SeqSpoof` не использует `0` как fallback, если SYN уже был виден.

## Верификация

Добавить unit test в `conntrack.rs`:

```rust
#[test]
fn test_observe_tcp_syn_updates_existing_zero_isn() {
    let ct = Conntrack::default();
    let key = test_key();
    let mut e = test_entry();
    e.client_isn = 0;
    ct.insert(key, e);
    ct.observe_tcp_syn(key, 12345, 0, 42);
    assert_eq!(ct.get(&key).unwrap().client_isn, 12345);
}
```

Запустить:

```bash
cargo test -p freedpi-core conntrack -- --nocapture
cargo check --workspace --all-targets
```

---

## Обязательная встроенная конкретизация из GLM-review: QUIC layer parsing и PN-gap quarantine

## Проблема

`engine/mod.rs` вызывает `extract_quic_pn_and_dcid(&packet)`, где `packet` — полный IP packet. Функция в `desync/quic.rs` ожидает QUIC packet layer. В результате первый байт — `0x45` или `0x60`, а не QUIC first byte; parser уходит в неверную ветку и пишет garbage/zero в conntrack.

Дополнительная проблема: даже если передать правильный UDP payload, QUIC packet number нельзя корректно извлечь обычным slicing: packet number truncated to 1..4 bytes и header-protected. Без снятия header protection и packet number decoding контекстом PN gap detection является ложной подсистемой.

## Решение и обоснование

Разделить функцию на две:

1. `extract_quic_long_header_ids(udp_payload: &[u8]) -> Option<QuicLongHeaderIds>` — безопасно читает version, DCID, SCID, token offset, length offset из QUIC long header до encrypted payload.
2. `extract_quic_pn_and_dcid` удалить из decision path или переименовать в `extract_quic_visible_ids_only`; PN не использовать для принятия решений, пока не реализовано снятие header protection.

Для адаптации и anti-replay достаточно DCID/SCID + five-tuple + first-flight marker. PN-based logic в текущем виде не должна влиять на packet path.

## Реализация

В `core/src/desync/quic.rs` добавить:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicLongHeaderIds<'a> {
    pub first_byte: u8,
    pub version: u32,
    pub dcid: &'a [u8],
    pub scid: &'a [u8],
}

pub fn extract_quic_long_header_ids(packet: &[u8]) -> Option<QuicLongHeaderIds<'_>> {
    if packet.len() < 7 {
        return None;
    }
    let first = packet[0];
    if (first & 0x80) == 0 || (first & 0x40) == 0 {
        return None;
    }
    let version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);
    if version == 0 {
        return None; // Version Negotiation is not a client Initial candidate.
    }

    let dcid_len = packet[5] as usize;
    if dcid_len > 20 || 6 + dcid_len >= packet.len() {
        return None;
    }
    let dcid_start = 6;
    let dcid_end = dcid_start + dcid_len;

    let scid_len = *packet.get(dcid_end)? as usize;
    if scid_len > 20 || dcid_end + 1 + scid_len > packet.len() {
        return None;
    }
    let scid_start = dcid_end + 1;
    let scid_end = scid_start + scid_len;

    Some(QuicLongHeaderIds {
        first_byte: first,
        version,
        dcid: &packet[dcid_start..dcid_end],
        scid: &packet[scid_start..scid_end],
    })
}
```

В `engine/mod.rs::process_quic_sync` заменить вычисление PN/DCID на UDP payload:

```rust
let udp_payload_offset = ip.header_len() + 8;
let quic_payload = match packet.get(udp_payload_offset..) {
    Some(p) => p,
    None => return Ok(PacketDecision::Forward),
};
let quic_ids = crate::desync::quic::extract_quic_long_header_ids(quic_payload);
let quic_dcid: smallvec::SmallVec<[u8; 20]> = quic_ids
    .as_ref()
    .map(|ids| ids.dcid.iter().copied().collect())
    .unwrap_or_default();
```

Удалить/обнулить запись `quic_pn` в conntrack или заменить её на `Option<u64>` с `None`:

```rust
entry.quic_pn = None;
entry.quic_dcid.clear();
entry.quic_dcid.extend_from_slice(&quic_dcid);
```

Если `ConntrackEntry.quic_pn` сейчас `u64`, заменить на `Option<u64>` и обновить все вызывающие места. Если это слишком широкий diff для первого патча, оставить поле `u64`, но всегда писать `0` и добавить комментарий:

```rust
// QUIC PN is header-protected and cannot be decoded here without QUIC-TLS keys.
entry.quic_pn = 0;
```

## Критерии готовности

- Ни один QUIC parser в engine не получает full IP packet, если ожидает QUIC layer.
- DCID/SCID извлекаются только из long header UDP payload.
- PN gap detection не заявляется и не влияет на решения, пока нет header-protection removal.
- Tests покрывают IPv4+UDP offset и IPv6+extension-header+UDP offset.

## Верификация

Unit tests в `desync/quic.rs`:

```rust
#[test]
fn extracts_long_header_dcid_scid_from_udp_payload() {
    let pkt = [
        0xC0, 0x00, 0x00, 0x00, 0x01, // Initial, version 1
        0x08, 1,2,3,4,5,6,7,8,        // DCID
        0x04, 9,10,11,12,              // SCID
        0x00,                          // token length varint=0
        0x40, 0x10,                    // length varint reserved for later backpatch in this function
        0x00,                          // packet number byte reserved for later backpatch in this function
    ];
    let ids = extract_quic_long_header_ids(&pkt).unwrap();
    assert_eq!(ids.version, 1);
    assert_eq!(ids.dcid, &[1,2,3,4,5,6,7,8]);
    assert_eq!(ids.scid, &[9,10,11,12]);
}

#[test]
fn rejects_full_ipv4_packet_as_quic_payload() {
    let pkt = [0x45, 0, 0, 0, 0, 0, 0, 0];
    assert!(extract_quic_long_header_ids(&pkt).is_none());
}
```

---

---

# P0-05. Исправить `DscpRandom`: IPv4 и IPv6 имеют разные layout и checksum semantics

## Проблема

`core/src/desync/ip.rs::dscp_random()` сейчас читает DSCP как `(packet[1] >> 2) & 0x3F`, пишет `modified[1]`, а затем всегда обновляет bytes `10..12` как IPv4 header checksum. Для IPv6 это корраптит пакет: IPv6 не имеет header checksum, а поле Traffic Class не совпадает с IPv4 TOS byte layout. В IPv6 первые 32 бита — `Version | Traffic Class | Flow Label`, то есть Traffic Class занимает младшие 4 бита byte 0 и старшие 4 бита byte 1.

## Решение и обоснование

Разделить реализацию на `dscp_random_v4()` и `dscp_random_v6()`:

- IPv4: менять byte 1 целиком как DSCP+ECN и обновлять IPv4 checksum инкрементально.
- IPv6: менять Traffic Class через bytes 0/1, сохранять Version и Flow Label, **не** трогать никакой checksum.

Это соответствует фактической структуре IPv6 base header: Traffic Class — отдельное 8-битное поле после 4-битного Version, а extension headers находятся после фиксированного заголовка и не меняют расположение Traffic Class.

## Реализация

Полностью заменить `pub fn dscp_random(...)` в `core/src/desync/ip.rs` на:

```rust
pub fn dscp_random(packet: &[u8], dscp_value: u8) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };

    match ip {
        ParsedIpHeader::V4(_) => dscp_random_v4(packet, dscp_value),
        ParsedIpHeader::V6(_) => dscp_random_v6(packet, dscp_value),
    }
}

#[inline]
fn dscp_random_v4(packet: &[u8], dscp_value: u8) -> DesyncResult {
    if packet.len() < 20 {
        return DesyncResult::passthrough();
    }

    let current_tos = packet[1];
    let current_dscp = current_tos >> 2;
    let ecn = current_tos & 0x03;
    let new_dscp = dscp_value & 0x3F;
    let new_tos = (new_dscp << 2) | ecn;

    if new_tos == current_tos {
        return DesyncResult::passthrough();
    }

    let mut modified = packet.to_vec();
    modified[1] = new_tos;

    // IPv4 checksum covers 16-bit words. DSCP/ECN is the low byte of word [0]=Version/IHL,TOS.
    let old_word = u16::from_be_bytes([packet[0], packet[1]]);
    let new_word = u16::from_be_bytes([modified[0], modified[1]]);
    let old_csum = u16::from_be_bytes([packet[10], packet[11]]);
    let new_csum = crate::desync::update_checksum_word(old_csum, old_word, new_word);
    modified[10..12].copy_from_slice(&new_csum.to_be_bytes());

    debug!("[CT4] DscpRandom IPv4: DSCP {} -> {}", current_dscp, new_dscp);
    DesyncResult::modified_only(modified)
}

#[inline]
fn dscp_random_v6(packet: &[u8], dscp_value: u8) -> DesyncResult {
    if packet.len() < 40 || (packet[0] >> 4) != 6 {
        return DesyncResult::passthrough();
    }

    let version = packet[0] & 0xF0;
    let old_tc = ((packet[0] & 0x0F) << 4) | (packet[1] >> 4);
    let old_dscp = old_tc >> 2;
    let ecn = old_tc & 0x03;
    let new_dscp = dscp_value & 0x3F;
    let new_tc = (new_dscp << 2) | ecn;

    if new_tc == old_tc {
        return DesyncResult::passthrough();
    }

    let mut modified = packet.to_vec();

    // byte0: Version high nibble + TrafficClass high nibble.
    modified[0] = version | (new_tc >> 4);
    // byte1: TrafficClass low nibble + FlowLabel high nibble; preserve low nibble.
    modified[1] = (new_tc << 4) | (packet[1] & 0x0F);

    // IPv6 has no header checksum. Do not touch bytes 10..12 or any pseudo-header fields.
    debug!("[CT4] DscpRandom IPv6: DSCP {} -> {}", old_dscp, new_dscp);
    DesyncResult::modified_only(modified)
}
```

## Критерии готовности

- Для IPv4 меняется только DSCP bits и IPv4 header checksum.
- Для IPv6 меняются только Traffic Class bits; Version и Flow Label сохраняются.
- Для IPv6 функция не пишет в `modified[10..12]`.
- Для одинакового DSCP функция возвращает passthrough, а не создаёт лишний modified packet.

## Верификация

Добавить тесты в `core/src/desync/ip.rs`:

```rust
#[test]
fn dscp_random_v6_preserves_version_and_flow_label() {
    let mut pkt = vec![0u8; 40 + 8];
    pkt[0] = 0x60; // Version=6, TC high=0
    pkt[1] = 0x0A; // Flow label high nibble = 0xA
    pkt[2] = 0xBC;
    pkt[3] = 0xDE;
    pkt[4..6].copy_from_slice(&8u16.to_be_bytes());
    pkt[6] = 17;
    pkt[7] = 64;

    let out = dscp_random(&pkt, 0x2A);
    let modified = out.modified.expect("IPv6 DSCP must modify packet");

    assert_eq!(modified[0] >> 4, 6);
    let tc = ((modified[0] & 0x0F) << 4) | (modified[1] >> 4);
    assert_eq!(tc >> 2, 0x2A);
    assert_eq!(modified[1] & 0x0F, pkt[1] & 0x0F);
    assert_eq!(&modified[2..4], &pkt[2..4]);
}

#[test]
fn dscp_random_ipv6_does_not_touch_source_address_prefix() {
    let mut pkt = vec![0u8; 40 + 8];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&8u16.to_be_bytes());
    pkt[6] = 17;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&[0xAA; 16]);

    let out = dscp_random(&pkt, 0x10);
    let modified = out.modified.expect("IPv6 DSCP must modify packet");
    assert_eq!(&modified[8..24], &[0xAA; 16]);
}
```

---

---

# P0-06. Исправить checksum в `tls_record_pad`: использовать реальный IPv4 IHL, не `[..20]`

## Проблема

`core/src/desync/tls.rs::tls_record_pad()` после вставки padding пересчитывает IP checksum так:

```rust
let ip_csum = crate::desync::ipv4_checksum(&modified[..20]);
```

Это неверно для IPv4 packets с options (`IHL > 5`), потому что checksum считается по полному IPv4 header, а не только по первым 20 байтам. В результате пакет с IP options после TLS padding получает некорректный IPv4 checksum.

## Решение и обоснование

Использовать `ip.header_len()` из уже распарсенного `ParsedIpHeader`. Для IPv4 это `IHL * 4`. Для IPv6 header checksum отсутствует; поэтому обновлять IPv4 checksum нужно только в ветке `ParsedIpHeader::V4`.

## Реализация

В `tls_record_pad()` заменить блок пересчёта IP checksum на:

```rust
match ip {
    crate::desync::ParsedIpHeader::V4(_) => {
        let ihl = ip.header_len();
        if ihl < 20 || ihl > modified.len() {
            return DesyncResult::passthrough();
        }
        modified[10] = 0;
        modified[11] = 0;
        let ip_csum = crate::desync::ipv4_checksum(&modified[..ihl]);
        modified[10..12].copy_from_slice(&ip_csum.to_be_bytes());
    }
    crate::desync::ParsedIpHeader::V6(_) => {
        // IPv6 has no header checksum. Total length update must be IPv6-specific if supported.
    }
}
```

Также исправить обновление total length: текущий код всегда пишет `modified[2..4]` как IPv4 total length. Для IPv6 эти bytes являются частью Traffic Class / Flow Label. Поэтому в этой же функции сделать:

```rust
match ip {
    crate::desync::ParsedIpHeader::V4(_) => {
        let new_total = modified.len() as u16;
        modified[2..4].copy_from_slice(&new_total.to_be_bytes());
    }
    crate::desync::ParsedIpHeader::V6(_) => {
        let payload_len = modified.len().saturating_sub(40);
        if payload_len > u16::MAX as usize {
            return DesyncResult::passthrough();
        }
        modified[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    }
}
```

Если `tls_record_pad()` фактически не поддерживает IPv6 TCP checksum with extension headers, то для IPv6 она должна явно возвращать passthrough до полной поддержки:

```rust
if matches!(ip, crate::desync::ParsedIpHeader::V6(_)) {
    return DesyncResult::passthrough();
}
```

Выбрать один путь. Рекомендация для первого патча: **сделать IPv6 passthrough**, потому что корректный TCP checksum для IPv6 при extension headers требует использовать upper-layer length без extension headers. IPv4 correctness важнее и безопаснее.

## Критерии готовности

- IPv4 packets с IHL=5 и IHL>5 получают корректный checksum.
- Функция больше не пишет IPv4 total length поля в IPv6 packet.
- Если IPv6 не поддержан, он явно passthrough, а не silent corruption.

## Верификация

Добавить тест с искусственным IPv4 header length 24 bytes:

```rust
#[test]
fn tls_record_pad_uses_full_ipv4_ihl_for_checksum() {
    let packet = build_ipv4_tcp_tls_clienthello_with_ip_options(4); // helper in tests only
    let out = tls_record_pad(&packet, 8, 1);
    let modified = out.modified.expect("padding must modify packet");
    let ihl = ((modified[0] & 0x0F) as usize) * 4;
    assert_eq!(ihl, 24);
    let mut hdr = modified[..ihl].to_vec();
    hdr[10] = 0;
    hdr[11] = 0;
    let expected = crate::desync::ipv4_checksum(&hdr);
    let actual = u16::from_be_bytes([modified[10], modified[11]]);
    assert_eq!(actual, expected);
}
```

Если helper ещё отсутствует, сделать его в тестовом модуле полностью: IPv4 header с IHL=6, TCP header 20 bytes, минимальный TLS ClientHello record payload; заполнить checksums до вызова.

---

---

# P0-07. Перестать считать local generation outcome как AutoTune success

## Проблема

Hot path пишет `tune.record(profile, success, latency)` сразу после применения desync, где `success = inject || modified`. Это не успех обхода DPI, а факт локальной генерации результата. После P0-01 ложный success уменьшится, но метрика всё равно математически неверна.

## Решение и обоснование

Разделить две метрики:

- `record_application(profile, changed, latency)` — локальная cost/changed metric.
- `record_outcome(strategy_id, FlowOutcome, latency)` — реальный результат соединения.

AutoTune должен принимать решения только по outcome. До внедрения полного outcome observer горячий path не должен увеличивать success/fail. Это сохраняет адаптацию честной: лучше отсутствие решения, чем ложная уверенность.

## Реализация

Файл: `core/src/adaptive/auto_tune.rs`.

Добавить enum:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowOutcome {
    Established,
    ResponseSeen,
    QuicOneRttSeen,
    Timeout,
    Reset,
    IcmpUnreachable,
}

impl FlowOutcome {
    #[inline]
    pub fn is_success(self) -> bool {
        matches!(self, Self::Established | Self::ResponseSeen | Self::QuicOneRttSeen)
    }
}
```

Добавить atomics в `StrategyMetrics`:

```rust
    pub applied_count: AtomicU64,
    pub changed_count: AtomicU64,
    pub application_latency_us: AtomicU64,
```

Обновить `StrategyMetrics::new()`:

```rust
                applied_count: AtomicU64::new(0),
                changed_count: AtomicU64::new(0),
                application_latency_us: AtomicU64::new(0),
```

Добавить методы:

```rust
    pub fn avg_application_latency_us(&self) -> u64 {
        let n = self.applied_count.load(Ordering::Relaxed);
        if n == 0 { return 0; }
        self.application_latency_us.load(Ordering::Relaxed) / n
    }
```

В `impl AutoTune` добавить:

```rust
    pub fn record_application(&mut self, strategy_name: &str, changed: bool, latency_us: u64) {
        let idx = self.get_or_create_index(strategy_name);
        let m = &self.metrics[idx];
        m.applied_count.fetch_add(1, Ordering::Relaxed);
        if changed {
            m.changed_count.fetch_add(1, Ordering::Relaxed);
        }
        m.application_latency_us.fetch_add(latency_us, Ordering::Relaxed);
    }

    pub fn record_outcome(&mut self, strategy_name: &str, outcome: FlowOutcome, latency_us: u64) {
        self.record(strategy_name, outcome.is_success(), latency_us);
    }
```

В `StrategySnapshot` добавить поля:

```rust
    pub applied_count: u64,
    pub changed_count: u64,
    pub avg_application_latency_us: u64,
```

Обновить `get_metrics()` и `all_metrics()`, добавив эти поля из atomics.

Файл: `core/src/engine/mod.rs`.

В TLS/QUIC/HTTP processing заменить блоки `success = ...; tune.record(...)` на:

```rust
        {
            let latency_us = tune_start.elapsed().as_micros() as u64;
            let changed = !result.inject.is_empty() || result.modified.is_some() || result.drop;
            let mut tune = self.auto_tune.lock().unwrap();
            tune.record_application(&profile.name, changed, latency_us);
        }
```

Не вызывать `should_escalate()` на application metric. Escalation вернётся в P2-02 после outcome observer.

## Критерии готовности

- `success_count/fail_count` больше не меняются от самого факта вызова desync техники.
- `applied_count/changed_count` отражают локальный pipeline cost.
- `recommend()` до появления outcome использует manual overrides или default params, но не выдумывает успех.

## Верификация

Добавить тест:

```rust
#[test]
fn test_record_application_does_not_affect_success_rate() {
    let mut tune = AutoTune::new();
    tune.record_application("x", true, 100);
    let m = tune.get_metrics("x").unwrap();
    assert_eq!(m.success_count, 0);
    assert_eq!(m.fail_count, 0);
    assert_eq!(m.applied_count, 1);
    assert_eq!(m.changed_count, 1);
}
```

---

---


---

# P0-08. Исправить buffer-pool ownership: убрать `CapturedPacket.data.clone()` lifetime bug

## Проблема

В `core/src/engine/mod.rs::worker_loop` packet из pool превращается в `CapturedPacket` через `data.clone()`. В ветках `PacketDecision::Modify` и `PacketDecision::Drop` код вызывает `pool.release_bytes(data)`, пока `captured.data` ещё жив. `PacketBufferPool::release_bytes()` вызывает `Bytes::try_into_mut()`, а эта операция возвращает allocation в `BytesMut` только при уникальном ownership. Пока существует `captured.data`, refcount > 1, поэтому pool silently misses именно на packets, которые система активно обрабатывает.

Итог: pool работает для passthrough/Forward, но не для desync/drop/modify hot path. Это разрушает заявленный steady-state zero-allocation и вносит malloc/free в самый важный путь.

## Решение и обоснование

Минимальный фикс `drop(captured)` перед `release_bytes(data)` исправляет lifetime, но оставляет atomic refcount bump/drop на каждый packet. Полноценный фикс для V4: убрать owning `CapturedPacket` из hot path. `process_one_sync()` и `process_one_sync_dispatch()` должны принимать borrow:

```rust
pub(crate) fn process_one_sync_dispatch(
    &self,
    data: &bytes::Bytes,
    addr: &WinDivertAddress<NetworkLayer>,
) -> Result<PacketDecision, anyhow::Error>
```

`CapturedPacket` можно оставить только для queue ownership между capture-thread и shard-worker после P1-00, но не для classification/processing внутри worker. Это устраняет и pool bug, и atomic clone overhead.

## Реализация

Файл `core/src/engine/mod.rs`.

1. Изменить сигнатуры:

```rust
pub(crate) fn process_one_sync(
    &self,
    data: &bytes::Bytes,
    addr: &WinDivertAddress<NetworkLayer>,
) -> Result<PacketDecision, anyhow::Error> {
    self.process_one_sync_dispatch(data, addr)
}

pub(crate) fn process_one_sync_dispatch(
    &self,
    data: &bytes::Bytes,
    addr: &WinDivertAddress<NetworkLayer>,
) -> Result<PacketDecision, anyhow::Error> {
    let classification = Classifier::classify(data);
    // все бывшие captured.data -> data
    // все бывшие captured.addr -> addr
    // если downstream требует owned Bytes, использовать data.clone() только в той ветке,
    // где реально нужен owned packet для modified/inject result.
}
```

2. В `worker_loop` заменить pattern:

```rust
let captured = CapturedPacket { data: data.clone(), addr: addr.clone() };
match pipeline.process_one_sync(&captured) { ... }
```

на:

```rust
match pipeline.process_one_sync(&data, &addr) {
    Ok(PacketDecision::Forward) => {
        forward_batch.push((data, addr));
    }
    Ok(PacketDecision::Modify(modified)) => {
        pool.release_bytes(data);
        forward_batch.push((modified, addr));
    }
    Ok(PacketDecision::Drop) => {
        pool.release_bytes(data);
        pipeline.stats.dropped.fetch_add(1, Ordering::Relaxed);
    }
    Ok(PacketDecision::Desync { inject, modified, inject_protocol, inter_delay_us }) => {
        // old logic unchanged, но release original только после того, как нет clone data.
        if let Some(modified) = modified {
            pool.release_bytes(data);
            forward_batch.push((modified, addr.clone()));
        } else {
            forward_batch.push((data, addr.clone()));
        }
        // inject handling remains as in current code.
    }
    Err(e) => {
        tracing::debug!("Packet processing error: {}", e);
        forward_batch.push((data, addr));
        pipeline.stats.errors.fetch_add(1, Ordering::Relaxed);
    }
}
```

3. Если `CapturedPacket` используется как queue item в P1-00, изменить его назначение:

```rust
pub(crate) struct CapturedPacket {
    pub data: bytes::Bytes,
    pub addr: WinDivertAddress<NetworkLayer>,
}
```

Но внутри shard worker сразу передавать borrow `&pkt.data`, `&pkt.addr`; не клонировать `Bytes` для classification.

4. Добавить pool metrics:

```rust
pub struct PacketBufferPool {
    pool: ArrayQueue<BytesMut>,
    returned: AtomicU64,
    return_miss_shared: AtomicU64,
}

pub fn release_bytes(&self, packet: Bytes) {
    match packet.try_into_mut() {
        Ok(buf) => {
            self.returned.fetch_add(1, Ordering::Relaxed);
            self.release(buf);
        }
        Err(_) => {
            self.return_miss_shared.fetch_add(1, Ordering::Relaxed);
        }
    }
}
```

Если текущий `Bytes::try_into_mut()` возвращает `Result<BytesMut, Bytes>` в используемой версии crate, использовать `Err(_)`; если возвращает `Result<BytesMut, Bytes>`, код выше компилируется. Агент обязан сверить точную сигнатуру установленной версии `bytes` по `Cargo.lock`.

## Критерии готовности

- В hot path нет `CapturedPacket { data: data.clone(), ... }` перед `process_one_sync`.
- `release_bytes(data)` в `Modify`/`Drop` вызывается при unique ownership исходного `Bytes`.
- Pool hit-rate для modify/drop/desync packets > 95% в synthetic test без intentional clones.
- `Bytes::clone()` на packet path остаётся только там, где нужен owned `Bytes` для inject/modified result и это зафиксировано комментарием.

## Верификация

Unit test для pool:

```rust
#[test]
fn pool_release_fails_while_bytes_is_cloned_and_succeeds_after_drop() {
    let pool = PacketBufferPool::new(8, 2048);
    let mut b = bytes::BytesMut::with_capacity(2048);
    b.extend_from_slice(&[1, 2, 3, 4]);
    let bytes = b.freeze();
    let cloned = bytes.clone();
    pool.release_bytes(bytes);
    assert_eq!(pool.return_miss_shared(), 1);
    drop(cloned);

    let mut b2 = bytes::BytesMut::with_capacity(2048);
    b2.extend_from_slice(&[5, 6, 7, 8]);
    let unique = b2.freeze();
    pool.release_bytes(unique);
    assert_eq!(pool.returned(), 1);
}
```

Integration/perf check:

```powershell
cargo test -p freedpi-core pool_release
cargo test -p freedpi-core worker_loop_does_not_clone_packet_for_classification
```

Runtime metrics gate under synthetic desync workload:

- `pool.return_miss_shared / processed_modified < 0.01`.
- allocator sample no longer shows allocation per modified/drop packet.


---


# P0-09. Заменить XOR-fold IPv6/tuple mixing на keyed full-5-tuple `FlowKey` и `conn_id`

## Проблема

DeepSeek-review указал на `ip_to_u64(IpAddr::V6)` через `upper ^ lower` и последующий `conn_id = src ^ dst << 32 ^ ports`. Даже если фактическая collision rate зависит от распределения IPv6 адресов, сама схема теряет структуру 128-bit адресов, плохо смешивает tuple и делает per-connection RNG/fingerprint variability зависимой от предсказуемого XOR-fold. Это особенно плохо после P1-00, где `FlowKey` становится базой flow-affinity, conntrack и per-connection randomization.

## Решение и обоснование

Ввести один canonical `FlowKey` для TCP/UDP flows и отдельный `ConnIdHasher` для RNG/conn_id. Для flow-affinity можно использовать быстрый stable hash, но для RNG seed/conn_id нужен process-secret keyed hasher над полным normalized 5-tuple. Не использовать `DefaultHasher` как контракт: Rust документация говорит, что default hashing algorithm сейчас SipHash 1-3, но может измениться.

## Реализация

Добавить модуль `core/src/flow_key.rs` или разместить рядом с conntrack, если там уже есть tuple/key types. Не плодить две несовместимые модели tuple.

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Endpoint {
    pub ip: std::net::IpAddr,
    pub port: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct FlowKey {
    pub proto: u8,
    pub a: Endpoint,
    pub b: Endpoint,
}

impl FlowKey {
    pub fn new_bidirectional(
        proto: u8,
        src_ip: std::net::IpAddr,
        src_port: u16,
        dst_ip: std::net::IpAddr,
        dst_port: u16,
    ) -> Self {
        let src = Endpoint { ip: src_ip, port: src_port };
        let dst = Endpoint { ip: dst_ip, port: dst_port };
        let src_key = endpoint_sort_key(src);
        let dst_key = endpoint_sort_key(dst);
        if src_key <= dst_key {
            Self { proto, a: src, b: dst }
        } else {
            Self { proto, a: dst, b: src }
        }
    }
}

fn endpoint_sort_key(e: Endpoint) -> ([u8; 16], u16) {
    let ip = match e.ip {
        std::net::IpAddr::V4(v4) => {
            let mut out = [0u8; 16];
            out[12..].copy_from_slice(&v4.octets());
            out
        }
        std::net::IpAddr::V6(v6) => v6.octets(),
    };
    (ip, e.port)
}

pub struct ConnIdHasher {
    k0: u64,
    k1: u64,
}

impl ConnIdHasher {
    pub fn new_from_os_rng() -> Self {
        let mut seed = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut seed);
        Self {
            k0: u64::from_le_bytes(seed[0..8].try_into().unwrap()),
            k1: u64::from_le_bytes(seed[8..16].try_into().unwrap()),
        }
    }

    #[inline]
    pub fn conn_id(&self, key: &FlowKey) -> u64 {
        use siphasher::sip::SipHasher13;
        use std::hash::{Hash, Hasher};
        let mut h = SipHasher13::new_with_keys(self.k0, self.k1);
        key.hash(&mut h);
        h.finish()
    }
}
```

Если `siphasher` ещё не в dependencies, добавить его в `core/Cargo.toml`. Если проект уже использует другой keyed hasher с явными ключами, можно использовать его, но нельзя использовать `upper ^ lower` или `DefaultHasher` как стабильный security-sensitive контракт.

Обновить все места, где строится `conn_id`, `ConnKey`, flow-affinity worker index и per-connection RNG fork. Нельзя оставить часть кода на старом XOR-fold, иначе разные подсистемы будут считать разные идентификаторы одного flow.

## Критерии готовности

- `rg -n "ip_to_u64|upper \^ lower|to_bits\(\).*<< 32" core/src` не находит старого conn_id mixing в production path.
- IPv4 и IPv6 используют один `FlowKey` foundation.
- Per-flow worker index и per-connection RNG seed строятся из одного canonical tuple, но могут использовать разные hasher keys.
- Unit test: два направления одного TCP flow дают один `FlowKey`.
- Unit test: IPv6 адреса в одной `/64` с разными lower bits дают разные `conn_id`.

## Верификация

```bash
cargo test -p freedpi-core flow_key
cargo test -p freedpi-core conn_id_ipv6_no_xor_fold_collision_smoke
rg -n "ip_to_u64|upper \^ lower" core/src
```

---

# P0-10. Direction-aware inject model: не терять `DesyncResult.is_outbound_inject` и не inject'ить RST в локальный стек

## Проблема

Gemini-review указал на баг, который подтверждается текущим кодом: `DesyncResult` уже содержит `is_outbound_inject`, `rst_selective` выставляет его в `true`, но при преобразовании результата в `PacketDecision::Desync` это поле теряется. Worker затем делает inject через `addr.clone()` исходного packet. Если техника сгенерировала fake RST при обработке inbound packet, WinDivert address остаётся inbound, и RST уходит в локальный TCP/IP stack клиента, а не наружу в сторону сервера/DPI.

Это не косметика. Для WinDivert направление reinjection задаётся metadata address: outbound inject отправляет packet как покидающий локальную машину, inbound inject — как прибывающий к ней. Поэтому direction является частью семантики packet, а не просто свойством IP/TCP tuple.

## Решение и обоснование

Нельзя передавать direction одним bool на весь `PacketDecision::Desync`, потому что один результат может содержать разные inject packets: fake TTL, fake RST, retry/close, delayed fragments. Нужно ввести per-packet wrapper.

## Реализация

Добавить тип:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectDirection {
    PreserveOriginal,
    ForceOutbound,
    ForceInbound,
    DerivedFromPacketTuple,
}

#[derive(Debug, Clone)]
pub struct InjectPacket {
    pub bytes: bytes::Bytes,
    pub protocol: InjectProtocol,
    pub direction: InjectDirection,
    pub inter_delay_us: u32,
}
```

Заменить в `DesyncResult` / `PacketDecision::Desync` поле `inject: SmallVec<[Bytes; 4]>` на `inject: SmallVec<[InjectPacket; 4]>` либо, если миграция слишком велика для одного PR, добавить параллельное поле `inject_meta: SmallVec<[InjectDirection; 4]>` с обязательной проверкой одинаковой длины. Предпочтителен первый вариант.

Маппинг legacy helpers:

```rust
impl InjectPacket {
    pub fn preserve(bytes: bytes::Bytes, protocol: InjectProtocol, inter_delay_us: u32) -> Self {
        Self { bytes, protocol, direction: InjectDirection::PreserveOriginal, inter_delay_us }
    }

    pub fn force_outbound(bytes: bytes::Bytes, protocol: InjectProtocol, inter_delay_us: u32) -> Self {
        Self { bytes, protocol, direction: InjectDirection::ForceOutbound, inter_delay_us }
    }
}
```

`rst_selective` обязан возвращать `InjectPacket::force_outbound(...)`. Worker обязан применять direction перед send:

```rust
let mut inject_addr = addr.clone();
match inject.direction {
    InjectDirection::PreserveOriginal => {}
    InjectDirection::ForceOutbound => inject_addr.set_outbound(true),
    InjectDirection::ForceInbound => inject_addr.set_outbound(false),
    InjectDirection::DerivedFromPacketTuple => {
        let outbound = infer_outbound_from_tuple(&inject.bytes, &pipeline.local_addr_table)
            .unwrap_or(addr.is_outbound());
        inject_addr.set_outbound(outbound);
    }
}
inject_batch.push((inject.bytes, inject_addr));
```

Если текущая WinDivert wrapper использует `Direction` enum вместо `set_outbound(bool)`, использовать фактические методы wrapper из архива. Не писать новый abstraction без проверки сигнатур.

## Критерии готовности

- `rg "is_outbound_inject"` показывает, что поле больше не теряется между `DesyncResult` и worker send path.
- `rst_selective` явно force-outbound.
- Ни один inject packet не наследует inbound direction случайно, если техника требует outbound.
- Direction задан per-inject, а не одним bool на весь result.

## Верификация

Добавить unit/integration test:

```rust
#[test]
fn rst_selective_from_inbound_trigger_is_injected_outbound() {
    // Build inbound SYN-ACK-like captured address.
    // Apply rst_selective path.
    // Assert generated InjectPacket.direction == ForceOutbound.
    // Assert worker address rewrite sets outbound true before send.
}
```

Добавить grep gate:

```bash
rg "PacketDecision::Desync" core/src/engine core/src/desync
rg "addr\.clone\(\).*inject" core/src/engine && exit 1 || true
```

# P0-11. TCP real-vs-decoy fragment invariant: `tls_record_frag`, `multisplit`, `multidisorder_new` не должны пересылать original CH или сжигать real bytes TTL'ом

## Проблема

Gemini-review указал две связанные ошибки, которые нужно закрывать не точечной правкой, а инвариантом:

1. `tls_record_frag` формирует inject fragments, но может оставлять `modified = None` и `drop = false`; тогда worker пересылает оригинальный полный ClientHello вместе с фрагментами. DPI всё равно видит исходный CH, а сервер получает перекрывающиеся TCP ranges.
2. `multisplit` / `multidisorder_new` могут отправлять первые реальные bytes TLS ClientHello с fake TTL, который не доходит до сервера. Сервер получает только хвост, видит TCP sequence gap и зависает на duplicate ACKs.

## Решение и обоснование

Нужно различать два класса packets:

- `RealPath`: bytes, которые нужны серверу для корректной TCP reassembly. Они обязаны идти с нормальным TTL/HopLimit и корректной SEQ continuity.
- `DecoyPath`: fake/overlap/poison bytes, которые предназначены для DPI и не должны быть необходимы серверу.

Любая техника split/fragment/disorder должна проходить server-reassembly simulation: если удалить все low-TTL/decoy packets, сервер всё равно должен собрать исходный real payload из normal-TTL path.

## Реализация

Добавить classification для generated segments:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentRole {
    RealPath,
    DecoyPath,
}

#[derive(Debug, Clone)]
pub struct InjectPacket {
    pub bytes: bytes::Bytes,
    pub protocol: InjectProtocol,
    pub direction: InjectDirection,
    pub role: SegmentRole,
    pub inter_delay_us: u32,
}
```

Если `role == RealPath`, builder обязан использовать original TTL/HopLimit. Low TTL разрешён только для `DecoyPath`.

Для `tls_record_frag` запрещён результат вида:

```text
inject != empty && modified == None && drop == false
```

если inject packets содержат real bytes исходного ClientHello. Правильные варианты:

- `inject = [frag1 RealPath]`, `modified = Some(frag2 RealPath)`, original заменён;
- либо `inject = [frag1, frag2, ... RealPath]`, `drop = true`, original не проходит;
- либо decoy-only inject + original forward, но тогда inject не должен содержать unique real bytes, необходимые серверу.

Для `multisplit` / `multidisorder_new`:

```rust
let ttl_for_segment = match segment_role {
    SegmentRole::RealPath => original_ttl,
    SegmentRole::DecoyPath => original_ttl.saturating_sub(fake_ttl_offset),
};
```

## Критерии готовности

- `tls_record_frag` не пропускает оригинальный полный ClientHello одновременно с real fragments.
- Все real fragments имеют нормальный TTL/HopLimit.
- Low-TTL packets не содержат unique bytes, без которых сервер не соберёт поток.
- В `DesyncResult`/`InjectPacket` есть возможность отличить real path от decoy path.

## Верификация

Добавить deterministic tests:

```rust
#[test]
fn tls_record_frag_does_not_forward_original_full_client_hello() { /* ... */ }

#[test]
fn multisplit_real_path_reassembles_original_payload_without_decoys() { /* ... */ }

#[test]
fn low_ttl_segments_are_not_required_for_server_reassembly() { /* ... */ }
```

Добавить helper:

```rust
fn simulate_tcp_reassembly(pkts: &[GeneratedTcpSegment], original_seq: u32) -> Vec<u8> {
    // Collect only SegmentRole::RealPath packets with normal TTL.
    // Sort by SEQ.
    // Reject gaps/overlaps unless explicitly allowed by technique profile.
}
```

# P1-00. Ввести flow-affinity architecture: один capture loop + bounded per-worker queues

## Проблема

Текущая модель запускает 2..16 worker threads, и каждый worker читает один общий WinDivert handle. WinDivert отдаёт packets тому thread, который первым вызвал recv, а в коде нет steering по flow. Для desync это опаснее, чем для обычного proxy/firewall: `SeqSpoof`, split/multisplit, fake ClientHello inject, conntrack seq/ack update и delayed injections предполагают, что packets одного flow наблюдаются и reinject-ятся в порядке.

Под нагрузкой возможен сценарий: worker A обрабатывает первый TLS ClientHello segment и inject-ит split/fake sequence, worker B одновременно получает retransmit или следующий segment того же flow и forward-ит его раньше завершения inject sequence. FreeDPI сам создаёт reordering, который ломает TCP-sensitive desync.

## Решение и обоснование

Заменить модель “N workers читают shared handle” на software RSS:

1. Один capture thread быстро вызывает `recv_batch_into()`/`recv_batch()` и извлекает минимальный `FlowKey`.
2. `FlowKey` нормализован bidirectional: оба направления одного TCP/UDP connection попадают в один shard.
3. Capture thread отправляет owned packet в bounded queue соответствующего shard.
4. Каждый shard worker единолично обрабатывает свои flows и выполняет forward/inject batching.
5. При queue overflow default policy — fail-open forward для non-critical packets, а не silent drop; для packets, уже признанных desync-critical, включить metric + controlled backpressure.

Это сохраняет per-flow ordering и одновременно даёт parallelism по flow-set. После этого `Conntrack` locking остаётся safety net, а не основным способом синхронизировать racing workers.

## Реализация

Создать `core/src/engine/flow_affinity.rs`:

```rust
use crate::classifier::{Classification, Classifier};
use crate::conntrack::ConnKey;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct FlowEndpoint {
    pub ip: IpAddr,
    pub port: u16,
}

impl Ord for FlowEndpoint {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        let ip_ord = match (self.ip, other.ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => a.octets().cmp(&b.octets()),
            (IpAddr::V6(a), IpAddr::V6(b)) => a.octets().cmp(&b.octets()),
            (IpAddr::V4(_), IpAddr::V6(_)) => Ordering::Less,
            (IpAddr::V6(_), IpAddr::V4(_)) => Ordering::Greater,
        };
        ip_ord.then_with(|| self.port.cmp(&other.port))
    }
}

impl PartialOrd for FlowEndpoint {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct FlowKey {
    pub a: FlowEndpoint,
    pub b: FlowEndpoint,
    pub proto: u8,
}

impl FlowKey {
    #[inline]
    pub fn from_conn_key(k: &ConnKey) -> Self {
        let left = FlowEndpoint { ip: k.src_ip, port: k.src_port };
        let right = FlowEndpoint { ip: k.dst_ip, port: k.dst_port };
        let (a, b) = if left <= right { (left, right) } else { (right, left) };
        Self { a, b, proto: k.proto }
    }
}

#[inline]
pub fn classify_flow_key(packet: &[u8]) -> Option<FlowKey> {
    match Classifier::classify(packet) {
        Classification::Tls(cp)
        | Classification::Quic(cp)
        | Classification::Dns(cp)
        | Classification::Http(cp)
        | Classification::Other(cp) => Some(FlowKey::from_conn_key(&cp.conn_key)),
        Classification::Unknown => None,
    }
}

#[inline]
pub fn shard_for_flow(key: Option<FlowKey>, packet: &[u8], shards: usize) -> usize {
    let shards = shards.max(1);
    let mut h = rustc_hash::FxHasher::default();
    match key {
        Some(k) => k.hash(&mut h),
        None => {
            // Unknown/fragments: stable fallback by first bytes, not random worker.
            // Fragment handling from P0-03 should classify fragments as Forward/quarantine before desync.
            packet.len().hash(&mut h);
            packet.get(..16).unwrap_or(packet).hash(&mut h);
        }
    }
    (h.finish() as usize) % shards
}
```

Добавить dependency, если ещё нет:

```toml
rustc-hash = "2"
crossbeam-channel = "0.5"
```

В `core/src/engine/mod.rs` добавить тип queue item:

```rust
pub(crate) struct ShardPacket {
    pub data: bytes::Bytes,
    pub addr: WinDivertAddress<NetworkLayer>,
}
```

Заменить старт workers:

```rust
let n_workers = num_cpus::get().clamp(2, 16);
let mut txs = Vec::with_capacity(n_workers);
let mut rxs = Vec::with_capacity(n_workers);
for _ in 0..n_workers {
    let (tx, rx) = crossbeam_channel::bounded::<ShardPacket>(8192);
    txs.push(tx);
    rxs.push(rx);
}

// capture thread: единственный читатель WinDivert handle
{
    let engine = self.packet_engine.clone();
    let pool = self.packet_pool.clone();
    let shutdown = shutdown_flag.clone();
    let txs = txs.clone();
    std::thread::Builder::new()
        .name("fp-capture".to_string())
        .spawn(move || {
            while !shutdown.load(Ordering::Relaxed) {
                let packets = engine.recv_batch(&pool);
                for (data, addr) in packets {
                    let key = crate::engine::flow_affinity::classify_flow_key(&data);
                    let shard = crate::engine::flow_affinity::shard_for_flow(key, &data, txs.len());
                    let pkt = ShardPacket { data, addr };
                    match txs[shard].try_send(pkt) {
                        Ok(()) => {}
                        Err(crossbeam_channel::TrySendError::Full(pkt)) => {
                            // fail-open: не держим WinDivert queue; forward через capture thread
                            let _ = engine.send_batch(&[(pkt.data, pkt.addr)]);
                        }
                        Err(crossbeam_channel::TrySendError::Disconnected(_)) => return,
                    }
                }
            }
        })?;
}

// shard workers: не вызывают recv, только process+send/inject своих queues
for (id, rx) in rxs.into_iter().enumerate() {
    let engine = self.packet_engine.clone();
    let pipeline = self.clone_for_worker();
    let pool = self.packet_pool.clone();
    let shutdown = shutdown_flag.clone();
    std::thread::Builder::new()
        .name(format!("fp-shard-{}", id))
        .spawn(move || Self::shard_worker_loop(id, rx, engine, pipeline, pool, shutdown))?;
}
```

Реализовать `shard_worker_loop` через существующую decision handling logic, но без recv:

```rust
fn shard_worker_loop(
    id: usize,
    rx: crossbeam_channel::Receiver<ShardPacket>,
    engine: Arc<PacketEngine>,
    pipeline: Arc<ProcessingPipeline>,
    pool: Arc<PacketBufferPool>,
    shutdown: Arc<AtomicBool>,
) {
    let mut forward_batch: Vec<(bytes::Bytes, WinDivertAddress<NetworkLayer>)> = Vec::with_capacity(64);
    let mut inject_batch: Vec<(bytes::Bytes, WinDivertAddress<NetworkLayer>)> = Vec::with_capacity(64);

    while !shutdown.load(Ordering::Relaxed) {
        let first = match rx.recv_timeout(std::time::Duration::from_millis(1)) {
            Ok(pkt) => pkt,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        };

        Self::handle_shard_packet(first, &engine, &pipeline, &pool, &mut forward_batch, &mut inject_batch);
        while forward_batch.len() < 64 {
            match rx.try_recv() {
                Ok(pkt) => Self::handle_shard_packet(pkt, &engine, &pipeline, &pool, &mut forward_batch, &mut inject_batch),
                Err(_) => break,
            }
        }

        if !forward_batch.is_empty() {
            let _ = engine.send_batch(&forward_batch);
            for (data, _) in forward_batch.drain(..) {
                pool.release_bytes(data);
            }
        }
        if !inject_batch.is_empty() {
            let _ = engine.inject_batch_via_divert(&inject_batch);
            inject_batch.clear();
        }
    }
}
```

`handle_shard_packet()` должен использовать P0-08 borrow API:

```rust
fn handle_shard_packet(
    pkt: ShardPacket,
    engine: &PacketEngine,
    pipeline: &ProcessingPipeline,
    pool: &PacketBufferPool,
    forward_batch: &mut Vec<(bytes::Bytes, WinDivertAddress<NetworkLayer>)>,
    inject_batch: &mut Vec<(bytes::Bytes, WinDivertAddress<NetworkLayer>)>,
) {
    let ShardPacket { data, addr } = pkt;
    match pipeline.process_one_sync(&data, &addr) {
        Ok(PacketDecision::Forward) => forward_batch.push((data, addr)),
        Ok(PacketDecision::Modify(modified)) => {
            pool.release_bytes(data);
            forward_batch.push((modified, addr));
        }
        Ok(PacketDecision::Drop) => {
            pool.release_bytes(data);
            pipeline.stats.dropped.fetch_add(1, Ordering::Relaxed);
        }
        Ok(PacketDecision::Desync { inject, modified, inject_protocol, inter_delay_us }) => {
            // перенести существующий Desync arm без изменения семантики;
            // inject ordering now protected by shard affinity.
            // Если inter_delay_us > 0, отправить в delayed injector из P1-04, не sleep здесь.
            if let Some(modified) = modified {
                pool.release_bytes(data);
                forward_batch.push((modified, addr));
            } else {
                forward_batch.push((data, addr));
            }
            for p in inject {
                inject_batch.push((p, addr.clone()));
            }
        }
        Err(e) => {
            tracing::debug!("shard packet processing error: {}", e);
            forward_batch.push((data, addr));
        }
    }
}
```

Если текущие types не позволяют `clone_for_worker()`, использовать уже существующую `Arc<ProcessingPipeline>` модель; не вводить `Mutex<ProcessingPipeline>`.

## Критерии готовности

- Только capture thread вызывает `PacketEngine::recv_batch*`.
- Shard workers не читают WinDivert handle.
- Packets одного bidirectional `FlowKey` всегда попадают в один shard.
- Overflow policy измеряется metric `shard_queue_full_total` и default fail-open forward не создаёт silent drop.
- Inject/forward ordering для одного flow исходит из одного worker.

## Верификация

Unit tests:

```rust
#[test]
fn flow_key_is_bidirectional() {
    let a = ConnKey::new("10.0.0.1".parse::<std::net::IpAddr>().unwrap(), "1.1.1.1".parse::<std::net::IpAddr>().unwrap(), 50000, 443, 6);
    let b = ConnKey::new("1.1.1.1".parse::<std::net::IpAddr>().unwrap(), "10.0.0.1".parse::<std::net::IpAddr>().unwrap(), 443, 50000, 6);
    assert_eq!(FlowKey::from_conn_key(&a), FlowKey::from_conn_key(&b));
}

#[test]
fn same_flow_same_shard() {
    let key = FlowKey::from_conn_key(&ConnKey::new("10.0.0.1".parse::<std::net::IpAddr>().unwrap(), "1.1.1.1".parse::<std::net::IpAddr>().unwrap(), 50000, 443, 6));
    assert_eq!(shard_for_flow(Some(key), &[], 16), shard_for_flow(Some(key), &[1,2,3], 16));
}
```

Stress test:

- Generate interleaved packets for 10k flows.
- Assert per-flow sequence observed by `handle_shard_packet` is monotonic in original enqueue order.
- Assert no two workers process same `FlowKey`.

Windows validation:

```powershell
cargo test -p freedpi-core flow_affinity
# Run service with debug metric: all recv calls must come from fp-capture thread only.
```


# P1-00A. Shutdown/control-plane correctness: не polling broadcast вокруг бесконечного worker loop

## Проблема

DeepSeek-review указал, что внешний цикл с `shutdown_rx.try_recv()` вокруг бесконечного `worker_loop()` не является рабочей shutdown-моделью: если `worker_loop` не возвращается, проверка `broadcast::Receiver` происходит только до входа в него. Кроме того, control-plane polling не должен попадать в packet hot loop. `try_recv()` сам по себе является неблокирующей попыткой чтения, но hot-path polling control channel создаёт шум и усложняет shutdown semantics.

## Решение и обоснование

После P1-00 shutdown должен быть единым `Arc<AtomicBool>` или `CancellationToken`, который проверяется внутри:

1. RX/capture loop.
2. Worker queue drain loop.
3. Delayed injector loop.
4. DNS/AWG side workers.

Broadcast channel может оставаться на async service boundary, но только один async task должен переводить его событие в `shutdown_flag.store(true, Release)`. Packet workers не должны вызывать `try_recv()` в tight loop.

## Реализация

```rust
pub struct RuntimeShutdown {
    flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl RuntimeShutdown {
    #[inline]
    pub fn is_shutdown(&self) -> bool {
        self.flag.load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn trigger(&self) {
        self.flag.store(true, std::sync::atomic::Ordering::Release);
    }
}
```

В `run()`:

```rust
let shutdown_flag = Arc::new(AtomicBool::new(false));
let shutdown_ctl = RuntimeShutdown { flag: shutdown_flag.clone() };

let shutdown_watcher = {
    let shutdown_ctl = shutdown_ctl.clone();
    crate::Runtime::global().io.spawn(async move {
        let _ = shutdown.recv().await;
        shutdown_ctl.trigger();
    })
};

// spawn rx dispatcher + workers, each gets shutdown_ctl.clone()
```

В RX/worker loops:

```rust
while !shutdown.is_shutdown() {
    // recv, dispatch, drain queue, send batches
}
```

Если используется `crossbeam_channel`, shutdown должен также будить blocked workers: либо bounded queues получают sentinel, либо worker использует `recv_timeout(Duration::from_millis(10))` и проверяет flag.

## Критерии готовности

- Нет внешнего цикла `loop { try_recv(); worker_loop(); }`, если `worker_loop` бесконечный.
- `rg -n "try_recv\(\)" core/src/engine` не показывает packet hot-loop polling.
- Shutdown latency < 100 ms в idle и under-load smoke test.
- При shutdown RX dispatcher перестаёт читать WinDivert, workers drain/drop bounded queues согласно policy, delayed injector не зависает.

## Верификация

```bash
cargo test -p freedpi-core shutdown_flag
rg -n "try_recv\(\).*worker_loop|worker_loop\(.*\).*try_recv" core/src/engine
```

Windows smoke: запустить сервис, дать трафик, отправить shutdown, убедиться что все `fp-*` threads завершаются без forced kill.

---

# P1-01. Сузить default WinDivert filter: outbound TLS CH, outbound DNS request, outbound QUIC Initial only

## Проблема

`config.rs::default_filter()` перехватывает `udp.DstPort == 443` без `outbound` и без QUIC Initial predicate. Это тащит весь двусторонний QUIC media/data поток через userspace, хотя desync нужен только на первом клиентском Initial. Также `udp.DstPort == 53` без глобального `outbound` может перехватывать лишнее.

## Решение и обоснование

Фильтр должен максимально точно соответствовать packet types, для которых pipeline реально меняет поведение:

- TLS: outbound TCP 443 ClientHello record.
- DNS: outbound UDP 53 requests.
- QUIC: outbound UDP 443 long-header Initial only, not short-header data packets.

WinDivert сам рекомендует фильтровать subset как можно точнее, чтобы не платить user-mode diversion overhead за ненужный трафик.

## Реализация

В `core/src/config.rs` заменить `default_filter()` на:

```rust
fn default_filter() -> String {
    // QUIC Initial first byte:
    // bit7 Header Form=1, bit6 Fixed Bit=1, bits5..4 Long Packet Type=0.
    // Lower 4 bits are protected/type-specific, so mask with 0xF0.
    "(ip or ipv6) && outbound && ( \
        (tcp.DstPort == 443 && tcp.PayloadLength > 5 \
            && tcp.Payload[0] == 0x16 && tcp.Payload[1] == 0x03 && tcp.Payload[5] == 0x01) \
        or (udp.DstPort == 443 && udp.PayloadLength >= 7 \
            && (udp.Payload[0] & 0xF0) == 0xC0 \
            && (udp.Payload[1] != 0 or udp.Payload[2] != 0 or udp.Payload[3] != 0 or udp.Payload[4] != 0)) \
        or udp.DstPort == 53 \
    )".to_string()
}
```

Не использовать `udp.Payload[1..5]` slice syntax, если текущий WinDivert crate/filter compiler не гарантирует её поддержку. Byte-by-byte predicate безопаснее.

В `PacketEngine::new()` или там, где открывается filter, добавить compile-time validation:

```rust
windivert::WinDivert::check_filter(&filter)
    .map_err(|e| anyhow::anyhow!("invalid WinDivert filter `{}`: {e}", filter))?;
```

Если crate не экспортирует `check_filter`, использовать доступный helper `WinDivertHelperCompileFilter` через `windows`/`windivert_sys` binding либо integration test с фактическим `WinDivert::network(&filter, ...)`.

## Критерии готовности

- QUIC short-header packets не попадают в userspace при default config.
- Inbound UDP:443 не попадает в userspace при default config.
- Outbound QUIC Initial попадает в userspace.
- Outbound DNS request попадает в userspace; inbound DNS response не перехватывается default filter.
- Пользовательский filter в config по-прежнему уважается и не переписывается default-ом.

## Верификация

1. Unit test на строку фильтра:

```rust
#[test]
fn default_filter_is_outbound_and_quic_initial_only() {
    let f = Config::default_filter();
    assert!(f.contains("outbound"));
    assert!(f.contains("udp.DstPort == 443"));
    assert!(f.contains("(udp.Payload[0] & 0xF0) == 0xC0"));
    assert!(!f.contains("udp.DstPort == 443 \\n    )"));
}
```

2. Windows integration:

```powershell
# Запустить YouTube/Chrome с QUIC enabled + параллельный iperf UDP.
# Counters userspace received должны расти только на Initial/retry handshakes, не на весь media stream.
```

3. Проверить WinDivert filter compiler на startup; invalid filter должен быть fatal config error, а не silent fallback на широкий перехват.

---

---

# P1-16. Feature-dependent SYN capture: не пропускать SYN для MSS/SOCKS/FakeIP, но не расширять filter до всего TCP/UDP

## Проблема

Gemini-review указал важный режимный баг: дефолтный TCP capture predicate ориентирован на payload-bearing TLS ClientHello, поэтому outbound TCP SYN с `PayloadLength == 0` не попадает в pipeline. Если включены SYN-dependent функции — MSS clamp, TCP window clamp, SOCKS/FakeIP redirect — они не могут сработать, потому что их packet вообще не capture'ится.

Решение вида `outbound and (tcp or udp)` недопустимо: оно убивает capture budget и противоречит принципу narrow WinDivert filter.

## Решение и обоснование

Filter builder должен строиться от включённых функций:

- TLS desync: outbound TLS ClientHello predicate.
- QUIC desync: outbound QUIC Initial predicate.
- DNS proxy: outbound UDP/53 predicate.
- MSS/window clamp или SOCKS/FakeIP redirect: outbound TCP SYN predicate только для нужных target ports/ranges.

## Реализация

Расширить filter builder:

```rust
pub struct FilterFeatures {
    pub tls_desync: bool,
    pub quic_desync: bool,
    pub dns_proxy: bool,
    pub mss_clamp: bool,
    pub win_size_clamp: bool,
    pub socks_redirect: bool,
    pub fakeip_redirect: bool,
    pub target_ports: SmallVec<[u16; 8]>,
}

pub fn build_windivert_filter(features: &FilterFeatures) -> String {
    let mut terms = Vec::new();

    if features.mss_clamp || features.win_size_clamp || features.socks_redirect || features.fakeip_redirect {
        let ports = render_port_predicate("tcp.DstPort", &features.target_ports);
        terms.push(format!("(tcp.Syn && !tcp.Ack && {})", ports));
    }

    if features.tls_desync {
        terms.push("(tcp.DstPort == 443 && tcp.PayloadLength > 5 && tcp.Payload[0] == 0x16 && tcp.Payload[1] == 0x03 && tcp.Payload[5] == 0x01)".to_string());
    }

    if features.quic_desync {
        terms.push("(udp.DstPort == 443 && udp.PayloadLength >= 1200 && (udp.Payload[0] & 0xC0) == 0xC0 && (udp.Payload[0] & 0x30) == 0x00)".to_string());
    }

    if features.dns_proxy {
        terms.push("udp.DstPort == 53".to_string());
    }

    format!("(ip or ipv6) && outbound && ({})", terms.join(" or "))
}
```

`target_ports` не должен быть hardcoded только на 443, если конфигурация разрешает custom ports. Но если список пуст, fallback должен быть безопасным: `443`, `80` только если соответствующие функции включены.

## Критерии готовности

- При включённом MSS/window/SOCKS/FakeIP redirect SYN попадает в pipeline.
- При выключенных SYN-dependent функциях filter не capture'ит весь SYN traffic.
- Capture Budget Governor учитывает SYN branch как отдельную причину capture.
- Filter compile-before-swap остаётся обязательным.

## Верификация

```bash
cargo test -p freedpi-core filter_includes_syn_when_mss_enabled
cargo test -p freedpi-core filter_excludes_syn_when_no_syn_features_enabled
```

Windows integration: включить MSS clamp, открыть TCP/443 соединение, убедиться через counter `captured_tcp_syn_total`, что SYN был обработан.

# P1-02. Убрать blind window при `update_filter()` и включить `QueueSize`

## Проблема

`PacketEngine::update_filter()` сначала публикует `None`, drop старого handle, потом открывает новый. Worker видит `None` и спит 10 ms. Это blind window. Также `QueueSize` не выставлен, хотя wrapper его поддерживает.

## Решение и обоснование

Новый handle создаётся и настраивается до atomic publication. Старый handle dropается после swap. Это устраняет состояние `None` в live rotation. `QueueSize` настраивается вместе с `QueueLength`/`QueueTime`.

## Реализация

Файл: `core/src/packet_engine.rs`.

Добавить helper в `impl PacketEngine`:

```rust
    fn tune_divert(divert: &WinDivert) -> Result<()> {
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
```

В `new()` заменить три вызова настройки на:

```rust
        Self::tune_divert(&divert)?;
```

Заменить `update_filter()` на:

```rust
    pub fn update_filter(&self, filter: &str) -> Result<()> {
        let new_divert = WinDivert::network(filter, WINDIVERT_PRIORITY, WinDivertFlags::default())
            .context("Failed to update WinDivert filter")?;
        Self::tune_divert(&new_divert)
            .context("Failed to tune new WinDivert handle")?;

        let old = self.divert.swap(Arc::new(Some(new_divert)));
        drop(old);

        debug!("WinDivert filter updated: {}", filter);
        Ok(())
    }
```

## Критерии готовности

- `update_filter()` не публикует `None`.
- Worker не попадает в 10 ms sleep при штатной rotation.
- `QueueSize` выставляется и в `new()`, и в `update_filter()`.

## Верификация

Команды:

```bash
cargo check -p freedpi-core --all-targets
```

Windows smoke:

```powershell
# Под admin: запустить сервис, трижды изменить blacklist/whitelist/filter.
# В логах не должно быть "WinDivert not initialized" во время rotation.
```

---

---

# P1-03. Убрать per-batch allocation в `recv_batch`, `send_batch`, `inject_batch_via_divert`

## Проблема

`recv_batch()` выделяет `Vec` на каждый batch. `send_batch()` и `inject_batch_via_divert()` выделяют `Vec<WinDivertPacket>` на каждый batch. На high packet rate это heap churn и cache pressure.

## Решение и обоснование

Переиспользовать caller-owned output vec для receive и thread-local vec для WinDivertPacket wrappers на send/inject. Это не делает path true zero-copy, но убирает регулярные allocations без изменения API wrapper.

## Реализация

Файл: `core/src/packet_engine.rs`.

Добавить счетчики в `PacketBufferPool`:

```rust
pub struct PacketBufferPool {
    free: ArrayQueue<BytesMut>,
    alloc_miss: AtomicU64,
    return_drop: AtomicU64,
}
```

Обновить `new()`:

```rust
        Self {
            free,
            alloc_miss: AtomicU64::new(0),
            return_drop: AtomicU64::new(0),
        }
```

Обновить `acquire()`:

```rust
    #[inline]
    pub fn acquire(&self) -> BytesMut {
        self.free.pop().unwrap_or_else(|| {
            self.alloc_miss.fetch_add(1, Ordering::Relaxed);
            let mut b = BytesMut::with_capacity(POOLED_BUF_SIZE);
            b.resize(POOLED_BUF_SIZE, 0);
            b
        })
    }
```

Обновить `release()`:

```rust
    #[inline]
    pub fn release(&self, mut buf: BytesMut) {
        if buf.capacity() < POOLED_BUF_SIZE {
            return;
        }
        buf.resize(POOLED_BUF_SIZE, 0);
        if self.free.push(buf).is_err() {
            self.return_drop.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn alloc_miss(&self) -> u64 {
        self.alloc_miss.load(Ordering::Relaxed)
    }

    pub fn return_drop(&self) -> u64 {
        self.return_drop.load(Ordering::Relaxed)
    }
```

Добавить новый receive API:

```rust
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

        thread_local! {
            static BATCH_BUF: std::cell::RefCell<Vec<u8>> =
                std::cell::RefCell::new(vec![0u8; RECV_BATCH_BUFFER_SIZE]);
        }

        let n = BATCH_BUF.with(|buf| -> Result<usize> {
            let mut buf = buf.borrow_mut();
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

        self.stats.packets_received.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
```

Оставить старый `recv_batch()` только как compatibility wrapper:

```rust
    pub fn recv_batch(
        &self,
        pool: &PacketBufferPool,
    ) -> Result<Vec<(bytes::Bytes, WinDivertAddress<NetworkLayer>)>> {
        let mut out = Vec::with_capacity(RECV_BATCH_SIZE);
        self.recv_batch_into(pool, &mut out)?;
        Ok(out)
    }
```

В `worker_loop()` добавить:

```rust
        let mut recv_batch: Vec<(bytes::Bytes, WinDivertAddress<NetworkLayer>)> = Vec::with_capacity(64);
```

Заменить receive block:

```rust
            let packet_count = match engine.recv_batch_into(&pool, &mut recv_batch) {
                Ok(n) => {
                    if n == 0 {
                        empty_spins += 1;
                        if empty_spins < 100 { std::hint::spin_loop(); }
                        else {
                            std::thread::sleep(std::time::Duration::from_micros(100));
                            empty_spins = 0;
                        }
                        continue;
                    }
                    empty_spins = 0;
                    n
                }
                Err(e) => {
                    if !engine.has_divert() {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                        continue;
                    }
                    tracing::error!("recv_batch error: {}", e);
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
            };
            pipeline.stats.total_received.fetch_add(packet_count as u64, Ordering::Relaxed);
```

Заменить loop:

```rust
            for (data, addr) in recv_batch.drain(..) {
```

Для `send_batch()` и `inject_batch_via_divert()` заменить local `Vec::with_capacity` на thread-local reusable buffer невозможно безопасно хранить с borrowed packet slices через `RefCell<Vec<WinDivertPacket<'_>>>` из-за lifetimes. Поэтому используем `smallvec::SmallVec`, которая не аллоцирует до 64 элементов:

```rust
        let mut wd_packets: smallvec::SmallVec<[WinDivertPacket<'_>; 64]> = smallvec::SmallVec::new();
```

Если компилятор не принимает explicit lifetime в type alias wrapper, использовать:

```rust
        let mut wd_packets = smallvec::SmallVec::<[_; 64]>::new();
```

и оставить остальной push-код без изменений. Это полноценная реализация: wrapper packets живут до `send_ex()`.

## Критерии готовности

- Receive worker больше не получает owned `Vec` из `recv_batch()`.
- На steady-state `alloc_miss` и `return_drop` близки к нулю при pool capacity `workers * 64 * 4`.
- Send/inject не выделяют heap для batch <= 64.

## Верификация

```bash
cargo check -p freedpi-core --all-targets
cargo test -p freedpi-core packet_engine -- --nocapture
```

Perf smoke: добавить temporary log `pool.alloc_miss()/return_drop()` раз в 10 секунд; при iperf3/TLS browse значения не должны расти постоянно.

---

---

# P1-04. Убрать `sleep()` из packet worker через bounded delayed injector

## Проблема

`worker_loop()` и `execute_decision_sync()` вызывают `std::thread::sleep(Duration::from_micros(...))` прямо в packet worker. На Windows это не microsecond timing, а yield с latency cliff. Пока поток спит, WinDivert queue наполняется.

## Решение и обоснование

Inject packets с задержкой уходят в отдельный bounded scheduler. Worker не ждёт. Если scheduler full, packet path не блокируется: delayed inject дропается с метрикой, original packet идёт по политике решения.

## Реализация

Создать файл: `core/src/engine/delayed_inject.rs`.

```rust
use crate::packet_engine::PacketEngine;
use bytes::Bytes;
use std::cmp::Ordering as CmpOrdering;
use std::collections::BinaryHeap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use windivert::prelude::{NetworkLayer, WinDivertAddress};

#[derive(Debug)]
struct ScheduledPacket {
    at: Instant,
    data: Bytes,
    addr: WinDivertAddress<NetworkLayer>,
}

impl PartialEq for ScheduledPacket {
    fn eq(&self, other: &Self) -> bool { self.at == other.at }
}
impl Eq for ScheduledPacket {}
impl PartialOrd for ScheduledPacket {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> { Some(self.cmp(other)) }
}
impl Ord for ScheduledPacket {
    fn cmp(&self, other: &Self) -> CmpOrdering { other.at.cmp(&self.at) }
}

#[derive(Debug)]
pub struct DelayedInject {
    tx: crossbeam::channel::Sender<ScheduledPacket>,
    dropped: AtomicU64,
    sent: AtomicU64,
}

impl DelayedInject {
    pub fn start(engine: Arc<PacketEngine>, capacity: usize) -> Arc<Self> {
        let (tx, rx) = crossbeam::channel::bounded::<ScheduledPacket>(capacity);
        let this = Arc::new(Self {
            tx,
            dropped: AtomicU64::new(0),
            sent: AtomicU64::new(0),
        });
        let worker_self = Arc::clone(&this);
        std::thread::Builder::new()
            .name("fp-delayed-inject".into())
            .spawn(move || worker_self.run(engine, rx))
            .expect("spawn delayed inject worker");
        this
    }

    fn run(self: Arc<Self>, engine: Arc<PacketEngine>, rx: crossbeam::channel::Receiver<ScheduledPacket>) {
        let mut heap = BinaryHeap::<ScheduledPacket>::new();
        loop {
            let now = Instant::now();
            while heap.peek().is_some_and(|pkt| pkt.at <= now) {
                let pkt = heap.pop().expect("peeked Some");
                if engine.inject_batch_via_divert(&[(pkt.data, pkt.addr)]).is_ok() {
                    self.sent.fetch_add(1, Ordering::Relaxed);
                }
            }

            let timeout = heap
                .peek()
                .map(|pkt| pkt.at.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|| Duration::from_millis(10));

            match rx.recv_timeout(timeout) {
                Ok(pkt) => heap.push(pkt),
                Err(crossbeam::channel::RecvTimeoutError::Timeout) => {}
                Err(crossbeam::channel::RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    #[inline]
    pub fn try_schedule(&self, delay_us: u32, data: Bytes, addr: WinDivertAddress<NetworkLayer>) -> bool {
        let pkt = ScheduledPacket {
            at: Instant::now() + Duration::from_micros(delay_us as u64),
            data,
            addr,
        };
        match self.tx.try_send(pkt) {
            Ok(()) => true,
            Err(crossbeam::channel::TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(crossbeam::channel::TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    pub fn dropped(&self) -> u64 { self.dropped.load(Ordering::Relaxed) }
    pub fn sent(&self) -> u64 { self.sent.load(Ordering::Relaxed) }
}
```

Файл: `core/src/engine/mod.rs`.

Вверху добавить:

```rust
mod delayed_inject;
use delayed_inject::DelayedInject;
```

В `ProcessingPipeline` struct добавить поле:

```rust
    delayed_inject: Arc<DelayedInject>,
```

В `new()` перед `Self { ... }`:

```rust
        let delayed_inject = DelayedInject::start(packet_engine.clone(), 65_536);
```

и в initializer:

```rust
            delayed_inject,
```

В `worker_loop()` заменить блок `PacketDecision::Desync` так:

- для TCP inject: если `inter_delay_us == 0`, добавлять в `inject_batch`; если `> 0`, первый inject отправить batch/сразу, последующие schedule.
- для UDP inject: если `inter_delay_us == 0`, как сейчас; если `> 0`, schedule через delayed injector вместо sleep.

Точный replacement для внутреннего `match inject_protocol`:

```rust
                                match inject_protocol {
                                    InjectProtocol::Tcp => {
                                        for (i, inject_pkt) in inject.iter().enumerate() {
                                            if i == 0 || inter_delay_us == 0 {
                                                inject_batch.push((inject_pkt.clone(), addr.clone()));
                                            } else {
                                                let scheduled = pipeline.delayed_inject.try_schedule(
                                                    inter_delay_us.saturating_mul(i as u32),
                                                    inject_pkt.clone(),
                                                    addr.clone(),
                                                );
                                                if scheduled {
                                                    pipeline.stats.fake_ch_injected.fetch_add(1, Ordering::Relaxed);
                                                }
                                            }
                                        }
                                    }
                                    InjectProtocol::Udp => {
                                        for (i, inject_pkt) in inject.iter().enumerate() {
                                            if i == 0 || inter_delay_us == 0 {
                                                if let Err(e) = engine.inject_raw_udp(inject_pkt) {
                                                    tracing::warn!("Failed to inject UDP desync packet: {}", e);
                                                } else {
                                                    pipeline.stats.fake_ch_injected.fetch_add(1, Ordering::Relaxed);
                                                }
                                            } else {
                                                let scheduled = pipeline.delayed_inject.try_schedule(
                                                    inter_delay_us.saturating_mul(i as u32),
                                                    inject_pkt.clone(),
                                                    addr.clone(),
                                                );
                                                if scheduled {
                                                    pipeline.stats.fake_ch_injected.fetch_add(1, Ordering::Relaxed);
                                                }
                                            }
                                            pool.release_bytes(inject_pkt.clone());
                                        }
                                    }
                                }
```

Заменить jitter sleep после inject в `execute_decision_sync()` и worker path на no-op или scheduling policy. В production worker path `execute_decision_sync()` не используется, но чтобы не оставить мину, заменить:

```rust
                let delay_us = self.config.desync.inject_delay_us;
                if delay_us > 0 {
                    let jitter = crate::desync::rand::random_range(0, delay_us as u32);
                    std::thread::sleep(Duration::from_micros(jitter as u64));
                }
```

на:

```rust
                let _delay_us = self.config.desync.inject_delay_us;
                // No sleeping in packet worker. Jitter is represented only by delayed inject packets.
```

## Критерии готовности

- В `core/src/engine/mod.rs` не осталось `std::thread::sleep(Duration::from_micros(...))` в packet processing path.
- Worker не блокируется на меж-инжектной задержке.
- При переполнении delayed queue есть метрика `DelayedInject::dropped()`.

## Верификация

```bash
rg -n "thread::sleep\(.*from_micros|from_micros\(" core/src/engine
cargo check -p freedpi-core --all-targets
```

Runtime: профиль с `inter_delay_us > 0`, flood TCP/443. Worker CPU не должен уходить в sleep-heavy state, WinDivert drops не должны расти при включении задержки.

---

---

# P1-05. Убрать async DNS `block_on()` из packet worker

## Проблема

`process_one_sync_dispatch()` вызывает `Runtime::global().block_on(self.dns_proxy.handle_dns_query(...))`. Любая DNS задержка блокирует WinDivert worker.

## Решение и обоснование

DNS proxy должен быть отдельным async consumer с bounded queue. Packet worker только `try_send()` запрос и немедленно `Drop` original DNS packet, если запрос принят. Если очередь заполнена — fail-open forward original, чтобы не создавать локальный DoS.

## Реализация

Файл: `core/src/engine/dns_async.rs`.

```rust
use crate::dns::dns_proxy::DnsProxy;
use crate::packet_engine::PacketEngine;
use bytes::Bytes;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use windivert::prelude::{NetworkLayer, WinDivertAddress};

struct DnsJob {
    data: Bytes,
    addr: WinDivertAddress<NetworkLayer>,
}

#[derive(Debug)]
pub struct DnsAsyncBridge {
    tx: tokio::sync::mpsc::Sender<DnsJob>,
    accepted: AtomicU64,
    queue_full: AtomicU64,
}

impl DnsAsyncBridge {
    pub fn start(proxy: Arc<DnsProxy>, engine: Arc<PacketEngine>, capacity: usize) -> Arc<Self> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<DnsJob>(capacity);
        let bridge = Arc::new(Self {
            tx,
            accepted: AtomicU64::new(0),
            queue_full: AtomicU64::new(0),
        });
        crate::Runtime::global().io.spawn(async move {
            while let Some(job) = rx.recv().await {
                if let Some(resp_data) = proxy.handle_dns_query(&job.data).await {
                    let mut addr = job.addr;
                    addr.set_outbound(false);
                    if let Err(e) = engine.inject_via_divert(&resp_data, &addr) {
                        tracing::warn!("DNS async bridge inject failed: {}", e);
                    }
                }
            }
        });
        bridge
    }

    #[inline]
    pub fn try_enqueue(&self, data: Bytes, addr: WinDivertAddress<NetworkLayer>) -> bool {
        match self.tx.try_send(DnsJob { data, addr }) {
            Ok(()) => {
                self.accepted.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                self.queue_full.fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    pub fn accepted(&self) -> u64 { self.accepted.load(Ordering::Relaxed) }
    pub fn queue_full(&self) -> u64 { self.queue_full.load(Ordering::Relaxed) }
}
```

Файл: `core/src/engine/mod.rs`.

Добавить:

```rust
mod dns_async;
use dns_async::DnsAsyncBridge;
```

В struct добавить:

```rust
    dns_bridge: Arc<DnsAsyncBridge>,
```

В `new()` после создания `dns_proxy` и перед `Self`:

```rust
        let dns_bridge = DnsAsyncBridge::start(dns_proxy.clone(), packet_engine.clone(), 8192);
```

В initializer:

```rust
            dns_bridge,
```

Заменить DNS interception block в `process_one_sync_dispatch()` на:

```rust
        if let Classification::Dns(ref cp) = classification {
            if cp.dst_port == 53 && self.dns_proxy.config.enabled {
                if self.dns_bridge.try_enqueue(captured.data.clone(), captured.addr.clone()) {
                    self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                    return Ok(PacketDecision::Drop);
                }
                tracing::warn!("DNS async queue full; forwarding original DNS query");
                return Ok(PacketDecision::Forward);
            }
        }
```

## Критерии готовности

- В `core/src/engine/mod.rs` не осталось `block_on(self.dns_proxy.handle_dns_query(...))`.
- DNS proxy работает через bounded queue.
- Queue full не блокирует worker.

## Верификация

```bash
rg -n "block_on\(self\.dns_proxy|handle_dns_query" core/src/engine
cargo check -p freedpi-core --all-targets
```

Runtime: flood UDP/53. Worker threads не блокируются, DNS bridge `queue_full` может расти, но packet receive продолжается.

---

---

# P1-06. Убрать Tokio task per UDP/QUIC proxy packet для AWG

## Проблема

При `RoutingDecision::Proxy` для UDP/QUIC код делает `to_vec()` и `tokio::spawn()` на каждый packet. Это task explosion и heap allocation per packet.

## Решение и обоснование

Ввести bounded writer queue: packet worker делает один controlled copy в `Vec<u8>` и `try_send()`. Один async worker читает очередь и вызывает `awg.send_ip_packet(data).await`. При queue full — drop с метрикой или fallback policy, но без spawn storm.

## Реализация

Создать файл `core/src/engine/awg_async.rs`:

```rust
use crate::proxy::awg_tunnel::AwgTunnel;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug)]
pub struct AwgAsyncWriter {
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    accepted: AtomicU64,
    dropped: AtomicU64,
}

impl AwgAsyncWriter {
    pub fn start(tunnel: Arc<AwgTunnel>, capacity: usize) -> Arc<Self> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(capacity);
        let this = Arc::new(Self {
            tx,
            accepted: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        });
        let stats = Arc::clone(&this);
        crate::Runtime::global().io.spawn(async move {
            while let Some(pkt) = rx.recv().await {
                if let Err(e) = tunnel.send_ip_packet(pkt).await {
                    tracing::error!("AWG: failed to send packet: {e:#}");
                    stats.dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        this
    }

    #[inline]
    pub fn try_send(&self, packet: &[u8]) -> bool {
        match self.tx.try_send(packet.to_vec()) {
            Ok(()) => {
                self.accepted.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    pub fn accepted(&self) -> u64 { self.accepted.load(Ordering::Relaxed) }
    pub fn dropped(&self) -> u64 { self.dropped.load(Ordering::Relaxed) }
}
```

Файл `core/src/engine/mod.rs`.

Добавить:

```rust
mod awg_async;
use awg_async::AwgAsyncWriter;
```

Заменить поле:

```rust
    awg_tunnel: ArcSwap<Option<Arc<crate::proxy::awg_tunnel::AwgTunnel>>>,
```

дополнить новым полем:

```rust
    awg_writer: ArcSwap<Option<Arc<AwgAsyncWriter>>>,
```

В `new()` initializer:

```rust
            awg_writer: ArcSwap::from_pointee(None),
```

В месте, где AWG tunnel создаётся/публикуется (найти `awg_tunnel.store`), после создания `Arc<AwgTunnel>` создать writer:

```rust
let writer = AwgAsyncWriter::start(Arc::clone(&tunnel), 65_536);
self.awg_writer.store(Arc::new(Some(writer)));
self.awg_tunnel.store(Arc::new(Some(tunnel)));
```

В UDP proxy branch заменить spawn block:

```rust
                            let writer_guard = self.awg_writer.load();
                            if let Some(ref writer) = **writer_guard {
                                if writer.try_send(&captured.data) {
                                    self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                                    return Ok(PacketDecision::Drop);
                                }
                                tracing::warn!("AWG queue full; dropping UDP/QUIC packet to avoid worker stall");
                                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                                return Ok(PacketDecision::Drop);
                            }
```

## Критерии готовности

- В UDP/QUIC proxy path нет `Runtime::global().io.spawn`.
- На packet path нет allocation кроме неизбежной `to_vec()` в `try_send`; нет task per packet.
- Queue full видна метрикой.

## Верификация

```bash
rg -n "send_ip_packet\(|to_vec\(\).*spawn|io\.spawn" core/src/engine core/src/proxy
cargo check -p freedpi-core --all-targets
```

---

---

# P1-07. Убрать clone `DesyncGroup` на каждый packet

## Проблема

`apply_desync_sync()` клонирует `DesyncGroup`, затем вызывает `set_context()`. Это копирует vector техник/конфиг на каждый TLS/QUIC/HTTP packet и загрязняет cache.

## Решение и обоснование

`DesyncGroup` уже хранит context как `Option<Arc<...>>`, но context одинаков для pipeline lifetime. Нужно строить группы с context при создании registry или передавать context by reference в apply. Минимальная неинвазивная реализация: добавить `apply_with_context()` без clone.

## Реализация

Файл `core/src/desync/group.rs`.

Добавить метод:

```rust
    pub fn apply_with_runtime_context(
        &self,
        packet: &bytes::Bytes,
        dscp_value: Option<u8>,
        override_params: Option<ConfigOverride>,
        is_resumption: Option<bool>,
        conn_rng: Option<crate::desync::rand::PerConnRng>,
        hop_tab: Arc<crate::adaptive::hop_tab::HopTab>,
        conntrack: Arc<crate::conntrack::Conntrack>,
    ) -> DesyncResult {
        let mut state = PipelineState::from_packet(packet.clone());
        state.is_resumption = is_resumption;
        state.conn_rng = conn_rng;
        for technique in &self.techniques {
            self.apply_to_state_with_context(
                technique,
                &mut state,
                dscp_value,
                override_params,
                Some(&hop_tab),
                Some(&conntrack),
            );
            if state.drop { break; }
        }
        state.into_result()
    }
```

Переименовать текущий `apply_to_state()` в `apply_to_state_with_context()` и добавить параметры:

```rust
        hop_tab_override: Option<&Arc<crate::adaptive::hop_tab::HopTab>>,
        conntrack_override: Option<&Arc<crate::conntrack::Conntrack>>,
```

Внутри `apply_seq_spoof()` сделать новую функцию:

```rust
    fn apply_seq_spoof_with_context(
        &self,
        state: &mut PipelineState,
        hop_tab_override: Option<&Arc<crate::adaptive::hop_tab::HopTab>>,
        conntrack_override: Option<&Arc<crate::conntrack::Conntrack>>,
    ) {
        let hop_tab = match hop_tab_override.or(self.hop_tab.as_ref()) {
            Some(ht) => ht.as_ref(),
            None => {
                tracing::warn!("SeqSpoof requires HopTab — not set, skipping");
                return;
            }
        };
        let conntrack = match conntrack_override.or(self.conntrack.as_ref()) {
            Some(ct) => ct.as_ref(),
            None => {
                tracing::warn!("SeqSpoof requires Conntrack — not set, skipping");
                return;
            }
        };
        self.apply_seq_spoof_core(state, hop_tab, conntrack);
    }
```

Вынести тело текущего `apply_seq_spoof()` после получения refs в:

```rust
    fn apply_seq_spoof_core(
        &self,
        state: &mut PipelineState,
        hop_tab: &crate::adaptive::hop_tab::HopTab,
        conntrack: &crate::conntrack::Conntrack,
    ) {
        // существующее тело начиная с parse IP header
    }
```

В `match DesyncTechnique::SeqSpoof` вызвать:

```rust
                self.apply_seq_spoof_with_context(state, hop_tab_override, conntrack_override);
```

Файл `core/src/engine/mod.rs`, заменить `apply_desync_sync()` на:

```rust
    fn apply_desync_sync(
        &self,
        group: &DesyncGroup,
        packet: bytes::Bytes,
        dscp_value: Option<u8>,
        tune_params: Option<TuneParams>,
        is_resumption: Option<bool>,
        conn_rng_fork: Option<crate::desync::rand::PerConnRng>,
    ) -> crate::desync::DesyncResult {
        let override_params: Option<crate::desync::group::ConfigOverride> = tune_params.map(Into::into);
        group.apply_with_runtime_context(
            &packet,
            dscp_value,
            override_params,
            is_resumption,
            conn_rng_fork,
            self.hop_tab.clone(),
            self.conntrack.clone(),
        )
    }
```

## Критерии готовности

- `apply_desync_sync()` не вызывает `group.clone()` и `set_context()`.
- `SeqSpoof` всё ещё получает `HopTab` и `Conntrack`.
- Старый `apply()`/`apply_with_rng()` продолжает работать в тестах.

## Верификация

```bash
rg -n "group_clone|set_context\(" core/src/engine core/src/desync/group.rs
cargo test -p freedpi-core desync::group -- --nocapture
```

---

---

# P1-08. Сделать `injected_seqs` атомарным check-and-mark, без `contains_key` + `insert` race

## Проблема

`moka::sync::Cache<SeqKey, ()>` используется как de-dup set для injected SEQ. Pattern `contains_key` затем `insert` не атомарен: два worker могут одновременно решить, что SEQ ещё не обработан, и оба применить desync к одной ретрансмиссии/дубликату.

## Решение и обоснование

Нужен атомарный `try_mark_first_seen(key) -> bool`. Для минимального diff использовать `DashMap<SeqKey, Instant>` и `entry()`; TTL eviction выполнить отдельным sweeper task. Это сохраняет concurrent sharding и убирает check-then-act race.

## Реализация

В `ProcessingPipeline` заменить поле:

```rust
// было
injected_seqs: moka::sync::Cache<SeqKey, ()>,

// стало
injected_seqs: Arc<dashmap::DashMap<SeqKey, std::time::Instant>>,
```

В constructor:

```rust
let injected_seqs = Arc::new(dashmap::DashMap::with_capacity(100_000));
Self::spawn_injected_seq_sweeper(injected_seqs.clone());
```

Добавить helper:

```rust
impl ProcessingPipeline {
    #[inline]
    fn try_mark_injected_seq(&self, key: SeqKey) -> bool {
        use dashmap::mapref::entry::Entry;
        match self.injected_seqs.entry(key) {
            Entry::Occupied(_) => false,
            Entry::Vacant(v) => {
                v.insert(std::time::Instant::now());
                true
            }
        }
    }

    fn spawn_injected_seq_sweeper(map: Arc<dashmap::DashMap<SeqKey, std::time::Instant>>) {
        crate::Runtime::global().io.spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                let now = std::time::Instant::now();
                map.retain(|_, seen| now.duration_since(*seen) < std::time::Duration::from_secs(60));
            }
        });
    }
}
```

В местах обработки TLS/QUIC, где сейчас есть `contains_key` или `insert`, заменить на:

```rust
if !self.try_mark_injected_seq(key) {
    return Ok(PacketDecision::Forward);
}
```

Важно: mark должен происходить **после** того, как classifier подтвердил, что это именно packet candidate для desync, но **до** генерации injects, чтобы две гоняющиеся worker-итерации не применили технику дважды.

Если генерация desync после mark возвращает passthrough из-за malformed payload, это допустимо: такой key считается обработанным и не будет бесконечно гоняться.

## Критерии готовности

- В коде нет `contains_key` + `insert` для `injected_seqs`.
- На одинаковый `SeqKey` при гонке только один thread получает `true`.
- Sweeper ограничивает memory growth.
- Нет `Mutex` на hot path.

## Верификация

Добавить concurrent test:

```rust
#[test]
fn injected_seq_mark_is_atomic() {
    let map = Arc::new(dashmap::DashMap::new());
    let key = (1, 2, 443, 50000, 12345);
    let wins = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    std::thread::scope(|s| {
        for _ in 0..32 {
            let map = map.clone();
            let wins = wins.clone();
            s.spawn(move || {
                use dashmap::mapref::entry::Entry;
                match map.entry(key) {
                    Entry::Occupied(_) => {}
                    Entry::Vacant(v) => {
                        v.insert(std::time::Instant::now());
                        wins.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            });
        }
    });

    assert_eq!(wins.load(std::sync::atomic::Ordering::Relaxed), 1);
}
```

---

---

# P1-09. Сделать `BadChecksum` dependency-aware: никакого silent no-op и никакой порчи real packet

## Проблема

`DesyncTechnique::BadChecksum` сейчас портит checksum только у `state.injects`. Если техника стоит до `FakeSni`/`FakeDataSplit`/другой inject-producing техники, `state.injects` пуст и `BadChecksum` молча no-op. GLM предложил применять bad checksum к `state.packet`, если injects пусты, но это опасно: можно отправить серверу единственную копию с плохим checksum и сломать соединение.

## Решение и обоснование

`BadChecksum` должен быть post-processing modifier только для fake/inject packets. Если в pipeline до него нет inject-producing техники, конфигурация невалидна. Исправление — dependency validation + deterministic reordering внутри `DesyncGroup::validate()` или fail-fast.

Выбран fail-fast: лучше отказать в запуске профиля с некорректным порядком, чем молча выпускать wire-visible поведение, отличное от конфигурации.

## Реализация

В `core/src/desync/group.rs` добавить helper:

```rust
impl DesyncTechnique {
    #[inline]
    pub fn produces_inject(self) -> bool {
        matches!(
            self,
            DesyncTechnique::FakeSni
                | DesyncTechnique::FakeDataSplit
                | DesyncTechnique::SeqSpoof
                | DesyncTechnique::TcpFrag
                | DesyncTechnique::OobInjection
                | DesyncTechnique::Disorder
                | DesyncTechnique::IpFragPrimitives
                | DesyncTechnique::BadChecksum // produces inject only when applied to existing injects; not a source
        )
    }

    #[inline]
    pub fn is_inject_source(self) -> bool {
        matches!(
            self,
            DesyncTechnique::FakeSni
                | DesyncTechnique::FakeDataSplit
                | DesyncTechnique::SeqSpoof
                | DesyncTechnique::TcpFrag
                | DesyncTechnique::OobInjection
                | DesyncTechnique::Disorder
                | DesyncTechnique::IpFragPrimitives
        )
    }
}
```

В `DesyncGroup::validate()` добавить:

```rust
let mut has_prior_inject_source = false;
for technique in &self.techniques {
    if *technique == DesyncTechnique::BadChecksum && !has_prior_inject_source {
        return Err(DesyncError::InvalidCombination(
            "BadChecksum must appear after a technique that creates inject packets; \
             it is not allowed to corrupt the real packet".to_string(),
        ));
    }
    if technique.is_inject_source() {
        has_prior_inject_source = true;
    }
}
```

В `apply_to_state` сохранить текущую semantics, но добавить debug assert:

```rust
DesyncTechnique::BadChecksum => {
    debug_assert!(
        !state.injects.is_empty(),
        "BadChecksum reached runtime without prior injects; validate() must reject this"
    );
    if state.injects.is_empty() {
        tracing::warn!("BadChecksum skipped: no inject packets; invalid profile escaped validation");
        return;
    }
    state.injects = state.injects
        .iter()
        .flat_map(|pkt| {
            let result = ip::bad_checksum(pkt);
            if result.inject.is_empty() {
                smallvec::smallvec![pkt.clone()]
            } else {
                result.inject
            }
        })
        .collect();
}
```

Если `DesyncError::InvalidCombination(String)` не существует, добавить вариант в существующий enum и обновить `Display`/`thiserror` derive.

## Критерии готовности

- Конфиг `techniques = ["BadChecksum", "FakeSni"]` не стартует как валидный профиль.
- Конфиг `techniques = ["FakeSni", "BadChecksum"]` стартует и портит checksum только у fake injects.
- `BadChecksum` никогда не портит `state.packet`, который должен достичь сервера.
- В runtime нет silent no-op для BadChecksum ordering.

## Верификация

```rust
#[test]
fn bad_checksum_before_inject_source_is_invalid() {
    let mut group = DesyncGroup::new(DesyncConfig::default());
    group.add(DesyncTechnique::BadChecksum);
    group.add(DesyncTechnique::FakeSni);
    assert!(group.validate().is_err());
}

#[test]
fn bad_checksum_after_fake_sni_is_valid() {
    let mut group = DesyncGroup::new(DesyncConfig::default());
    group.add(DesyncTechnique::FakeSni);
    group.add(DesyncTechnique::BadChecksum);
    assert!(group.validate().is_ok());
}
```

---

---

# P1-10. Сделать `TtlManipulation` не no-op: параметризовать и запретить standalone destructive mode

## Проблема

`DesyncTechnique::TtlManipulation` вызывается как:

```rust
ip::ttl_manipulation(&state.packet, 64)
```

TTL=64 — обычное значение Linux/macOS; для многих исходных пакетов это no-op. Если же изменить TTL реального packet на маленькое значение, можно не пройти до сервера и сломать соединение.

## Решение и обоснование

Развести две разные semantics:

1. `TtlManipulation` как modifier для **inject packets**: fake packet получает TTL/hop-limit `observed_hops - fake_ttl_offset`, чтобы пройти DPI и не достичь сервера.
2. Реальный `state.packet` не должен получать destructive TTL manipulation, кроме explicit config `allow_real_ttl_manipulation = true`, выключенной по умолчанию.

То есть технику не удаляем, а делаем meaningful и safe.

## Реализация

В `DesyncConfig` добавить:

```rust
#[serde(default)]
pub allow_real_ttl_manipulation: bool,
```

Default: `false`.

В `DesyncGroup::apply_to_state` заменить ветку:

```rust
DesyncTechnique::TtlManipulation => {
    let target_ttl = state
        .hop_ttl_hint
        .unwrap_or_else(|| state.packet_ttl().saturating_sub(fake_ttl_offset).max(1));

    if !state.injects.is_empty() {
        for pkt in state.injects.iter_mut() {
            let changed = ip::ttl_manipulation(pkt, target_ttl);
            if let Some(modified) = changed.modified {
                *pkt = modified;
            }
        }
    } else if self.config.allow_real_ttl_manipulation {
        self.merge_into_state(state, ip::ttl_manipulation(&state.packet, target_ttl));
    } else {
        tracing::warn!(
            "TtlManipulation skipped: no inject packets and allow_real_ttl_manipulation=false"
        );
    }
}
```

Если `PipelineState` ещё не имеет `hop_ttl_hint`/`packet_ttl()`, добавить безопасный helper:

```rust
impl PipelineState {
    #[inline]
    fn packet_ttl(&self) -> u8 {
        crate::desync::parse_ip_header(&self.packet)
            .map(|h| h.ttl())
            .unwrap_or(64)
    }
}
```

`hop_ttl_hint` можно не добавлять в первом patch: `packet_ttl().saturating_sub(fake_ttl_offset).max(1)` уже лучше, чем hardcoded 64. Следующий patch может подключить HopTab-calibrated TTL.

## Критерии готовности

- В коде нет hardcoded `ttl_manipulation(..., 64)`.
- По умолчанию `TtlManipulation` не меняет real packet, если нет inject packets.
- В комбинации `FakeSni + TtlManipulation` меняется TTL именно у fake injects.
- IPv4 checksum и IPv6 Hop Limit semantics остаются корректными через существующий `ip::ttl_manipulation()`.

## Верификация

```rust
#[test]
fn ttl_manipulation_without_injects_does_not_modify_real_packet_by_default() {
    let mut group = DesyncGroup::new(DesyncConfig::default());
    group.add(DesyncTechnique::TtlManipulation);
    let pkt = build_ipv4_tcp_packet_with_ttl(64);
    let out = group.apply(&pkt.into(), None, None, None);
    assert!(out.modified.is_none());
}
```

---

---

# P1-11. Убрать hot-path allocation в `extract_tcp_options()` и `tls_record_pad()`

## Проблема

`desync/tcp.rs::extract_tcp_options()` возвращает `Vec<u8>` и делает `to_vec()` на TCP options. Это allocation на каждую технику, которая пересобирает TCP packet with options.

`desync/tls.rs::tls_record_pad()` делает `random_bytes(pad_size)` + `packet.to_vec()` + `Vec::splice()`. Это минимум две аллокации и O(n) memmove на hot path.

## Решение и обоснование

- TCP options должны возвращаться borrowed slice `&[u8]` из исходного packet.
- TLS padding должен строиться через один `BytesMut` нужного размера и in-place random fill.

## Реализация A — TCP options borrowed slice

В `core/src/desync/tcp.rs` заменить:

```rust
fn extract_tcp_options(packet: &[u8]) -> Vec<u8>
```

на:

```rust
fn extract_tcp_options(packet: &[u8]) -> &[u8] {
    let ip = match pnet_packet::ipv4::Ipv4Packet::new(packet) {
        Some(p) => p,
        None => return &[],
    };
    let ip_hdr_len = ip.get_header_length() as usize * 4;
    let tcp_data = match packet.get(ip_hdr_len..) {
        Some(d) => d,
        None => return &[],
    };
    let tcp = match pnet_packet::tcp::TcpPacket::new(tcp_data) {
        Some(t) => t,
        None => return &[],
    };
    let data_offset = tcp.get_data_offset() as usize * 4;
    if data_offset > 20 && data_offset <= tcp_data.len() {
        &tcp_data[20..data_offset]
    } else {
        &[]
    }
}
```

В местах использования оставить `tcp_options.len()` и `copy_from_slice(tcp_options)`; `&[u8]` совместим.

## Реализация B — TLS padding one allocation

Добавить в `desync/rand.rs`, если отсутствует:

```rust
pub fn fill_random_bytes(dst: &mut [u8]) {
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(dst);
}
```

В `tls_record_pad()` заменить padding/splice блок:

```rust
let new_len = packet.len().saturating_add(pad_size);
if new_len > u16::MAX as usize {
    return DesyncResult::passthrough();
}

let tcp_payload_offset = ip.header_len() + data_offset;
let insert_pos = tcp_payload_offset + ch_end;
if insert_pos > packet.len() {
    return DesyncResult::passthrough();
}

let mut modified = bytes::BytesMut::with_capacity(new_len);
modified.extend_from_slice(&packet[..insert_pos]);
let pad_start = modified.len();
modified.resize(pad_start + pad_size, 0);
crate::desync::rand::fill_random_bytes(&mut modified[pad_start..pad_start + pad_size]);
modified.extend_from_slice(&packet[insert_pos..]);
let mut modified = modified.freeze().to_vec(); // keep existing checksum code simple in first patch
```

Второй этап оптимизации: не делать `freeze().to_vec()`, а выполнять checksum writes до `freeze()`. Если текущие helper functions требуют `&mut [u8]`, лучше сразу оставить `BytesMut` mutable до конца:

```rust
let mut modified = bytes::BytesMut::with_capacity(new_len);
// ... fill/copy ...
// write checksums directly into modified[..]
DesyncResult::modified_only(modified.freeze())
```

## Критерии готовности

- `extract_tcp_options()` больше не аллоцирует.
- `tls_record_pad()` не использует `Vec::splice()` и `random_bytes()` intermediate Vec.
- Functional output идентичен: TLS record length, IP total length, TCP checksum корректны.

## Верификация

- `grep -R "extract_tcp_options(packet.*Vec" core/src/desync/tcp.rs` не находит старой сигнатуры.
- `grep -R "splice(insert_pos" core/src/desync/tls.rs` пуст.
- `cargo test -p freedpi-core desync::tls`.
- Perf microbench: `tls_record_pad` allocations/op должны снизиться минимум на 1 allocation по сравнению с baseline.

---

---

# P1-12. Исправить HopTab robustness: `observe_robust()` в engine и `u16` generation counter

## Проблема

GLM нашёл две отдельные проблемы:

1. Engine вызывает `HopTab::observe()`, а не `observe_robust()`, хотя именно robust path содержит EMA/outlier rejection.
2. `gen_counters[set].fetch_add(...) as u8` ломает LRU после 256 insertions per set.

## Решение и обоснование

HopTab используется для TTL/hop estimation в fake packet strategies. Ошибка в hop estimate даёт fake TTL, который не доходит до DPI или доходит до сервера. Поэтому robust observation должен быть default, а LRU generation должен выдерживать горячие CDN/DHT buckets.

## Реализация A — robust observe

В `engine/mod.rs`, где сейчас:

```rust
self.hop_tab.observe(HopTab::ip_to_u32(&cp.dst_ip), ip_packet.get_ttl());
```

заменить на:

```rust
self.hop_tab.observe_robust(HopTab::ip_to_u32(&cp.dst_ip), ip_packet.get_ttl());
```

Для IPv6 добавить аналог, используя `parse_ip_header()`:

```rust
if self.config.hop_tab_enabled {
    if let Some(ip) = crate::desync::parse_ip_header(original_packet) {
        self.hop_tab.observe_robust(
            HopTab::ip_to_u32(&ip.dst()),
            ip.ttl(),
        );
    }
}
```

Если `HopTab::ip_to_u32()` не принимает IPv6 корректно, добавить stable hash для IPv6:

```rust
pub fn ip_to_key(ip: &std::net::IpAddr) -> u32 {
    match ip {
        std::net::IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()),
        std::net::IpAddr::V6(v6) => {
            let o = v6.octets();
            u32::from_be_bytes([o[0] ^ o[12], o[1] ^ o[13], o[2] ^ o[14], o[3] ^ o[15]])
        }
    }
}
```

и обновить вызывающие места.

## Реализация B — `u16` generation

В `adaptive/hop_tab.rs` заменить packing:

```rust
fn pack_entry(ip: u32, hops: u8, gen: u16) -> u64 {
    (ip as u64) | ((hops as u64) << 32) | ((gen as u64) << 40)
}

fn unpack_entry(val: u64) -> (u32, u8, u16) {
    let ip = val as u32;
    let hops = (val >> 32) as u8;
    let gen = (val >> 40) as u16;
    (ip, hops, gen)
}
```

Заменить `AtomicU8`/cast-to-u8 counter на `AtomicU16`:

```rust
use std::sync::atomic::AtomicU16;

gen_counters: [AtomicU16; NUM_SETS],
```

И:

```rust
let gen = self.gen_counters[set].fetch_add(1, Ordering::Relaxed);
```

Если массив `[AtomicU16; NUM_SETS]` инициализируется вручную, использовать `std::array::from_fn(|_| AtomicU16::new(0))`.

## Критерии готовности

- Engine нигде не вызывает plain `observe()` для live packet observations.
- Generation counter больше не truncates to `u8`.
- LRU eviction остаётся deterministic после >256 insertions в один set.
- IPv6 destinations получают stable HopTab key или явно не участвуют, но не corrupt state.

## Верификация

```rust
#[test]
fn hop_tab_generation_survives_more_than_256_inserts_per_set() {
    let tab = HopTab::new();
    for i in 0..300u32 {
        let ip = i << 10; // подобрать pattern, который попадает в один set согласно hash
        tab.observe_robust(ip, 58);
    }
    // Тест должен проверять, что самый новый entry не выбирается как oldest только из-за wrap.
}
```

Если set selection сложная, добавить `#[cfg(test)] fn set_for_key(key: u32) -> usize` и подобрать keys программно.

---

---

# P1-13. Переписать TLS 1.3 resumption-aware fake ClientHello: зеркалировать shape, не random ticket fantasy

## Проблема

Текущий resumption detector/fake CH generator мыслит через `session_ticket`, но в TLS 1.3 resumption/0-RTT observable shape определяется extensions `pre_shared_key`, `psk_key_exchange_modes`, `early_data`, `key_share` и binders. Случайно сгенерированный fake ticket/extension набор может отличаться от реального ClientHello и стать fingerprint-сигнатурой.

## Решение и обоснование

Fake CH не должен изобретать resumption structure. Он должен зеркалировать форму реального ClientHello:

- Если real CH не содержит `pre_shared_key`, fake CH тоже не должен содержать PSK/early_data.
- Если real CH содержит PSK, fake CH должен копировать **observable extension ordering/classes** и длиновую форму, но не пытаться создать cryptographically valid binder.
- Если нельзя безопасно зеркалировать PSK/binder shape, fake CH для resumption должен отключаться для этой flow и использовать non-CH desync techniques: split/frag/oob/tcp-level.

## Реализация

Добавить parsed summary:

```rust
#[derive(Debug, Clone, Default)]
pub struct ClientHelloShape {
    pub has_pre_shared_key: bool,
    pub has_psk_key_exchange_modes: bool,
    pub has_early_data: bool,
    pub extension_order: smallvec::SmallVec<[u16; 32]>,
    pub pre_shared_key_len: Option<usize>,
}
```

В TLS parser добавить:

```rust
pub fn parse_client_hello_shape(tls_record: &[u8]) -> Option<ClientHelloShape> {
    // Реализовать поверх уже существующего ClientHello parser.
    // Обязательно: без allocation на hot path кроме SmallVec inline capacity.
    // Extension IDs:
    // pre_shared_key = 0x0029, psk_key_exchange_modes = 0x002D, early_data = 0x002A.
    // Возвращать None на malformed/truncated.
}
```

В `PipelineState` добавить:

```rust
pub client_hello_shape: Option<ClientHelloShape>,
```

В engine перед `apply_desync_sync` заполнить shape из TLS payload, не full IP packet:

```rust
let tls_payload = packet.get(cp.payload_offset..).unwrap_or_default();
let ch_shape = crate::desync::tls::parse_client_hello_shape(tls_payload);
```

В `FakeSni`/`ch_gen`:

```rust
if let Some(shape) = &state.client_hello_shape {
    if shape.has_pre_shared_key {
        tracing::debug!("resumption ClientHello detected; disabling fake CH generator for fingerprint safety");
        return DesyncResult::passthrough();
    }
}
```

Это консервативный первый полноценный вариант: не генерировать потенциально fingerprintable fake resumption CH. Чтобы не терять обход, профиль должен fallback-ить на `TlsRecordFrag`, `SniMicrofrag`, `OobInjection` или TCP-level техники. После реализации binder-shape mirroring можно включить fake CH для PSK flows.


## DeepSeek-merged safe default

Default policy: если реальный ClientHello содержит TLS 1.3 PSK/0-RTT resumption shape (`pre_shared_key`, `psk_key_exchange_modes`, `early_data` или binders), `FakeSni` по умолчанию отключается для этого flow. Advanced mirrored fake CH разрешён только если builder копирует форму PSK/0-RTT без порчи real CH и проходит regression tests. Нельзя менять real SNI на resumption path: ticket/PSK может быть связан с исходным SNI и серверным контекстом.

## Критерии готовности

- Fake CH generator не создаёт случайный PSK/ticket для TLS 1.3 resumption.
- Resumption flow получает безопасный fallback technique, а не просто passthrough всего профиля.
- Extension IDs `0x0029`, `0x002D`, `0x002A` покрыты тестами.

## Верификация

```rust
#[test]
fn fake_ch_is_disabled_for_tls13_psk_shape() {
    let ch = build_tls13_clienthello_with_psk_extensions();
    let shape = parse_client_hello_shape(&ch).unwrap();
    assert!(shape.has_pre_shared_key);
    assert!(shape.has_psk_key_exchange_modes);
    let out = fake_sni_with_shape(&ch, "example.org", Some(&shape));
    assert!(out.inject.is_empty());
    assert!(out.modified.is_none());
}
```

---

---

# P1-14. Полностью убрать `Mutex<AutoTune>` с hot path

## Проблема

Даже после P0-04 `self.auto_tune.lock()` остаётся в recommend/record_application. Это lock convoy на многоядерной нагрузке.

## Решение

Перейти с `HashMap<String, usize>` и `HashMap<String, TuneParams>` под mutex на immutable registry mapping + `ArcSwap<HashMap<String, TuneParams>>` для overrides и atomics в `DashMap<String, Arc<StrategyMetrics>>` или, лучше, `Vec<StrategyMetrics>` по `strategy_id`.

## Реализация

Это большая PR после P2. Не делать одновременно с P0, чтобы не смешивать correctness и performance. Конкретный контракт:

```rust
pub struct AutoTune {
    metrics_by_id: Vec<StrategyMetrics>,
    name_to_id: std::collections::HashMap<String, u32>,
    overrides: arc_swap::ArcSwap<std::collections::HashMap<String, TuneParams>>,
    tune_threshold: f64,
}
```

- `record_application_by_id(id, ...)` и `record_outcome_by_id(id, ...)` принимают `u32` и не берут lock.
- `recommend(name)` читает `overrides.load()` и atomics без mutex.
- `set_override/clear_override` clone-on-write: load map, clone, mutate, store.

## Критерии готовности

- `rg -n "auto_tune\.lock" core/src/engine` не находит hot path.
- `MAX_STRATEGIES=16` удалён.
- Метрики не коллизируют по длине имени.

## Верификация

Unit: создать 64 профиля с разными именами одинаковой длины, записать outcome для каждого, проверить отсутствие коллизий.

---

---


# P1-15. Заменить string-based active profiles на `ProfileId`/`AtomicU32` и ProfileId-indexed AutoTune metrics

## Проблема

DeepSeek-review правильно уточнил уже известную проблему `Mutex<AutoTune>`: даже если убрать mutex, string-based active-profile lookup и `HashMap<String, ...>` в steady-state оставляют hot-path зависимость от строк и map lookup. `ArcSwap<String>` для активного профиля не является главным bottleneck сам по себе, но он закрепляет неправильную модель: runtime data path должен работать с числовым immutable profile id, а строки должны остаться на config/API boundary.

## Решение и обоснование

После загрузки конфигурации `StrategyProfileRegistry` должен выдавать стабильные `ProfileId`. Active profile для TLS/QUIC/HTTP хранится как `AtomicU32`, AutoTune metrics — preallocated `Vec<StrategyMetrics>` или boxed slice по `ProfileId`. Manual API всё ещё принимает names, но переводит name -> id вне packet path.

Это сильнее, чем `DashMap<String, Arc<StrategyMetrics>>`: registration может оставаться map-based, но packet path должен быть `id -> array[index]`.

## Реализация

```rust
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProfileId(pub u32);

pub struct StrategyProfile {
    pub id: ProfileId,
    pub name: Arc<str>,
    pub category: StrategyCategory,
    pub desync_group: Arc<DesyncGroup>,
    pub default_params: TuneParams,
}

pub struct StrategyProfileRegistry {
    profiles: Vec<StrategyProfile>,
    name_to_id: std::collections::HashMap<Arc<str>, ProfileId>,
}

impl StrategyProfileRegistry {
    #[inline]
    pub fn get_by_id(&self, id: ProfileId) -> Option<&StrategyProfile> {
        self.profiles.get(id.0 as usize)
    }

    pub fn id_by_name(&self, name: &str) -> Option<ProfileId> {
        self.name_to_id.get(name).copied()
    }
}
```

В `ProcessingPipeline`:

```rust
active_profile_tls: AtomicU32,
active_profile_quic: AtomicU32,
active_profile_http: AtomicU32,
```

В AutoTune:

```rust
pub struct AutoTune {
    metrics_by_profile: Box<[StrategyMetrics]>,
    overrides: arc_swap::ArcSwap<Vec<Option<TuneParams>>>,
}

impl AutoTune {
    #[inline]
    pub fn recommend_by_id(&self, id: ProfileId) -> TuneParams {
        if let Some(Some(p)) = self.overrides.load().get(id.0 as usize) {
            return p.clone();
        }
        self.metrics_by_profile[id.0 as usize].recommend()
    }

    #[inline]
    pub fn record_outcome_by_id(&self, id: ProfileId, outcome: StrategyOutcome) {
        self.metrics_by_profile[id.0 as usize].record_outcome(outcome);
    }
}
```

Call-site rule: `process_outbound_tls_sync`, `process_quic_sync`, `process_http_sync` must resolve active profile by atomic id, not by string. API handlers may still call `id_by_name()` once per request.

## Критерии готовности

- `rg -n "active_profile_.*ArcSwap|active_profile_.*String" core/src` не находит hot-path active profile string storage.
- `rg -n "recommend\(&profile\.name|record\(&profile\.name" core/src` не находит packet-path AutoTune by string.
- Manual config/API still accepts profile names.
- Changing active profile через API updates `AtomicU32` and affects next packet without string lookup.
- AutoTune metrics count by `ProfileId` and cannot collide by string length/name hash.

## Верификация

```bash
cargo test -p freedpi-core strategy_profile_id_registry
cargo test -p freedpi-core autotune_profile_id_metrics
rg -n "active_profile_.*String|auto_tune\.lock|recommend\(&profile\.name" core/src
```

---

# P2-01. Уважать `StrategyProfileConfig.enabled` и активировать профиль при запуске

## Проблема

`enabled` в `[[strategies]]` декларирован как “предварительно активирует профиль”, но `from_config()` смотрит только `default`. Пользовательская конфигурация может быть валидной и не влиять на runtime.

## Решение и обоснование

`default = true` и `enabled = true` должны оба устанавливать category default для startup active profile. Разница: `default` документировать как preferred default, `enabled` как backward-compatible alias. Не удаляем поле.

## Реализация

Файл `core/src/adaptive/strategy_profile.rs`.

Заменить:

```rust
                    if user_cfg.default == Some(true) {
                        registry.category_defaults.insert(category, name.clone());
                    }
```

на:

```rust
                    if user_cfg.default == Some(true) || user_cfg.enabled == Some(true) {
                        registry.category_defaults.insert(category, name.clone());
                    }
```

Дополнительно в `profile_config_to_profile()` заменить:

```rust
        desync_group: std::sync::Arc::new(DesyncGroup::new(DesyncConfig::default())),
```

на полноценную группу из переданных техник невозможно, потому что функция не принимает `base_config`. Поэтому изменить сигнатуру:

```rust
pub fn profile_config_to_profile(
    config: &StrategyProfileConfig,
    strategy_id: u32,
    base_config: &crate::desync::DesyncConfig,
) -> Result<crate::adaptive::strategy_profile::StrategyProfile, String>
```

и внутри:

```rust
    let mut group = DesyncGroup::new(base_config.clone());
    for t in &techniques {
        group.add(*t);
    }
    if let Err(e) = group.validate() {
        return Err(format!("Invalid technique composition in strategy '{}': {}", config.name, e));
    }
```

Initializer:

```rust
        desync_group: std::sync::Arc::new(group),
```

В `from_config()` заменить вызов:

```rust
            match crate::config::profile_config_to_profile(user_cfg, id, base_config) {
```

## Критерии готовности

- `enabled=true` активирует профиль при startup так же, как `default=true`.
- `profile_config_to_profile()` не возвращает `StrategyProfile` с пустым `DesyncGroup`.
- Невалидная композиция пользовательских техник даёт explicit error, а не silent fallback.

## Верификация

Добавить тест в `strategy_profile.rs`:

```rust
#[test]
fn test_user_enabled_sets_category_default() {
    let cfg = crate::config::StrategyProfileConfig {
        name: "my_tls".into(),
        protocol: "tls".into(),
        techniques: vec!["multisplit".into()],
        split_size: Some(1),
        split_count: Some(2),
        fake_ttl_offset: Some(1),
        max_seg_size: Some(100),
        default: None,
        enabled: Some(true),
    };
    let registry = StrategyProfileRegistry::from_config(&DesyncConfig::default(), &[cfg], &[]);
    assert_eq!(
        registry.get_default_for_category(StrategyCategory::Tls).unwrap().name,
        "my_tls"
    );
}
```

---

---

# P2-02. Замкнуть Probe -> StrategyProfile -> Pipeline contour

## Проблема

Probe subsystem возвращает рекомендации/JSON/history, но не применяет их к active pipeline. Это диагностический UI, не адаптивный контур.

## Решение и обоснование

Probe должен возвращать `strategy_id` + `TuneParams`, а service должен вызывать `ProcessingPipeline::apply_strategy_tune()`. Это уже существующая точка изменения runtime; её надо использовать автоматически при `auto_probe` и вручную из API.

## Реализация

Файл `core/src/adaptive/probe_tune_run.rs` или текущий тип результата probe: добавить conversion function. Если текущий `recommend()` возвращает собственный тип, реализовать в этом файле:

```rust
use crate::adaptive::auto_tune::TuneParams;

pub fn recommendation_to_tune_params(rec: &ProbeRecommendation) -> TuneParams {
    TuneParams {
        split_size: rec.split_size,
        split_count: rec.split_count,
        fake_ttl_offset: rec.fake_ttl_offset,
        max_seg_size: rec.max_seg_size,
    }
}
```

Если полей у `ProbeRecommendation` нет, добавить их в структуру результата probe, заполняя из существующей логики выбора стратегии. Не возвращать `None` для выбранной стратегии: если probe выбрал strategy, всегда заполнять параметры из registry default.

Файл `service/src/main.rs`.

В startup auto-probe block, после `let rec = module.recommend(&result);`, добавить:

```rust
if let Some(strategy_id) = rec.strategy_id {
    let params = freedpi_core::adaptive::probe_tune_run::recommendation_to_tune_params(&rec);
    engine.apply_strategy_tune(strategy_id, params);
    tracing::info!(
        "Auto-probe applied strategy_id={} for domain={} verdict={:?}",
        strategy_id,
        domain,
        result.verdict
    );
}
```

В API handler `probe_domain()` добавить то же применение только если request содержит `apply=true`. Если такого поля нет, расширить request struct:

```rust
#[derive(Deserialize)]
struct ProbeRequest {
    domain: String,
    #[serde(default)]
    apply: bool,
}
```

и:

```rust
if req.apply {
    if let Some(strategy_id) = rec.strategy_id {
        let params = freedpi_core::adaptive::probe_tune_run::recommendation_to_tune_params(&rec);
        engine.apply_strategy_tune(strategy_id, params);
    }
}
```

## Критерии готовности

- `auto_probe` реально меняет `active_profile_*` через `apply_strategy_tune()`.
- API probe по умолчанию остаётся read-only; `apply=true` применяет результат.
- В логах есть событие применения с `strategy_id`, category и profile name.

## Верификация

- Unit: mock recommendation with `strategy_id=31`, call apply, assert active QUIC profile changes.
- Integration: blocked canary domain -> auto_probe -> `GET /strategies/active` показывает выбранный профиль.

---

---

# P2-03. Подключить SplitTunnel decisions к live data path

## Проблема

`SplitTunnel` создаётся и управляется API, но его decision methods (`should_bypass_ip_fast`, `should_bypass_ip`, `should_bypass_domain`, `decide`, `build_win_divert_filter`) не вызываются из engine. Пользовательская split-tunnel конфигурация не влияет на packets.

## Решение и обоснование

SplitTunnel должен быть ранним bypass gate перед AdaptiveRouter/desync/proxy. Если flow/domain/IP marked bypass — packet должен идти Forward без DPI-evasion transformations и без proxy. Это одновременно снижает latency и уважает настройки пользователя.

## Реализация

1. Передать `Arc<SplitTunnel>` в `ProcessingPipeline`.

В `ProcessingPipeline` добавить:

```rust
split_tunnel: Option<Arc<crate::split_tunnel::SplitTunnel>>,
```

В constructor добавить параметр или setter:

```rust
pub fn with_split_tunnel(mut self, split_tunnel: Arc<crate::split_tunnel::SplitTunnel>) -> Self {
    self.split_tunnel = Some(split_tunnel);
    self
}
```

Лучше изменить `ProcessingPipeline::new(config, split_tunnel: Option<Arc<SplitTunnel>>)` и обновить все вызывающие места, чтобы bypass был доступен с момента старта.

2. Сделать SplitTunnel internals hot-path safe. Если внутри сейчас `Mutex<HashMap<...>>`, заменить на `ArcSwap<SplitTunnelSnapshot>`:

```rust
#[derive(Debug, Clone, Default)]
pub struct SplitTunnelSnapshot {
    pub bypass_ips: Vec<ipnet::IpNet>,
    pub bypass_domains: Vec<String>,
    pub proxy_domains: Vec<String>,
}

pub struct SplitTunnel {
    snapshot: arc_swap::ArcSwap<SplitTunnelSnapshot>,
}

impl SplitTunnel {
    pub fn update_snapshot(&self, next: SplitTunnelSnapshot) {
        self.snapshot.store(Arc::new(next));
    }

    #[inline]
    pub fn should_bypass_ip_fast(&self, ip: &std::net::IpAddr) -> bool {
        let snap = self.snapshot.load();
        snap.bypass_ips.iter().any(|net| net.contains(ip))
    }

    #[inline]
    pub fn should_bypass_domain(&self, domain: &str) -> bool {
        let snap = self.snapshot.load();
        snap.bypass_domains.iter().any(|suffix| {
            domain == suffix || domain.ends_with(&format!(".{suffix}"))
        })
    }
}
```

Если allocation в `format!` вызывает concern, заменить на suffix check без allocation:

```rust
fn domain_matches_suffix(domain: &str, suffix: &str) -> bool {
    domain == suffix || (domain.len() > suffix.len()
        && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.'
        && domain.ends_with(suffix))
}
```

3. В `process_one_sync_dispatch` до AdaptiveRouter:

```rust
if let Some(st) = &self.split_tunnel {
    if st.should_bypass_ip_fast(&cp.dst_ip) {
        return Ok(PacketDecision::Forward);
    }
    if let Some(domain) = self.fake_ip.lookup(&cp.dst_ip) {
        if st.should_bypass_domain(&domain) {
            return Ok(PacketDecision::Forward);
        }
    }
}
```

## Критерии готовности

- SplitTunnel API changes обновляют snapshot, который читает packet path.
- Hot path не берёт `Mutex`.
- Bypass decision происходит до desync/proxy.
- Tests на API-only state больше не тестируют dead code: они проверяют real pipeline decision.

## Верификация

Integration test:

```rust
#[test]
fn split_tunnel_bypass_domain_reaches_pipeline_decision() {
    let st = Arc::new(SplitTunnel::new());
    st.update_snapshot(SplitTunnelSnapshot {
        bypass_domains: vec!["example.org".to_string()],
        ..Default::default()
    });
    let pipeline = ProcessingPipeline::new_api_only(config).with_split_tunnel(st);
    pipeline.fake_ip.insert_for_test(IpAddr::V4([1,2,3,4].into()), "example.org");
    let pkt = build_tls_clienthello_to_ip(IpAddr::V4([1,2,3,4].into()));
    let decision = pipeline.process_one_for_test(pkt).unwrap();
    assert!(matches!(decision, PacketDecision::Forward));
}
```

---

---

# P2-04. Замкнуть AdaptiveRouter `CircuitBreaker` и `ThroughputTracker`

## Проблема

`record_rst`, `record_success`, `record_bytes` существуют, но не вызываются из live worker path. Поэтому CircuitBreaker всегда Closed, throughput routing всегда видит 0, и AdaptiveRouter не адаптируется.

## Решение и обоснование

Нужно подключить события datapath:

- На outbound first packet with selected route/strategy: создать flow routing state.
- На inbound TCP RST для tracked flow: `record_rst(route_key)`.
- На inbound data bytes для flow после desync/proxy decision: `record_success(route_key)` и `record_bytes(route_key, bytes)`.

Если default filter не перехватывает inbound data ради производительности, нужен отдельный узкий observer filter для tracked flows или sampling mode. Без inbound наблюдений CircuitBreaker должен быть отключён, а не притворяться активным.

## Реализация

1. Добавить config:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveRouterConfig {
    #[serde(default = "default_observe_inbound_failures")]
    pub observe_inbound_failures: bool,
    // existing fields...
}

fn default_observe_inbound_failures() -> bool { true }
```

2. В classifier добавить recognition inbound TCP RST:

```rust
#[derive(Debug, Clone)]
pub enum Classification {
    // existing...
    TcpControl(ConnectionPacket),
}
```

или использовать existing `Classification::Tcp` если есть. Главное — engine должен видеть TCP flags.

3. В engine на inbound RST:

```rust
if cp.is_inbound && cp.protocol == 6 && cp.tcp_flags & pnet_packet::tcp::TcpFlags::RST != 0 {
    if let Some(route_key) = self.conntrack.route_key_for_reverse_flow(&cp) {
        self.adaptive_router.record_rst(&route_key);
    }
    return Ok(PacketDecision::Forward);
}
```

4. На успешный outbound decision записать route key в conntrack:

```rust
entry.route_key = Some(decision.route_key.clone());
entry.desync_applied = matches!(decision.action, RouteAction::Desync | RouteAction::Proxy);
```

5. На inbound non-RST data:

```rust
if cp.is_inbound && cp.payload_len > 0 {
    if let Some(route_key) = self.conntrack.route_key_for_reverse_flow(&cp) {
        self.adaptive_router.record_success(&route_key);
        self.adaptive_router.record_bytes(&route_key, cp.payload_len as u64);
    }
}
```

Если inbound observation слишком expensive, не добавлять его в default WinDivert filter для всех packets. Вместо этого открыть second observer handle с narrow filter for TCP RST and small sampled inbound SYN/ACK/data, либо per-flow observation на первые N packets после desync.

## Критерии готовности

- `record_rst`, `record_success`, `record_bytes` имеют live call sites outside tests/dead `execute_decision_sync`.
- CircuitBreaker state меняется в тесте при серии RST.
- ThroughputTracker показывает non-zero throughput при inbound data.
- Если inbound observer выключен, AdaptiveRouter явно не использует CB/throughput decisions.

## Верификация

```rust
#[test]
fn adaptive_router_circuit_breaker_opens_from_live_rst_events() {
    let router = AdaptiveRouter::new(test_config_with_low_rst_threshold());
    for _ in 0..5 {
        router.record_rst("direct");
    }
    assert!(router.is_circuit_open_for_test("direct"));
}
```

Integration на Windows: сервер, который RST-ит connection после ClientHello; pipeline должен после threshold перестать выбирать failing route.

---

---

# P2-05. Встроить FallbackChain, TargetEscalator и ProbeTuneRun в единый adaptive contour

## Проблема

GLM нашёл, что FallbackChain, TargetEscalator и ProbeTuneRun существуют как код/тесты, но не влияют на packet path. Это создаёт ложную зрелость: система заявляет fallback/escalation/probing, но runtime не меняет стратегию на основании наблюдений.

## Решение и обоснование

Сделать единую модель:

- `ProbeTuneRun` генерирует candidate policy для домена/ASN/route.
- `TargetEscalator` повышает aggressiveness при реальных failure signals: early RST, timeout before response, ICMP unreachable, repeated connection aborts.
- `FallbackChain` выбирает следующую стратегию при circuit-open/low network outcome.
- `AutoTune` получает две разные категории данных: local CPU/application metric из P0-07 и delayed network outcome из conntrack/router.
- `AdaptiveRouter::decide()` больше не опирается на tautological success_rate; proxy fallback branch должен становиться достижимым при реальном падении network outcome.
- `StrategyProfileRegistry` публикует выбранную runtime policy через `ArcSwap<RuntimePolicy>`.
- Packet path читает только immutable snapshot, без блокировок.

## Реализация

Добавить тип runtime policy:

```rust
#[derive(Debug, Clone)]
pub struct RuntimePolicy {
    pub tls_profile: String,
    pub quic_profile: String,
    pub http_profile: String,
    pub aggressiveness: u8,
    pub updated_at: std::time::Instant,
    pub reason: RuntimePolicyReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimePolicyReason {
    StartupDefault,
    ProbeRecommendation,
    FallbackAfterFailure,
    ManualOverride,
}
```

В `ProcessingPipeline`:

```rust
runtime_policy: ArcSwap<RuntimePolicy>,
fallback_chain: Arc<crate::adaptive::fallback::FallbackChain>,
target_escalator: Arc<crate::adaptive::target_escalator::TargetEscalator>,
```

Packet path:

```rust
let policy = self.runtime_policy.load();
let profile_name = match classification {
    Classification::Tls(_) => &policy.tls_profile,
    Classification::Quic(_) => &policy.quic_profile,
    Classification::Http(_) => &policy.http_profile,
    _ => return Ok(PacketDecision::Forward),
};
let profile = self.profile_registry.get(profile_name).unwrap_or_else(|| self.profile_registry.default_for(...));
```

Outcome path:

```rust
fn on_flow_outcome(&self, flow: FlowId, outcome: FlowOutcome) {
    match outcome {
        FlowOutcome::Blocked | FlowOutcome::ServerRst | FlowOutcome::Timeout => {
            self.fallback_chain.record_failure(flow.target_key());
            if let Some(next) = self.fallback_chain.next_strategy(flow.target_key()) {
                let mut current = (**self.runtime_policy.load()).clone();
                current.tls_profile = next.tls_profile;
                current.quic_profile = next.quic_profile;
                current.aggressiveness = self.target_escalator.escalate(flow.target_key());
                current.updated_at = std::time::Instant::now();
                current.reason = RuntimePolicyReason::FallbackAfterFailure;
                self.runtime_policy.store(Arc::new(current));
            }
        }
        FlowOutcome::Established => {
            self.fallback_chain.record_success(flow.target_key());
        }
    }
}
```

ProbeTuneRun integration:

```rust
pub fn apply_probe_recommendation(&self, rec: ProbeRecommendation) {
    let mut current = (**self.runtime_policy.load()).clone();
    if let Some(tls) = rec.tls_profile { current.tls_profile = tls; }
    if let Some(quic) = rec.quic_profile { current.quic_profile = quic; }
    current.reason = RuntimePolicyReason::ProbeRecommendation;
    current.updated_at = std::time::Instant::now();
    self.runtime_policy.store(Arc::new(current));
}
```

Если реальные names/types в `fallback.rs`/`target_escalator.rs` отличаются, агент обязан адаптировать wrapper layer, но invariant остаётся: output этих подсистем должен менять `runtime_policy`, который читает packet path.

## Критерии готовности

- `FallbackChain::record_success/record_failure/next/advance` имеют live call sites.
- `TargetEscalator` имеет live call site на failure outcome.
- `ProbeTuneRun` recommendation вызывает `runtime_policy.store(...)`.
- Packet path выбирает profile из `runtime_policy`, а не только из startup constants.
- Manual override имеет приоритет над auto policy и сохраняется до явного сброса.

## Верификация

```rust
#[test]
fn probe_recommendation_changes_runtime_profile_used_by_packet_path() {
    let pipeline = ProcessingPipeline::new_api_only(test_config());
    pipeline.apply_probe_recommendation(ProbeRecommendation {
        tls_profile: Some("tls_aggressive".into()),
        quic_profile: None,
        http_profile: None,
    });
    let pkt = build_tls_clienthello_packet();
    let selected = pipeline.selected_profile_for_test(&pkt).unwrap();
    assert_eq!(selected.name, "tls_aggressive");
}
```

---

---


---

# P2-06. Заменить ложный `Conntrack::gc_incremental` на timing-wheel/bucketed GC с доказуемым покрытием

## Проблема

`Conntrack::gc_incremental()` заявлен как round-robin по shards, но фактически делает `DashMap::iter().skip(start)`, где `start` меняется только в диапазоне 0..15. Это пропускает несколько entries логического итератора, а не shard. При большой таблице и 1ms budget функция будет снова и снова сканировать начало итератора, а хвост map может никогда не посещаться. Полный `gc()` существует, но production loop вызывает `gc_incremental()`.

Это long-run memory leak под torrent/DHT/high-churn нагрузкой: stale `ConntrackEntry` с `PerConnRng`, `Vec<u8>` QUIC DCID и state остаются навсегда, если попали за предел достижимого окна iterator scan.

## Решение и обоснование

Не пытаться строить cursor поверх `DashMap::iter()`: этот iterator не даёт стабильного shard/cursor API. Вместо этого добавить timing-wheel index по expiration slots. Work per tick bounded: GC обрабатывает один slot, проверяет фактический `last_activity`, удаляет stale или requeue в будущий slot.

Это лучше, чем `DashMap::retain()` с deadline внутри closure: `retain()` всё равно должен пройти map, а deadline только меняет keep/delete, но не останавливает обход. Timing wheel даёт реальное покрытие и bounded work.

## Реализация

В `core/src/conntrack.rs` добавить imports:

```rust
use crossbeam_queue::SegQueue;
```

Добавить dependency, если ещё нет:

```toml
crossbeam-queue = "0.3"
```

Заменить `gc_cursor` в `ConntrackInner`:

```rust
const GC_WHEEL_SLOTS: usize = 256;

struct ConntrackInner {
    map: DashMap<ConnKey, ConntrackEntry>,
    gc_interval: Duration,
    total_created: AtomicU64,
    active_count: AtomicU64,
    gc_tick: AtomicUsize,
    gc_wheel: Vec<SegQueue<ConnKey>>,
}
```

`Conntrack::new()`:

```rust
let mut gc_wheel = Vec::with_capacity(GC_WHEEL_SLOTS);
for _ in 0..GC_WHEEL_SLOTS {
    gc_wheel.push(SegQueue::new());
}
Self {
    inner: Arc::new(ConntrackInner {
        map: DashMap::new(),
        gc_interval,
        total_created: AtomicU64::new(0),
        active_count: AtomicU64::new(0),
        gc_tick: AtomicUsize::new(0),
        gc_wheel,
    }),
}
```

Добавить helper:

```rust
impl Conntrack {
    #[inline]
    fn schedule_gc_key(&self, key: ConnKey, max_idle: Duration) {
        let interval_ms = self.inner.gc_interval.as_millis().max(1) as usize;
        let idle_ms = max_idle.as_millis().max(1) as usize;
        let ticks_ahead = (idle_ms / interval_ms).max(1);
        let current = self.inner.gc_tick.load(Ordering::Relaxed);
        let slot = current.wrapping_add(ticks_ahead) % GC_WHEEL_SLOTS;
        self.inner.gc_wheel[slot].push(key);
    }
}
```

В `upsert()` после insert/update вызвать schedule:

```rust
match self.inner.map.entry(key) {
    Entry::Vacant(e) => {
        e.insert(entry);
        self.inner.total_created.fetch_add(1, Ordering::Relaxed);
        self.inner.active_count.fetch_add(1, Ordering::Relaxed);
        self.schedule_gc_key(key, self.inner.gc_interval);
    }
    Entry::Occupied(mut e) => {
        e.get_mut().last_activity = Instant::now();
        self.schedule_gc_key(key, self.inner.gc_interval);
    }
}
```

Также в `check_and_apply_desync()` и `update_seq_monotonic()` после успешного изменения `last_activity` вызвать `schedule_gc_key(*key, self.inner.gc_interval)`.

Переписать `gc_incremental()`:

```rust
pub fn gc_incremental(&self, max_idle: Duration) {
    const MAX_KEYS_PER_TICK: usize = 8192;
    let now = Instant::now();
    let tick = self.inner.gc_tick.fetch_add(1, Ordering::Relaxed);
    let slot = tick % GC_WHEEL_SLOTS;
    let queue = &self.inner.gc_wheel[slot];
    let mut processed = 0usize;
    let mut evicted = 0u64;

    while processed < MAX_KEYS_PER_TICK {
        let Some(key) = queue.pop() else { break; };
        processed += 1;

        let stale = match self.inner.map.get(&key) {
            Some(entry) => now.duration_since(entry.last_activity) >= max_idle,
            None => false,
        };

        if stale {
            if self.inner.map.remove(&key).is_some() {
                evicted += 1;
            }
        } else if self.inner.map.contains_key(&key) {
            // Not stale yet; requeue based on current last_activity/idle window.
            self.schedule_gc_key(key, max_idle);
        }
    }

    if evicted > 0 {
        self.inner.active_count.fetch_sub(evicted, Ordering::Relaxed);
        debug!("Conntrack timing-wheel GC: slot={} processed={} evicted={}", slot, processed, evicted);
    }
}
```

Важно: duplicate keys в wheel допустимы. Проверка `last_activity` перед удалением делает requeued старые tickets безопасными. Это дешевле, чем пытаться удалять старый ticket из middle of queue.

## Критерии готовности

- В production больше нет `DashMap::iter().skip(start).take_while(deadline)`.
- Каждый active key имеет будущий GC ticket.
- Старые duplicate tickets не удаляют свежий entry.
- Work per tick bounded by `MAX_KEYS_PER_TICK`, а не размером всей map.
- `active_count` не уходит в underflow при duplicate tickets.

## Верификация

Unit tests:

```rust
#[test]
fn timing_wheel_gc_eventually_reaches_tail_entries() {
    let ct = Conntrack::new(Duration::from_millis(10));
    for i in 0..50_000u16 {
        let key = ConnKey::new(std::net::Ipv4Addr::new(10, 0, (i >> 8) as u8, i as u8), std::net::Ipv4Addr::new(1,1,1,1), i, 443, 6);
        let mut entry = test_entry();
        entry.last_activity = Instant::now() - Duration::from_secs(3600);
        ct.insert(key, entry);
    }
    for _ in 0..(GC_WHEEL_SLOTS * 4) {
        ct.gc_incremental(Duration::from_millis(1));
    }
    assert_eq!(ct.active_count(), 0);
}

#[test]
fn stale_ticket_does_not_remove_refreshed_connection() {
    let ct = Conntrack::new(Duration::from_millis(10));
    let key = test_key();
    let mut entry = test_entry();
    entry.last_activity = Instant::now() - Duration::from_secs(3600);
    ct.insert(key, entry);
    ct.update_seq_monotonic(&key, 1234, 1); // refresh + requeue
    for _ in 0..GC_WHEEL_SLOTS {
        ct.gc_incremental(Duration::from_secs(30));
    }
    assert!(ct.contains(&key));
}
```

Perf gate:

- 1M stale entries: each `gc_incremental()` tick stays below configured per-tick key budget.
- Over 2..4 wheel cycles stale entries monotonically drain to zero.

# P2-07. Добавить lifecycle sweeper для `redirect_table`

## Проблема

`redirect_table.sweep_stale` существует, но не вызывается. NAT/redirect state может расти и хранить stale entries после закрытия flows.

## Решение и обоснование

Redirect state должен иметь owner lifecycle. Создать один periodic sweeper task при старте pipeline. Не вызывать sweep из packet path.

## Реализация

В `ProcessingPipeline::new()` после создания `redirect_table`:

```rust
Self::spawn_redirect_table_sweeper(redirect_table.clone());
```

Добавить:

```rust
impl ProcessingPipeline {
    fn spawn_redirect_table_sweeper(table: Arc<crate::desync::redirect_table::RedirectTable>) {
        crate::Runtime::global().io.spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                let removed = table.sweep_stale(std::time::Duration::from_secs(300));
                if removed > 0 {
                    tracing::debug!("redirect_table sweeper removed {} stale entries", removed);
                }
            }
        });
    }
}
```

Если `sweep_stale` signature другая, адаптировать call, но не переносить sweep в packet path.

## Критерии готовности

- `sweep_stale` имеет live call site.
- Sweep interval и TTL конфигурируемы или задокументированы.
- No packet path locking from sweep.

## Верификация

```rust
#[tokio::test]
async fn redirect_table_sweeper_removes_stale_entries() {
    let table = Arc::new(RedirectTable::new());
    table.insert_for_test(stale_entry_older_than(Duration::from_secs(600)));
    let removed = table.sweep_stale(Duration::from_secs(300));
    assert_eq!(removed, 1);
}
```

---

---

# P2-08. Реализовать NamedPipe IPC вместо заглушки

## Проблема

`infra/named_pipe.rs::PipeServer::run()` только логирует и возвращает `Ok(())`. Комментарии заявляют защищённый IPC для AI agent, но runtime сервера нет.

## Решение и обоснование

Так как workspace уже содержит `windows` crate с `Win32_System_Pipes`, `Win32_Storage_FileSystem`, `Win32_System_IO`, реализовать blocking Named Pipe server в dedicated thread. Не использовать packet worker/runtime hot path.

Protocol: newline-delimited JSON. Один request per line, один response per line. Это проще и надёжнее, чем length-prefix для первого патча, и достаточно для локального IPC.

## Реализация

Заменить `run()` на Windows implementation под `#[cfg(windows)]`; для non-Windows вернуть clear unsupported error.

```rust
#[cfg(windows)]
pub fn run<H: PipeHandler + Send + Sync + 'static>(self, handler: H) -> Result<()> {
    use std::ffi::OsStr;
    use std::io::{Read, Write};
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe,
        PIPE_ACCESS_DUPLEX, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    let name: Vec<u16> = OsStr::new(&self.pipe_path).encode_wide().chain(Some(0)).collect();
    let handler = std::sync::Arc::new(handler);

    loop {
        let pipe = unsafe {
            CreateNamedPipeW(
                PCWSTR(name.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                16,
                64 * 1024,
                64 * 1024,
                0,
                None,
            )
        };

        if pipe == INVALID_HANDLE_VALUE {
            return Err(anyhow::anyhow!("CreateNamedPipeW failed for {}", self.pipe_path));
        }

        let connected = unsafe { ConnectNamedPipe(pipe, None).as_bool() };
        if !connected {
            unsafe { CloseHandle(pipe)?; }
            continue;
        }

        let h = handler.clone();
        std::thread::spawn(move || {
            let _ = handle_pipe_client(pipe, h.as_ref());
            unsafe {
                let _ = DisconnectNamedPipe(pipe);
                let _ = CloseHandle(pipe);
            }
        });
    }
}

#[cfg(windows)]
fn handle_pipe_client<H: PipeHandler>(pipe: windows::Win32::Foundation::HANDLE, handler: &H) -> Result<()> {
    use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};

    let mut buf = [0u8; 8192];
    let mut pending = Vec::<u8>::with_capacity(8192);

    loop {
        let mut read = 0u32;
        let ok = unsafe { ReadFile(pipe, Some(&mut buf), Some(&mut read), None).as_bool() };
        if !ok || read == 0 {
            return Ok(());
        }
        pending.extend_from_slice(&buf[..read as usize]);

        while let Some(pos) = pending.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = pending.drain(..=pos).collect();
            let msg: PipeMessage = match serde_json::from_slice(&line[..line.len().saturating_sub(1)]) {
                Ok(m) => m,
                Err(e) => PipeMessage::Ping, // заменяется ниже response error
            };
            let resp = handler.handle(&msg);
            let mut out = serde_json::to_vec(&resp)?;
            out.push(b'\n');
            let mut written = 0u32;
            let ok = unsafe { WriteFile(pipe, Some(&out), Some(&mut written), None).as_bool() };
            if !ok || written as usize != out.len() {
                return Ok(());
            }
        }
    }
}

#[cfg(not(windows))]
pub fn run<H: PipeHandler + Send + Sync + 'static>(self, _handler: H) -> Result<()> {
    Err(anyhow::anyhow!("NamedPipe IPC is supported only on Windows"))
}
```

Important correction: do not convert malformed JSON into Ping. Replace the temporary example block above with explicit error response:

```rust
let resp = match serde_json::from_slice::<PipeMessage>(&line[..line.len().saturating_sub(1)]) {
    Ok(msg) => handler.handle(&msg),
    Err(e) => PipeResponse {
        success: false,
        data: serde_json::json!({"error": format!("invalid json: {e}")}),
    },
};
```

## Критерии готовности

- `PipeServer::run()` blocks and accepts clients on Windows.
- Malformed JSON returns structured error, not panic and not Ping.
- Each connection is isolated in its own thread; no packet worker involvement.
- Non-Windows build returns unsupported error explicitly.

## Верификация

Windows manual test:

```powershell
# Start service with named pipe enabled.
# In PowerShell/.NET client connect to \\.\pipe\FreeDPI_agent and send:
'{"type":"ping"}' + "`n"
# Expect: {"success":true,"data":{"pong":true}}
```

Unit test for parser/handler can use a fake in-memory function that takes newline-delimited bytes and returns response bytes; do not require OS pipe for all CI.

---

---

# P2-09. Dead-code policy: duplicate SOCKS redirector, obfs helpers, HTTP/MSS/window clamp, classifier `direction`

## Проблема

GLM нашёл несколько блоков, которые выглядят реализованными, но не достигают runtime: duplicate `socks/redirector.rs`, obfs `entropy_padding`/`pad_size`/`poisson_delay`, HTTP header tamper helpers, MSS/window clamp, classifier `direction` field. Удаление без понимания цели может потерять продуктовый intent, но оставлять как “активное” тоже нельзя.

## Решение и обоснование

Ввести policy для каждого dead component:

1. Если механизм имеет уникальный продуктовый смысл — подключить к profile registry и packet path.
2. Если механизм дублирует другой live implementation — мигрировать недостающий функционал в live implementation, затем удалить duplicate с тестом на отсутствие публичного re-export.
3. Если механизм экспериментальный и не готов — пометить feature flag `experimental_*`, исключить из default profile и из API списка активных техник.

## Реализация

### Duplicate `socks/redirector.rs`

- Сравнить capabilities `core/src/socks/redirector.rs` и `core/src/proxy/redirector.rs`.
- Если `socks/redirector.rs` содержит уникальный Opera/masquerade behavior, перенести этот behavior в `proxy::redirector::SocksRedirector`.
- После миграции удалить `pub mod socks;` только если public API не обещает этот module. Если обещает — оставить thin re-export wrapper:

```rust
pub mod socks {
    pub use crate::proxy::redirector::SocksRedirector;
}
```

### HTTP/MSS/window clamp

Каждая technique должна иметь:

- enum variant;
- parser/handler implementation;
- StrategyProfile registration;
- config deserialization mapping;
- at least one live pipeline test.

Для MSS clamp в TCP SYN path:

```rust
if tcp.get_flags() & TcpFlags::SYN != 0 {
    let out = tcp::mss_clamp(&state.packet, self.config.max_seg_size);
    self.merge_into_state(state, out);
}
```

Если default WinDivert filter не перехватывает SYN, technique не должна быть listed as active. Для включения MSS clamp нужен отдельный filter branch:

```text
outbound && tcp.Syn && tcp.DstPort == 443
```

но включать его только если профиль содержит MSS clamp, иначе это расширит capture surface.

### Obfs helpers

`entropy_padding`, `pad_size`, `poisson_delay` должны использоваться только через bounded delayed injector из V1 P1-03. Никаких `sleep()` в worker.

## Критерии готовности

- `cargo test` не содержит tests, которые проходят только на dead functions без live call site.
- API `GET /techniques` или аналог не показывает experimental-disabled техники как active.
- Для каждой listed active technique есть test `profile_uses_technique_reaches_apply_to_state`.
- Duplicate socks redirector либо merged, либо re-exported to live implementation.

## Верификация

Добавить script `scripts/check_dead_techniques.ps1`:

```powershell
$techniques = rg "DesyncTechnique::[A-Za-z0-9_]+" src/core/src/adaptive src/core/src/desync -o |
  % { ($_ -split '::')[-1] } | sort -Unique
foreach ($t in $techniques) {
  $uses = rg "DesyncTechnique::$t" src/core/src | measure-object | % Count
  if ($uses -lt 3) { Write-Error "Technique $t has suspiciously few call sites: $uses" }
}
```

Это не заменяет ревью, но ловит новые “написали enum variant и забыли подключить”.

---

---


---

# P2-10. Harden/delete `DesyncGroup::apply_single_safe`: wildcard passthrough запрещён

## Проблема

`DesyncGroup::apply_single_safe()` является private dead code, но выглядит как готовый safe dispatcher. Он дублирует часть `apply_to_state`, покрывает не все `DesyncTechnique` variants и имеет `_ => DesyncResult::passthrough()`. Если агент или будущий разработчик подключит его как “single technique API”, часть техник станет silent no-op без compiler error.

## Решение и обоснование

Допустимы только два состояния:

1. Функция удалена полностью, если context-free single-technique API не нужен.
2. Функция остаётся, но match exhaustive без wildcard arm. Все context-required variants перечислены явно и возвращают typed error или logged passthrough.

Для этого проекта лучше оставить hardened version только для tests/probe, потому что probe может хотеть “применить одну технику” без полного profile pipeline.

## Реализация

Изменить сигнатуру:

```rust
#[derive(Debug, thiserror::Error)]
pub enum SingleTechniqueError {
    #[error("{0:?} requires full pipeline context")]
    RequiresContext(DesyncTechnique),
}

fn apply_single_safe(
    &self,
    technique: DesyncTechnique,
    packet: &bytes::Bytes,
) -> Result<DesyncResult, SingleTechniqueError> {
    let c = &self.config;
    match technique {
        DesyncTechnique::MutualSpoof => Ok(ip::mutual_spoof(packet)),
        DesyncTechnique::DscpRandom => Ok(ip::dscp_random(packet, c.dscp_value.unwrap_or(0))),
        DesyncTechnique::TlsRecordPad => Ok(tls::tls_record_pad(packet, c.tls_record_pad_size, c.fake_ttl_offset)),
        // перечислить все реально context-free variants

        DesyncTechnique::SeqSpoof
        | DesyncTechnique::MultiSplit
        | DesyncTechnique::Disorder
        | DesyncTechnique::UdpCoalescing
        | DesyncTechnique::BadChecksum
        | DesyncTechnique::TtlManipulation => Err(SingleTechniqueError::RequiresContext(technique)),

        // NO `_ =>` arm.
    }
}
```

Если exhaustive list слишком велик для поддержки, удалить функцию и заменить tests/probe callers на `DesyncGroup::apply_with_rng()`.

## Критерии готовности

- В `apply_single_safe` нет wildcard `_ =>`.
- Добавление нового `DesyncTechnique` ломает compile до обновления dispatcher.
- Context-required techniques не превращаются в silent passthrough.
- Если функция удалена, `grep -R "apply_single_safe"` показывает 0 matches.

## Верификация

```powershell
cargo check --workspace --all-targets
rg "_ => DesyncResult::passthrough" src/core/src/desync/group.rs
# Ожидание: нет wildcard passthrough в apply_single_safe.
```

Unit:

```rust
#[test]
fn single_safe_rejects_context_required_techniques() {
    let group = DesyncGroup::new(DesyncConfig::default());
    let pkt = bytes::Bytes::from_static(&[0u8; 64]);
    assert!(matches!(group.apply_single_safe(DesyncTechnique::SeqSpoof, &pkt), Err(SingleTechniqueError::RequiresContext(_))));
}
```


# P2-11. DeepSeek dead-code triage: конкретно закрыть `has_non_empty_session_ticket`, `zero_config`, legacy sync send/forward/inject/execute

## Проблема

DeepSeek-review перечислил конкретные поля и функции с `#[allow(dead_code)]`: `has_non_empty_session_ticket`, `zero_config`, `send_packet_sync`, `forward_packet_sync`, `inject_tcp_packet_sync`, `execute_decision_sync`. Часть этого может быть legacy от старой архитектуры, но оставлять `allow(dead_code)` рядом с packet engine опасно: будущий агент может подключить устаревший path и обойти новые invariants/flow-affinity/metrics.

## Решение и обоснование

Для каждого элемента выполнить triage по правилу: integrate, migrate, quarantine, or delete with proof.

- `has_non_empty_session_ticket`: если не читается, удалить field; состояние TLS resumption должно жить в conntrack/connection metadata и использоваться P1-13.
- `zero_config`: не удалять автоматически. Сначала проследить intended path ZeroConfigEngine -> WhitelistDetector/DnsProxyEngine/runtime bypass. Если поле сирота, либо подключить к routing decision, либо удалить field после подтверждения, что zero-config работает через другие owners.
- legacy sync send/forward/inject/execute functions: если batch/flow-affinity path полностью заменяет их, удалить; если какая-то API/test path нуждается в них, переписать через новый invariant-guarded send API.

## Реализация

Добавить в PR отдельный `dead_code_audit.md` или раздел в changelog:

```text
Item: execute_decision_sync
Call-site search: rg -n "execute_decision_sync" .
Decision: removed / migrated to worker batch dispatch
Reason: unreachable legacy path; if reconnected, bypasses P1-00 flow-affinity and P5-02 invariant guard
Tests: cargo test ..., rg proof
```

Кодовое правило: не оставлять `#[allow(dead_code)]` на production packet path без ссылки на tracking issue/test-only reason.

## Критерии готовности

- `rg -n "allow\(dead_code\).*send_packet_sync|allow\(dead_code\).*execute_decision_sync|has_non_empty_session_ticket|zero_config" core/src/engine` либо ничего не находит, либо находит документированный test-only/quarantine item.
- P1-13 uses conntrack TLS resumption state, не dead field.
- Любой удалённый legacy function имеет proof, что нет call sites.
- Если `zero_config` сохраняется, есть test showing it affects routing/bypass decision.

## Верификация

```bash
rg -n "has_non_empty_session_ticket|zero_config|send_packet_sync|forward_packet_sync|inject_tcp_packet_sync|execute_decision_sync" core/src service/src api/src
cargo test --workspace
```

---

# P2-12. FakeIP Manager eviction/TTL: cache exhaustion не должен ломать DNS до рестарта службы

## Проблема

Gemini-review указал, что `FakeIpManager::allocate()` при достижении `max_entries` возвращает `None`. Если eviction/TTL отсутствуют, после достаточного числа уникальных доменов FakeIP перестаёт выдавать адреса до рестарта сервиса.

Нельзя вытеснять `domain_to_ip.iter().next()` как предложено в ревью: это не FIFO/LRU, может удалить активный mapping и сломать живое соединение.

## Решение и обоснование

Реализовать TTL/LRU-ish eviction с generation и conntrack-awareness:

1. Каждая запись имеет `created_at`, `last_access`, `generation`.
2. Periodic sweeper удаляет expired/stale mappings.
3. При переполнении выбирается самый старый неактивный mapping.
4. Mapping не переиспользуется, если есть активные conntrack entries, ссылающиеся на fake IP.

## Реализация

```rust
pub struct FakeIpEntry {
    pub domain: Arc<str>,
    pub ip: Ipv4Addr,
    pub created_at_ms: u64,
    pub last_access_ms: AtomicU64,
    pub generation: u64,
}

pub struct FakeIpManager {
    domain_to_ip: DashMap<Arc<str>, Ipv4Addr>,
    ip_to_entry: DashMap<Ipv4Addr, FakeIpEntry>,
    next_ip: AtomicU32,
    generation: AtomicU64,
    max_entries: usize,
    ttl_ms: u64,
}
```

`allocate(domain)` flow:

1. Если domain есть, обновить `last_access_ms`, вернуть IP.
2. Если capacity reached, вызвать `evict_one(now, conntrack_view)`.
3. Если eviction невозможен из-за активных mappings, вернуть explicit error `FakeIpExhausted` и метрику, а не silent `None`.
4. Вставить новую запись.

```rust
pub enum FakeIpAllocError {
    ExhaustedAllMappingsActive,
}

pub fn allocate(&self, domain: &str, active: &dyn ActiveFakeIpSet) -> Result<Ipv4Addr, FakeIpAllocError> {
    if let Some(ip) = self.domain_to_ip.get(domain) {
        if let Some(entry) = self.ip_to_entry.get(ip.value()) {
            entry.last_access_ms.store(now_ms(), Ordering::Relaxed);
        }
        return Ok(*ip);
    }

    if self.domain_to_ip.len() >= self.max_entries {
        self.evict_one(now_ms(), active)?;
    }

    // Allocate next non-reserved IP, insert both maps, and increment generation.
    // The coding agent must implement this with the current FakeIpManager fields;
    // final patch must allocate next non-reserved IP and insert both maps here, using current FakeIpManager fields.
}
```


## Критерии готовности

- После `max_entries + N` уникальных доменов DNS продолжает работать.
- Активный mapping не вытесняется, пока conntrack сообщает active flow.
- Stale mappings вытесняются детерминированно.
- Есть metrics: `fakeip_entries`, `fakeip_evictions_total`, `fakeip_exhausted_total`, `fakeip_active_eviction_skipped_total`.

## Верификация

```bash
cargo test -p freedpi-core fakeip_evicts_stale_entries_when_full
cargo test -p freedpi-core fakeip_does_not_evict_active_mapping
cargo test -p freedpi-core fakeip_recovers_after_capacity_pressure
```

# P3-01. Исправить QUIC Version Negotiation packet

## Проблема

`quic_version_downgrade()` пишет fake version в Version field, хотя Version Negotiation packet должен иметь `Version = 0`. CID lengths также должны копироваться из original long header, а не быть hardcoded.

## Решение и обоснование

Парсим original long header до DCID/SCID, строим VN с `0u32` в version field и списком unsupported/reserved versions. Если packet malformed — passthrough.

## Реализация

Файл `core/src/desync/quic.rs`, заменить `quic_version_downgrade()` на:

```rust
pub fn quic_version_downgrade(
    packet: &[u8],
    fake_version: u32,
    fake_ttl_offset: u8,
) -> DesyncResult {
    let ip = match parse_ip_header(packet) {
        Some(h) => h,
        None => return DesyncResult::passthrough(),
    };
    let udp_start = ip.header_len() + 8;
    let udp_data = match packet.get(udp_start..) {
        Some(p) if p.len() >= 7 => p,
        _ => return DesyncResult::passthrough(),
    };
    if udp_data[0] & 0x80 == 0 {
        return DesyncResult::passthrough();
    }

    let version = u32::from_be_bytes([udp_data[1], udp_data[2], udp_data[3], udp_data[4]]);
    if version == 0 || version == fake_version {
        return DesyncResult::passthrough();
    }

    let dcid_len = udp_data[5] as usize;
    let dcid_start = 6usize;
    let dcid_end = dcid_start + dcid_len;
    if dcid_end >= udp_data.len() {
        return DesyncResult::passthrough();
    }
    let scid_len = udp_data[dcid_end] as usize;
    let scid_start = dcid_end + 1;
    let scid_end = scid_start + scid_len;
    if scid_end > udp_data.len() {
        return DesyncResult::passthrough();
    }

    let mut fake_payload = Vec::with_capacity(1 + 4 + 1 + dcid_len + 1 + scid_len + 8);
    fake_payload.push(0x80 | 0x40);
    fake_payload.extend_from_slice(&0u32.to_be_bytes());
    fake_payload.push(dcid_len as u8);
    fake_payload.extend_from_slice(&udp_data[dcid_start..dcid_end]);
    fake_payload.push(scid_len as u8);
    fake_payload.extend_from_slice(&udp_data[scid_start..scid_end]);
    fake_payload.extend_from_slice(&fake_version.to_be_bytes());
    fake_payload.extend_from_slice(&0x0a0a0a0au32.to_be_bytes());

    let src_port = extract_src_port(packet).unwrap_or(443);
    let fake_udp = build_udp_packet(
        ip.src(),
        ip.dst(),
        src_port,
        443,
        &fake_payload,
        ip.ttl().saturating_sub(fake_ttl_offset),
        ip.identification().wrapping_add(1),
    );
    DesyncResult::inject_only(fake_udp)
}
```

## Критерии готовности

- VN packet version field равен `0`.
- DCID/SCID lengths и bytes копируются из original packet.
- Malformed packet даёт passthrough без panic.

## Верификация

Добавить тест:

```rust
#[test]
fn test_quic_version_downgrade_uses_zero_version() {
    let pkt = build_test_quic_initial_packet();
    let result = quic_version_downgrade(&pkt, 0x0a0a0a0a, 1);
    assert_eq!(result.inject.len(), 1);
    let inj = &result.inject[0];
    let ip = crate::desync::parse_ip_header(inj).unwrap();
    let udp = &inj[ip.header_len() + 8..];
    assert_eq!(&udp[1..5], &[0, 0, 0, 0]);
}
```

---

---

# P3-02. Переписать QUIC Initial builder: varint, TLS extensions, random, no unencrypted fallback

## Проблема

`build_quic_initial_with_crypto()` портит TLS extensions length, использует deterministic random, пишет QUIC Length как raw u16, fallback возвращает unencrypted packet. Такой packet является DPI-сигнатурой.

## Решение и обоснование

Оставляем существующий AES-GCM/HKDF/header protection backend, но строим корректный plaintext: CRYPTO frame with TLS 1.3 ClientHello, supported_versions, ALPN h3, signature_algorithms, supported_groups, key_share correctly sized randomized value, QUIC transport parameters extension. Все QUIC lengths пишутся varint. Если encryption не удалась — `None`, caller делает passthrough. Никаких unencrypted fallbacks.

## Реализация

Файл `core/src/desync/quic.rs`.

Добавить helpers рядом с `parse_quic_varint()`:

```rust
fn append_quic_varint(out: &mut Vec<u8>, value: u64) -> Option<()> {
    if value < 64 {
        out.push(value as u8);
    } else if value < 16_384 {
        let v = 0x4000u16 | value as u16;
        out.extend_from_slice(&v.to_be_bytes());
    } else if value < 1_073_741_824 {
        let v = 0x8000_0000u32 | value as u32;
        out.extend_from_slice(&v.to_be_bytes());
    } else if value < 4_611_686_018_427_387_904 {
        let v = 0xC000_0000_0000_0000u64 | value;
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        return None;
    }
    Some(())
}

fn append_u16_len_prefixed(out: &mut Vec<u8>, data: &[u8]) -> Option<()> {
    let len = u16::try_from(data.len()).ok()?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    Some(())
}

fn append_tls_extension(out: &mut Vec<u8>, ext_type: u16, body: &[u8]) -> Option<()> {
    let len = u16::try_from(body.len()).ok()?;
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    Some(())
}

fn random_bytes_vec(len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    crate::desync::rand::fill_random_bytes(&mut v);
    v
}
```

Добавить TLS ClientHello builder:

```rust
fn build_quic_tls_client_hello(fake_sni: &str) -> Option<Vec<u8>> {
    let sni = fake_sni.as_bytes();
    if sni.is_empty() || sni.len() > 253 {
        return None;
    }

    let mut exts = Vec::with_capacity(512);

    let mut sni_body = Vec::new();
    let list_len = 1usize + 2 + sni.len();
    sni_body.extend_from_slice(&(list_len as u16).to_be_bytes());
    sni_body.push(0x00);
    sni_body.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    sni_body.extend_from_slice(sni);
    append_tls_extension(&mut exts, 0x0000, &sni_body)?;

    let mut supported_versions = Vec::new();
    supported_versions.push(2);
    supported_versions.extend_from_slice(&[0x03, 0x04]);
    append_tls_extension(&mut exts, 0x002b, &supported_versions)?;

    let mut alpn = Vec::new();
    alpn.extend_from_slice(&[0x00, 0x03, 0x02, b'h', b'3']);
    append_tls_extension(&mut exts, 0x0010, &alpn)?;

    let sigalgs: [u8; 14] = [
        0x00, 0x0c,
        0x04, 0x03,
        0x08, 0x04,
        0x04, 0x01,
        0x05, 0x03,
        0x08, 0x05,
        0x05, 0x01,
    ];
    append_tls_extension(&mut exts, 0x000d, &sigalgs)?;

    let groups: [u8; 8] = [0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18];
    append_tls_extension(&mut exts, 0x000a, &groups)?;

    let mut key_share = Vec::new();
    let x25519_key = random_bytes_vec(32);
    key_share.extend_from_slice(&(2 + 2 + x25519_key.len() as u16).to_be_bytes());
    key_share.extend_from_slice(&[0x00, 0x1d]);
    key_share.extend_from_slice(&(x25519_key.len() as u16).to_be_bytes());
    key_share.extend_from_slice(&x25519_key);
    append_tls_extension(&mut exts, 0x0033, &key_share)?;

    let mut quic_tp = Vec::new();
    append_quic_varint(&mut quic_tp, 0x04)?;
    append_quic_varint(&mut quic_tp, 4)?;
    quic_tp.extend_from_slice(&65536u32.to_be_bytes());
    append_quic_varint(&mut quic_tp, 0x05)?;
    append_quic_varint(&mut quic_tp, 4)?;
    quic_tp.extend_from_slice(&65536u32.to_be_bytes());
    append_quic_varint(&mut quic_tp, 0x06)?;
    append_quic_varint(&mut quic_tp, 4)?;
    quic_tp.extend_from_slice(&262144u32.to_be_bytes());
    append_quic_varint(&mut quic_tp, 0x07)?;
    append_quic_varint(&mut quic_tp, 4)?;
    quic_tp.extend_from_slice(&100u32.to_be_bytes());
    append_tls_extension(&mut exts, 0x0039, &quic_tp)?;

    let mut body = Vec::with_capacity(128 + exts.len());
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&random_bytes_vec(32));
    body.push(0x00);
    let ciphers: [u8; 6] = [0x13, 0x01, 0x13, 0x02, 0x13, 0x03];
    append_u16_len_prefixed(&mut body, &ciphers)?;
    body.extend_from_slice(&[0x01, 0x00]);
    append_u16_len_prefixed(&mut body, &exts)?;

    let body_len = body.len();
    if body_len > 0x00ff_ffff {
        return None;
    }
    let mut ch = Vec::with_capacity(4 + body.len());
    ch.push(0x01);
    ch.extend_from_slice(&[(body_len >> 16) as u8, (body_len >> 8) as u8, body_len as u8]);
    ch.extend_from_slice(&body);
    Some(ch)
}

fn build_crypto_frame(payload: &[u8]) -> Option<Vec<u8>> {
    let mut frame = Vec::with_capacity(payload.len() + 8);
    frame.push(0x06);
    append_quic_varint(&mut frame, 0)?;
    append_quic_varint(&mut frame, payload.len() as u64)?;
    frame.extend_from_slice(payload);
    Some(frame)
}
```

Заменить `build_quic_initial_with_crypto()` на:

```rust
pub fn build_quic_initial_with_crypto(dcid: &[u8], scid: &[u8], fake_sni: &str) -> Option<Vec<u8>> {
    if dcid.len() > 20 || scid.len() > 20 {
        return None;
    }

    let client_hello = build_quic_tls_client_hello(fake_sni)?;
    let crypto_frame = build_crypto_frame(&client_hello)?;
    let pn_len = 4usize;
    let packet_number = crate::desync::rand::random_u32() as u64;

    let mut header = Vec::with_capacity(64);
    header.push(0xC3);
    header.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
    header.push(dcid.len() as u8);
    header.extend_from_slice(dcid);
    header.push(scid.len() as u8);
    header.extend_from_slice(scid);
    append_quic_varint(&mut header, 0)?;

    let length_offset = header.len();
    append_quic_varint(&mut header, 0)?;
    let pn_offset = header.len();

    let min_payload_len = 1200usize
        .saturating_sub(header.len())
        .saturating_sub(pn_len)
        .saturating_sub(QUIC_AEAD_TAG_LEN);
    let mut payload = crypto_frame;
    if payload.len() < min_payload_len {
        payload.resize(min_payload_len, 0);
    }

    let packet_len_after_len = pn_len + payload.len() + QUIC_AEAD_TAG_LEN;
    let mut final_header = Vec::with_capacity(header.len() + 8);
    final_header.extend_from_slice(&header[..length_offset]);
    append_quic_varint(&mut final_header, packet_len_after_len as u64)?;

    debug_assert_eq!(final_header.len(), pn_offset);
    quic_v1_initial_encrypt(&final_header, packet_number, pn_len, &payload, dcid)
}
```

Заменить caller в `quic_initial_inject()`:

```rust
    let fake_payload = match build_quic_initial_with_crypto(dcid, scid, fake_sni) {
        Some(p) => p,
        None => return DesyncResult::passthrough(),
    };
```

Удалять `build_quic_initial()` не надо, но перевести его в test-only, чтобы production не мог вызвать unencrypted fallback:

```rust
#[cfg(test)]
fn build_quic_initial(dcid: &[u8], _sni: &str) -> Vec<u8> { ... }
```

## Критерии готовности

- Production path не возвращает unencrypted fake QUIC Initial.
- QUIC Length/CRYPTO Length/Token Length пишутся через varint.
- TLS ClientHello содержит SNI, supported_versions, ALPN h3, signature_algorithms, supported_groups, key_share, QUIC transport parameters.
- TLS random и key_share не deterministic.

## Верификация

Добавить тесты:

```rust
#[test]
fn test_append_quic_varint_roundtrip_boundaries() {
    for v in [0, 63, 64, 15293, 16383, 16384, 1_000_000] {
        let mut out = Vec::new();
        append_quic_varint(&mut out, v).unwrap();
        let (parsed, n) = parse_quic_varint(&out).unwrap();
        assert_eq!(parsed, v);
        assert_eq!(n, out.len());
    }
}

#[test]
fn test_quic_initial_builder_no_unencrypted_fallback() {
    let dcid = [1,2,3,4,5,6,7,8];
    let scid = [8,7,6,5,4,3,2,1];
    let pkt = build_quic_initial_with_crypto(&dcid, &scid, "www.google.com").unwrap();
    assert!(pkt.len() >= 1200);
    assert_eq!(&pkt[1..5], &QUIC_VERSION_1.to_be_bytes());
}
```

---

---

# P3-02A. QUIC Initial crypto fallback ban: не выпускать unprotected zero-padded Initial на wire

## Проблема

Gemini-review указал подтверждённый опасный сценарий: `quic_initial_inject` может вызвать `build_quic_initial_with_crypto(...).unwrap_or_else(|| build_quic_initial(...))`, а fallback строит Initial-like payload без полноценной QUIC packet/header protection и добивает его нулями. Это создаёт стабильную wire-сигнатуру FreeDPI.

## Решение и обоснование

Если техника заявлена как valid QUIC Initial, fallback на unencrypted packet запрещён. QUIC Initial protection/header protection являются частью protocol-valid packet model. При сбое crypto builder нужно не inject'ить packet, а вернуть passthrough/controlled fallback и метрику.

## Реализация

Удалить/запретить все вызовы вида:

```rust
build_quic_initial_with_crypto(...).unwrap_or_else(|| build_quic_initial(...))
```

Заменить на:

```rust
let Some(fake_payload) = build_quic_initial_with_crypto(dcid, scid, fake_sni) else {
    tracing::warn!("QUIC Initial crypto build failed; skipping injection to avoid wire-visible invalid QUIC");
    metrics.quic_initial_crypto_build_failed.fetch_add(1, Ordering::Relaxed);
    return DesyncResult::passthrough();
};
```

Если `build_quic_initial_with_crypto()` сам содержит fallback `Some(unencrypted_packet)`, изменить сигнатуру результата:

```rust
pub enum QuicInitialBuildError {
    InvalidOriginalPacket,
    CryptoDeriveFailed,
    AeadFailed,
    HeaderProtectionFailed,
    SizeInvariantFailed,
}

pub fn build_quic_initial_with_crypto(...) -> Result<bytes::Bytes, QuicInitialBuildError>;
```

`build_quic_initial()` оставить только как internal test fixture для parser tests, пометить `#[cfg(test)]` или `pub(crate)` с названием `build_unprotected_quic_initial_for_tests_only`.

## Критерии готовности

- Production code не содержит fallback from crypto QUIC Initial to unprotected Initial.
- QUIC Initial injection either produces protocol-valid protected packet or does not inject.
- Metric `quic_initial_crypto_build_failed_total` добавлена.
- Runtime Packet Invariant Guard ловит QUIC Initial `< 1200` и invalid obvious length fields, но не используется как замена crypto validation.

## Верификация

```bash
rg "unwrap_or_else\(\|\| build_quic_initial" core/src/desync/quic.rs && exit 1 || true
rg "Fallback: return unencrypted" core/src/desync/quic.rs && exit 1 || true
cargo test -p freedpi-core quic_initial_crypto_failure_skips_injection
```

# P3-04A. QUIC original port preservation: никаких hardcoded UDP/443 в packet builders

## Проблема

Gemini-review указал, что `quic_initial_inject` и потенциально другие QUIC builders используют destination port `443` вместо порта исходного UDP flow. Это ломает QUIC на нестандартных портах и делает fake packet нерелевантным для DPI, который анализирует реальный flow.

## Решение и обоснование

Все QUIC builders должны брать source/destination ports из единого `PacketContext`, построенного L3/L4 parser'ом. Ad-hoc `extract_src_port()` недостаточно: нужен полный context с `src_port`, `dst_port`, offsets, IP version, TTL/HopLimit.

## Реализация

Добавить/расширить context:

```rust
pub struct PacketContext {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub proto: u8,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub ip_header_len: usize,
    pub transport_header_len: usize,
    pub payload_offset: usize,
    pub ttl_or_hop_limit: u8,
}
```

QUIC functions должны принимать `&PacketContext`:

```rust
pub fn quic_initial_inject(
    packet: &[u8],
    ctx: &PacketContext,
    fake_sni: &str,
    fake_ttl_offset: u8,
) -> DesyncResult {
    let Some(src_port) = ctx.src_port else { return DesyncResult::passthrough(); };
    let Some(dst_port) = ctx.dst_port else { return DesyncResult::passthrough(); };

    let fake_udp = build_udp_packet(
        ctx.src_ip,
        ctx.dst_ip,
        src_port,
        dst_port,
        &fake_payload,
        fake_ttl,
        identification,
    );
    // ...
}
```

Запретить hardcoded `443` в QUIC packet builders кроме filter predicates/default config constants.

## Критерии готовности

- QUIC/8443 fake packet имеет UDP dst port 8443.
- `rg "build_udp_packet\([^\n]*443" core/src/desync/quic.rs` не находит production builders.
- PacketContext используется всеми QUIC injection techniques.

## Верификация

```bash
cargo test -p freedpi-core quic_initial_inject_preserves_original_dst_port
cargo test -p freedpi-core quic_retry_inject_preserves_original_dst_port
```

# P3-03. Добавить TLS first-record reassembly для ClientHello

## Проблема

Classifier видит ClientHello только если TLS record и handshake header попали в один TCP payload. Реальные ClientHello могут быть сегментированы; DPI reassembles, а FreeDPI — нет.

## Решение и обоснование

Добавить bounded per-flow buffer до 8192 bytes и TTL 5 sec. Он включается только для TCP/443 candidate до первого desync decision. Это ограничивает память и не держит весь flow в userspace.

## Реализация

Создать файл `core/src/tls_reassembly.rs`:

```rust
use crate::conntrack::ConnKey;
use bytes::BytesMut;
use dashmap::DashMap;
use std::time::{Duration, Instant};

const MAX_CLIENT_HELLO_BUF: usize = 8192;
const ENTRY_TTL: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct Entry {
    buf: BytesMut,
    last: Instant,
}

#[derive(Debug, Default)]
pub struct TlsReassembler {
    entries: DashMap<ConnKey, Entry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReassemblyState {
    NeedMore,
    Complete,
    NotTls,
    TooLarge,
}

impl TlsReassembler {
    pub fn new() -> Self { Self::default() }

    pub fn observe(&self, key: ConnKey, payload: &[u8]) -> (ReassemblyState, Option<Vec<u8>>) {
        if payload.is_empty() {
            return (ReassemblyState::NeedMore, None);
        }
        if !payload.starts_with(&[0x16]) && self.entries.get(&key).is_none() {
            return (ReassemblyState::NotTls, None);
        }

        let mut entry = self.entries.entry(key).or_insert_with(|| Entry {
            buf: BytesMut::with_capacity(2048),
            last: Instant::now(),
        });
        entry.last = Instant::now();
        if entry.buf.len() + payload.len() > MAX_CLIENT_HELLO_BUF {
            drop(entry);
            self.entries.remove(&key);
            return (ReassemblyState::TooLarge, None);
        }
        entry.buf.extend_from_slice(payload);

        let state = classify_tls_client_hello_buffer(&entry.buf);
        match state {
            ReassemblyState::Complete => {
                let data = entry.buf.to_vec();
                drop(entry);
                self.entries.remove(&key);
                (ReassemblyState::Complete, Some(data))
            }
            ReassemblyState::NotTls | ReassemblyState::TooLarge => {
                drop(entry);
                self.entries.remove(&key);
                (state, None)
            }
            ReassemblyState::NeedMore => (ReassemblyState::NeedMore, None),
        }
    }

    pub fn gc(&self) {
        let now = Instant::now();
        self.entries.retain(|_, v| now.duration_since(v.last) <= ENTRY_TTL);
    }
}

fn classify_tls_client_hello_buffer(buf: &[u8]) -> ReassemblyState {
    if buf.len() < 5 {
        return ReassemblyState::NeedMore;
    }
    if buf[0] != 0x16 || buf[1] != 0x03 {
        return ReassemblyState::NotTls;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let record_end = 5usize.saturating_add(record_len);
    if record_end > MAX_CLIENT_HELLO_BUF {
        return ReassemblyState::TooLarge;
    }
    if buf.len() < record_end {
        return ReassemblyState::NeedMore;
    }
    if buf.len() < 9 || buf[5] != 0x01 {
        return ReassemblyState::NotTls;
    }
    let hs_len = ((buf[6] as usize) << 16) | ((buf[7] as usize) << 8) | buf[8] as usize;
    if 9 + hs_len > record_end {
        return ReassemblyState::NeedMore;
    }
    ReassemblyState::Complete
}
```

Файл `core/src/lib.rs` добавить:

```rust
pub mod tls_reassembly;
```

Файл `core/src/engine/mod.rs`:

В struct добавить:

```rust
    tls_reassembler: crate::tls_reassembly::TlsReassembler,
```

В `new()` initializer:

```rust
            tls_reassembler: crate::tls_reassembly::TlsReassembler::new(),
```

В TLS branch заменить `Classifier::is_client_hello(payload)` decision:

```rust
                let payload = match captured.data.get(cp.payload_offset..) {
                    Some(p) => p,
                    None => return Ok(PacketDecision::Forward),
                };
                let mut should_desync = false;
                if Classifier::is_client_hello(payload) && payload.len() >= 50 {
                    should_desync = self.conntrack.check_and_apply_desync(conn_key, || Self::conn_id_for(&cp));
                } else {
                    match self.tls_reassembler.observe(conn_key, payload).0 {
                        crate::tls_reassembly::ReassemblyState::Complete => {
                            should_desync = self.conntrack.check_and_apply_desync(conn_key, || Self::conn_id_for(&cp));
                        }
                        crate::tls_reassembly::ReassemblyState::NeedMore => return Ok(PacketDecision::Forward),
                        crate::tls_reassembly::ReassemblyState::NotTls => return Ok(PacketDecision::Forward),
                        crate::tls_reassembly::ReassemblyState::TooLarge => return Ok(PacketDecision::Forward),
                    }
                }
```

Это не модифицирует уже прошедшие ранние fragments; поэтому для полного desync segmented ClientHello нужна P3-04. Но этот шаг уже устраняет blind classification и позволяет outcome/adaptive видеть, что flow был TLS ClientHello candidate. В P3-04 добавляется “hold first fragments until complete” policy.

## Критерии готовности

- Segmented ClientHello распознаётся как complete после накопления.
- Memory bounded: 8192 bytes per candidate, TTL 5 sec.
- Non-TLS payload не остаётся в map.

## Верификация

```bash
cargo test -p freedpi-core tls_reassembly -- --nocapture
```

Добавить unit tests для `NeedMore`, `Complete`, `TooLarge`.

---

---


---

# P3-04. Подключить unreachable QUIC arsenal через variants/dispatch/profile gates и protocol-validity tests

## Проблема

`core/src/desync/quic.rs` содержит продвинутые функции QUIC evasion (`quic_initial_inject`, `quic_short_header_poison`, `quic_padding_flood`, `udp_coalescing`, `doppelganger_grease`, `quic_long_header_drop`, `quic_normalizer`) и crypto-correct QUIC v1 Initial stack, но часть этих функций не имеет `DesyncTechnique` variants и dispatch arms в `desync/group.rs`. В результате QUIC arsenal существует как код, но не достигает runtime.

Это особенно критично для QUIC/HTTP3-aware DPI: синтаксически валидный QUIC Initial и controlled GREASE/coalescing могут быть полезнее, чем невалидный fake packet, но сейчас система не может выбрать эти техники ни profile config, ни AutoTune, ни manual API.

## Решение и обоснование

Подключать не механически, а через three-stage gate:

1. `DesyncTechnique` variants + `name()/effect()/category()/source()` registration.
2. `apply_to_state` dispatch только для single-packet techniques.
3. Protocol-validity tests: forged Initial должен парситься как QUIC v1 Initial, иметь корректные varints, correct DCID/SCID layout, UDP datagram size >= 1200 для client Initial path, и не заявлять PN analysis без header protection removal.

`UdpCoalescing` не встраивать в `apply_to_state`: она требует same-flow look-ahead и должна работать только после P1-00 в shard worker, где есть per-flow ordering.

## Реализация

Файл `core/src/desync/mod.rs`, enum `DesyncTechnique`:

```rust
QuicInitialInject,
QuicShortHeaderPoison,
QuicPaddingFlood,
DoppelgangerGrease,
QuicLongHeaderDrop,
QuicNormalizer,
UdpCoalescing,
```

Во всех match arms `name()`, `effect()`, `category()`, `source()` добавить явные ветки. Пример:

```rust
DesyncTechnique::QuicInitialInject => "quic_initial_inject",
DesyncTechnique::DoppelgangerGrease => "doppelganger_grease",
DesyncTechnique::UdpCoalescing => "udp_coalescing",
```

`effect()`:

```rust
DesyncTechnique::QuicInitialInject
| DesyncTechnique::QuicShortHeaderPoison
| DesyncTechnique::QuicPaddingFlood
| DesyncTechnique::DoppelgangerGrease => TechniqueEffect::InvalidatesSeq,
DesyncTechnique::QuicLongHeaderDrop => TechniqueEffect::HeaderOnly,
DesyncTechnique::QuicNormalizer => TechniqueEffect::HeaderOnly,
DesyncTechnique::UdpCoalescing => TechniqueEffect::Split,
```

Если текущий `TechniqueEffect` не имеет QUIC-appropriate variants, не втискивать неверную семантику: добавить `TechniqueEffect::InjectOnly` и `TechniqueEffect::DatagramCoalescing`, затем обновить `validate()`.

Файл `core/src/desync/group.rs`, `apply_to_state`:

```rust
DesyncTechnique::QuicInitialInject => {
    let fake_sni = state.config.fake_sni.as_deref().unwrap_or("www.microsoft.com");
    self.merge_into_state(state, quic::quic_initial_inject(&state.packet, fake_sni, c.fake_ttl_offset), *technique);
}
DesyncTechnique::QuicShortHeaderPoison => {
    self.merge_into_state(state, quic::quic_short_header_poison(&state.packet, c.fake_ttl_offset), *technique);
}
DesyncTechnique::QuicPaddingFlood => {
    let count = c.split_count.max(1).min(8);
    self.merge_into_state(state, quic::quic_padding_flood(&state.packet, count, c.fake_ttl_offset), *technique);
}
DesyncTechnique::DoppelgangerGrease => {
    self.merge_into_state(state, quic::doppelganger_grease(&state.packet, c.fake_ttl_offset), *technique);
}
DesyncTechnique::QuicLongHeaderDrop => {
    self.merge_into_state(state, quic::quic_long_header_drop(&state.packet), *technique);
}
DesyncTechnique::QuicNormalizer => {
    self.merge_into_state(state, quic::quic_normalizer(&state.packet), *technique);
}
DesyncTechnique::UdpCoalescing => {
    tracing::warn!("UdpCoalescing requires per-flow datagram context; use shard-worker coalescing path, not apply_to_state");
}
```

Файл `core/src/engine/mod.rs` или новый `engine/quic_coalesce.rs` после P1-00:

```rust
pub struct RecentQuicDatagrams {
    by_flow: dashmap::DashMap<crate::engine::flow_affinity::FlowKey, smallvec::SmallVec<[bytes::Bytes; 4]>>,
}

impl RecentQuicDatagrams {
    pub fn push_and_coalesce(&self, flow: FlowKey, current: &bytes::Bytes) -> Option<crate::desync::DesyncResult> {
        let mut entry = self.by_flow.entry(flow).or_default();
        let extras: smallvec::SmallVec<[&[u8]; 4]> = entry.iter().map(|b| b.as_ref()).collect();
        let result = crate::desync::quic::udp_coalescing(current, &extras, 1);
        entry.clear();
        entry.push(current.clone());
        if result.inject.is_empty() && result.modified.is_none() { None } else { Some(result) }
    }
}
```

Включать `UdpCoalescing` только если strategy profile содержит эту технику и flow worker имеет recent datagram context. Не делать global look-ahead.

## Критерии готовности

- Все новые variants парсятся из config names и отображаются в metrics/API.
- Ни одна новая QUIC technique не silent passthrough из-за пропущенного match arm.
- `UdpCoalescing` не вызывается из context-free `apply_to_state`.
- `DoppelgangerGrease` и GREASE-like техники выключены по умолчанию; включаются только profile/config.
- QUIC fake Initial не отправляется, если validity test fails.

## Верификация

Unit tests:

```rust
#[test]
fn all_quic_techniques_have_names_and_dispatch() {
    let techniques = [
        DesyncTechnique::QuicInitialInject,
        DesyncTechnique::QuicShortHeaderPoison,
        DesyncTechnique::QuicPaddingFlood,
        DesyncTechnique::DoppelgangerGrease,
        DesyncTechnique::QuicLongHeaderDrop,
        DesyncTechnique::QuicNormalizer,
        DesyncTechnique::UdpCoalescing,
    ];
    for t in techniques {
        assert!(!t.name().is_empty());
        assert_ne!(format!("{:?}", t.effect()), "Unknown");
    }
}
```

Protocol tests:

- Build sample QUIC v1 Initial packet.
- Apply `QuicInitialInject`.
- Assert injected datagram begins with long header/fixed bit/type Initial.
- Assert version is `0x00000001` or allowed configured version.
- Assert UDP payload length for client Initial path >= 1200.
- If crypto decrypt test helpers exist, decrypt Initial payload with RFC 9001 initial secrets derived from DCID; otherwise mark test `#[ignore]` but include it in Windows/manual validation.


---

# P3-05. Реализовать `SniMasking` dispatcher и audit HTTP/2/obfs helpers как intended techniques

## Проблема

Claude-review указал на важный no-op class: standalone `desync/tls.rs::sni_masking` существует, но `DesyncTechnique::SniMasking` в dispatcher может возвращать passthrough напрямую. Аналогичный риск есть у HTTP/2/obfs helpers (`h2_hpack_aware`, `hpack_bomber`, `host_obfuscation`, `entropy_padding`, `ip_ppxor`, `poisson_delay_fast`): код написан с намерением, но не обязательно достижим из strategy profile.

Согласно проектному требованию, не удалять намерение. Нужно либо полноценно подключить technique, либо перевести её в explicit quarantine/deprecated так, чтобы пользовательская конфигурация не думала, что техника активна.

## Решение и обоснование

1. `SniMasking` должен вызывать реальную implementation и иметь tests на изменение ClientHello.
2. Для helper функций составить mapping: helper -> `DesyncTechnique` variant -> dispatcher arm -> strategy profile usage.
3. Если helper требует контекст, добавить context-aware path, а не silent passthrough.
4. Wildcard passthrough запрещён для intended techniques.

## Реализация

В `core/src/desync/group.rs` заменить arm:

```rust
DesyncTechnique::SniMasking => DesyncResult::passthrough(),
```

на:

```rust
DesyncTechnique::SniMasking => {
    self.merge_into_state(state, tls::sni_masking(&state.packet), *technique);
}
```

Если текущая сигнатура `tls::sni_masking` принимает дополнительные параметры, использовать resolved `DesyncConfig`; не создавать random defaults внутри dispatcher.

Добавить compile-time dispatch coverage test:

```rust
#[test]
fn sni_masking_is_not_passthrough_for_valid_clienthello() {
    let pkt = build_ipv4_tcp_tls_clienthello_with_sni("blocked.example");
    let cfg = DesyncConfig::default();
    let mut group = DesyncGroup::new(cfg);
    group.add(DesyncTechnique::SniMasking);
    let out = group.apply(&bytes::Bytes::from(pkt));
    assert!(out.modified.is_some() || !out.inject.is_empty(), "SniMasking must modify or inject for valid CH");
}
```

Для HTTP/2/obfs helpers создать таблицу в коде теста:

```rust
#[test]
fn intended_helpers_have_reachable_techniques() {
    let reachable = DesyncTechnique::all_names_for_test();
    for expected in ["entropy_padding", "ip_ppxor", "poisson_delay_fast", "h2_hpack_aware", "host_obfuscation", "hpack_bomber"] {
        assert!(reachable.contains(expected) || crate::desync::quarantine::is_explicitly_quarantined(expected), "{} is implemented but neither reachable nor quarantined", expected);
    }
}
```

Если `all_names_for_test()` отсутствует, добавить test-only method:

```rust
#[cfg(test)]
impl DesyncTechnique {
    pub fn all_names_for_test() -> std::collections::HashSet<&'static str> {
        use DesyncTechnique::*;
        [SniMasking /* + all variants */].into_iter().map(|t| t.name()).collect()
    }
}
```

## Критерии готовности

- `SniMasking` больше не no-op на валидном TLS ClientHello.
- Helper functions, которые остаются недостижимыми, явно перечислены в `quarantine` с причиной и тестом.
- Пользовательская config не может включить “активную” технику, которая silent passthrough.

## Верификация

```powershell
cargo test -p freedpi-core sni_masking
cargo test -p freedpi-core intended_helpers_have_reachable_techniques
```

Manual pcap gate: включить профиль только с `SniMasking`, отправить TLS ClientHello с SNI, убедиться, что wire packet отличается от original или создаёт documented inject.


# P3-06. QUIC fallback policy: запретить raw `CONNECTION_CLOSE`, разрешать только valid protected/profiled fallback или controlled drop/jitter

## Проблема

DeepSeek-review правильно заметил, что silent drop всех QUIC packets может стать fingerprint: QUIC Initial исчезает, затем появляется TCP fallback. Но предложенный raw QUIC `CONNECTION_CLOSE` опасен сильнее: QUIC control frames находятся внутри QUIC packet protection/header protection model, а неправдоподобный close/retry packet может стать стабильной сигнатурой FreeDPI.

## Решение и обоснование

Ввести explicit QUIC fallback policy:

```rust
pub enum QuicFallbackPolicy {
    /// Default: drop limited Initial attempts with browser-like timeout/jitter profile.
    ControlledDropJitter,
    /// Allowed only if builder produces RFC9000/9001-valid protected packet and passes fingerprint profile tests.
    ValidConnectionClose,
    /// Allowed only if retry packet is syntactically valid and source-address-token policy is plausible.
    ValidRetry,
    /// No QUIC fallback manipulation; pass through.
    PassThrough,
}
```

Default должен быть `ControlledDropJitter` или `PassThrough` в зависимости от config. `ValidConnectionClose` нельзя включать, пока P3-02/P3-04/P5-02 tests не доказывают protocol validity.

## Реализация

1. Найти все места, где UDP:443 fake-ip/proxy policy делает unconditional drop.
2. Заменить boolean/drop branch на `QuicFallbackPolicy`.
3. Для `ControlledDropJitter` ограничить число dropped Initial per flow и не трогать established short-header traffic, если narrow filter уже исключает его.
4. Для `ValidConnectionClose` использовать только существующий QUIC protected builder, если он валидируется; raw frame `0x1c` в UDP payload запрещён.
5. Добавить metrics:
   - `quic_fallback_controlled_drop_total`
   - `quic_fallback_valid_close_total`
   - `quic_fallback_invalid_close_blocked_total`

## Критерии готовности

- `rg -n "ConnectionClose|CONNECTION_CLOSE|0x1c" core/src/desync core/src/engine` показывает только paths, проходящие через QUIC builder + invariant guard.
- Нет raw unprotected QUIC close packet injection.
- Default config не включает `ValidConnectionClose`.
- QUIC fallback decision имеет metric and trace reason.

## Верификация

```bash
cargo test -p freedpi-core quic_fallback_policy
cargo test -p freedpi-core quic_connection_close_requires_valid_builder
rg -n "0x1c" core/src
```

PCAP smoke: QUIC Initial -> controlled fallback не создаёт постоянный одинаковый UDP close fingerprint.

---


# P4-00. Pool capacity sizing policy: пул не может быть фиксированным `64` при batch workers

## Проблема

DeepSeek-review указал, что `PacketBufferPool::new(64)` не соответствует модели batch processing. Даже после P0-08 lifetime fix и P1-00 flow-affinity, одновременно живых buffers может быть больше 64: RX batch, queued packets, worker processing, forward/inject batches, delayed injector. Малый пул создаёт allocator fallback и делает zero-allocation claim ложным.

## Решение и обоснование

Capacity должен зависеть от worker_count, receive batch size, queueing model и safety factor. Статический минимум допустим, но не `64`.

Рекомендуемая формула после P1-00:

```rust
pub fn packet_pool_capacity(worker_count: usize, recv_batch_size: usize) -> usize {
    let rx_prefetch = 2usize;
    let send_backlog = 2usize;
    let safety_factor = 2usize;
    let base = recv_batch_size
        .saturating_mul(worker_count + rx_prefetch + send_backlog)
        .saturating_mul(safety_factor);
    base.clamp(512, 8192)
}
```

Если per-worker queue capacity намного больше batch size, не пытаться preallocate весь queue: pool должен покрывать normal in-flight, а overload должен отражаться метриками/backpressure, не бесконечным ростом памяти.

## Реализация

- Убрать hardcoded `PacketBufferPool::new(64)`.
- Передать `worker_count`/`RECV_BATCH_SIZE` в sizing function.
- Добавить pool metrics:
  - `pool_acquire_total`
  - `pool_acquire_miss_total`
  - `pool_release_success_total`
  - `pool_release_refcount_failed_total`
  - `pool_capacity`
- P5 Capture Budget Governor должен использовать `pool_acquire_miss_rate` как pressure signal.

## Критерии готовности

- `rg -n "PacketBufferPool::new\(64\)" core/src` ничего не находит.
- При `worker_count=16`, `recv_batch_size=64` capacity >= 2048 или обоснованная формула с тестом.
- Pool miss-rate виден в metrics.
- Under synthetic batch load pool не истощается сразу после первого worker batch.

## Верификация

```bash
cargo test -p freedpi-core packet_pool_capacity
cargo test -p freedpi-core packet_pool_metrics
```

Perf smoke: при pcap replay/burst `pool_acquire_miss_total / pool_acquire_total` остаётся ниже заданного threshold после warmup.

---

# P4-01. Не отключать RSS глобально

## Проблема

`disable_offload()` вызывает `netsh int tcp set global rss=disabled`. RSS нужен для multi-core receive на 5–10 Gbps. Отключение RSS лечит симптом ordering, но убивает throughput.

## Решение и обоснование

RSS disable только explicit opt-in config, default false. Ordering решается P4-01 per-flow sharding.

## Реализация

Файл `core/src/config.rs`: добавить в `PacketEngine`/network config, если такого раздела нет — в `ProcessingConfig`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTuningConfig {
    #[serde(default)]
    pub disable_chimney: bool,
    #[serde(default)]
    pub disable_ecn: bool,
    #[serde(default)]
    pub disable_rss: bool,
}

impl Default for NetworkTuningConfig {
    fn default() -> Self {
        Self {
            disable_chimney: true,
            disable_ecn: true,
            disable_rss: false,
        }
    }
}
```

Файл `core/src/packet_engine.rs`: заменить `disable_offload()` на parameterized:

```rust
pub fn disable_offload(tuning: &crate::config::NetworkTuningConfig) -> Result<()> {
    if tuning.disable_chimney {
        let output = std::process::Command::new("netsh")
            .args(["int", "tcp", "set", "global", "chimney=disabled"])
            .output();
        match output {
            Ok(o) if o.status.success() => debug!("TCP Chimney Offload disabled"),
            Ok(o) => warn!("Failed to disable TCP Chimney: {}", String::from_utf8_lossy(&o.stderr)),
            Err(e) => warn!("Failed to run netsh: {}", e),
        }
    }

    if tuning.disable_rss {
        let output = std::process::Command::new("netsh")
            .args(["int", "tcp", "set", "global", "rss=disabled"])
            .output();
        match output {
            Ok(o) if o.status.success() => warn!("RSS disabled by explicit config; throughput may degrade"),
            Ok(o) => warn!("Failed to disable RSS: {}", String::from_utf8_lossy(&o.stderr)),
            Err(e) => warn!("Failed to run netsh for RSS: {}", e),
        }
    }

    if tuning.disable_ecn {
        let output = std::process::Command::new("netsh")
            .args(["int", "tcp", "set", "global", "ecn=disabled"])
            .output();
        match output {
            Ok(o) if o.status.success() => debug!("ECN disabled"),
            _ => debug!("ECN disable skipped (non-critical)"),
        }
    }

    Ok(())
}
```

`PacketEngine::new(filter)` currently has no config parameter. Do not hardcode default by constructing config there. Instead add new constructor:

```rust
pub fn new_with_tuning(filter: &str, tuning: &crate::config::NetworkTuningConfig) -> Result<Self> {
    // body of new(), but calls Self::disable_offload(tuning)
}

pub fn new(filter: &str) -> Result<Self> {
    Self::new_with_tuning(filter, &crate::config::NetworkTuningConfig::default())
}
```

Then update caller in engine/service to pass actual config.

## Критерии готовности

- Default path does not run `rss=disabled`.
- User can still opt-in to RSS disable explicitly.
- Throughput tests use RSS enabled.

## Верификация

```bash
rg -n "rss=disabled" core/src
cargo check --workspace --all-targets
```

The only remaining `rss=disabled` occurrence must be inside `if tuning.disable_rss`.

---

---


---

# P4-02. Добавить perf gates: capture ratio, pool hit-rate, shard queue pressure, p99 latency

## Проблема

После P0/P1 архитектурные fixes должны быть защищены от регрессий. Иначе следующие изменения снова могут вернуть hidden allocations, shared-handle workers или wide capture surface.

## Решение и обоснование

Добавить метрики, которые проверяют именно runtime-достижение решений:

- `capture_packets_total` по classification: TLS CH, QUIC Initial, DNS, Other.
- `pool_returned_total`, `pool_return_miss_shared_total`.
- `shard_queue_full_total`, `shard_queue_depth_current`.
- `flow_reorder_detected_total` в synthetic debug build.
- `desync_application_latency_us` отдельно от `flow_outcome_latency_us`.
- `windivert_recv_batch_size`, `send_batch_size`, `inject_batch_size`.

## Реализация

В существующий stats struct добавить atomics и expose через API/metrics endpoint. Для histogram можно начать с fixed buckets без allocation:

```rust
pub struct FixedLatencyHist {
    buckets: [AtomicU64; 16],
}

impl FixedLatencyHist {
    pub const fn new() -> Self {
        Self { buckets: [const { AtomicU64::new(0) }; 16] }
    }

    pub fn observe_us(&self, v: u64) {
        let idx = match v {
            0..=9 => 0,
            10..=24 => 1,
            25..=49 => 2,
            50..=99 => 3,
            100..=249 => 4,
            250..=499 => 5,
            500..=999 => 6,
            1_000..=2_499 => 7,
            2_500..=4_999 => 8,
            5_000..=9_999 => 9,
            10_000..=24_999 => 10,
            25_000..=49_999 => 11,
            50_000..=99_999 => 12,
            100_000..=249_999 => 13,
            250_000..=999_999 => 14,
            _ => 15,
        };
        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
    }
}
```

Если Rust version не позволяет `[const { ... }; 16]`, использовать `std::array::from_fn(|_| AtomicU64::new(0))` в `new()` без `const`.

## Критерии готовности

- Perf regression виден без profiler.
- Synthetic workload показывает pool hit-rate и queue pressure.
- Wide capture regression ловится по `capture_other_udp443_total`.

## Верификация

В CI добавить perf-smoke test под `--ignored`:

```powershell
cargo test -p freedpi-core -- --ignored perf_smoke_pool_and_shard_metrics
```

Ожидаемые gates:

- pool return miss shared < 1% для modified/drop synthetic packets.
- shard queue full = 0 на baseline pps.
- captured QUIC non-Initial ratio близок к 0 после P1-01.



# P4-03. Оценить true pool-backed `RecvEx` только после проверки crate/FFI support; не обещать scatter/gather zero-copy без доказательства

## Проблема

DeepSeek-review предложил принимать batch directly into pool buffers. Направление полезное, но его нельзя записывать как обязательный quick fix без проверки фактического API `windivert` crate и safety model. WinDivert batch APIs уменьшают user/kernel transitions, но это не автоматически означает scatter/gather receive в arbitrary `BytesMut` allocations.

## Решение и обоснование

Сделать отдельный investigation/implementation gate:

1. Проверить текущий `windivert` crate: есть ли safe API для receive into multiple caller-provided buffers.
2. Если нет — оценить FFI wrapper поверх `WinDivertRecvEx` только после изучения address array, packet lengths, alignment and ownership semantics.
3. До этого не удалять существующий safe copy path.
4. Если реализуется FFI fast path, оставить fallback на текущий safe path и добавить differential tests.

## Критерии готовности

- В плане/коде нет утверждения “zero-copy RecvEx” без теста и feature gate.
- Если fast path реализован: есть feature flag, fallback, Miri/unsafe justification comment, bounds tests.
- Если fast path не реализован: documentation явно говорит “single kernel->batch copy + batch->pool copy remains”.

## Верификация

```bash
cargo test -p freedpi-core recv_batch_safe_fallback
rg -n "unsafe" core/src/packet_engine.rs
```

---

# P4-04. Per-connection RNG seeding: убрать `OsRng` с new-flow hot path

## Проблема

Gemini-review указал, что `PerConnRng::new(conn_id)` вызывает `OsRng.fill_bytes()` при создании каждого соединения. Даже если системный RNG обычно быстрый, syscall/OS entropy на каждое новое соединение создаёт ненужный latency risk при high churn. Для DPI-evasion также важна контролируемая уникальность seed: она должна зависеть от process secret и canonical FlowKey, а не от слабого XOR-fold или случайного повторного syscall.

## Решение и обоснование

Использовать OS entropy один раз при старте для process secret. Per-connection seed выводить через keyed derivation из:

- process secret;
- canonical normalized `FlowKey`;
- monotonic per-process counter или connection generation;
- optional boot/session salt.

Не использовать `OsRng` внутри `PerConnRng::new` на hot path.

## Реализация

```rust
pub struct RngSeedDeriver {
    key: [u8; 32],
    counter: AtomicU64,
}

impl RngSeedDeriver {
    pub fn from_os_rng_once() -> anyhow::Result<Self> {
        let mut key = [0u8; 32];
        rand_core::OsRng.try_fill_bytes(&mut key)?;
        Ok(Self { key, counter: AtomicU64::new(1) })
    }

    pub fn derive_for_flow(&self, flow: &FlowKey) -> [u8; 32] {
        let ctr = self.counter.fetch_add(1, Ordering::Relaxed);
        // Use a keyed hash available in the project. Preferred: blake3 keyed_hash.
        // If blake3 is not already a dependency, use HKDF/HMAC from existing crypto deps.
        let mut input = Vec::with_capacity(128);
        encode_flow_key(flow, &mut input);
        input.extend_from_slice(&ctr.to_le_bytes());
        blake3::keyed_hash(&self.key, &input).into()
    }
}
```

Если `blake3` отсутствует и добавление зависимости нежелательно, использовать уже имеющиеся HKDF/HMAC primitives из QUIC crypto code. Не писать custom crypto mixer.

`PerConnRng::new(conn_id)` заменить на:

```rust
pub fn from_seed(seed: [u8; 32], conn_id: u64) -> Self {
    // Mix conn_id into both fast and crypto streams, but seed already unique.
}
```

## Критерии готовности

- `rg "OsRng" core/src/desync/rand.rs core/src/conntrack.rs` показывает OS RNG только в startup/seed-deriver path, не в per-flow constructor.
- Per-connection seed зависит от full `FlowKey`, не от XOR-fold IPv6.
- Startup entropy failure handled explicitly, not panic in packet path.

## Верификация

```bash
cargo test -p freedpi-core per_conn_rng_seed_differs_for_ipv6_same_prefix
cargo test -p freedpi-core per_conn_rng_new_does_not_call_osrng_hot_path
```

# P4-05. Proxy rewrite copy-on-write/in-place: убрать unconditional `packet_data.to_vec()` в `rewrite_dst_addr` / `rewrite_src_addr`

## Проблема

Gemini-review указал, что proxy rewrite path может делать полную копию packet через `packet_data.to_vec()` для изменения адресов/портов. Для redirect-heavy traffic это heap allocation на hot path.

## Решение и обоснование

Нельзя просто “мутировать WinDivert buffer”, если текущий pipeline хранит packet как immutable `Bytes`. Нужно copy-on-write policy:

1. Если ownership unique, получить `BytesMut` через `try_into_mut()` и rewrite inplace.
2. Если не unique, сделать controlled `BytesMut::from(&packet[..])` как fallback и посчитать метрику.
3. Пересчитать IPv4/TCP/UDP checksums корректно.
4. Вернуть `Bytes` через `freeze()`.

## Реализация

```rust
pub enum RewritePath {
    InPlace,
    CopyFallback,
}

pub fn rewrite_dst_addr_cow(
    packet: bytes::Bytes,
    new_dst_ip: IpAddr,
    new_dst_port: u16,
) -> anyhow::Result<(bytes::Bytes, RewritePath)> {
    let mut buf = match packet.try_into_mut() {
        Ok(mut unique) => {
            rewrite_dst_addr_inplace(&mut unique[..], new_dst_ip, new_dst_port)?;
            return Ok((unique.freeze(), RewritePath::InPlace));
        }
        Err(shared) => bytes::BytesMut::from(&shared[..]),
    };

    rewrite_dst_addr_inplace(&mut buf[..], new_dst_ip, new_dst_port)?;
    Ok((buf.freeze(), RewritePath::CopyFallback))
}
```

`rewrite_dst_addr_inplace` / `rewrite_src_addr_inplace` должны использовать общий parser/checksum модуль из P0-03/P0-05, не локальные ad-hoc checksum functions.

## Критерии готовности

- Production rewrite path не содержит unconditional `packet_data.to_vec()`.
- Metrics: `rewrite_inplace_success_total`, `rewrite_copy_fallback_total`, `rewrite_error_total`.
- IPv4, IPv6, TCP, UDP rewrite tests проходят.

## Верификация

```bash
rg "to_vec\(\)" core/src/proxy/rewrite.rs && exit 1 || true
cargo test -p freedpi-core rewrite_dst_addr_cow_uses_inplace_when_unique
cargo test -p freedpi-core rewrite_dst_addr_cow_fallback_when_shared
```

# P5-01. Capture Budget Governor: runtime-контроль capture surface и safe filter rotation

## Проблема

После P1-01 default WinDivert filter становится узким, но он всё ещё остаётся статическим решением. В реальной эксплуатации конфиг, включённые техники, QUIC/TLS профили, DNS proxy, SplitTunnel и fallback режимы будут меняться. Если при деградации агент просто расширит фильтр или оставит `udp.DstPort == 443` широким, приложение снова начнёт тащить media/data plane через userspace и потеряет выигрыш от flow-affinity, batch I/O и buffer pool.

WinDivert — user-mode capture/modification/re-injection механизм. Его performance зависит от filter selectivity, batch processing, queue parameters и thread topology; это должно быть runtime-управляемым контуром, а не комментариями в конфиге.

## Решение и обоснование

Добавить отдельный `CaptureBudgetGovernor`, который раз в окно измеряет:

- `rx_pps`: сколько packets реально попало в userspace;
- `drop_ratio_ppm`: доля drops/errors;
- `max_worker_queue_depth`: максимальная глубина per-flow worker queues после P1-00;
- `capture_other_udp443_total`: сколько UDP/443 не похоже на QUIC Initial;
- `mode_dwell`: минимальное время удержания режима, чтобы избежать oscillation.

Governor не должен принимать desync-решения. Его единственная ответственность — выбрать capture mode и безопасно обновить WinDivert filter через compile-before-swap. Это отделяет “какую технику применить” от “какой объём трафика вообще можно заводить в userspace”.

## Реализация

Создать `core/src/capture_budget.rs`:

```rust
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureMode {
    /// Минимальный режим: outbound TLS ClientHello, outbound QUIC Initial, outbound DNS request.
    Strict,
    /// Нормальный режим: разрешает включённые production techniques, но не весь UDP:443.
    Balanced,
    /// Временный диагностический режим: шире Strict, но должен иметь dwell и warning metrics.
    SafeFallback,
}

#[derive(Debug, Clone)]
pub struct CaptureBudgetConfig {
    pub max_capture_pps: u64,
    pub max_drop_ratio_ppm: u64,
    pub max_worker_queue_depth: usize,
    pub max_other_udp443_pps: u64,
    pub min_mode_dwell: Duration,
}

impl Default for CaptureBudgetConfig {
    fn default() -> Self {
        Self {
            max_capture_pps: 150_000,
            max_drop_ratio_ppm: 1_000, // 0.1%
            max_worker_queue_depth: 4096,
            max_other_udp443_pps: 100,
            min_mode_dwell: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CapturePressure {
    pub rx_pps: u64,
    pub drop_ratio_ppm: u64,
    pub max_worker_queue_depth: usize,
    pub other_udp443_pps: u64,
}

#[derive(Debug)]
pub struct CaptureBudgetGovernor {
    cfg: CaptureBudgetConfig,
    mode: CaptureMode,
    last_switch: Instant,
    last_rx: AtomicU64,
    last_drop: AtomicU64,
    last_other_udp443: AtomicU64,
}

impl CaptureBudgetGovernor {
    pub fn new(cfg: CaptureBudgetConfig) -> Self {
        Self {
            cfg,
            mode: CaptureMode::Strict,
            last_switch: Instant::now(),
            last_rx: AtomicU64::new(0),
            last_drop: AtomicU64::new(0),
            last_other_udp443: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn mode(&self) -> CaptureMode {
        self.mode
    }

    pub fn observe_window(
        &mut self,
        total_received: u64,
        total_dropped: u64,
        total_other_udp443: u64,
        window: Duration,
        max_worker_queue_depth: usize,
    ) -> Option<CaptureMode> {
        if self.last_switch.elapsed() < self.cfg.min_mode_dwell {
            return None;
        }

        let prev_rx = self.last_rx.swap(total_received, Ordering::Relaxed);
        let prev_drop = self.last_drop.swap(total_dropped, Ordering::Relaxed);
        let prev_other = self.last_other_udp443.swap(total_other_udp443, Ordering::Relaxed);

        let rx_delta = total_received.saturating_sub(prev_rx);
        let drop_delta = total_dropped.saturating_sub(prev_drop);
        let other_delta = total_other_udp443.saturating_sub(prev_other);
        let secs = window.as_secs().max(1);

        let pressure = CapturePressure {
            rx_pps: rx_delta / secs,
            drop_ratio_ppm: if rx_delta == 0 { 0 } else { drop_delta.saturating_mul(1_000_000) / rx_delta },
            max_worker_queue_depth,
            other_udp443_pps: other_delta / secs,
        };

        let next = self.decide(pressure);
        if next != self.mode {
            self.mode = next;
            self.last_switch = Instant::now();
            Some(next)
        } else {
            None
        }
    }

    fn decide(&self, p: CapturePressure) -> CaptureMode {
        let overloaded = p.rx_pps > self.cfg.max_capture_pps
            || p.drop_ratio_ppm > self.cfg.max_drop_ratio_ppm
            || p.max_worker_queue_depth > self.cfg.max_worker_queue_depth
            || p.other_udp443_pps > self.cfg.max_other_udp443_pps;

        match (self.mode, overloaded) {
            (_, true) => CaptureMode::Strict,
            (CaptureMode::Strict, false) => CaptureMode::Balanced,
            (CaptureMode::Balanced, false) => CaptureMode::Balanced,
            (CaptureMode::SafeFallback, false) => CaptureMode::Balanced,
        }
    }
}

pub fn build_filter(mode: CaptureMode, enable_dns: bool, enable_quic: bool) -> String {
    let mut terms: Vec<String> = Vec::with_capacity(4);

    terms.push(
        "(tcp.DstPort == 443 && tcp.PayloadLength > 5 \
          && tcp.Payload[0] == 0x16 && tcp.Payload[1] == 0x03 \
          && tcp.Payload[5] == 0x01)".to_string(),
    );

    if enable_quic {
        terms.push(
            "(udp.DstPort == 443 && udp.PayloadLength >= 1200 \
              && (udp.Payload[0] & 0xC0) == 0xC0 \
              && (udp.Payload[0] & 0x30) == 0x00)".to_string(),
        );
    }

    if enable_dns {
        terms.push("udp.DstPort == 53".to_string());
    }

    match mode {
        CaptureMode::Strict | CaptureMode::Balanced => {
            format!("(ip or ipv6) && outbound && ({})", terms.join(" or "))
        }
        CaptureMode::SafeFallback => {
            "(ip or ipv6) && outbound && \
             ((tcp.DstPort == 443 && tcp.PayloadLength > 0) \
             or (udp.DstPort == 443 && udp.PayloadLength > 0) \
             or udp.DstPort == 53)".to_string()
        }
    }
}
```

В `core/src/lib.rs` добавить:

```rust
pub mod capture_budget;
```

В `PacketEngine::update_filter()` или в новом safe wrapper реализовать compile-before-swap:

```rust
pub fn update_filter_checked(&self, new_filter: &str) -> anyhow::Result<()> {
    // 1. Сначала проверить filter compile/eval helper на текущей платформе.
    // Точную функцию взять из используемой windivert crate binding.
    crate::windivert_ext::compile_filter(new_filter)
        .map_err(|e| anyhow::anyhow!("WinDivert filter compile failed: {e}"))?;

    // 2. Открыть новый handle до закрытия старого.
    let new_handle = WinDivert::network(new_filter)
        .map_err(|e| anyhow::anyhow!("WinDivert open failed for new filter: {e}"))?;

    // 3. Настроить queue params на новом handle до публикации.
    self.configure_handle(&new_handle)?;

    // 4. Atomic/synchronized swap handle. Старый handle закрывается только после успешного открытия нового.
    self.handle.swap(Arc::new(new_handle));
    Ok(())
}
```

Если текущий binding не экспонирует compile helper, добавить thin FFI wrapper к `WinDivertHelperCompileFilter()` в одном месте. Не использовать `WinDivertHelperEvalFilter()` в hot path: он предназначен для evaluation и может включать compile overhead.

## Критерии готовности

- Governor встроен в service loop и вызывается периодически, например раз в 1 секунду.
- При перегрузе по queue depth/drop ratio governor переводит режим в `Strict` и публикует новый filter через safe rotation.
- Invalid filter никогда не оставляет pipeline без активного WinDivert handle.
- `SafeFallback` логируется как warning и имеет dwell/exit condition.
- Метрики доступны через API/logging: `capture_mode`, `capture_rx_pps`, `capture_drop_ratio_ppm`, `capture_other_udp443_pps`, `capture_max_worker_queue_depth`, `capture_filter_update_failures_total`.

## Верификация

Unit tests:

```powershell
cargo test -p freedpi-core capture_budget
```

Windows smoke:

```powershell
# 1. Запустить service с default config.
# 2. Создать UDP:443 flood короткими datagrams, не похожими на QUIC Initial.
# 3. Проверить, что mode переходит в Strict, а userspace UDP:443 non-Initial capture падает.
# 4. Подать invalid filter через API/update path и проверить, что старый handle продолжает работать.
```

Expected gates:

- `capture_other_udp443_pps` стремится к 0 в Strict.
- Нет `WinDivert not initialized` во время filter rotation.
- `capture_filter_update_failures_total` увеличивается при invalid filter, но traffic path остаётся живым.

# P5-02. Runtime Packet Invariant Guard: не выпускать malformed generated packets на wire

## Проблема

V4 чинит конкретные checksum/offset ошибки, но в системе остаётся десятки техник, которые генерируют modified/inject packets. Любая новая техника или future refactor может снова создать malformed IPv4 total length, неверный IPv4 header checksum, некорректный TCP data offset, UDP length mismatch, IPv6 payload length mismatch или QUIC Initial меньше 1200 bytes. Если такой пакет ушёл на wire, это одновременно packet loss, нестабильность соединения и fingerprint FreeDPI.

## Решение и обоснование

Добавить lightweight validation gate перед `send_batch`/`inject_batch_via_divert`. В release `Fast` режим проверяет только boundaries/lengths/critical QUIC invariants. В debug/CI или sampling mode `Strict` дополнительно проверяет IPv4 header checksum. Guard не должен чинить packets автоматически: он должен drop/error malformed generated packet и поднять счётчик, чтобы дефект техники был виден.

## Реализация

Создать `core/src/packet_invariants.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketInvalidReason {
    TooShort,
    UnsupportedIpVersion(u8),
    Ipv4HeaderTooShort,
    Ipv4TotalLengthMismatch,
    Ipv4BadHeaderChecksum,
    Ipv6PayloadLengthMismatch,
    TcpHeaderTooShort,
    UdpHeaderTooShort,
    UdpLengthMismatch,
    QuicInitialTooSmall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationMode {
    Fast,
    Strict,
}

pub fn validate_before_send(packet: &[u8], mode: ValidationMode) -> Result<(), PacketInvalidReason> {
    let Some(first) = packet.first().copied() else {
        return Err(PacketInvalidReason::TooShort);
    };

    match first >> 4 {
        4 => validate_ipv4(packet, mode),
        6 => validate_ipv6(packet),
        v => Err(PacketInvalidReason::UnsupportedIpVersion(v)),
    }
}

fn validate_ipv4(packet: &[u8], mode: ValidationMode) -> Result<(), PacketInvalidReason> {
    if packet.len() < 20 {
        return Err(PacketInvalidReason::TooShort);
    }

    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return Err(PacketInvalidReason::Ipv4HeaderTooShort);
    }

    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len != packet.len() {
        return Err(PacketInvalidReason::Ipv4TotalLengthMismatch);
    }

    if matches!(mode, ValidationMode::Strict) {
        let mut header = packet[..ihl].to_vec();
        header[10] = 0;
        header[11] = 0;
        let expected = crate::desync::ipv4_checksum(&header);
        let actual = u16::from_be_bytes([packet[10], packet[11]]);
        if expected != actual {
            return Err(PacketInvalidReason::Ipv4BadHeaderChecksum);
        }
    }

    match packet[9] {
        6 => validate_tcp(packet, ihl),
        17 => validate_udp(packet, ihl),
        _ => Ok(()),
    }
}

fn validate_ipv6(packet: &[u8]) -> Result<(), PacketInvalidReason> {
    if packet.len() < 40 {
        return Err(PacketInvalidReason::TooShort);
    }

    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    if payload_len + 40 > packet.len() {
        return Err(PacketInvalidReason::Ipv6PayloadLengthMismatch);
    }

    // Верхний offset для TCP/UDP с extension headers уже валидируется classifier/parsing foundation P0-03.
    // Здесь guard намеренно дешёвый: он не должен заново полностью парсить весь IPv6 chain в hot path.
    Ok(())
}

fn validate_tcp(packet: &[u8], tcp_off: usize) -> Result<(), PacketInvalidReason> {
    if packet.len() < tcp_off + 20 {
        return Err(PacketInvalidReason::TcpHeaderTooShort);
    }

    let data_offset = ((packet[tcp_off + 12] >> 4) as usize) * 4;
    if data_offset < 20 || packet.len() < tcp_off + data_offset {
        return Err(PacketInvalidReason::TcpHeaderTooShort);
    }

    Ok(())
}

fn validate_udp(packet: &[u8], udp_off: usize) -> Result<(), PacketInvalidReason> {
    if packet.len() < udp_off + 8 {
        return Err(PacketInvalidReason::UdpHeaderTooShort);
    }

    let udp_len = u16::from_be_bytes([packet[udp_off + 4], packet[udp_off + 5]]) as usize;
    if udp_len < 8 || udp_off + udp_len > packet.len() {
        return Err(PacketInvalidReason::UdpLengthMismatch);
    }

    let dst_port = u16::from_be_bytes([packet[udp_off + 2], packet[udp_off + 3]]);
    if dst_port == 443 {
        let payload = &packet[udp_off + 8..udp_off + udp_len];
        if is_quic_initial(payload) && payload.len() < 1200 {
            return Err(PacketInvalidReason::QuicInitialTooSmall);
        }
    }

    Ok(())
}

fn is_quic_initial(payload: &[u8]) -> bool {
    payload.len() >= 6
        && (payload[0] & 0x80) != 0
        && (payload[0] & 0x40) != 0
        && (payload[0] & 0x30) == 0x00
        && payload[1..5] != [0, 0, 0, 0]
}
```

В `core/src/lib.rs` добавить:

```rust
pub mod packet_invariants;
```

Перед batch send/inject добавить фильтрацию generated packets:

```rust
fn push_checked_send(
    safe_batch: &mut Vec<(bytes::Bytes, windivert::address::WinDivertAddress<windivert::layer::NetworkLayer>)>,
    packet: bytes::Bytes,
    addr: windivert::address::WinDivertAddress<windivert::layer::NetworkLayer>,
    stats: &PipelineStats,
) {
    match crate::packet_invariants::validate_before_send(
        &packet,
        crate::packet_invariants::ValidationMode::Fast,
    ) {
        Ok(()) => safe_batch.push((packet, addr)),
        Err(reason) => {
            tracing::warn!(?reason, len = packet.len(), "dropping malformed generated packet before wire");
            stats.errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            stats.dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}
```

Не применять guard к исходным passthrough packets в Fast path, иначе можно начать дропать чужой malformed traffic и менять semantics firewall. Guard обязателен для packets, созданных или изменённых FreeDPI: `PacketDecision::Modify`, `PacketDecision::Desync.inject`, generated DNS/QUIC/TLS fakes.

## Критерии готовности

- Guard включён для all generated/modified packets.
- Guard не включён для untouched passthrough packets, кроме explicit debug/sampling режима.
- Все причины drop имеют метрики: `packet_invariant_drop_total{reason=...}`.
- QUIC Initial меньше 1200 bytes не уходит на wire.
- IPv4 checksum strict validation доступен в tests/sampling.

## Верификация

Unit tests:

```powershell
cargo test -p freedpi-core packet_invariants
```

Обязательные cases:

- IPv4 total length mismatch -> error.
- IPv4 IHL > 5 checksum считается по полному IHL.
- IPv6 payload length mismatch -> error.
- UDP length mismatch -> error.
- QUIC Initial payload length < 1200 -> error.
- TCP data offset < 20 -> error.

# P5-03. PCAP Replay + Fuzz Regression Harness: воспроизводимый стенд для parser/desync regression

## Проблема

После V4 проект получает больше строгих parser/desync invariants, но без corpus-based replay каждый следующий refactor может снова сломать IPv6 extension offsets, QUIC Initial detection, TLS first-record reassembly, fragmented IPv4 или checksum handling. Нужен дешёвый воспроизводимый контур, который прогоняет реальные/synthetic packets через classifier, parser foundation и invariant guard.

## Решение и обоснование

Добавить `test_support` PCAP reader и replay tests для pure core logic. WinDivert integration остаётся Windows-only, но parser/desync/fingerprint regression должны гоняться в обычном CI. Дополнительно добавить `cargo-fuzz` target для classifier + invariant guard: fuzzing должен искать panics, out-of-bounds и invalid offset states.

## Реализация

Добавить `core/src/test_support/mod.rs`:

```rust
pub mod pcap;
```

Подключить модуль условно:

```rust
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
```

Создать `core/src/test_support/pcap.rs`:

```rust
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Ethernet,
    RawIp,
    Unsupported(u32),
}

#[derive(Debug)]
pub struct PcapPacket {
    pub ts_sec: u32,
    pub ts_frac: u32,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct PcapFile {
    pub link_type: LinkType,
    pub packets: Vec<PcapPacket>,
}

pub fn read_pcap(path: impl AsRef<Path>) -> io::Result<PcapFile> {
    let mut bytes = Vec::new();
    File::open(path)?.read_to_end(&mut bytes)?;

    if bytes.len() < 24 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "pcap header too short"));
    }

    let magic_le = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let big_endian = match magic_le {
        0xa1b2c3d4 | 0xa1b23c4d => false,
        0xd4c3b2a1 | 0x4d3cb2a1 => true,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "bad pcap magic")),
    };

    let rd_u16 = |s: &[u8]| -> u16 {
        if big_endian { u16::from_be_bytes(s.try_into().unwrap()) } else { u16::from_le_bytes(s.try_into().unwrap()) }
    };
    let rd_u32 = |s: &[u8]| -> u32 {
        if big_endian { u32::from_be_bytes(s.try_into().unwrap()) } else { u32::from_le_bytes(s.try_into().unwrap()) }
    };

    let major = rd_u16(&bytes[4..6]);
    let _minor = rd_u16(&bytes[6..8]);
    if major != 2 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported pcap version"));
    }

    let snaplen = rd_u32(&bytes[16..20]) as usize;
    let network = rd_u32(&bytes[20..24]);
    let link_type = match network {
        1 => LinkType::Ethernet,
        101 => LinkType::RawIp,
        x => LinkType::Unsupported(x),
    };

    let mut pos = 24;
    let mut packets = Vec::new();

    while pos + 16 <= bytes.len() {
        let ts_sec = rd_u32(&bytes[pos..pos + 4]);
        let ts_frac = rd_u32(&bytes[pos + 4..pos + 8]);
        let incl_len = rd_u32(&bytes[pos + 8..pos + 12]) as usize;
        let orig_len = rd_u32(&bytes[pos + 12..pos + 16]) as usize;
        pos += 16;

        if incl_len > snaplen || incl_len > orig_len || pos + incl_len > bytes.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid or truncated pcap packet"));
        }

        packets.push(PcapPacket {
            ts_sec,
            ts_frac,
            data: bytes[pos..pos + incl_len].to_vec(),
        });
        pos += incl_len;
    }

    Ok(PcapFile { link_type, packets })
}

pub fn network_packet(link: LinkType, frame: &[u8]) -> Option<&[u8]> {
    match link {
        LinkType::RawIp => Some(frame),
        LinkType::Ethernet => {
            if frame.len() < 14 {
                return None;
            }
            match u16::from_be_bytes([frame[12], frame[13]]) {
                0x0800 | 0x86dd => Some(&frame[14..]),
                0x8100 if frame.len() >= 18 => match u16::from_be_bytes([frame[16], frame[17]]) {
                    0x0800 | 0x86dd => Some(&frame[18..]),
                    _ => None,
                },
                _ => None,
            }
        }
        LinkType::Unsupported(_) => None,
    }
}
```

Создать `core/tests/pcap_replay.rs`:

```rust
use freedpi_core::classifier::{Classification, Classifier};

#[test]
fn replay_tls_quic_corpus_does_not_panic_or_misparse_offsets() {
    let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pcap_corpus");
    if !corpus.exists() {
        return;
    }

    for entry in std::fs::read_dir(corpus).expect("pcap corpus dir must be readable") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|s| s.to_str()) != Some("pcap") {
            continue;
        }

        let pcap = freedpi_core::test_support::pcap::read_pcap(&path).expect("pcap must parse");
        for pkt in pcap.packets {
            let Some(ip) = freedpi_core::test_support::pcap::network_packet(pcap.link_type, &pkt.data) else {
                continue;
            };

            let class = Classifier::classify(ip);
            match class {
                Classification::Tls(cp)
                | Classification::Quic(cp)
                | Classification::Http(cp)
                | Classification::Dns(cp) => {
                    assert!(cp.payload_offset <= ip.len(), "bad payload offset in {:?}", path);
                }
                _ => {}
            }

            let _ = freedpi_core::packet_invariants::validate_before_send(
                ip,
                freedpi_core::packet_invariants::ValidationMode::Fast,
            );
        }
    }
}
```

Создать fuzz target `fuzz/fuzz_targets/classifier_invariants.rs`:

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = freedpi_core::classifier::Classifier::classify(data);
    let _ = freedpi_core::packet_invariants::validate_before_send(
        data,
        freedpi_core::packet_invariants::ValidationMode::Fast,
    );
});
```

Если `freedpi_core` workspace пока не настроен для cargo-fuzz, добавить `fuzz/Cargo.toml` по шаблону `cargo fuzz init`, затем вручную проверить dependency path на core crate.

## Критерии готовности

- В `core/tests/pcap_corpus/` есть минимум следующие fixtures: IPv4 TLS ClientHello, IPv6 TLS ClientHello with extension header, QUIC Initial, QUIC short header, fragmented IPv4, malformed short packet, VLAN Ethernet frame.
- `pcap_replay` не делает network I/O и не требует WinDivert/admin.
- Fuzz target не вызывает WinDivert, DNS, proxy, Tokio runtime, filesystem или clock-sensitive code.
- Любая новая parser/desync техника добавляет synthetic fixture или pcap regression case.

## Верификация

```powershell
cargo test -p freedpi-core pcap_replay
cargo test -p freedpi-core packet_invariants
```

Fuzz smoke в Linux/macOS CI:

```bash
cargo fuzz run classifier_invariants -- -runs=100000
```

Long fuzz nightly:

```bash
cargo fuzz run classifier_invariants -- -max_total_time=1800
```

Expected gates:

- Нет panic/out-of-bounds на arbitrary input.
- Classifier никогда не возвращает payload offset больше packet length.
- Invariant guard никогда не panic на random bytes.
- PCAP reader отвергает truncated/invalid packet records.

# P5-04. Final validation matrix

## Критерии готовности всего плана

1. `cargo fmt --all` clean.
2. `cargo check --workspace --all-targets` clean.
3. `cargo test --workspace` clean.
4. `rg` checks:

```bash
rg -n "block_on\(self\.dns_proxy|thread::sleep\(.*from_micros|group_clone|modified: Some\(self.packet\)|rss=disabled|return unencrypted|will be detected by DPI" src
```

Ни один из этих паттернов не должен оставаться в production path.

5. Runtime smoke under admin Windows:

```powershell
# 1. Start service with WinDivert.
# 2. Open several HTTPS sites, HTTP site, QUIC-enabled site.
# 3. Run iperf3 TCP and UDP in parallel.
# 4. Toggle strategy profile via API.
# 5. Toggle filter/blacklist to exercise update_filter.
```

Expected:

- No worker panic.
- No `WinDivert not initialized` during filter rotation.
- DNS queries do not block workers; queue-full is visible if overloaded.
- QUIC PN/DCID logs show non-empty DCID for long headers.
- `AutoTune.success_count/fail_count` changes only after outcome observer is wired, not after local packet modification.
- Pool `alloc_miss`/`return_drop` do not grow steadily under stable MTU traffic.
- Capture Budget Governor publishes `capture_mode` and never leaves the service without an active filter after invalid update.
- Packet Invariant Guard drops generated malformed packets and increments reason-labelled counters.
- PCAP replay corpus passes and fuzz smoke target runs without panic.

## Performance gates

Минимальный gate до merge:

- 1 Gbps TCP TLS browsing/iperf mixed: no packet loss attributable to worker stall.
- 500 Mbps UDP/QUIC mixed: no Tokio task explosion, stable memory.
- p99 packet processing latency measured inside worker under 500 us for passthrough and under 2 ms for desync path without delayed scheduler backlog.

Gate перед 5–10 Gbps:

- P4-01 per-flow sharding merged.
- RSS default enabled.
- No global `Mutex<AutoTune>` on hot path; this can be a follow-up if P0-04 still leaves `Mutex` only for `record_application`. For full 10 Gbps, replace it with `ArcSwap` overrides + atomics indexed by `strategy_id`.

---

## Дополнительные gates, уже встроенные в v3

После выполнения соответствующих v3-задач обязательны следующие проверки:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Windows-only smoke:

```powershell
# 1. AWG enabled startup
cargo run -p freedpi-service -- --config .\config-awg-enabled.toml

# 2. WinDivert default filter compile/start
cargo run -p freedpi-service -- --config .\config-default.toml

# 3. IPv6 extension header classification
cargo test -p freedpi-core ipv6_hop_by_hop_tcp_uses_actual_transport_offset

# 4. QUIC Initial only capture
# Open Chrome with QUIC enabled; verify userspace packet counters do not track entire video stream.

# 5. Named pipe IPC
# Send {"type":"ping"}\n to \\.\pipe\FreeDPI_agent and verify JSON response.
```

Perf gates to rerun after merged GLM-derived tasks:

- No `block_on` in packet worker.
- No `sleep()` in packet worker.
- No `Vec::splice()` in `desync/tls.rs` hot path.
- No `to_vec()` in `extract_tcp_options`.
- No `contains_key` + `insert` for injected sequence de-duplication.
- Default QUIC capture ratio: userspace QUIC packets during 4K streaming should be close to connection setup packets, not media packets.


---

# V5 integrated DeepSeek verification gates

Эти gates не являются appendix override; они перечислены здесь как итоговая cross-phase матрица для задач, уже встроенных выше.

```bash
# DeepSeek merge gates
rg -n "PacketBufferPool::new\(64\)|ip_to_u64|upper \^ lower|active_profile_.*String|active_profile_.*ArcSwap" core/src
rg -n "try_recv\(\).*worker_loop|worker_loop\(.*\).*try_recv" core/src/engine
rg -n "0x1c|CONNECTION_CLOSE|ConnectionClose" core/src/desync core/src/engine
cargo test -p freedpi-core flow_key
cargo test -p freedpi-core packet_pool_capacity
cargo test -p freedpi-core strategy_profile_id_registry
cargo test -p freedpi-core quic_fallback_policy
```

Required outcomes:

- No XOR-fold IPv6/tuple mixing remains in conn_id/RNG seed path.
- No fixed pool capacity 64 remains in production initialization.
- No packet worker polls broadcast receiver in a tight loop or outside an infinite worker loop.
- Active profiles are numeric IDs on packet path; names exist only at config/API boundary.
- QUIC fallback does not inject raw unprotected `CONNECTION_CLOSE` by default.
- DeepSeek dead-code list is resolved by integration/migration/removal with call-site proof.


## V6 Gemini verification gates

Эти gates обязательны сверх V5:

```bash
# Direction-aware inject: не терять direction metadata
rg "is_outbound_inject" core/src/desync core/src/engine
rg "addr\.clone\(\).*inject" core/src/engine && echo "manual review required: inject must apply InjectDirection"

# QUIC Initial: no unprotected fallback
rg "unwrap_or_else\(\|\| build_quic_initial" core/src/desync/quic.rs && exit 1 || true
rg "Fallback: return unencrypted" core/src/desync/quic.rs && exit 1 || true

# QUIC ports: no hardcoded 443 in builders, except filter/default constants
rg "build_udp_packet" core/src/desync/quic.rs

# FakeIP capacity: no permanent None on max_entries without eviction path
rg "max_entries" core/src/dns/fakeip.rs

# RNG: OsRng only in startup seed-deriver path
rg "OsRng" core/src/desync core/src/conntrack.rs

# Proxy rewrite: no unconditional packet_data.to_vec()
rg "to_vec\(\)" core/src/proxy/rewrite.rs
```

Required new tests:

```bash
cargo test -p freedpi-core rst_selective_from_inbound_trigger_is_injected_outbound
cargo test -p freedpi-core tls_record_frag_does_not_forward_original_full_client_hello
cargo test -p freedpi-core multisplit_real_path_reassembles_original_payload_without_decoys
cargo test -p freedpi-core quic_initial_crypto_failure_skips_injection
cargo test -p freedpi-core quic_initial_inject_preserves_original_dst_port
cargo test -p freedpi-core fakeip_evicts_stale_entries_when_full
cargo test -p freedpi-core per_conn_rng_seed_differs_for_ipv6_same_prefix
cargo test -p freedpi-core rewrite_dst_addr_cow_uses_inplace_when_unique
cargo test -p freedpi-core filter_includes_syn_when_mss_enabled
```
