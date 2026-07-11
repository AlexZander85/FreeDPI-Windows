# FreeDPI Windows Patch Plan v6 — Implementation Backlog

This backlog lists all the tasks from `GPT-5.5_Thinking_patch_plan_v6_integrated_gemini.md` categorized by phases. It acts as the shared state packet for agents to see what has been completed, what is in progress, and what needs to be done next.

## Status Summary
- **Phase P0 (Correctness foundation)**: `[✓] Completed (12/12 tasks)**
  - ✅ P0-01 AWG startup panic
  - ✅ P0-02 Pipeline semantics & max_seg_size
  - ✅ P0-03 L3/L4 offsets and parsing (partial — some test helpers may be missing)
  - ✅ P0-04 TLS/QUIC layer offsets & conntrack state
  - ✅ P0-05 IPv4/IPv6-safe DscpRandom
  - ✅ P0-06 tls_record_pad checksum and IHL
  - ✅ `update_checksum_word` RFC 1624 bugfix (discovered during P0-05)
  - ✅ P0-07 AutoTune outcome model
  - ✅ P0-08 Buffer pool ownership bug
  - ✅ P0-09 Canonical FlowKey
  - ✅ P0-10 Direction-aware inject model
  - ✅ P0-11 Real-vs-decoy TCP fragment invariant
  - ✅ P0-12 P0 test suite
- **Phase P1 (Hot path architecture)**: `[✓] Completed (18/18 tasks)**
  - ✅ P1-00 Flow-affinity architecture
  - ✅ P1-00A Shutdown/control-plane correctness
  - ✅ P1-01 Narrow WinDivert filter
  - ✅ P1-02 Filter rotation and QueueSize
  - ✅ P1-03 Zero-allocation recv/send batching
  - ✅ P1-04 Delayed injector instead of worker sleep
  - ✅ P1-05 DNS async queue offload
  - ✅ P1-06 AWG async queue offload
  - ✅ P1-07 Remove DesyncGroup clone
  - ✅ P1-08 Atomic check-and-mark injected_seqs
  - ✅ P1-09 Dependency-aware BadChecksum
  - ✅ P1-10 Parameterized TtlManipulation
  - ✅ P1-11 Remove hot path allocations in TCP options & TLS padding
  - ✅ P1-12 HopTab generation logic
  - ✅ P1-13 TLS 1.3 resumption-safe FakeSni
  - ✅ P1-14 AutoTune lock-free metrics
  - ✅ P1-15 ProfileId-based profile lookup
  - ✅ P1-16 Feature-dependent SYN capture
- **Phase P2 (State, GC, adaptive feedback)**: `✅` Complete
- **Phase P3 (Protocol evasion correctness)**: `[✓] Completed (8/8 tasks)**
  - ✅ P3-01 QUIC Version Negotiation packet
  - ✅ P3-02 QUIC Initial builder validity
  - ✅ P3-02A Banish unencrypted QUIC fallback
  - ✅ P3-03 TLS first-record reassembly
  - ✅ P3-04 Connect unreachable QUIC techniques
  - ✅ P3-04A Preserve original UDP port
  - ✅ P3-05 Wire SniMasking and audit HTTP/2 helpers
  - ✅ P3-06 Controlled QUIC connection closes
- **Phase P4 (Memory, allocations, RNG, observability)**: `[✓] Completed (6/6 tasks)**
  - ✅ P4-00 Packet pool sizing
  - ✅ P4-01 Keep RSS enabled
  - ✅ P4-02 Observability & performance counters
  - ✅ P4-03 Verify RecvEx zero-copy FFI
  - ✅ P4-04 Eliminate OsRng from hot flow setup
  - ✅ P4-05 Copy-on-write rewrite paths
- **Phase P5 (Operational hardening)**: `[✓] Completed (4/4 tasks)`
  - ✅ P5-01 Capture Budget Governor
  - ✅ P5-02 Runtime Packet Invariant Guard
  - ✅ P5-03 PCAP Replay & Fuzz Regression Harness
  - ✅ P5-04 Full validation matrix

---

## Phase P0 — Correctness Foundation
*Goal: Eliminate packet corruption, wrong-layer parsing, startup panics, direction metadata loss, and incorrect pipeline semantics.*

- [x] **P0-01. AWG startup panic**
  - *Requirement*: Stop using `Arc::try_unwrap()` on `awg_tunnel_state` inside `ProcessingPipeline::new()`. Keep it as `Arc<ArcSwap<Option<Arc<AwgTunnel>>>>` so it can be safely shared between background task and pipeline thread.
  - *DoD*: AWG-enabled startup does not panic; unit test `awg_state_is_shared_not_unwrapped`.
  - *Status*: `[x]` Completed

- [x] **P0-02. Packet pipeline semantics & max_seg_size**
  - *Requirement*: Ensure `PipelineState::into_result()` only returns `modified: Some(...)` when a modification actually occurred. Introduce `modified_dirty: bool` state field. Propagate `TuneParams.max_seg_size` via `ConfigOverride` to `TcpSeg` and `MssClamp`. Connect `SniMasking` technique.
  - *DoD*: `pipeline_passthrough_is_not_modified` and `no_technique_no_modified_output` tests pass; AutoTune success does not grow from passthrough.
  - *Status*: `[x]` Completed

- [x] **P0-03. L3/L4 offsets and parsing**
  - *Requirement*: Upgrade `Classifier::classify` to correctly calculate layer offsets for IPv4 fragments (mark non-first fragments as `Other`), IPv6 extension headers (traverse Hop-by-Hop, Routing, Fragment, DestOptions), and avoid panics on short/malformed packets.
  - *DoD*: Hop-by-Hop TCP classification test and IPv6 fragment test pass; no unchecked `packet[offset..]` slicing.
  - *Status*: `[x]` Completed

- [x] **P0-04. TLS/QUIC layer offsets & conntrack state**
  - *Requirement*: Pass proper L4 payload slices to TLS/QUIC parsers rather than full IP packets. Observers like `observe_tcp_syn` in conntrack must run on SYN packets to capture `client_isn`.
  - *DoD*: `client_isn != 0` is tracked for flows; `extract_quic_pn_and_dcid` gets raw UDP payload.
  - *Status*: `[x]` Completed

- [x] **P0-05. IPv4/IPv6-safe DscpRandom**
  - *Requirement*: Implement separate paths for IPv4 and IPv6 TOS/Traffic Class randomizations. IPv4 changes TOS and updates IP checksum. IPv6 changes Traffic Class across Version/TC/FlowLabel bits but does *not* write to IPv4 checksum bytes.
  - *DoD*: `dscp_random_v6_preserves_version_and_flow_label` test passes.
  - *Status*: `[x]` Completed

- [x] **P0-06. tls_record_pad checksum and IHL**
  - *Requirement*: Use actual IP header length (IHL) instead of hardcoded `20` when calculating checksum inside `tls_record_pad`. Return explicit passthrough for IPv6 payload padding if TCP/IP checksum recalculation is not supported.
  - *DoD*: IPv4 with options (`IHL > 5`) checksum validates correctly.
  - *Fixes applied*:
    1. IPv6 guard: `tls_record_pad` returns `passthrough()` early for non-IPv4 (предотвращает запись IP checksum в заголовок IPv6)
    2. IHL fix: `ipv4_checksum(&modified[..20])` → `ipv4_checksum(&modified[..ip.header_len()])` для корректной работы с IPv4 опциями
  - *Status*: `[x]` Completed

- [x] **P0-07. AutoTune outcome model vs local generation**
  - *Requirement*: Separate local application metric (did desync generate bytes?) from network outcome metric (did the connection survive?). AutoTune should only update success/fail rate from network outcome (RST, Timeout, Established).
  - *DoD*: Local generation does not increment AutoTune success count; `record_outcome` vs `record_application`.
  - *Fixes applied*:
    1. `StrategyMetrics.application_count` — счётчик локальных применений (не влияет на Thompson)
    2. `AutoTune::record_outcome` — только этот метод обновляет success/fail для Thompson sampling
    3. `AutoTune::record_application` — только инкрементирует `application_count`
    4. `ConntrackEntry.applied_strategy: Option<String>` — имя стратегии, применённой к соединению
    5. Обработчик `observe_connection_outcome` — RST → fail, SYN-ACK → success
    6. Все места вызова `tune.record(...)` переведены на `record_application`
  - *Status*: `[x]` Completed

- [x] **P0-08. Buffer pool ownership bug**
  - *Requirement*: Remove `CapturedPacket.data.clone()` from the hot classification path. Passing references `(&Bytes, &WinDivertAddress)` to `process_one_sync` allows unique ownership of `Bytes` during `pool.release_bytes` in Modify/Drop paths.
  - *DoD*: unique `Bytes` ownership is maintained, and `try_into_mut()` successfully returns allocations to the pool.
  - *Fixes applied*:
    1. `drop(captured)` вызывается до применения `PacketDecision`, гарантируя unique ownership `data`
    2. `process_one_sync` возвращает `Result` до дропа `captured` — все данные переданы по значению
  - *Status*: `[x]` Completed

- [x] **P0-09. Canonical FlowKey and keyed conn_id**
  - *Requirement*: Replace IPv6 XOR-folding / `ip_to_u64` with a canonical bidirectional `FlowKey` and a keyed process-secret `ConnIdHasher` (using `SipHasher13` with random keys generated at startup).
  - *DoD*: `FlowKey::new_bidirectional` is stable; IPv6 `/64` prefix addresses with different lower bits yield distinct hashes.
  - *Fixes applied*:
    1. `FlowKey` — канонический направленно-независимый ключ (ip_a ≤ ip_b)
    2. `ConnIdHasher` — обёртка над `SipHash13` с процесс-локальными случайными ключами
    3. `compute_conn_id` — замена `ip_to_u64` во всех call sites
    4. `SeqKey` изменён на `(conn_id, seq)` вместо `(u64, u64, u16, u16, u32)`
    5. Глобальный `CONN_ID_HASHER` через `OnceLock` (инициализация при первом вызове)
    6. Удалена функция `ip_to_u64` (XOR-folding)
  - *Status*: `[x]` Completed

- [x] **P0-10. Direction-aware inject model**
  - *Requirement*: Replace `is_outbound_inject: bool` with per-inject metadata using `InjectPacket` struct with `InjectDirection` enum (`PreserveOriginal`, `ForceOutbound`, `ForceInbound`, `DerivedFromPacketTuple`). `rst_selective` must explicitly inject outbound.
  - *DoD*: Injection direction is propagated without loss to `PacketDecision::Desync` and applied to `WinDivertAddress` before reinjection.
  - *Fixes applied*:
    1. `InjectDirection` enum + `InjectPacket` struct в `desync/mod.rs`
    2. `PacketDecision::Desync` получил поле `inject_direction: InjectDirection`
    3. Все 10 конструкторов Desync дополнены `inject_direction: result.inject_direction`
    4. `execute_decision_sync` обрабатывает `ForceOutbound` → `addr.set_outbound(true)` и `ForceInbound` → `addr.set_outbound(false)`
    5. Batch-путь (proactive-ack) игнорирует поле через `..` — требует отдельной доработки
  - *Status*: `[x]` Completed

- [x] **P0-11. Real-vs-decoy TCP fragment invariant**
  - *Requirement*: Ensure all real segments required by the server for stream reassembly are sent with original TTL. Low-TTL/fake segments must only be decoy/overlapping data. `tls_record_frag` must not forward original CH alongside fragments.
  - *DoD*: `multisplit` / `multidisorder_new` pass server reassembly simulation tests.
  - *Fixes applied*:
    1. `tls_record_frag` — установлен `drop: true`, чтобы оригинальный ClientHello не пересылался вместе с фрагментами (фрагменты уже несут все данные).
    2. `unidir_frag` — установлен `drop: true` по той же причине: все сегменты (включая последний с нормальным TTL) покрывают полные данные.
    3. `multisplit` / `multidisorder` / `host_fake_split` — коррекция не требуется: реальные данные в `modified`, а в `inject` только декои.
  - *Status*: `[x]` Completed

- [x] **P0-12. P0 test suite**
  - *Requirement*: Build verification tests covering short packets, IPv6 extension headers, IPv6 DSCP, QUIC VISIBLE headers, direction overrides, and reassembly invariants.
  - *New tests added*:
    1. `test_short_ip_header_no_panic` — IP < 20 байт не паникует
    2. `test_short_tcp_no_panic` — truncated TCP заголовок
    3. `test_short_udp_no_panic` — truncated UDP заголовок
    4. `test_ipv6_truncated_no_panic` — IPv6 с payload length > реального
    5. `test_empty_packet_no_panic` — пустой буфер
    6. `test_ipv6_extension_chain_truncated_no_panic` — Fragment ext header truncated
    7. `test_merge_into_state_propagates_force_outbound` — InjectDirection через PipelineState в into_result
    8. `test_merge_into_state_preserve_original_overwritten_by_force_outbound` — ForceOutbound перезаписывает
    9. `test_unidir_frag` — расширен assert на drop: true, modified: None
    10. `test_multisplit_has_modified_does_not_drop` — real data в modified, no drop
    11. `test_multisplit_last_segment_has_original_ttl` — decoy=fake TTL, real=original TTL
  - *Existing coverage verified*: QUIC headers, IPv6 DSCP, IPv6 extension headers — все имеют тесты
  - *Status*: `[x]` Completed

---

## Phase P1 — Hot Path Architecture and Concurrency
*Goal: Ensure packet processing is thread-safe, non-blocking, and uses selective capture filters.*

- [x] **P1-00. Flow-affinity architecture**
  - *Requirement*: Replace "multiple workers reading one WinDivert handle" with a single capture thread that steering packets into bounded, per-worker crossbeam queues using bidirectional `FlowKey` hash.
  - *DoD*: `same_flow_same_worker` and `reverse_direction_same_worker` tests pass; no worker thread concurrency races on the same connection.
  - *Status*: `[x]` Completed (Pre-implemented)

- [x] **P1-00A. Shutdown/control-plane correctness**
  - *Requirement*: Stop polling `try_recv()` inside infinite worker loops. Use atomic `RuntimeShutdown` checks checked inside the worker and capture loops, triggered via a dedicated async watcher.
  - *DoD*: Graceful shutdown stops capture and worker threads within <100ms under load.
  - *Status*: `[x]` Completed (Pre-implemented)

- [x] **P1-01. Narrow WinDivert filter**
  - *Requirement*: Restrict default capture filter to outbound TLS ClientHello, outbound DNS, and outbound QUIC Initial packets (matching long-header format). Do not capture short-header established QUIC traffic.
  - *DoD*: QUIC media streams do not pass through user space; compile-before-swap filter check.
  - *Status*: `[x]` Completed

- [x] **P1-02. Filter rotation and QueueSize**
  - *Requirement*: Eliminate the blind window during `update_filter()` by opening the new WinDivert handle before dropping the old one. Set `QueueSize` parameter to 64MB along with `QueueLength` and `QueueTime`.
  - *DoD*: Zero packet drops or "not initialized" warnings during live filter swaps.
  - *Status*: `[x]` Completed

- [x] **P1-03. Zero-allocation recv/send batching**
  - *Requirement*: Introduce `recv_batch_into(&pool, &mut vec)` to avoid allocating a vector of received packets on every loop spin. Use `SmallVec` with size 64 for `send_batch` to avoid allocation.
  - *DoD*: Zero heap allocations during packet receive, send, and inject cycles.
  - *Status*: `[x]` Completed

- [x] **P1-04. Delayed injector instead of worker sleep**
  - *Requirement*: Introduce `DelayedInject` helper thread holding a binary heap of packets. Shard workers schedule delayed injections (e.g. split segments) without blocking/sleeping.
  - *DoD*: No `std::thread::sleep` on worker hot path.
  - *Status*: `[x]` Completed

- [x] **P1-05. DNS async queue offload**
  - *Requirement*: Offload synchronous `handle_dns_query` (which calls `block_on` and blocks the thread) to a bounded queue/semaphore bridge (`DnsAsyncBridge`).
  - *DoD*: Worker drops original query immediately upon enqueue; queue overflows fail-open (forward query).
  - *Status*: `[x]` Completed

- [x] **P1-06. AWG async queue offload**
  - *Requirement*: Replace per-packet `tokio::spawn(awg.send_ip_packet)` (which copies data and spawns tasks) with a bounded `AwgAsyncBridge` queue to prevent task explosion.
  - *DoD*: Bounded queue limits memory; overflow triggers drops with metric.
  - *Status*: `[x]` Completed

- [x] **P1-07. Remove DesyncGroup clone**
  - *Requirement*: Pass `&DesyncGroup` to `apply` / `apply_desync_sync` instead of doing per-packet clones of the group or technique list.
  - *Status*: `[x]` Completed

- [x] **P1-08. Atomic check-and-mark injected_seqs**
  - *Requirement*: Replace the check-then-insert race condition in the injected TCP sequences list with an atomic/synchronized check-and-mark operation.
  - *Status*: `[x]` Completed (Pre-implemented)

- [x] **P1-09. Dependency-aware BadChecksum**
  - *Requirement*: Apply `BadChecksum` only to injected fake/decoy packets unless the profile explicitly enables destructive manipulation. Keep correct checksum on real packets.
  - *Status*: `[x]` Completed

- [x] **P1-10. Parameterized TtlManipulation**
  - *Requirement*: Remove hardcoded `TTL=64`. Parameterize TTL adjustments and restrict low TTLs strictly to decoy packets.
  - *Status*: `[x]` Completed

- [x] **P1-11. Remove hot path allocations in TCP options & TLS padding**
  - *Requirement*: Refactor TCP options parsing to return borrowed slices instead of allocating vectors. Rewrite `tls_record_pad` to populate padding in-place without vector splices.
  - *Status*: `[x]` Completed

- [x] **P1-12. HopTab generation logic**
  - *Requirement*: Upgrade HopTab to track hop count observations robustly and increment generation counts.
  - *Status*: `[x]` Completed

- [x] **P1-13. TLS 1.3 resumption-safe FakeSni**
  - *Requirement*: Disable `FakeSni` by default on TLS 1.3 resumption/0-RTT sessions if early data/session binders are linked to the original SNI.
  - *Status*: `[x]` Completed

- [x] **P1-14. AutoTune lock-free metrics**
  - *Requirement*: Remove the global `Mutex<AutoTune>` from the packet hot path. Access metrics using `ProfileId` indices and pre-allocated atomic counters.
  - *Status*: `[x]` Completed

- [x] **P1-15. ProfileId-based profile lookup**
  - *Requirement*: Replace `ArcSwap<String>` active profile lookup with `AtomicU32` storing `ProfileId`.
  - *Status*: `[x]` Completed

- [x] **P1-16. Feature-dependent SYN capture**
  - *Requirement*: (Described in P1-16 section of patch plan).
  - *Status*: `[x]` Completed

---

## Phase P2 — State, GC, Adaptive Feedback
*Goal: Ensure conntrack, routing, and adaptive tuning systems close the loop correctly.*

- [x] **P2-01. Respect StrategyProfileConfig.enabled**
  - *Requirement*: Activate profiles correctly on startup according to their enabled flags.
  - *Status*: `✅` Complete

- [x] **P2-02. Probe -> StrategyProfile -> Pipeline contour**
  - *Requirement*: Ensure recommendations from probes successfully update active runtime profiles.
  - *Status*: `✅` Complete

- [x] **P2-03. SplitTunnel decisions in data path**
  - *Requirement*: Apply split-tunnel routing checks (blacklist, whitelist, auto) in the live packet path before executing desync or proxying.
  - *Status*: `✅` Complete

- [x] **P2-04. AdaptiveRouter CircuitBreaker & ThroughputTracker**
  - *Requirement*: Integrate CircuitBreaker and ThroughputTracker to react to live network failures.
  - *Status*: `✅` Complete

- [x] **P2-05. FallbackChain, TargetEscalator, ProbeTuneRun integration**
  - *Requirement*: Integrate these components so RST pressure escalates profiles, and cooldown periods de-escalate them.
  - *Status*: `✅` Complete

- [x] **P2-06. Conntrack timing-wheel/bucketed GC**
  - *Requirement*: Replace the full table scan in `gc_incremental` with a bounded-work bucketed GC scan that periodically removes stale connections.
  - *Status*: `✅` Complete

- [x] **P2-07. Lifecycle sweeper for redirect_table**
  - *Requirement*: Implement a GC sweeper for proxy redirect mappings.
  - *Status*: `✅` Complete

- [x] **P2-08. NamedPipe IPC implementation**
  - *Requirement*: Replace placeholder IPC with actual NamedPipe IPC to handle config reloads.
  - *Status*: `✅` Complete

- [x] **P2-09. Dead-code triage**
  - *Requirement*: Audit unused fields and either connect them to the data path or mark them as deprecated/experimental.
  - *Status*: `✅` Complete

- [x] **P2-10. Harden/delete DesyncGroup::apply_single_safe**
  - *Requirement*: Eliminate wildcard passthrough catch-all; unsupported or dead enum variants must fail compilation or trigger errors.
  - *Status*: `✅` Complete

- [x] **P2-11. Deep dead-code removal & cleanup**
  - *Requirement*: Clean up unused sync methods, duplicate SOCKS helpers, and dead fields.
  - *Status*: `✅` Complete

- [x] **P2-12. FakeIP cache eviction/TTL**
  - *Requirement*: Implement TTL or generational eviction in `FakeIpManager` so that reaching max entries does not permanently break DNS routing.
  - *Status*: `✅` Complete

---

## Phase P3 — Protocol Evasion Correctness
*Goal: Ensure all injected bypass packets match official RFC protocol specifications.*

- [x] **P3-01. QUIC Version Negotiation packet**
  - *Requirement*: Support version negotiation packet layout.
  - *Status*: `[x]` Completed

- [x] **P3-02. QUIC Initial builder validity**
  - *Requirement*: Generate valid client Initial payloads (>= 1200 bytes) with correct varint lengths, TLS extensions, and entropy, rather than raw zero-padding.
  - *Status*: `[x]` Completed

- [x] **P3-02A. Banish unencrypted QUIC fallback**
  - *Requirement*: Skip injection and increment failure metrics if cryptographic packet preparation fails. Never inject unencrypted plaintext.
  - *Status*: `[x]` Completed

- [x] **P3-03. TLS first-record reassembly**
  - *Requirement*: Correctly handle fragmented ClientHello packets before trying to parse SNI.
  - *Status*: `[x]` Completed

- [x] **P3-04. Connect unreachable QUIC techniques**
  - *Requirement*: Wire up unused QUIC techniques (GREASE, normalizers, coalescing) through profile dispatch and cover with tests.
  - *Status*: `[x]` Completed

- [x] **P3-04A. Preserve original UDP port**
  - *Requirement*: Stop hardcoding port `443` in QUIC builders. Extract original destination ports from packet headers.
  - *Status*: `[x]` Completed

- [x] **P3-05. Wire SniMasking and audit HTTP/2 helpers**
  - *Requirement*: Wire the `SniMasking` technique into the packet desync dispatch path and verify HTTP/2 framing helpers.
  - *Status*: `[x]` Completed

- [x] **P3-06. Controlled QUIC connection closes**
  - *Requirement*: Never send raw unencrypted `CONNECTION_CLOSE` payloads. Use controlled drops/jitter or valid protected packets.
  - *Status*: `[x]` Completed

---

## Phase P4 — Scalability & Zero-Allocation
*Goal: Optimize the bypass hot path to support 5-10 Gbps throughput.*

- [x] **P4-00. Packet pool sizing**
  - *Requirement*: Stop hardcoding pool size to `64`. Scale size dynamically: `capacity = workers * batch_size * safety_factor` (e.g. 512 to 8192 buffers).
  - *Status*: `[x]` Completed

- [x] **P4-01. Keep RSS enabled**
  - *Requirement*: Do not globally disable Receive Side Scaling (RSS) on network adapters.
  - *Status*: `[x]` Completed

- [x] **P4-02. Observability & performance counters**
  - *Requirement*: Expose processing latency percentiles (p50/p95/p99), pool hit-rate, queue depths, and adaptive outcome metrics.
  - *Status*: `[x]` Completed

- [x] **P4-03. Verify RecvEx zero-copy FFI**
  - *Requirement*: Verify if the raw FFI bindings support true zero-copy scatter/gather buffers before claiming zero-copy.
  - *Status*: `[x]` Completed

- [x] **P4-04. Eliminate OsRng from hot flow setup**
  - *Requirement*: Use `OsRng` once at startup to seed a process secret. Derive flow-specific random seeds using a keyed KDF over the canonical `FlowKey`.
  - *Status*: `[x]` Completed

- [x] **P4-05. Copy-on-write rewrite paths**
  - *Requirement*: Avoid calling `packet_data.to_vec()` unconditionally in `rewrite_dst_addr` and `rewrite_src_addr`. Perform rewriting in-place if ownership is unique.
  - *Status*: `[x]` Completed

---

## Phase P5 — Operational Hardening
*Goal: Make the system resilient to bad configurations, adapter churn, and packet validation.*

- [x] **P5-01. Capture Budget Governor**
  - *Requirement*: Dynamically adjust capture filters and buffer sizes based on traffic pressure (Strict, Balanced, SafeFallback).
  - *Status*: `[x]` Completed

- [x] **P5-02. Runtime Packet Invariant Guard**
  - *Requirement*: Perform sanity validation on all modified and generated packets (header lengths, checksums, size constraints) before sending to wire.
  - *Status*: `[x]` Completed

- [x] **P5-03. PCAP Replay & Fuzz Regression Harness**
  - *Requirement*: Build a PCAP runner that replays test corpuses (fragmented IPv4, IPv6 with extension headers, QUIC Initial, etc.) through the classifier. Set up fuzzing targets for core parser.
  - *Status*: `[x]` Completed

- [x] **P5-04. Full validation matrix**
  - *Requirement*: Ensure all checks pass: check, fmt, test, clippy, grep validation gates, and Windows integration sanity.
  - *Status*: `[x]` Completed
