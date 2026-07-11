//! DesyncGroup — pipeline применение техник.
//!
//! ## Режим
//! **Pipeline**: каждая техника видит modified packet предыдущей.
//! Concurrent mode удалён (был гонкой с потерей данных).

use crate::adaptive::auto_tune::TuneParams;
use crate::desync::{http, ip, obfs, quic, tcp, tls};
use crate::desync::{DesyncConfig, DesyncResult, DesyncTechnique, TechniqueEffect};
use smallvec::SmallVec;
use std::sync::Arc;

/// Override параметры для одного вызова apply() — из AutoTune.
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

/// Стейт pipeline — передаётся между техниками. Не Clone — содержит PerConnRng.
#[derive(Debug)]
pub struct PipelineState {
    pub packet: bytes::Bytes,
    cached_payload_offset: Option<usize>,
    cached_tcp_seq: Option<u32>,
    pub injects: SmallVec<[crate::desync::InjectPacket; 4]>,
    pub drop: bool,
    /// T43: флаг TLS 1.3 session resumption.
    /// Передаётся из engine в desync техники, чтобы fake CH
    /// мог включать/исключать early_data extension.
    pub is_resumption: Option<bool>,
    /// T44.5: per-connection RNG для техник, которым нужен non-deterministic random.
    /// Передаётся из engine; техники могут fork() для независимости.
    pub conn_rng: Option<crate::desync::rand::PerConnRng>,
    /// true только если хотя бы одна техника реально вернула modified packet.
    pub modified_dirty: bool,
    pub client_hello_shape: Option<crate::desync::tls::ClientHelloShape>,
}

impl PipelineState {
    pub fn from_packet(packet: bytes::Bytes) -> Self {
        Self {
            packet,
            cached_payload_offset: None,
            cached_tcp_seq: None,
            injects: SmallVec::new(),
            drop: false,
            is_resumption: None,
            conn_rng: None,
            modified_dirty: false,
            client_hello_shape: None,
        }
    }

    pub fn tcp_payload_offset(&mut self) -> usize {
        *self
            .cached_payload_offset
            .get_or_insert_with(|| Self::find_tcp_payload_offset(&self.packet))
    }

    pub fn tcp_seq(&mut self) -> u32 {
        *self
            .cached_tcp_seq
            .get_or_insert_with(|| Self::extract_tcp_seq(&self.packet))
    }

    pub fn invalidate_header_cache(&mut self) {
        self.cached_payload_offset = None;
        self.cached_tcp_seq = None;
    }

    fn find_tcp_payload_offset(packet: &[u8]) -> usize {
        if packet.len() < 20 {
            return 0;
        }
        let ihl = (packet[0] & 0xF) as usize * 4;
        if packet.len() < ihl + 12 {
            return ihl;
        }
        let tcp_header_len = ((packet[ihl + 12] >> 4) & 0xF) as usize * 4;
        ihl + tcp_header_len
    }

    fn extract_tcp_seq(packet: &[u8]) -> u32 {
        if packet.len() < 20 {
            return 0;
        }
        let ihl = (packet[0] & 0xF) as usize * 4;
        if packet.len() < ihl + 16 {
            return 0;
        }
        u32::from_be_bytes([
            packet[ihl + 4],
            packet[ihl + 5],
            packet[ihl + 6],
            packet[ihl + 7],
        ])
    }

    pub fn into_result(self) -> DesyncResult {
        DesyncResult {
            modified: if self.modified_dirty {
                Some(self.packet)
            } else {
                None
            },
            inject: self.injects,
            inter_delay_us: 0,
            drop_original: self.drop,
        }
    }
}

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
        if result.drop_original {
            state.drop = true;
        }
    }
}

// SPLIT_TECHNIQUES removed in T38 — validate() now uses `TechniqueEffect::Split` via `effect()`.

#[derive(Clone)]
pub struct DesyncGroup {
    config: DesyncConfig,
    techniques: Vec<DesyncTechnique>,
    hop_tab: Option<Arc<crate::adaptive::hop_tab::HopTab>>,
    conntrack: Option<Arc<crate::conntrack::Conntrack>>,
}

impl std::fmt::Debug for DesyncGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DesyncGroup")
            .field("config", &self.config)
            .field("techniques", &self.techniques)
            .field("hop_tab_present", &self.hop_tab.is_some())
            .field("conntrack_present", &self.conntrack.is_some())
            .finish()
    }
}

impl DesyncGroup {
    pub fn new(config: DesyncConfig) -> Self {
        Self {
            config,
            techniques: Vec::new(),
            hop_tab: None,
            conntrack: None,
        }
    }

    pub fn with_context(
        config: DesyncConfig,
        hop_tab: Arc<crate::adaptive::hop_tab::HopTab>,
        conntrack: Arc<crate::conntrack::Conntrack>,
    ) -> Self {
        Self {
            config,
            techniques: Vec::new(),
            hop_tab: Some(hop_tab),
            conntrack: Some(conntrack),
        }
    }

    pub fn set_context(
        &mut self,
        hop_tab: Arc<crate::adaptive::hop_tab::HopTab>,
        conntrack: Arc<crate::conntrack::Conntrack>,
    ) {
        self.hop_tab = Some(hop_tab);
        self.conntrack = Some(conntrack);
    }

    pub fn default_set() -> Self {
        let mut group = Self::new(DesyncConfig::default());
        // FakeSni (InvalidatesSeq) + MultiSplit (Split) — невалидная композиция после T38.
        // Убираем MultiSplit — FakeSni + BadChecksum безопасны.
        group.add(DesyncTechnique::FakeSni);
        group.add(DesyncTechnique::BadChecksum);
        group
    }

    pub fn add(&mut self, technique: DesyncTechnique) {
        self.techniques.push(technique);
    }
    pub fn clear(&mut self) {
        self.techniques.clear();
    }
    pub fn techniques(&self) -> &[DesyncTechnique] {
        &self.techniques
    }

    /// Валидация группы техник.
    ///
    /// Проверяет:
    /// 1. Не более одной Split техники в группе (взаимоисключающие).
    /// 2. InvalidatesPayloadLength НЕ может идти перед Split
    ///    (split positions съедут после изменения длины payload).
    /// 3. InvalidatesSeq НЕ может идти перед Split
    ///    (SEQ-relative расчёты в split станут некорректными).
    ///
    /// Возвращает Err с конкретными именами техник при нарушении.
    pub fn validate(&self) -> Result<(), GroupError> {
        // 1. Не более одной Split техники
        let split_techniques: Vec<_> = self
            .techniques
            .iter()
            .filter(|t| matches!(t.effect(), TechniqueEffect::Split))
            .collect();
        if split_techniques.len() > 1 {
            return Err(GroupError::MultipleSplitTechniques);
        }

        // 2. InvalidatesPayloadLength НЕ может идти перед Split
        let mut seen_length_changing: Option<DesyncTechnique> = None;
        for technique in &self.techniques {
            match technique.effect() {
                TechniqueEffect::InvalidatesPayloadLength => {
                    seen_length_changing = Some(*technique);
                }
                TechniqueEffect::Split => {
                    if let Some(length_tech) = seen_length_changing {
                        return Err(GroupError::LengthChangeBeforeSplit(length_tech, *technique));
                    }
                }
                _ => {}
            }
        }

        // 3. InvalidatesSeq НЕ может идти перед Split
        let mut seen_seq_invalidating: Option<DesyncTechnique> = None;
        for technique in &self.techniques {
            match technique.effect() {
                TechniqueEffect::InvalidatesSeq => {
                    seen_seq_invalidating = Some(*technique);
                }
                TechniqueEffect::Split => {
                    if let Some(seq_tech) = seen_seq_invalidating {
                        return Err(GroupError::SeqInvalidationBeforeSplit(seq_tech, *technique));
                    }
                }
                _ => {}
            }
        }

        // 4. BadChecksum requires preceding inject techniques
        if let Some(bad_checksum_idx) = self
            .techniques
            .iter()
            .position(|t| matches!(t, DesyncTechnique::BadChecksum))
        {
            let has_preceding_inject = self.techniques[..bad_checksum_idx].iter().any(|t| {
                matches!(t.effect(), TechniqueEffect::InvalidatesSeq)
                    || matches!(
                        t,
                        DesyncTechnique::HostFakeSplit | DesyncTechnique::FakeDataSplit
                    )
            });
            if !has_preceding_inject {
                return Err(GroupError::BadChecksumWithoutInject);
            }
        }

        Ok(())
    }

    pub fn apply(
        &self,
        packet: &bytes::Bytes,
        dscp_value: Option<u8>,
        override_params: Option<ConfigOverride>,
        is_resumption: Option<bool>,
    ) -> DesyncResult {
        self.apply_pipeline(
            packet.clone(),
            dscp_value,
            override_params,
            is_resumption,
            None,
        )
    }

    /// Same as `apply`, but accepts a per-connection RNG for non-deterministic
    /// per-packet fields (TLS random, GREASE, etc.).  The engine should pass
    /// a fork of the conntrack entry's RNG so each desync decision gets an
    /// independent stream.
    pub fn apply_with_rng(
        &self,
        packet: &bytes::Bytes,
        dscp_value: Option<u8>,
        override_params: Option<ConfigOverride>,
        is_resumption: Option<bool>,
        conn_rng: Option<crate::desync::rand::PerConnRng>,
    ) -> DesyncResult {
        self.apply_with_runtime_context(
            packet,
            dscp_value,
            override_params,
            is_resumption,
            conn_rng,
            self.hop_tab.as_deref(),
            self.conntrack.as_deref(),
            None,
        )
    }

    pub fn apply_with_runtime_context(
        &self,
        packet: &bytes::Bytes,
        dscp_value: Option<u8>,
        override_params: Option<ConfigOverride>,
        is_resumption: Option<bool>,
        conn_rng: Option<crate::desync::rand::PerConnRng>,
        hop_tab: Option<&crate::adaptive::hop_tab::HopTab>,
        conntrack: Option<&crate::conntrack::Conntrack>,
        client_hello_shape: Option<crate::desync::tls::ClientHelloShape>,
    ) -> DesyncResult {
        let mut state = PipelineState::from_packet(packet.clone());
        state.is_resumption = is_resumption;
        state.conn_rng = conn_rng;
        state.client_hello_shape = client_hello_shape;
        for technique in &self.techniques {
            self.apply_to_state_with_context(
                technique,
                &mut state,
                dscp_value,
                override_params,
                hop_tab,
                conntrack,
            );
            if state.drop {
                break;
            }
        }
        state.into_result()
    }

    fn apply_pipeline(
        &self,
        packet: bytes::Bytes,
        dscp_value: Option<u8>,
        override_params: Option<ConfigOverride>,
        is_resumption: Option<bool>,
        conn_rng: Option<crate::desync::rand::PerConnRng>,
    ) -> DesyncResult {
        self.apply_with_runtime_context(
            &packet,
            dscp_value,
            override_params,
            is_resumption,
            conn_rng,
            self.hop_tab.as_deref(),
            self.conntrack.as_deref(),
            None,
        )
    }

    fn apply_to_state_with_context(
        &self,
        technique: &DesyncTechnique,
        state: &mut PipelineState,
        dscp_value: Option<u8>,
        override_params: Option<ConfigOverride>,
        hop_tab: Option<&crate::adaptive::hop_tab::HopTab>,
        conntrack: Option<&crate::conntrack::Conntrack>,
    ) {
        let c = &self.config;
        let split_size = override_params
            .and_then(|p| p.split_size)
            .unwrap_or(c.split_size);
        let split_count = override_params
            .and_then(|p| p.split_count)
            .unwrap_or(c.split_count);
        let fake_ttl_offset = override_params
            .and_then(|p| p.fake_ttl_offset)
            .unwrap_or(c.fake_ttl_offset);
        let max_seg_size = override_params
            .and_then(|p| p.max_seg_size)
            .unwrap_or(c.max_seg_size);
        let fake_sni_str: &str = &c.fake_sni;

        match technique {
            DesyncTechnique::FakeSni => {
                if let Some(shape) = &state.client_hello_shape {
                    if shape.has_pre_shared_key {
                        tracing::debug!("resumption ClientHello detected; disabling fake CH generator for fingerprint safety");
                        return;
                    }
                }
                let resumption = state.is_resumption.unwrap_or(false);
                let result = if let Some(ref mut rng) = state.conn_rng {
                    tcp::fake_sni(
                        &state.packet,
                        fake_sni_str,
                        fake_ttl_offset,
                        Some(rng),
                        resumption,
                    )
                } else {
                    tcp::fake_sni(
                        &state.packet,
                        fake_sni_str,
                        fake_ttl_offset,
                        None,
                        resumption,
                    )
                };
                self.merge_into_state(state, result);
            }
            DesyncTechnique::MultiSplit => {
                let result = tcp::multisplit(
                    &state.packet,
                    split_size,
                    split_count,
                    fake_ttl_offset,
                    c.inter_delay_us,
                );
                state.invalidate_header_cache();
                self.merge_into_state(state, result);
            }
            DesyncTechnique::MultiDisorder => {
                let result =
                    tcp::multidisorder(&state.packet, split_size, split_count, fake_ttl_offset);
                state.invalidate_header_cache();
                self.merge_into_state(state, result);
            }
            DesyncTechnique::Disorder => {
                let result = tcp::disorder(&state.packet, split_size, fake_ttl_offset);
                state.invalidate_header_cache();
                self.merge_into_state(state, result);
            }
            DesyncTechnique::FakeDataSplit => {
                let result = tcp::fakedsplit(&state.packet, fake_sni_str, fake_ttl_offset);
                state.invalidate_header_cache();
                self.merge_into_state(state, result);
            }
            DesyncTechnique::BadChecksum => {
                state.injects = state
                    .injects
                    .iter()
                    .flat_map(|pkt| {
                        let result = ip::bad_checksum(&pkt.bytes);
                        if result.inject.is_empty() {
                            // passthrough — keep original
                            smallvec::smallvec![pkt.clone()]
                        } else {
                            result.inject
                        }
                    })
                    .collect();
                if self.config.allow_destructive_manipulation {
                    self.merge_into_state(state, ip::bad_checksum(&state.packet));
                }
            }
            DesyncTechnique::TtlManipulation => {
                let ttl_val = self.config.ttl_value;
                for inject_pkt in &mut state.injects {
                    let result = ip::ttl_manipulation(&inject_pkt.bytes, ttl_val);
                    if let Some(modified) = result.modified {
                        inject_pkt.bytes = modified;
                    }
                }
                if self.config.allow_real_ttl_manipulation {
                    self.merge_into_state(state, ip::ttl_manipulation(&state.packet, ttl_val));
                }
            }
            DesyncTechnique::TlsRecordFrag => {
                self.merge_into_state(
                    state,
                    tls::tls_record_frag(&state.packet, 5, fake_ttl_offset),
                );
            }
            DesyncTechnique::SniMasking => {
                let result = tls::sni_masking(&state.packet, 0x2A);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::TlsRecordRewrap => {
                self.merge_into_state(
                    state,
                    tls::tls_record_rewrap(&state.packet, 100, fake_ttl_offset),
                );
            }
            DesyncTechnique::TlsVersionSpoof => {
                self.merge_into_state(state, tls::tls_version_overwrite(&state.packet));
            }
            DesyncTechnique::SniRecordFrag => {
                self.merge_into_state(
                    state,
                    tls::sni_record_frag(&state.packet, 2, fake_ttl_offset),
                );
            }
            DesyncTechnique::RstDropIpId => {
                self.merge_into_state(state, ip::rst_drop_ip_id(&state.packet));
            }
            DesyncTechnique::DscpRandom => {
                match dscp_value {
                    Some(dscp) => {
                        self.merge_into_state(state, ip::dscp_random(&state.packet, dscp));
                    }
                    None => {
                        // No per-connection DSCP — skip (не применяем per-packet random, это аномалия)
                        tracing::trace!("DscpRandom skipped — no per-connection dscp_value");
                    }
                }
            }
            #[allow(deprecated)]
            DesyncTechnique::TcpPreopen => {
                tracing::warn!(
                    "TcpPreopen is deprecated and non-functional in pipeline mode — ignoring"
                );
            }
            // === Remaining TCP techniques ===
            DesyncTechnique::TcpSeg => {
                let result = tcp::tcpseg(&state.packet, max_seg_size, fake_ttl_offset);
                state.invalidate_header_cache();
                self.merge_into_state(state, result);
            }
            DesyncTechnique::SynData => {
                let result = tcp::syndata(
                    &state.packet,
                    &fake_sni_str.as_bytes()[..4.min(fake_sni_str.len())],
                    fake_ttl_offset,
                );
                self.merge_into_state(state, result);
            }
            DesyncTechnique::HostFakeSplit => {
                let result = tcp::host_fake_split(&state.packet, fake_sni_str, fake_ttl_offset);
                state.invalidate_header_cache();
                self.merge_into_state(state, result);
            }
            DesyncTechnique::FakeDataDisorder => {
                let result = tcp::fake_data_disorder(
                    &state.packet,
                    fake_sni_str.as_bytes(),
                    fake_ttl_offset,
                );
                state.invalidate_header_cache();
                self.merge_into_state(state, result);
            }
            DesyncTechnique::SynAckSplit => {
                let result = tcp::syn_ack_split(&state.packet);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::WinSize => {
                let result = tcp::winsize(&state.packet, 1024);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::SynHide => {
                let result = tcp::synhide(&state.packet, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::OobInjection => {
                let result = tcp::oob_injection(&state.packet, fake_sni_str, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::MssClamp => {
                let mss = max_seg_size.clamp(68, u16::MAX as usize) as u16;
                let result = tcp::mss_clamp(&state.packet, mss, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::AckSuppress => {
                let result = tcp::ack_suppress(&state.packet, 2, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::PktReorder => {
                let result = tcp::pkt_reorder(&state.packet, true);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::RstSelective => {
                let result = tcp::rst_selective(&state.packet, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::SynFloodDecoy => {
                let result = tcp::syn_flood_decoy(&state.packet, 5, fake_sni_str, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::WinScaleManip => {
                let result = tcp::win_scale_manip(&state.packet, 1024, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::MultidisorderNew => {
                let result = tcp::multidisorder_new(&state.packet, split_count, fake_ttl_offset);
                state.invalidate_header_cache();
                self.merge_into_state(state, result);
            }
            DesyncTechnique::Disoob => {
                let result = tcp::disoob(&state.packet, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::HostFake => {
                let result = tcp::hostfake(&state.packet, fake_sni_str, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::FakeRst => {
                let result = tcp::fakerst(&state.packet, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::ByteByByte => {
                let result = tcp::byte_by_byte(&state.packet, 10, fake_ttl_offset);
                state.invalidate_header_cache();
                self.merge_into_state(state, result);
            }
            DesyncTechnique::UnidirFrag => {
                let result = tcp::unidir_frag(&state.packet, split_size, fake_ttl_offset);
                state.invalidate_header_cache();
                self.merge_into_state(state, result);
            }
            DesyncTechnique::PortShuffle => {
                let result = tcp::port_shuffle(&state.packet);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::Wclamp => {
                let result = tcp::wclamp(&state.packet, 1024);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::TsMd5 => {
                let result = tcp::ts_md5(&state.packet, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            // === IP techniques ===
            DesyncTechnique::FragOverlap => {
                let result = ip::frag_overlap(&state.packet, fake_sni_str, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::IpFragPrimitives => {
                let result = ip::ip_frag_primitives(&state.packet, split_size, fake_ttl_offset);
                state.invalidate_header_cache();
                self.merge_into_state(state, result);
            }
            DesyncTechnique::MutualSpoof => {
                let result = ip::mutual_spoof(&state.packet);
                self.merge_into_state(state, result);
            }
            // === TLS techniques ===
            DesyncTechnique::TlsRecordPad => {
                let result = tls::tls_record_pad(&state.packet, 32, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::SniMicrofrag => {
                let result = tls::sni_microfrag(&state.packet, 5, fake_ttl_offset);
                state.invalidate_header_cache();
                self.merge_into_state(state, result);
            }
            // === HTTP techniques ===
            DesyncTechnique::H2SettingsFlood => {
                let result = http::h2_settings_flood(&state.packet, 3, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::H2RstPadding => {
                let result = http::h2_rst_padding(&state.packet, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::H2WindowUpdateFlood => {
                let result = http::h2_window_update_flood(&state.packet, 2, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::H2PriorityAbuse => {
                let result = http::h2_priority_abuse(&state.packet, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::H2Goaway => {
                let result = http::h2_goaway_inject(&state.packet, 1, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::ChunkObfuscation => {
                let result = http::chunk_obfuscation(&state.packet, 3, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::H2FrameOrdering => {
                let result = http::h2_frame_ordering(&state.packet, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::HttpCaseMix => {
                let result = http::http_case_mix(&state.packet);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::Http11Pipeline => {
                let result = http::http11_pipeline(&state.packet, fake_sni_str, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::ContentLengthFuzz => {
                let result = http::content_length_fuzz(&state.packet, 100000);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::HttpUpgradeAbuse => {
                let result = http::http_upgrade_abuse(&state.packet);
                self.merge_into_state(state, result);
            }
            // === QUIC techniques ===
            DesyncTechnique::QuicBlocking => {
                let ctx = match crate::desync::PacketContext::from_packet(&state.packet) {
                    Some(c) => c,
                    None => return,
                };
                let conn_key = crate::conntrack::ConnKey::new(
                    ctx.src_ip,
                    ctx.dst_ip,
                    ctx.src_port.unwrap_or(0),
                    ctx.dst_port.unwrap_or(0),
                    ctx.proto,
                );
                let mut dropped_initials = 0u8;
                if let Some(ct) = conntrack {
                    if let Some(entry) = ct.get(&conn_key) {
                        dropped_initials = entry.quic_dropped_initials;
                    }
                }
                let mut dropped_count = dropped_initials;
                let result = quic::quic_blocking(
                    &state.packet,
                    &ctx,
                    self.config.quic_fallback_policy,
                    fake_ttl_offset,
                    &mut dropped_count,
                );
                if dropped_count != dropped_initials {
                    if let Some(ct) = conntrack {
                        if let Some(mut entry) = ct.get_mut(&conn_key) {
                            entry.quic_dropped_initials = dropped_count;
                        }
                    }
                }
                self.merge_into_state(state, result);
            }
            DesyncTechnique::QuicVersionDowngrade => {
                let ctx = match crate::desync::PacketContext::from_packet(&state.packet) {
                    Some(c) => c,
                    None => return,
                };
                let result =
                    quic::quic_version_downgrade(&state.packet, &ctx, 0xFF00001D, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::QuicRetryInject => {
                let ctx = match crate::desync::PacketContext::from_packet(&state.packet) {
                    Some(c) => c,
                    None => return,
                };
                let result = quic::quic_retry_inject(&state.packet, &ctx, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::QuicConnectionClose => {
                let ctx = match crate::desync::PacketContext::from_packet(&state.packet) {
                    Some(c) => c,
                    None => return,
                };
                let result =
                    quic::quic_connection_close(&state.packet, &ctx, 0x02, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::QuicStreamReset => {
                let ctx = match crate::desync::PacketContext::from_packet(&state.packet) {
                    Some(c) => c,
                    None => return,
                };
                let result = quic::quic_stream_reset(&state.packet, &ctx, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::QuicMaxStreams => {
                let ctx = match crate::desync::PacketContext::from_packet(&state.packet) {
                    Some(c) => c,
                    None => return,
                };
                let result = quic::quic_max_streams(&state.packet, &ctx, 100, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::QuicInitialInject => {
                let ctx = match crate::desync::PacketContext::from_packet(&state.packet) {
                    Some(c) => c,
                    None => return,
                };
                let result = quic::quic_initial_inject(
                    &state.packet,
                    &ctx,
                    &self.config.fake_sni,
                    fake_ttl_offset,
                );
                self.merge_into_state(state, result);
            }
            DesyncTechnique::QuicShortHeaderPoison => {
                let ctx = match crate::desync::PacketContext::from_packet(&state.packet) {
                    Some(c) => c,
                    None => return,
                };
                let result = quic::quic_short_header_poison(&state.packet, &ctx, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::QuicPaddingFlood => {
                let ctx = match crate::desync::PacketContext::from_packet(&state.packet) {
                    Some(c) => c,
                    None => return,
                };
                let result = quic::quic_padding_flood(&state.packet, &ctx, 5, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::DoppelgangerGrease => {
                let ctx = match crate::desync::PacketContext::from_packet(&state.packet) {
                    Some(c) => c,
                    None => return,
                };
                let result = quic::doppelganger_grease(&state.packet, &ctx, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::QuicLongHeaderDrop => {
                let ctx = match crate::desync::PacketContext::from_packet(&state.packet) {
                    Some(c) => c,
                    None => return,
                };
                let result = quic::quic_long_header_drop(&state.packet, &ctx);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::QuicNormalizer => {
                let ctx = match crate::desync::PacketContext::from_packet(&state.packet) {
                    Some(c) => c,
                    None => return,
                };
                let result = quic::quic_normalizer(&state.packet, &ctx);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::UdpCoalescing => {
                let ctx = match crate::desync::PacketContext::from_packet(&state.packet) {
                    Some(c) => c,
                    None => return,
                };
                let result = quic::udp_coalescing(&state.packet, &ctx, &[], fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            // === Obfs/Crypto techniques ===
            DesyncTechnique::Udp2Icmp => {
                let result = obfs::udp2icmp(&state.packet, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::XorFirst => {
                let result = obfs::xor_first(&state.packet, 4, 0xFF);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::WgObfs => {
                let result = obfs::wg_obfs(&state.packet, fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::ChaCha20 => {
                tracing::warn!("ChaCha20 disabled — broken by design for transparent proxy");
            }
            // === Composite ===
            DesyncTechnique::ReverseFragmentOrder => {
                let r = tcp::multisplit(
                    &state.packet,
                    split_size,
                    split_count,
                    fake_ttl_offset,
                    c.inter_delay_us,
                );
                let result = tcp::reverse_fragment_order(r);
                state.invalidate_header_cache();
                self.merge_into_state(state, result);
            }
            DesyncTechnique::SeqSpoof => {
                self.apply_seq_spoof_with_context(state, hop_tab, conntrack);
            }
        }
    }

    fn apply_seq_spoof_with_context(
        &self,
        state: &mut PipelineState,
        hop_tab: Option<&crate::adaptive::hop_tab::HopTab>,
        conntrack: Option<&crate::conntrack::Conntrack>,
    ) {
        let hop_tab = match hop_tab {
            Some(ht) => ht,
            None => {
                tracing::warn!("SeqSpoof requires HopTab — not set, skipping");
                return;
            }
        };
        let conntrack = match conntrack {
            Some(ct) => ct,
            None => {
                tracing::warn!("SeqSpoof requires Conntrack — not set, skipping");
                return;
            }
        };

        // Parse IP header
        let ip = match crate::desync::parse_ip_header(&state.packet) {
            Some(h) => h,
            None => return,
        };
        let tcp_data = &state.packet[ip.header_len()..];
        let tcp = match crate::desync::parse_tcp_packet(tcp_data) {
            Some(t) => t,
            None => return,
        };

        let src_ip = ip.src();
        let dst_ip = ip.dst();

        // Get client_isn from conntrack
        let conn_key =
            crate::conntrack::ConnKey::new(src_ip, dst_ip, tcp.src_port, tcp.dst_port, 6);
        let client_isn = match conntrack.get(&conn_key) {
            Some(entry) => entry.client_isn,
            None => {
                tracing::debug!(
                    "SeqSpoof: no conntrack entry for {:?}, using tcp.sequence",
                    conn_key
                );
                tcp.sequence // fallback
            }
        };

        // Call build_seq_spoof_packet (it already takes src_ip/dst_ip as IpAddr)
        let fake_sni = &self.config.fake_sni;
        let result = crate::adaptive::seq_spoof::build_seq_spoof_packet(
            fake_sni,
            src_ip,
            dst_ip,
            tcp.src_port,
            tcp.dst_port,
            client_isn,
            conntrack,
            hop_tab,
        );

        match result {
            Ok(spoof_result) => {
                state.injects.push(crate::desync::InjectPacket {
                    bytes: spoof_result.fake_packet,
                    protocol: crate::desync::InjectProtocol::Tcp,
                    direction: crate::desync::InjectDirection::ForceOutbound,
                    delay_us: 0,
                });
                tracing::debug!(
                    "SeqSpoof applied: fake_ttl={}, fake_seq_offset={}",
                    spoof_result.fake_ttl,
                    client_isn.wrapping_add(10000)
                );
            }
            Err(e) => {
                tracing::warn!("SeqSpoof failed: {}", e);
            }
        }
    }
}

impl Default for DesyncGroup {
    fn default() -> Self {
        Self::default_set()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GroupError {
    #[error("Multiple Split techniques in one group — they are mutually exclusive")]
    MultipleSplitTechniques,

    #[error(
        "Length-changing technique ({0:?}) cannot precede Split technique ({1:?}) — \
         split positions are invalidated by payload length change"
    )]
    LengthChangeBeforeSplit(DesyncTechnique, DesyncTechnique),

    #[error(
        "SEQ-invalidating technique ({0:?}) cannot precede Split technique ({1:?}) — \
         split SEQ calculations are invalidated"
    )]
    SeqInvalidationBeforeSplit(DesyncTechnique, DesyncTechnique),

    #[error(
        "BadChecksum technique cannot be used without preceding inject/decoy techniques \
         (e.g., FakeSni, HostFakeSplit) because it only applies to injected packets"
    )]
    BadChecksumWithoutInject,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_noop_does_not_mark_modified() {
        let group = DesyncGroup::new(DesyncConfig::default());
        let pkt = bytes::Bytes::from_static(b"not an ip packet");
        let result = group.apply(&pkt, None, None, None);
        assert!(result.modified.is_none());
        assert!(result.inject.is_empty());
        assert!(!result.drop_original);
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

    #[test]
    fn test_validate_multiple_split_rejected() {
        let mut group = DesyncGroup::new(DesyncConfig::default());
        group.add(DesyncTechnique::MultiSplit);
        group.add(DesyncTechnique::FakeDataSplit);
        assert!(matches!(
            group.validate(),
            Err(GroupError::MultipleSplitTechniques)
        ));
    }

    #[test]
    fn test_validate_length_change_before_split_rejected() {
        let mut group = DesyncGroup::new(DesyncConfig::default());
        group.add(DesyncTechnique::TlsRecordPad); // InvalidatesPayloadLength
        group.add(DesyncTechnique::MultiSplit); // Split
        assert!(matches!(
            group.validate(),
            Err(GroupError::LengthChangeBeforeSplit(
                DesyncTechnique::TlsRecordPad,
                DesyncTechnique::MultiSplit
            ))
        ));
    }

    #[test]
    fn test_validate_split_before_length_change_ok() {
        let mut group = DesyncGroup::new(DesyncConfig::default());
        group.add(DesyncTechnique::MultiSplit); // Split
        group.add(DesyncTechnique::TlsRecordPad); // InvalidatesPayloadLength
        assert!(group.validate().is_ok());
    }

    #[test]
    fn test_validate_seq_invalidation_before_split_rejected() {
        let mut group = DesyncGroup::new(DesyncConfig::default());
        group.add(DesyncTechnique::FakeSni); // InvalidatesSeq
        group.add(DesyncTechnique::MultiSplit); // Split
        assert!(matches!(
            group.validate(),
            Err(GroupError::SeqInvalidationBeforeSplit(
                DesyncTechnique::FakeSni,
                DesyncTechnique::MultiSplit
            ))
        ));
    }

    #[test]
    fn test_validate_header_only_before_split_ok() {
        let mut group = DesyncGroup::new(DesyncConfig::default());
        group.add(DesyncTechnique::TtlManipulation); // HeaderOnly
        group.add(DesyncTechnique::DscpRandom); // HeaderOnly
        group.add(DesyncTechnique::MultiSplit); // Split
        assert!(group.validate().is_ok());
    }

    #[test]
    fn test_technique_effect_classification() {
        assert_eq!(
            DesyncTechnique::TtlManipulation.effect(),
            TechniqueEffect::HeaderOnly
        );
        assert_eq!(
            DesyncTechnique::TlsRecordPad.effect(),
            TechniqueEffect::InvalidatesPayloadLength
        );
        assert_eq!(
            DesyncTechnique::FakeSni.effect(),
            TechniqueEffect::InvalidatesSeq
        );
        assert_eq!(DesyncTechnique::MultiSplit.effect(), TechniqueEffect::Split);
    }

    use crate::adaptive::hop_tab::HopTab;
    use crate::conntrack::{ConnKey, ConnState, Conntrack, ConntrackEntry};
    use std::net::Ipv4Addr;
    use std::time::Instant;

    fn setup_conntrack_with_isn() -> (Arc<Conntrack>, Arc<HopTab>) {
        let conntrack = Arc::new(Conntrack::default());
        let hop_tab = Arc::new(HopTab::new());

        // Insert conntrack entry with known ISN
        let key = ConnKey::new(
            Ipv4Addr::new(192, 168, 1, 2),
            Ipv4Addr::new(142, 250, 185, 46),
            54321,
            443,
            6,
        );
        let entry = ConntrackEntry {
            client_isn: 1000,
            server_isn: 0,
            client_seq: 1001,
            server_seq: 0,
            client_ack: 0,
            server_ack: 0,
            rtt_us: 0,
            state: ConnState::Established,
            desync_applied: false,
            dscp_spoof: 0,
            strategy_id: 0,
            last_activity: Instant::now(),
            dup_ack_count: 0,
            rng: None,
            quic_pn: 0,
            quic_dcid: vec![],
            is_resumption: false,
            applied_strategy: None,
            route_key: None,
            quic_dropped_initials: 0,
        };
        conntrack.insert(key, entry);

        // Insert HopTab entry (12 hops to destination)
        hop_tab.insert(
            HopTab::ip_to_u32(&std::net::IpAddr::V4(Ipv4Addr::new(142, 250, 185, 46))),
            12,
        );

        (conntrack, hop_tab)
    }

    fn build_test_tls_packet() -> bytes::Bytes {
        // Minimal IP + TCP + TLS ClientHello packet
        let pkt = vec![
            0x45, 0x00, 0x00, 0x40, // IP header
            0x00, 0x01, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01,
            0x02, // src: 192.168.1.2
            0x8e, 0xfa, 0xb9, 0x2e, // dst: 142.250.185.46
            // TCP header
            0xd4, 0x31, // src port: 54321
            0x01, 0xbb, // dst port: 443
            0x00, 0x00, 0x03, 0xe9, // seq: 1001
            0x00, 0x00, 0x00, 0x00, // ack: 0
            0x50, 0x18, 0x71, 0x10, // data offset + flags + window
            0x00, 0x00, 0x00, 0x00, // checksum + urgent
            // TLS ClientHello (minimal)
            0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00,
        ];
        bytes::Bytes::from(pkt)
    }

    #[test]
    fn test_seq_spoof_in_desync_technique_enum() {
        assert_eq!(DesyncTechnique::SeqSpoof.name(), "SeqSpoof");
        assert_eq!(DesyncTechnique::SeqSpoof.source(), "sni-spoofing-rust");
        assert_eq!(
            DesyncTechnique::SeqSpoof.effect(),
            crate::desync::TechniqueEffect::InvalidatesSeq
        );
    }

    #[test]
    fn test_seq_spoof_profile_valid() {
        let registry = crate::adaptive::strategy_profile::StrategyProfileRegistry::with_defaults(
            &DesyncConfig::default(),
            &[],
        );
        let profile = registry.get("outbound_tls_seqspoof").unwrap();
        let group = (*profile.desync_group).clone();
        assert!(
            group.validate().is_ok(),
            "SeqSpoof + BadChecksum should be valid"
        );
    }

    #[test]
    fn test_seq_spoof_plus_split_invalid() {
        let mut group = DesyncGroup::new(DesyncConfig::default());
        group.add(DesyncTechnique::SeqSpoof); // InvalidatesSeq
        group.add(DesyncTechnique::MultiSplit); // Split
        assert!(
            group.validate().is_err(),
            "SeqSpoof + MultiSplit should be invalid"
        );
    }

    #[test]
    fn test_seq_spoof_applies_with_context() {
        let (conntrack, hop_tab) = setup_conntrack_with_isn();
        let mut group = DesyncGroup::with_context(DesyncConfig::default(), hop_tab, conntrack);
        group.add(DesyncTechnique::SeqSpoof);

        let packet = build_test_tls_packet();
        let result = group.apply(&packet, None, None, None);

        // SeqSpoof должен создать inject (fake CH с out-of-window SEQ)
        assert!(
            !result.inject.is_empty(),
            "SeqSpoof should produce inject packets"
        );
        assert_eq!(
            result.inject.len(),
            1,
            "SeqSpoof should produce exactly 1 inject"
        );
    }

    #[test]
    fn test_seq_spoof_skips_without_context() {
        let mut group = DesyncGroup::new(DesyncConfig::default());
        group.add(DesyncTechnique::SeqSpoof);

        let packet = build_test_tls_packet();
        let result = group.apply(&packet, None, None, None);

        // Без HopTab/Conntrack — passthrough (no inject)
        assert!(
            result.inject.is_empty(),
            "SeqSpoof without context should produce no injects"
        );
    }

    // === P0-12: Direction override propagation ===

    #[test]
    fn test_merge_into_state_propagates_inject_packets() {
        let pkt = bytes::Bytes::from(vec![0u8; 40]);
        let mut state = PipelineState::from_packet(pkt.clone());
        assert_eq!(state.injects.len(), 0);

        let result = crate::desync::DesyncResult {
            modified: None,
            inject: smallvec::smallvec![crate::desync::InjectPacket::tcp(
                bytes::Bytes::from(vec![1, 2, 3]),
                crate::desync::InjectDirection::ForceOutbound
            )],
            inter_delay_us: 0,
            drop_original: false,
        };

        let config = DesyncConfig::default();
        let group = DesyncGroup::new(config);
        group.merge_into_state(&mut state, result);

        assert_eq!(state.injects.len(), 1);
        assert_eq!(
            state.injects[0].direction,
            crate::desync::InjectDirection::ForceOutbound
        );

        // Проверка into_result
        let final_result = state.into_result();
        assert_eq!(final_result.inject.len(), 1);
        assert_eq!(
            final_result.inject[0].direction,
            crate::desync::InjectDirection::ForceOutbound
        );
    }

    #[test]
    fn test_validate_bad_checksum_requires_inject() {
        let mut group = DesyncGroup::new(DesyncConfig::default());
        group.add(DesyncTechnique::BadChecksum);
        assert!(matches!(
            group.validate(),
            Err(GroupError::BadChecksumWithoutInject)
        ));
    }

    #[test]
    fn test_validate_bad_checksum_with_inject_ok() {
        let mut group = DesyncGroup::new(DesyncConfig::default());
        group.add(DesyncTechnique::FakeSni); // inject
        group.add(DesyncTechnique::BadChecksum);
        assert!(group.validate().is_ok());
    }
}
