//! DesyncGroup — pipeline и concurrent применение техник.
//!
//! ## Режимы
//! 1. **Pipeline** (новый): каждая техника видит modified packet предыдущей.
//!    Фейковые сегменты → Split получает modified offsets.
//! 2. **Concurrent** (старый): каждая техника видит оригинальный пакет.
//!    Inject'ы накапливаются.
//!
//! ## DesyncOp трейт
//! Каждая техника реализует `DesyncOp::apply()` с типизированным стейтом.
//! Pipeline передаёт мутированный стейт по цепочке.

use crate::desync::{DesyncConfig, DesyncResult, DesyncTechnique};
use crate::desync::{ip, tcp, tls, http, quic, obfs, crypto};
use tracing::debug;

/// Стейт pipeline — передаётся между техниками.
#[derive(Debug, Clone)]
pub struct PipelineState {
    /// Текущий пакет (zero-copy через Bytes).
    pub packet: bytes::Bytes,
    /// Смещение TCP payload (для корректного пересчёта offsets).
    pub tcp_payload_offset: usize,
    /// Текущий TCP SEQ (для корректного пересчёта).
    pub tcp_seq: u32,
    /// Накопленные inject'ы (zero-copy).
    pub injects: Vec<bytes::Bytes>,
    /// Дропнуть пакет.
    pub drop: bool,
}

impl PipelineState {
    /// Создаёт начальный стейт из оригинального пакета.
    pub fn from_packet(packet: &[u8]) -> Self {
        let tcp_payload_offset = Self::find_tcp_payload_offset(packet);
        let tcp_seq = Self::extract_tcp_seq(packet);

        Self {
            packet: bytes::Bytes::copy_from_slice(packet),
            tcp_payload_offset,
            tcp_seq,
            injects: Vec::new(),
            drop: false,
        }
    }

    /// Определяет смещение TCP payload в пакете.
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

    /// Извлекает TCP SEQ из пакета.
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

    /// Конвертирует стейт в DesyncResult.
    pub fn into_result(self) -> DesyncResult {
        DesyncResult {
            modified: Some(self.packet),
            inject: self.injects,
            drop: self.drop,
        }
    }
}

/// Техника desync — применяется к стейту pipeline.
pub trait DesyncOp {
    /// Применяет технику к стейту.
    /// Может модифицировать `state.packet` и добавлять inject'ы.
    fn apply(&self, state: &mut PipelineState, config: &DesyncConfig);

    /// Вес техники (для определения тяжёлых операций).
    /// 0 = lightweight (TTL, window), 1 = medium (split), 2 = heavy (crypto).
    fn weight(&self) -> u8 {
        1
    }
}

/// DesyncGroup — применяет техники pipeline или concurrent.
#[derive(Clone)]
pub struct DesyncGroup {
    config: DesyncConfig,
    techniques: Vec<DesyncTechnique>,
    /// Pipeline mode: каждая техника видит modified packet.
    pipeline_mode: bool,
}

impl DesyncGroup {
    pub fn new(config: DesyncConfig) -> Self {
        Self {
            config,
            techniques: Vec::new(),
            pipeline_mode: false,
        }
    }

    pub fn default_set() -> Self {
        let mut group = Self::new(DesyncConfig::default());
        group.add(DesyncTechnique::FakeSni);
        group.add(DesyncTechnique::MultiSplit);
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

    /// Включает pipeline mode (каждая техника видит modified packet).
    pub fn set_pipeline_mode(&mut self, enabled: bool) {
        self.pipeline_mode = enabled;
    }

    /// Применяет все техники к пакету.
    pub fn apply(&self, packet: &bytes::Bytes) -> DesyncResult {
        if self.pipeline_mode {
            self.apply_pipeline(packet)
        } else {
            self.apply_concurrent(packet)
        }
    }

    /// Concurrent mode: каждая техника видит оригинальный пакет.
    fn apply_concurrent(&self, packet: &bytes::Bytes) -> DesyncResult {
        let mut result = DesyncResult::passthrough();
        for technique in &self.techniques {
            let r = self.apply_single(technique, packet);
            result.merge(r);
        }
        if !result.inject.is_empty() {
            debug!("DesyncGroup(concurrent): {} techniques → {} injects",
                self.techniques.len(), result.inject.len());
        }
        result
    }

    /// Pipeline mode: каждая техника видит modified packet предыдущей.
    fn apply_pipeline(&self, packet: &[u8]) -> DesyncResult {
        let mut state = PipelineState::from_packet(packet);

        for technique in &self.techniques {
            self.apply_to_state(technique, &mut state);
            if state.drop {
                break;
            }
        }

        if !state.injects.is_empty() {
            debug!("DesyncGroup(pipeline): {} techniques → {} injects",
                self.techniques.len(), state.injects.len());
        }

        state.into_result()
    }

    /// Применяет технику к pipeline state.
    fn apply_to_state(&self, technique: &DesyncTechnique, state: &mut PipelineState) {
        let c = &self.config;

        match technique {
            // === TCP ===
            DesyncTechnique::FakeSni => {
                let result = tcp::fake_sni(&state.packet, &c.fake_sni, c.fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::MultiSplit => {
                let result = tcp::multisplit(&state.packet, c.split_size, c.split_count, c.fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::MultiDisorder => {
                let result = tcp::multidisorder(&state.packet, c.split_size, c.split_count, c.fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::Disorder => {
                let result = tcp::disorder(&state.packet, c.split_size, c.fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::FakeDataSplit => {
                let result = tcp::fakedsplit(&state.packet, &c.fake_sni, c.fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::BadChecksum => {
                let result = ip::bad_checksum(&state.packet);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::TtlManipulation => {
                let result = ip::ttl_manipulation(&state.packet, 64);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::TlsRecordFrag => {
                let result = tls::tls_record_frag(&state.packet, 5, c.fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::SniMasking => {
                let result = tls::sni_masking(&state.packet, 0x41);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::RstDropIpId => {
                let result = ip::rst_drop_ip_id(&state.packet);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::DscpRandom => {
                let result = ip::dscp_random(&state.packet);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::TtlJitter => {
                let result = ip::ttl_jitter(&state.packet, None);
                self.merge_into_state(state, result);
            }
            _ => {
                // Остальные техники — concurrent fallback
                let result = self.apply_single(technique, &state.packet);
                self.merge_into_state(state, result);
            }
        }
    }

    /// Объединяет DesyncResult в PipelineState.
    fn merge_into_state(&self, state: &mut PipelineState, result: DesyncResult) {
        if let Some(modified) = result.modified {
            state.packet = modified;
            state.tcp_payload_offset = PipelineState::find_tcp_payload_offset(&state.packet);
            state.tcp_seq = PipelineState::extract_tcp_seq(&state.packet);
        }
        state.injects.extend(result.inject);
        if result.drop {
            state.drop = true;
        }
    }

    /// Применяет одну технику (concurrent mode).
    fn apply_single(&self, technique: &DesyncTechnique, packet: &bytes::Bytes) -> DesyncResult {
        let c = &self.config;
        match technique {
            DesyncTechnique::MultiSplit => tcp::multisplit(packet, c.split_size, c.split_count, c.fake_ttl_offset),
            DesyncTechnique::MultiDisorder => tcp::multidisorder(packet, c.split_size, c.split_count, c.fake_ttl_offset),
            DesyncTechnique::FakeDataSplit => tcp::fakedsplit(packet, &c.fake_sni, c.fake_ttl_offset),
            DesyncTechnique::TcpSeg => tcp::tcpseg(packet, c.max_seg_size, c.fake_ttl_offset),
            DesyncTechnique::SynData => tcp::syndata(packet, &c.fake_sni.as_bytes()[..4], c.fake_ttl_offset),
            DesyncTechnique::WinSize => tcp::winsize(packet, 1024),
            DesyncTechnique::SynHide => tcp::synhide(packet, c.fake_ttl_offset),
            DesyncTechnique::FakeSni => tcp::fake_sni(packet, &c.fake_sni, c.fake_ttl_offset),
            DesyncTechnique::OobInjection => tcp::oob_injection(packet, &c.fake_sni, c.fake_ttl_offset),
            DesyncTechnique::TcpPreopen => tcp::tcp_preopen(packet, c.fake_ttl_offset),
            DesyncTechnique::MssClamp => tcp::mss_clamp(packet, 536, c.fake_ttl_offset),
            DesyncTechnique::AckSuppress => tcp::ack_suppress(packet, 2, c.fake_ttl_offset),
            DesyncTechnique::PktReorder => tcp::pkt_reorder(packet, true),
            DesyncTechnique::RstSelective => tcp::rst_selective(packet, c.fake_ttl_offset),
            DesyncTechnique::SynFloodDecoy => tcp::syn_flood_decoy(packet, 5, &c.fake_sni, c.fake_ttl_offset),
            DesyncTechnique::WinScaleManip => tcp::win_scale_manip(packet, 1024, c.fake_ttl_offset),
            DesyncTechnique::Disorder => tcp::disorder(packet, c.split_size, c.fake_ttl_offset),
            DesyncTechnique::MultidisorderNew => tcp::multidisorder_new(packet, c.split_count, c.fake_ttl_offset),
            DesyncTechnique::Disoob => tcp::disoob(packet, c.fake_ttl_offset),
            DesyncTechnique::HostFake => tcp::hostfake(packet, &c.fake_sni, c.fake_ttl_offset),
            DesyncTechnique::FakeRst => tcp::fakerst(packet, c.fake_ttl_offset),
            DesyncTechnique::ByteByByte => tcp::byte_by_byte(packet, 10, c.fake_ttl_offset),
            DesyncTechnique::UnidirFrag => tcp::unidir_frag(packet, c.split_size, c.fake_ttl_offset),
            DesyncTechnique::PortShuffle => tcp::port_shuffle(packet),
            DesyncTechnique::Wclamp => tcp::wclamp(packet, 1024),
            DesyncTechnique::TsMd5 => tcp::ts_md5(packet, c.fake_ttl_offset),
            DesyncTechnique::FragOverlap => ip::frag_overlap(packet, &c.fake_sni, c.fake_ttl_offset),
            DesyncTechnique::BadChecksum => ip::bad_checksum(packet),
            DesyncTechnique::TtlManipulation => ip::ttl_manipulation(packet, 64),
            DesyncTechnique::IpFragPrimitives => ip::ip_frag_primitives(packet, c.split_size, c.fake_ttl_offset),
            DesyncTechnique::RstDropIpId => ip::rst_drop_ip_id(packet),
            DesyncTechnique::TtlJitter => ip::ttl_jitter(packet, None),
            DesyncTechnique::DscpRandom => ip::dscp_random(packet),
            DesyncTechnique::MutualSpoof => ip::mutual_spoof(packet),
            DesyncTechnique::TlsRecordFrag => tls::tls_record_frag(packet, 5, c.fake_ttl_offset),
            DesyncTechnique::TlsRecordPad => tls::tls_record_pad(packet, 32, c.fake_ttl_offset),
            DesyncTechnique::SniMicrofrag => tls::sni_microfrag(packet, 5, c.fake_ttl_offset),
            DesyncTechnique::SniMasking => tls::sni_masking(packet, 0x41),
            DesyncTechnique::H2SettingsFlood => http::h2_settings_flood(packet, 3, c.fake_ttl_offset),
            DesyncTechnique::H2RstPadding => http::h2_rst_padding(packet, c.fake_ttl_offset),
            DesyncTechnique::H2WindowUpdateFlood => http::h2_window_update_flood(packet, 2, c.fake_ttl_offset),
            DesyncTechnique::H2PriorityAbuse => http::h2_priority_abuse(packet, c.fake_ttl_offset),
            DesyncTechnique::H2Goaway => http::h2_goaway_inject(packet, 1, c.fake_ttl_offset),
            DesyncTechnique::ChunkObfuscation => http::chunk_obfuscation(packet, 3, c.fake_ttl_offset),
            DesyncTechnique::H2FrameOrdering => http::h2_frame_ordering(packet, c.fake_ttl_offset),
            DesyncTechnique::Http11Pipeline => http::http11_pipeline(packet, &c.fake_sni, c.fake_ttl_offset),
            DesyncTechnique::ContentLengthFuzz => http::content_length_fuzz(packet, 99999),
            DesyncTechnique::HttpUpgradeAbuse => http::http_upgrade_abuse(packet),
            DesyncTechnique::QuicBlocking => quic::quic_blocking(packet),
            DesyncTechnique::QuicVersionDowngrade => quic::quic_version_downgrade(packet, 0xFF00001D, c.fake_ttl_offset),
            DesyncTechnique::QuicRetryInject => quic::quic_retry_inject(packet, c.fake_ttl_offset),
            DesyncTechnique::QuicConnectionClose => quic::quic_connection_close(packet, 0x01, c.fake_ttl_offset),
            DesyncTechnique::QuicStreamReset => quic::quic_stream_reset(packet, c.fake_ttl_offset),
            DesyncTechnique::QuicMaxStreams => quic::quic_max_streams(packet, 100, c.fake_ttl_offset),
            DesyncTechnique::Udp2Icmp => obfs::udp2icmp(packet, c.fake_ttl_offset),
            DesyncTechnique::XorFirst => obfs::xor_first(packet, 4, 0xFF),
            DesyncTechnique::WgObfs => obfs::wg_obfs(packet, c.fake_ttl_offset),
            DesyncTechnique::ChaCha20 => {
                let key = [0x42u8; 32];
                crypto::chacha20_encrypt(packet, &key)
            }
            DesyncTechnique::ReverseFragmentOrder => {
                let result = tcp::multisplit(packet, c.split_size, c.split_count, c.fake_ttl_offset);
                tcp::reverse_fragment_order(result)
            }
            DesyncTechnique::HostFakeSplit => tcp::host_fake_split(packet, &c.fake_sni, c.fake_ttl_offset),
            DesyncTechnique::FakeDataDisorder => tcp::fake_data_disorder(packet, c.fake_sni.as_bytes(), c.fake_ttl_offset),
            DesyncTechnique::SynAckSplit => tcp::syn_ack_split(packet),
        }
    }
}

impl Default for DesyncGroup {
    fn default() -> Self {
        Self::default_set()
    }
}
