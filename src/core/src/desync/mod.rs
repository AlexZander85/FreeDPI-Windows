//! Desync Engine — DPI-bypass техники (ядро ByeDPI).
//!
//! ## Архитектура
//!
//! ```text
//! DesyncEngine (dispatcher)
//!   ├── TCP техники (tcp.rs)     — multisplit, multidisorder, fakedsplit, ...
//!   ├── IP техники (ip.rs)       — frag_overlap, badsum, ttl_manip, ...
//!   ├── TLS техники (tls.rs)     — tls_frag, record_padding, ...
//!   └── DesyncGroup (group.rs)   — pipeline применения нескольких техник
//! ```
//!
//! ## DesyncResult
//! Каждая техника возвращает:
//! - `modified` — изменённый оригинальный пакет (для WinDivert send)
//! - `inject` — дополнительные пакеты для инъекции (raw socket)
//!
//! ## Источники
//! - [zapret](https://github.com/bol-van/zapret) — TCP desync (Z1-Z10)
//! - [byedpi](https://github.com/hufrea/byedpi) — OOB, fake SNI (03-05)
//! - [dpibreak](https://github.com/hufrea/dpibreak) — W series
//! - [sni-spoofing-rust](https://github.com/HirbodBehnam/sni-spoofing-rust) — SEQ Spoof

pub mod group;
pub mod http;
pub mod ip;
pub mod obfs;
pub mod quic;
pub mod rand;
pub mod redirect_table;
pub mod segment_plan;
pub mod tcp;
pub mod tls;

use smallvec::{smallvec, SmallVec};

use pnet_packet::ip::IpNextHeaderProtocol;
use pnet_packet::ipv4::MutableIpv4Packet;
use pnet_packet::ipv6::MutableIpv6Packet;
use pnet_packet::MutablePacket;
use pnet_packet::Packet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Результат применения desync техники.
///
/// ## Single-copy
/// single-copy (kernel-mandated), zero-alloc steady-state.
/// SmallVec для inject: 95% техник делают ≤4 inject, inline без heap.
#[derive(Debug, Clone)]
pub struct DesyncResult {
    /// Модифицированный оригинальный пакет (для отправки через WinDivert).
    pub modified: Option<bytes::Bytes>,
    /// Дополнительные пакеты для инъекции.
    pub inject: SmallVec<[bytes::Bytes; 4]>,
    /// Задержка между инъекциями (мкс). 0 = без задержки.
    pub inter_delay_us: u32,
    /// Дропнуть пакет (не отправлять).
    pub drop: bool,
    /// T44.6: флаг что inject пакеты должны быть отправлены как outbound (от клиента к серверу).
    /// Устанавливается rst_selective (T11) — RST должен идти к серверу, не к клиенту.
    /// По умолчанию false (большинство injects идут как inbound от server perspective в WinDivert).
    pub is_outbound_inject: bool,
}

impl DesyncResult {
    pub fn passthrough() -> Self {
        Self {
            modified: None,
            inject: SmallVec::new(),
            inter_delay_us: 0,
            drop: false,
            is_outbound_inject: false,
        }
    }

    pub fn modified_only(modified: impl Into<bytes::Bytes>) -> Self {
        Self {
            modified: Some(modified.into()),
            inject: SmallVec::new(),
            inter_delay_us: 0,
            drop: false,
            is_outbound_inject: false,
        }
    }

    pub fn inject_only(inject: impl Into<bytes::Bytes>) -> Self {
        Self {
            modified: None,
            inject: smallvec![inject.into()],
            inter_delay_us: 0,
            drop: false,
            is_outbound_inject: false,
        }
    }

    pub fn modify_and_inject(
        modified: impl Into<bytes::Bytes>,
        inject: impl Into<bytes::Bytes>,
    ) -> Self {
        Self {
            modified: Some(modified.into()),
            inject: smallvec![inject.into()],
            inter_delay_us: 0,
            drop: false,
            is_outbound_inject: false,
        }
    }

    pub fn inject_many(inject: impl IntoIterator<Item = bytes::Bytes>) -> Self {
        Self {
            modified: None,
            inject: inject.into_iter().collect(),
            inter_delay_us: 0,
            drop: false,
            is_outbound_inject: false,
        }
    }

    pub fn drop_packet() -> Self {
        Self {
            modified: None,
            inject: SmallVec::new(),
            inter_delay_us: 0,
            drop: true,
            is_outbound_inject: false,
        }
    }

    /// Объединяет два результата с detection конфликтов.
    pub fn merge(&mut self, other: Self) {
        if other.modified.is_some() {
            if self.modified.is_some() {
                tracing::warn!("DesyncResult::merge: conflict — two techniques modified the packet, last writer wins");
            }
            self.modified = other.modified;
        }
        self.inject.extend(other.inject);
        if other.drop {
            self.drop = true;
        }
    }

    /// Modified как &[u8] (zero-copy через Deref).
    pub fn modified_slice(&self) -> Option<&[u8]> {
        self.modified.as_ref().map(|b| b.as_ref())
    }

    /// Inject как срез Bytes (zero-copy через Deref).
    pub fn inject_slices(&self) -> &[bytes::Bytes] {
        &self.inject
    }
}

/// Тип desync техники.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum DesyncTechnique {
    // === TCP (P0-P3) ===
    MultiSplit,
    MultiDisorder,
    HostFakeSplit,
    FakeDataSplit,
    FakeDataDisorder,
    TcpSeg,
    SynData,
    SynAckSplit,
    WinSize,
    SynHide,
    FakeSni,
    OobInjection,
    // === P3 TCP ===
    /// Устарел — ненадёжен в transparent proxy.
    /// Используйте `FakeSni` вместо него.
    #[deprecated(
        note = "TcpPreopen is unreliable in transparent proxy mode — use FakeSni instead"
    )]
    TcpPreopen,
    MssClamp,
    AckSuppress,
    PktReorder,
    RstSelective,
    SynFloodDecoy,
    WinScaleManip,
    Disorder,
    MultidisorderNew,
    Disoob,
    HostFake,
    FakeRst,
    ByteByByte,
    UnidirFrag,
    PortShuffle,
    Wclamp,
    TsMd5,
    SeqSpoof,
    // === IP ===
    FragOverlap,
    BadChecksum,
    TtlManipulation,
    IpFragPrimitives,
    RstDropIpId,
    DscpRandom,
    MutualSpoof,
    // === TLS ===
    TlsRecordFrag,
    TlsRecordPad,
    SniMasking,
    SniMicrofrag,
    TlsRecordRewrap,
    TlsVersionSpoof,
    SniRecordFrag,
    // === HTTP (P4) ===
    H2SettingsFlood,
    H2RstPadding,
    H2WindowUpdateFlood,
    H2PriorityAbuse,
    H2Goaway,
    ChunkObfuscation,
    H2FrameOrdering,
    Http11Pipeline,
    ContentLengthFuzz,
    HttpUpgradeAbuse,
    HttpCaseMix,
    // === QUIC (P5) ===
    QuicBlocking,
    QuicVersionDowngrade,
    QuicRetryInject,
    QuicConnectionClose,
    QuicStreamReset,
    QuicMaxStreams,
    // === Obfs/Crypto (P6) ===
    Udp2Icmp,
    XorFirst,
    WgObfs,
    ChaCha20,
    // === Composite ===
    ReverseFragmentOrder,
}

impl DesyncTechnique {
    pub fn name(&self) -> &'static str {
        match self {
            Self::MultiSplit => "MultiSplit",
            Self::MultiDisorder => "MultiDisorder",
            Self::HostFakeSplit => "HostFakeSplit",
            Self::FakeDataSplit => "FakeDataSplit",
            Self::FakeDataDisorder => "FakeDataDisorder",
            Self::TcpSeg => "TcpSeg",
            Self::SynData => "SynData",
            Self::SynAckSplit => "SynAckSplit",
            Self::WinSize => "WinSize",
            Self::SynHide => "SynHide",
            Self::FakeSni => "FakeSni",
            Self::OobInjection => "OobInjection",
            #[allow(deprecated)]
            Self::TcpPreopen => "TcpPreopen",
            Self::MssClamp => "MssClamp",
            Self::AckSuppress => "AckSuppress",
            Self::PktReorder => "PktReorder",
            Self::RstSelective => "RstSelective",
            Self::SynFloodDecoy => "SynFloodDecoy",
            Self::WinScaleManip => "WinScaleManip",
            Self::Disorder => "Disorder",
            Self::MultidisorderNew => "MultidisorderNew",
            Self::Disoob => "Disoob",
            Self::HostFake => "HostFake",
            Self::FakeRst => "FakeRst",
            Self::ByteByByte => "ByteByByte",
            Self::UnidirFrag => "UnidirFrag",
            Self::PortShuffle => "PortShuffle",
            Self::Wclamp => "Wclamp",
            Self::TsMd5 => "TsMd5",
            Self::SeqSpoof => "SeqSpoof",
            Self::FragOverlap => "FragOverlap",
            Self::BadChecksum => "BadChecksum",
            Self::TtlManipulation => "TtlManipulation",
            Self::IpFragPrimitives => "IpFragPrimitives",
            Self::RstDropIpId => "RstDropIpId",
            Self::DscpRandom => "DscpRandom",
            Self::MutualSpoof => "MutualSpoof",
            Self::TlsRecordFrag => "TlsRecordFrag",
            Self::TlsRecordPad => "TlsRecordPad",
            Self::SniMasking => "SniMasking",
            Self::SniMicrofrag => "SniMicrofrag",
            Self::TlsRecordRewrap => "TlsRecordRewrap",
            Self::TlsVersionSpoof => "TlsVersionSpoof",
            Self::SniRecordFrag => "SniRecordFrag",
            Self::H2SettingsFlood => "H2SettingsFlood",
            Self::H2RstPadding => "H2RstPadding",
            Self::H2WindowUpdateFlood => "H2WindowUpdateFlood",
            Self::H2PriorityAbuse => "H2PriorityAbuse",
            Self::H2Goaway => "H2Goaway",
            Self::ChunkObfuscation => "ChunkObfuscation",
            Self::H2FrameOrdering => "H2FrameOrdering",
            Self::Http11Pipeline => "Http11Pipeline",
            Self::ContentLengthFuzz => "ContentLengthFuzz",
            Self::HttpUpgradeAbuse => "HttpUpgradeAbuse",
            Self::HttpCaseMix => "HttpCaseMix",
            Self::QuicBlocking => "QuicBlocking",
            Self::QuicVersionDowngrade => "QuicVersionDowngrade",
            Self::QuicRetryInject => "QuicRetryInject",
            Self::QuicConnectionClose => "QuicConnectionClose",
            Self::QuicStreamReset => "QuicStreamReset",
            Self::QuicMaxStreams => "QuicMaxStreams",
            Self::Udp2Icmp => "Udp2Icmp",
            Self::XorFirst => "XorFirst",
            Self::WgObfs => "WgObfs",
            Self::ChaCha20 => "ChaCha20",
            Self::ReverseFragmentOrder => "ReverseFragmentOrder",
        }
    }

    pub fn source(&self) -> &'static str {
        match self {
            Self::MultiSplit => "zapret",
            Self::MultiDisorder => "zapret",
            Self::HostFakeSplit => "zapret",
            Self::FakeDataSplit => "zapret",
            Self::FakeDataDisorder => "zapret",
            Self::TcpSeg => "zapret",
            Self::SynData => "zapret",
            Self::SynAckSplit => "zapret",
            Self::WinSize => "zapret",
            Self::SynHide => "zapret",
            Self::FakeSni => "byedpi",
            Self::OobInjection => "byedpi",
            #[allow(deprecated)]
            Self::TcpPreopen => "byedpi",
            Self::MssClamp => "dpibreak",
            Self::AckSuppress => "dpibreak",
            Self::PktReorder => "dpibreak",
            Self::RstSelective => "dpibreak",
            Self::SynFloodDecoy => "dpibreak",
            Self::WinScaleManip => "dpibreak",
            Self::Disorder => "RIPDPI",
            Self::MultidisorderNew => "RIPDPI",
            Self::Disoob => "RIPDPI",
            Self::HostFake => "RIPDPI",
            Self::FakeRst => "RIPDPI",
            Self::ByteByByte => "rust-no-dpi-socks",
            Self::UnidirFrag => "rust-no-dpi-socks",
            Self::PortShuffle => "CandyTunnel",
            Self::Wclamp => "RIPDPI",
            Self::TsMd5 => "RIPDPI",
            Self::SeqSpoof => "sni-spoofing-rust",
            Self::FragOverlap => "dpibreak",
            Self::BadChecksum => "zapret",
            Self::TtlManipulation => "zapret",
            Self::IpFragPrimitives => "zapret",
            Self::RstDropIpId => "offveil",
            Self::DscpRandom => "CandyTunnel",
            Self::MutualSpoof => "CandyTunnel",
            Self::TlsRecordFrag => "zapret",
            Self::TlsRecordPad => "zapret",
            Self::SniMasking => "offveil",
            Self::SniMicrofrag => "omoikane",
            Self::TlsRecordRewrap => "greentunnel",
            Self::TlsVersionSpoof => "demergi",
            Self::SniRecordFrag => "nodpi",
            Self::H2SettingsFlood => "NaiveProxy",
            Self::H2RstPadding => "NaiveProxy",
            Self::H2WindowUpdateFlood => "NaiveProxy",
            Self::H2PriorityAbuse => "NaiveProxy",
            Self::H2Goaway => "NaiveProxy",
            Self::ChunkObfuscation => "b4",
            Self::H2FrameOrdering => "RIPDPI",
            Self::Http11Pipeline => "byedpi",
            Self::ContentLengthFuzz => "byedpi",
            Self::HttpUpgradeAbuse => "byedpi",
            Self::HttpCaseMix => "demergi",
            Self::QuicBlocking => "zapret",
            Self::QuicVersionDowngrade => "zapret",
            Self::QuicRetryInject => "zapret",
            Self::QuicConnectionClose => "zapret",
            Self::QuicStreamReset => "zapret",
            Self::QuicMaxStreams => "zapret",
            Self::Udp2Icmp => "zapret",
            Self::XorFirst => "dpimyass",
            Self::WgObfs => "zapret",
            Self::ChaCha20 => "CandyTunnel",
            Self::ReverseFragmentOrder => "offveil",
        }
    }

    pub fn category(&self) -> TechniqueCategory {
        match self {
            Self::MultiSplit
            | Self::MultiDisorder
            | Self::HostFakeSplit
            | Self::FakeDataSplit
            | Self::FakeDataDisorder
            | Self::TcpSeg
            | Self::SynData
            | Self::SynAckSplit
            | Self::WinSize
            | Self::SynHide
            | Self::FakeSni
            | Self::OobInjection
            | Self::MssClamp
            | Self::AckSuppress
            | Self::PktReorder
            | Self::RstSelective
            | Self::SynFloodDecoy
            | Self::WinScaleManip
            | Self::Disorder
            | Self::MultidisorderNew
            | Self::Disoob
            | Self::HostFake
            | Self::FakeRst
            | Self::ByteByByte
            | Self::UnidirFrag
            | Self::PortShuffle
            | Self::Wclamp
            | Self::TsMd5
            | Self::SeqSpoof => TechniqueCategory::Tcp,
            #[allow(deprecated)]
            Self::TcpPreopen => TechniqueCategory::Tcp,
            Self::FragOverlap
            | Self::BadChecksum
            | Self::TtlManipulation
            | Self::IpFragPrimitives
            | Self::RstDropIpId
            | Self::DscpRandom
            | Self::MutualSpoof
            | Self::ReverseFragmentOrder => TechniqueCategory::Ip,
            Self::TlsRecordFrag
            | Self::TlsRecordPad
            | Self::SniMasking
            | Self::SniMicrofrag
            | Self::TlsRecordRewrap
            | Self::TlsVersionSpoof
            | Self::SniRecordFrag => TechniqueCategory::Tls,
            Self::H2SettingsFlood
            | Self::H2RstPadding
            | Self::H2WindowUpdateFlood
            | Self::H2PriorityAbuse
            | Self::H2Goaway
            | Self::ChunkObfuscation
            | Self::H2FrameOrdering
            | Self::Http11Pipeline
            | Self::ContentLengthFuzz
            | Self::HttpUpgradeAbuse
            | Self::HttpCaseMix => TechniqueCategory::Http,
            Self::QuicBlocking
            | Self::QuicVersionDowngrade
            | Self::QuicRetryInject
            | Self::QuicConnectionClose
            | Self::QuicStreamReset
            | Self::QuicMaxStreams
            | Self::Udp2Icmp => TechniqueCategory::Quic,
            Self::XorFirst | Self::WgObfs => TechniqueCategory::Obfs,
            Self::ChaCha20 => TechniqueCategory::Crypto,
        }
    }
}

/// Категория desync техники.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TechniqueCategory {
    Tcp,
    Ip,
    Tls,
    Http,
    Quic,
    Obfs,
    Crypto,
}

/// Категория эффекта desync техники на пакет.
/// Используется для валидации композиции техник в DesyncGroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TechniqueEffect {
    /// Меняет только поля IP/TCP заголовка (TTL, DSCP, checksum, window).
    /// НЕ инвалидирует payload offset, SEQ, или длину.
    /// Безопасно комбинировать с любыми другими техниками.
    HeaderOnly,

    /// Меняет длину TCP payload (TlsRecordPad, ChunkObfuscation, ContentLengthFuzz).
    /// Инвалидирует все downstream split positions.
    InvalidatesPayloadLength,

    /// Меняет SEQ (inject с другим SEQ: FakeSni, SynData, SynFloodDecoy, PktReorder).
    /// Инвалидирует downstream SEQ-relative расчёты.
    InvalidatesSeq,

    /// Split-техника — режет payload на сегменты.
    /// Взаимоисключающая с другими Split техниками в одной группе.
    Split,
}

impl DesyncTechnique {
    /// Возвращает категорию эффекта техники на пакет.
    /// Используется DesyncGroup::validate() для проверки композиции.
    pub fn effect(&self) -> TechniqueEffect {
        match self {
            // HeaderOnly — меняют только заголовок
            Self::TtlManipulation
            | Self::DscpRandom
            | Self::BadChecksum
            | Self::MssClamp
            | Self::WinSize
            | Self::WinScaleManip
            | Self::Wclamp
            | Self::RstDropIpId
            | Self::TsMd5
            | Self::TlsVersionSpoof => TechniqueEffect::HeaderOnly,

            // InvalidatesPayloadLength — меняют длину payload
            Self::TlsRecordPad
            | Self::ChunkObfuscation
            | Self::ContentLengthFuzz
            | Self::H2SettingsFlood
            | Self::H2RstPadding
            | Self::H2WindowUpdateFlood
            | Self::H2PriorityAbuse
            | Self::H2Goaway
            | Self::QuicMaxStreams => TechniqueEffect::InvalidatesPayloadLength,

            // InvalidatesSeq — inject с другим SEQ (но не split)
            Self::FakeSni
            | Self::SynData
            | Self::SynAckSplit
            | Self::SynHide
            | Self::OobInjection
            | Self::AckSuppress
            | Self::RstSelective
            | Self::SynFloodDecoy
            | Self::FakeRst
            | Self::Disoob
            | Self::HostFake
            | Self::QuicRetryInject
            | Self::QuicConnectionClose
            | Self::QuicStreamReset
            | Self::SeqSpoof
            | Self::Udp2Icmp => TechniqueEffect::InvalidatesSeq,
            #[allow(deprecated)]
            Self::TcpPreopen => TechniqueEffect::InvalidatesSeq,

            // Split — режут payload, взаимоисключающие
            Self::MultiSplit
            | Self::MultiDisorder
            | Self::TcpSeg
            | Self::Disorder
            | Self::FakeDataSplit
            | Self::FakeDataDisorder
            | Self::HostFakeSplit
            | Self::SniRecordFrag
            | Self::TlsRecordFrag
            | Self::SniMicrofrag
            | Self::TlsRecordRewrap
            | Self::ByteByByte
            | Self::UnidirFrag
            | Self::PktReorder
            | Self::MultidisorderNew
            | Self::ReverseFragmentOrder
            | Self::FragOverlap
            | Self::IpFragPrimitives
            | Self::SniMasking
            | Self::QuicBlocking
            | Self::QuicVersionDowngrade => TechniqueEffect::Split,

            // Crypto/Obfs — меняют содержимое payload, но не длину.
            // Классифицируем как HeaderOnly для целей композиции
            // (они не инвалидируют split positions)
            Self::XorFirst
            | Self::WgObfs
            | Self::MutualSpoof
            | Self::PortShuffle
            | Self::H2FrameOrdering
            | Self::Http11Pipeline
            | Self::HttpUpgradeAbuse
            | Self::HttpCaseMix => TechniqueEffect::HeaderOnly,

            // Удалённые/отключённые техники — HeaderOnly (no-op)
            Self::ChaCha20 => TechniqueEffect::HeaderOnly,
        }
    }
}

/// Единая конфигурация Desync Engine.
#[derive(Debug, Clone)]
pub struct DesyncConfig {
    /// Fake SNI для инъекции
    pub fake_sni: std::sync::Arc<str>,
    /// Размер сплита (байт) — для split-техник
    pub split_size: usize,
    /// Количество сегментов для multisplit
    pub split_count: usize,
    /// Максимальный размер сегмента для TcpSeg
    pub max_seg_size: usize,
    /// Использовать bad checksum для fake пакетов
    pub bad_checksum: bool,
    /// TTL offset для fake пакетов (обычно 1 — на 1 меньше реального)
    pub fake_ttl_offset: u8,
    /// Задержка между инъекциями (мкс) — jitter перед forward
    pub inject_delay_us: u64,
    /// Задержка между отдельными inject пакетами (мкс). 0 = без задержки.
    pub inter_delay_us: u32,
    /// Количество PRNG вызовов между reseed'ами.
    pub reseed_interval: u64,
    /// Prebuilt fake ClientHello (lazily initialized).
    pub(crate) fake_ch_payload: std::sync::OnceLock<bytes::Bytes>,
}

impl DesyncConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.split_count == 0 {
            return Err(ConfigError::Invalid("split_count must be >= 1".into()));
        }
        if self.split_size == 0 {
            return Err(ConfigError::Invalid("split_size must be >= 1".into()));
        }
        if self.max_seg_size == 0 {
            return Err(ConfigError::Invalid("max_seg_size must be >= 1".into()));
        }
        if self.fake_sni.is_empty() || self.fake_sni.len() > 253 {
            return Err(ConfigError::Invalid(
                "fake_sni length must be in [1, 253]".into(),
            ));
        }
        Ok(())
    }

    pub fn fake_ch(&self) -> &bytes::Bytes {
        self.fake_ch_payload.get_or_init(|| {
            crate::adaptive::ch_gen::build_client_hello_default(&self.fake_sni).into()
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Invalid config: {0}")]
    Invalid(String),
}

impl Default for DesyncConfig {
    fn default() -> Self {
        Self {
            fake_sni: std::sync::Arc::from("www.google.com"),
            split_size: 1,
            split_count: 3,
            max_seg_size: 10,
            bad_checksum: false,
            fake_ttl_offset: 1,
            inject_delay_us: 1000,
            inter_delay_us: 0,
            reseed_interval: 8192,
            fake_ch_payload: std::sync::OnceLock::new(),
        }
    }
}

/// Вспомогательная функция: вычисляет IP checksum.
/// Корректно обрабатывает IP headers любой длины (включая IP options).
pub fn ipv4_checksum(header: &[u8]) -> u16 {
    debug_assert!(header.len() >= 20);
    let ihl = (header[0] & 0x0F) as usize * 4;
    let header = &header[..ihl.min(header.len())];
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    if !header.len().is_multiple_of(2) {
        sum += (header[header.len() - 1] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Вспомогательная функция: вычисляет TCP checksum (IPv4 или IPv6).
pub fn tcp_checksum(src: IpAddr, dst: IpAddr, segment: &[u8]) -> u16 {
    use pnet_packet::util;
    match (src, dst) {
        (IpAddr::V4(src_v4), IpAddr::V4(dst_v4)) => util::ipv4_checksum(
            segment,
            8,
            &[],
            &src_v4,
            &dst_v4,
            pnet_packet::ip::IpNextHeaderProtocols::Tcp,
        ),
        (IpAddr::V6(src_v6), IpAddr::V6(dst_v6)) => util::ipv6_checksum(
            segment,
            8,
            &[],
            &src_v6,
            &dst_v6,
            pnet_packet::ip::IpNextHeaderProtocols::Tcp,
        ),
        _ => 0, // разнородные пары V4/V6 не встречаются
    }
}

/// Вспомогательная функция: вычисляет UDP checksum (IPv4 или IPv6).
/// Для IPv4 checksum опционален (0 = отключён).
/// Для IPv6 checksum обязателен (RFC 2460 §8.1).
pub fn udp_checksum(src: IpAddr, dst: IpAddr, segment: &[u8]) -> u16 {
    use pnet_packet::util;
    match (src, dst) {
        (IpAddr::V4(src_v4), IpAddr::V4(dst_v4)) => util::ipv4_checksum(
            segment,
            8,
            &[],
            &src_v4,
            &dst_v4,
            pnet_packet::ip::IpNextHeaderProtocols::Udp,
        ),
        (IpAddr::V6(src_v6), IpAddr::V6(dst_v6)) => util::ipv6_checksum(
            segment,
            8,
            &[],
            &src_v6,
            &dst_v6,
            pnet_packet::ip::IpNextHeaderProtocols::Udp,
        ),
        _ => 0,
    }
}

/// Парсит IP header (IPv4 или IPv6).
pub fn parse_ip_header(packet: &[u8]) -> Option<ParsedIpHeader> {
    if packet.is_empty() {
        return None;
    }
    let version = packet[0] >> 4;
    match version {
        4 => {
            let ip = pnet_packet::ipv4::Ipv4Packet::new(packet)?;
            Some(ParsedIpHeader::V4(ParsedIpHeaderV4 {
                src: ip.get_source(),
                dst: ip.get_destination(),
                protocol: ip.get_next_level_protocol(),
                identification: ip.get_identification(),
                ttl: ip.get_ttl(),
                header_len: (ip.get_header_length() as usize) * 4,
                total_len: ip.get_total_length() as usize,
            }))
        }
        6 => {
            let v6 = parse_ipv6_header(packet)?;
            Some(ParsedIpHeader::V6(ParsedIpHeaderV6 {
                src: v6.src,
                dst: v6.dst,
                next_header: v6.protocol,
                hop_limit: v6.hop_limit,
                header_len: v6.header_len,
                total_len: v6.header_len + v6.payload_len,
                fragment_offset: v6.fragment_offset,
                fragment_identification: v6.fragment_identification,
                fragment_more: v6.fragment_more,
            }))
        }
        _ => None,
    }
}

/// Парсит IPv6 header с цепочкой extension headers (RFC 2460 §4).
///
/// Поддерживает:
/// - Hop-by-Hop Options (0)
/// - Routing (43)
/// - Fragment Header (44) — извлекает offset/identification/More
/// - Destination Options (60)
/// - ESP (50) / AH (51) — останавливает парсинг (зашифровано)
/// - No Next Header (59) — конец пакета
///
/// Возвращает `ParsedIpv6Header` с актуальным `header_len` (включая extension headers)
/// и `protocol` = реальный протокол (TCP, UDP, ICMPv6, ...).
pub fn parse_ipv6_header(packet: &[u8]) -> Option<ParsedIpv6Header> {
    let ip = pnet_packet::ipv6::Ipv6Packet::new(packet)?;
    let mut next_header = ip.get_next_header().0;
    let mut offset = 40; // start after fixed IPv6 header (40 bytes)
    let mut fragment_offset_units: Option<u16> = None;
    let mut fragment_identification: Option<u32> = None;
    let mut fragment_more: Option<bool> = None;

    // Parse extension headers chain (RFC 2460 §4)
    loop {
        match next_header {
            0 | 43 | 60 => {
                // Hop-by-Hop / Routing / Destination Options
                // Format: next_header(1) + header_ext_len(1) + options(...)
                // header_ext_len is in 8-byte units, NOT including the first 8 bytes
                if offset + 2 > packet.len() {
                    break;
                }
                let ext_next = packet[offset];
                let ext_len = packet[offset + 1] as usize;
                let ext_total = (ext_len + 1) * 8; // +1 because length doesn't include first 8 bytes
                if offset + ext_total > packet.len() {
                    break;
                }
                offset += ext_total;
                next_header = ext_next;
            }
            44 => {
                // Fragment Header (RFC 2460 §4.5) — fixed 8 bytes
                // Format: next_header(1) + reserved(1) + fragment_offset(13bits)+res(2bits)+M(1bit) (2) + identification(4)
                if offset + 8 > packet.len() {
                    break;
                }
                let frag_next = packet[offset];
                let frag_field = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
                fragment_offset_units = Some(frag_field >> 3); // 13 bits
                fragment_more = Some((frag_field & 0x01) != 0);
                fragment_identification = Some(u32::from_be_bytes([
                    packet[offset + 4],
                    packet[offset + 5],
                    packet[offset + 6],
                    packet[offset + 7],
                ]));
                offset += 8;
                next_header = frag_next;
            }
            50 | 51 => {
                // ESP / AH — skip (encrypted/authenticated, can't parse further)
                break;
            }
            59 => {
                // No Next Header — packet ends here
                break;
            }
            _ => {
                // Terminal protocol (TCP=6, UDP=17, ICMPv6=58, etc.)
                break;
            }
        }
    }

    Some(ParsedIpv6Header {
        src: ip.get_source(),
        dst: ip.get_destination(),
        protocol: pnet_packet::ip::IpNextHeaderProtocol(next_header),
        hop_limit: ip.get_hop_limit(),
        header_len: offset, // actual offset including extension headers
        payload_len: packet.len().saturating_sub(offset),
        fragment_offset: fragment_offset_units,
        fragment_identification,
        fragment_more,
    })
}

/// Распарсенный IP header (IPv4 или IPv6).
#[derive(Debug, Clone)]
pub enum ParsedIpHeader {
    V4(ParsedIpHeaderV4),
    V6(ParsedIpHeaderV6),
}

/// Поля IPv4-заголовка.
#[derive(Debug, Clone)]
pub struct ParsedIpHeaderV4 {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: IpNextHeaderProtocol,
    pub identification: u16,
    pub ttl: u8,
    pub header_len: usize,
    pub total_len: usize,
}

/// Поля IPv6-заголовка (no identification, no header checksum).
#[derive(Debug, Clone)]
pub struct ParsedIpHeaderV6 {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub next_header: IpNextHeaderProtocol,
    pub hop_limit: u8,
    pub header_len: usize,
    pub total_len: usize,
    /// Fragment offset in 8-byte units (если есть Fragment Header)
    pub fragment_offset: Option<u16>,
    /// Fragment identification (если есть Fragment Header)
    pub fragment_identification: Option<u32>,
    /// More fragments flag (если есть Fragment Header)
    pub fragment_more: Option<bool>,
}

/// Полный распарсенный IPv6 заголовок с extension headers.
#[derive(Debug, Clone)]
pub struct ParsedIpv6Header {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub protocol: IpNextHeaderProtocol,
    pub hop_limit: u8,
    pub header_len: usize,
    pub payload_len: usize,
    /// Fragment offset in 8-byte units (если есть Fragment Header)
    pub fragment_offset: Option<u16>,
    /// Fragment identification (если есть Fragment Header)
    pub fragment_identification: Option<u32>,
    /// More fragments flag (если есть Fragment Header)
    pub fragment_more: Option<bool>,
}

impl ParsedIpHeader {
    pub fn src(&self) -> IpAddr {
        match self {
            ParsedIpHeader::V4(v4) => IpAddr::V4(v4.src),
            ParsedIpHeader::V6(v6) => IpAddr::V6(v6.src),
        }
    }
    pub fn dst(&self) -> IpAddr {
        match self {
            ParsedIpHeader::V4(v4) => IpAddr::V4(v4.dst),
            ParsedIpHeader::V6(v6) => IpAddr::V6(v6.dst),
        }
    }
    pub fn protocol(&self) -> IpNextHeaderProtocol {
        match self {
            ParsedIpHeader::V4(v4) => v4.protocol,
            ParsedIpHeader::V6(v6) => v6.next_header,
        }
    }
    /// Identification (IPv4: реальное значение; IPv6: 0 — нет фиксированного поля ID).
    pub fn identification(&self) -> u16 {
        match self {
            ParsedIpHeader::V4(v4) => v4.identification,
            ParsedIpHeader::V6(_) => 0,
        }
    }
    /// TTL (IPv4) / Hop Limit (IPv6).
    pub fn ttl(&self) -> u8 {
        match self {
            ParsedIpHeader::V4(v4) => v4.ttl,
            ParsedIpHeader::V6(v6) => v6.hop_limit,
        }
    }
    /// Длина IP заголовка (IPv4: IHL*4; IPv6: 40 + extension headers).
    pub fn header_len(&self) -> usize {
        match self {
            ParsedIpHeader::V4(v4) => v4.header_len,
            ParsedIpHeader::V6(v6) => v6.header_len,
        }
    }
    pub fn total_len(&self) -> usize {
        match self {
            ParsedIpHeader::V4(v4) => v4.total_len,
            ParsedIpHeader::V6(v6) => v6.total_len,
        }
    }
}

/// Парсит TCP пакет (payload после IP header).
pub fn parse_tcp_packet(packet: &[u8]) -> Option<ParsedTcpPacket<'_>> {
    let tcp = pnet_packet::tcp::TcpPacket::new(packet)?;
    let data_offset = tcp.get_data_offset() as usize * 4;
    Some(ParsedTcpPacket {
        src_port: tcp.get_source(),
        dst_port: tcp.get_destination(),
        sequence: tcp.get_sequence(),
        acknowledgment: tcp.get_acknowledgement(),
        flags: tcp.get_flags(),
        window: tcp.get_window(),
        data_offset,
        payload: packet.get(data_offset..)?,
        urg_ptr: tcp.get_urgent_ptr(),
    })
}

/// Распарсенный TCP packet (payload без IP header).
#[derive(Debug, Clone)]
pub struct ParsedTcpPacket<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub sequence: u32,
    pub acknowledgment: u32,
    pub flags: u8,
    pub window: u16,
    pub data_offset: usize,
    pub payload: &'a [u8],
    pub urg_ptr: u16,
}

/// Строит новый IP пакет (IPv4 или IPv6).
pub fn build_ip_packet(
    src: IpAddr,
    dst: IpAddr,
    protocol: IpNextHeaderProtocol,
    ttl: u8,
    identification: u16,
    payload: &[u8],
) -> bytes::Bytes {
    match (src, dst) {
        (IpAddr::V4(src_v4), IpAddr::V4(dst_v4)) => {
            let total_len = 20 + payload.len();
            let mut buf = bytes::BytesMut::with_capacity(total_len);
            buf.resize(total_len, 0);

            {
                let mut ip = MutableIpv4Packet::new(&mut buf).unwrap();
                ip.set_version(4);
                ip.set_header_length(5);
                ip.set_total_length(total_len as u16);
                ip.set_identification(identification);
                ip.set_flags(0);
                ip.set_fragment_offset(0);
                ip.set_ttl(ttl);
                ip.set_next_level_protocol(protocol);
                ip.set_source(src_v4);
                ip.set_destination(dst_v4);
                ip.payload_mut().copy_from_slice(payload);
            }

            let checksum = ipv4_checksum(&buf[..20]);
            buf[10..12].copy_from_slice(&checksum.to_be_bytes());
            buf.freeze()
        }
        (IpAddr::V6(src_v6), IpAddr::V6(dst_v6)) => {
            let total_len = 40 + payload.len();
            let mut buf = bytes::BytesMut::with_capacity(total_len);
            buf.resize(total_len, 0);

            {
                let mut ip = MutableIpv6Packet::new(&mut buf).unwrap();
                ip.set_version(6);
                ip.set_traffic_class(0);
                ip.set_flow_label(0);
                ip.set_payload_length(payload.len() as u16);
                ip.set_next_header(protocol);
                ip.set_hop_limit(ttl);
                ip.set_source(src_v6);
                ip.set_destination(dst_v6);
                ip.payload_mut().copy_from_slice(payload);
            }

            buf.freeze()
        }
        _ => {
            // Разнородные V4/V6 — невалидная комбинация, строим V4 с нулевыми адресами
            tracing::warn!("build_ip_packet: mixed V4/V6 src/dst, using V4 fallback");
            let total_len = 20 + payload.len();
            let mut buf = bytes::BytesMut::with_capacity(total_len);
            buf.resize(total_len, 0);
            let mut ip = MutableIpv4Packet::new(&mut buf).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length(total_len as u16);
            ip.set_identification(identification);
            ip.set_flags(0);
            ip.set_fragment_offset(0);
            ip.set_ttl(ttl);
            ip.set_next_level_protocol(protocol);
            ip.payload_mut().copy_from_slice(payload);
            let checksum = ipv4_checksum(&buf[..20]);
            buf[10..12].copy_from_slice(&checksum.to_be_bytes());
            buf.freeze()
        }
    }
}

/// Incremental IP/TCP checksum update для одного 16-bit слова.
/// RFC 1624: HC' = HC - ~m_old + ~m_new
#[inline(always)]
pub fn update_checksum_word(old_csum: u16, old_word: u16, new_word: u16) -> u16 {
    let mut sum = (!old_csum) as u32;
    sum = sum.wrapping_sub(!old_word as u32);
    sum = sum.wrapping_add(!new_word as u32);
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Incremental update для 32-bit поля (SEQ, ACK).
#[inline(always)]
pub fn update_checksum_dword(old_csum: u16, old_dword: u32, new_dword: u32) -> u16 {
    let old_hi = (old_dword >> 16) as u16;
    let old_lo = (old_dword & 0xFFFF) as u16;
    let new_hi = (new_dword >> 16) as u16;
    let new_lo = (new_dword & 0xFFFF) as u16;
    let csum = update_checksum_word(old_csum, old_hi, new_hi);
    update_checksum_word(csum, old_lo, new_lo)
}

/// Rewrites destination IP and Port, recalculating IP and TCP checksums.
/// Also decrements TTL/Hop Limit by 1 for loop prevention.
pub fn rewrite_dst_addr(
    packet_data: &[u8],
    new_dst_ip: IpAddr,
    new_dst_port: u16,
) -> anyhow::Result<bytes::Bytes> {
    let mut buf = bytes::BytesMut::from(packet_data);
    let mut ip_hdr = parse_ip_header(&buf).ok_or_else(|| anyhow::anyhow!("Invalid IP header"))?;
    let ip_hdr_len = ip_hdr.header_len();

    // 1. Update Destination IP and TTL/Hop Limit in IP Header
    match &mut ip_hdr {
        ParsedIpHeader::V4(_) => {
            if let IpAddr::V4(new_ip) = new_dst_ip {
                let mut ip_pkt = MutableIpv4Packet::new(&mut buf[..ip_hdr_len]).unwrap();
                ip_pkt.set_destination(new_ip);
                let new_ttl = ip_pkt.get_ttl().saturating_sub(1);
                ip_pkt.set_ttl(new_ttl);
                // Recalculate IPv4 Checksum
                ip_pkt.set_checksum(0);
                let csum = ipv4_checksum(ip_pkt.packet());
                ip_pkt.set_checksum(csum);
            }
        }
        ParsedIpHeader::V6(_) => {
            if let IpAddr::V6(new_ip) = new_dst_ip {
                let mut ip_pkt = MutableIpv6Packet::new(&mut buf[..ip_hdr_len]).unwrap();
                ip_pkt.set_destination(new_ip);
                let new_hl = ip_pkt.get_hop_limit().saturating_sub(1);
                ip_pkt.set_hop_limit(new_hl);
            }
        }
    }

    // 2. Update Destination Port in TCP Header
    {
        let mut tcp_pkt = pnet_packet::tcp::MutableTcpPacket::new(&mut buf[ip_hdr_len..])
            .ok_or_else(|| anyhow::anyhow!("Invalid TCP header"))?;
        tcp_pkt.set_destination(new_dst_port);
        // Recalculate TCP Checksum (includes Pseudo-Header)
        tcp_pkt.set_checksum(0);
    }

    let new_tcp_csum = tcp_checksum(ip_hdr.src(), new_dst_ip, &buf[ip_hdr_len..]);
    let mut tcp_pkt = pnet_packet::tcp::MutableTcpPacket::new(&mut buf[ip_hdr_len..]).unwrap();
    tcp_pkt.set_checksum(new_tcp_csum);

    Ok(buf.freeze())
}

/// Rewrites source IP and Port, recalculating IP and TCP checksums (for return path).
/// Also decrements TTL/Hop Limit by 1 for loop prevention.
pub fn rewrite_src_addr(
    packet_data: &[u8],
    new_src_ip: IpAddr,
    new_src_port: u16,
) -> anyhow::Result<bytes::Bytes> {
    let mut buf = bytes::BytesMut::from(packet_data);
    let mut ip_hdr = parse_ip_header(&buf).ok_or_else(|| anyhow::anyhow!("Invalid IP header"))?;
    let ip_hdr_len = ip_hdr.header_len();

    // 1. Update Source IP and TTL/Hop Limit in IP Header
    match &mut ip_hdr {
        ParsedIpHeader::V4(_) => {
            if let IpAddr::V4(new_ip) = new_src_ip {
                let mut ip_pkt = MutableIpv4Packet::new(&mut buf[..ip_hdr_len]).unwrap();
                ip_pkt.set_source(new_ip);
                let new_ttl = ip_pkt.get_ttl().saturating_sub(1);
                ip_pkt.set_ttl(new_ttl);
                // Recalculate IPv4 Checksum
                ip_pkt.set_checksum(0);
                let csum = ipv4_checksum(ip_pkt.packet());
                ip_pkt.set_checksum(csum);
            }
        }
        ParsedIpHeader::V6(_) => {
            if let IpAddr::V6(new_ip) = new_src_ip {
                let mut ip_pkt = MutableIpv6Packet::new(&mut buf[..ip_hdr_len]).unwrap();
                ip_pkt.set_source(new_ip);
                let new_hl = ip_pkt.get_hop_limit().saturating_sub(1);
                ip_pkt.set_hop_limit(new_hl);
            }
        }
    }

    // 2. Update Source Port in TCP Header
    {
        let mut tcp_pkt = pnet_packet::tcp::MutableTcpPacket::new(&mut buf[ip_hdr_len..])
            .ok_or_else(|| anyhow::anyhow!("Invalid TCP header"))?;
        tcp_pkt.set_source(new_src_port);
        // Recalculate TCP Checksum
        tcp_pkt.set_checksum(0);
    }

    let new_tcp_csum = tcp_checksum(new_src_ip, ip_hdr.dst(), &buf[ip_hdr_len..]);
    let mut tcp_pkt = pnet_packet::tcp::MutableTcpPacket::new(&mut buf[ip_hdr_len..]).unwrap();
    tcp_pkt.set_checksum(new_tcp_csum);

    Ok(buf.freeze())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet_packet::ipv4::Ipv4Packet;
    use pnet_packet::tcp::TcpPacket;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_address_rewriting() {
        // Construct a dummy IPv4 TCP packet
        let mut pkt_data = vec![0u8; 40]; // 20 bytes IP, 20 bytes TCP

        {
            let mut ip = MutableIpv4Packet::new(&mut pkt_data[..20]).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length(40);
            ip.set_ttl(64);
            ip.set_next_level_protocol(pnet_packet::ip::IpNextHeaderProtocols::Tcp);
            ip.set_source(Ipv4Addr::new(192, 168, 1, 10));
            ip.set_destination(Ipv4Addr::new(8, 8, 8, 8));
            ip.set_checksum(ipv4_checksum(ip.packet()));
        }

        {
            let mut tcp = pnet_packet::tcp::MutableTcpPacket::new(&mut pkt_data[20..]).unwrap();
            tcp.set_source(12345);
            tcp.set_destination(80);
            tcp.set_flags(0x02); // SYN
            let csum = tcp_checksum(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                tcp.packet(),
            );
            tcp.set_checksum(csum);
        }

        // Test rewrite_dst_addr
        let dst_rewritten =
            rewrite_dst_addr(&pkt_data, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 17650).unwrap();

        let ip_rewritten = Ipv4Packet::new(&dst_rewritten[..20]).unwrap();
        assert_eq!(ip_rewritten.get_destination(), Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(ip_rewritten.get_ttl(), 63); // decremented by 1

        let tcp_rewritten = TcpPacket::new(&dst_rewritten[20..]).unwrap();
        assert_eq!(tcp_rewritten.get_destination(), 17650);

        // Test rewrite_src_addr
        let src_rewritten =
            rewrite_src_addr(&dst_rewritten, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 80).unwrap();

        let ip_src_rewritten = Ipv4Packet::new(&src_rewritten[..20]).unwrap();
        assert_eq!(ip_src_rewritten.get_source(), Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(ip_src_rewritten.get_ttl(), 62); // decremented by 1

        let tcp_src_rewritten = TcpPacket::new(&src_rewritten[20..]).unwrap();
        assert_eq!(tcp_src_rewritten.get_source(), 80);
    }
}
