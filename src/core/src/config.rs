//! Configuration — загрузка, валидация и хранение конфигурации.

pub mod rule_override;

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::debug;

/// Режим работы приложения.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppMode {
    /// Полноценный сервис с API
    #[default]
    Service,
    /// Только CLI, без сервиса
    Cli,
}

/// Режим раздельного туннелирования.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SplitModeConfig {
    WhitelistOnly,
    #[default]
    BlacklistOnly,
    Auto,
}

/// Конфигурация DNS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// DoH сервер (Cloudflare по умолчанию)
    #[serde(default = "default_doh_url")]
    pub doh_url: String,
    /// DoT сервер
    #[serde(default = "default_dot_addr")]
    pub dot_addr: String,
    /// TTL кэша в секундах
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl: u64,
    /// Использовать persistent HTTP/2 для DoH (повторное использование сессии)
    #[serde(default = "default_true")]
    pub doh_persistent: bool,
    /// IP overrides для DNS: CIDR → IP (формат: "1.2.3.0/24=5.6.7.8")
    #[serde(default)]
    pub dns_ip_overrides: Vec<String>,
    /// SPKI hashes для certificate pinning DoH серверов (base64 SHA256)
    #[serde(default)]
    pub doh_pins: Vec<String>,
}

fn default_doh_url() -> String {
    "https://cloudflare-dns.com/dns-query".to_string()
}
fn default_dot_addr() -> String {
    "1.1.1.1:853".to_string()
}
fn default_cache_ttl() -> u64 {
    300
}

/// Конфигурация HTTP API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Порт API сервера (только localhost)
    #[serde(default = "default_api_port")]
    pub port: u16,
    /// API ключ для аутентификации
    #[serde(default = "default_api_key")]
    pub api_key: String,
    /// Включить API
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_api_port() -> u16 {
    11337
}
fn default_api_key() -> String {
    let key = uuid::Uuid::new_v4().to_string();
    debug!("Generated new API key: {}", key);
    key
}
fn default_true() -> bool {
    true
}

/// Конфигурация WinDivert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindivertConfig {
    /// Filter string
    #[serde(default = "default_filter")]
    pub filter: String,
    /// Queue length (packets)
    #[serde(default = "default_queue_len")]
    pub queue_length: u32,
    /// Queue time (ms)
    #[serde(default = "default_queue_time")]
    pub queue_time: u32,
}

/// Настройки сетевого тюнинга (RSS, Chimney, ECN)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTuningConfig {
    #[serde(default = "default_true")]
    pub disable_chimney: bool,
    #[serde(default = "default_true")]
    pub disable_ecn: bool,
    #[serde(default = "default_false")]
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

fn default_false() -> bool {
    false
}

pub fn default_filter() -> String {
    "(ip or ipv6) && ( \
        (outbound && tcp.DstPort == 443 && tcp.PayloadLength > 5 \
            && tcp.Payload[0] == 0x16 && tcp.Payload[1] == 0x03 && tcp.Payload[5] == 0x01) \
        or udp.DstPort == 53 \
        or udp.DstPort == 443 \
    )"
    .to_string()
}
fn default_queue_len() -> u32 {
    8192
}
fn default_queue_time() -> u32 {
    2000
}

/// Полная конфигурация приложения.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Режим работы
    #[serde(default)]
    pub mode: AppMode,
    /// Режим split tunnel
    #[serde(default)]
    pub split_mode: SplitModeConfig,
    /// DNS настройки
    #[serde(default)]
    pub dns: DnsConfig,
    /// API настройки
    #[serde(default)]
    pub api: ApiConfig,
    /// WinDivert настройки
    #[serde(default)]
    pub windivert: WindivertConfig,
    /// Путь к файлам списков
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// Количество потоков rayon (0 = все ядра)
    #[serde(default)]
    pub cpu_threads: usize,
    /// Desync настройки (техники, параметры)
    #[serde(default)]
    pub desync: DesyncSection,
    /// T57: Пользовательские профили стратегий из TOML [[strategies]] секции
    #[serde(default)]
    pub strategies: Vec<StrategyProfileConfig>,
    /// T60: Настройки SOCKS5 прокси и списков доменов
    #[serde(default)]
    pub proxy: ProxyConfig,
    /// T60: Adaptive Multi-Path Router config
    #[serde(default)]
    pub adaptive_router: crate::routing::adaptive_router::AdaptiveRouterConfig,
    /// T63: Zero-Config Whitelist Bypass config
    #[serde(default)]
    pub zero_config: ZeroConfigConfig,
    /// AmneziaWG configuration
    #[serde(default)]
    pub awg: AwgConfig,
    /// T64: Network tuning (ECN, Chimney, RSS)
    #[serde(default)]
    pub network_tuning: NetworkTuningConfig,
}

/// Desync секция конфигурации.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesyncSection {
    /// Fake SNI для инъекции
    #[serde(default = "default_fake_sni")]
    pub fake_sni: String,
    /// Размер сплита (байт)
    #[serde(default)]
    pub split_size: usize,
    /// Количество сегментов
    #[serde(default = "default_split_count")]
    pub split_count: usize,
    /// TTL offset для fake пакетов
    #[serde(default = "default_fake_ttl_offset")]
    pub fake_ttl_offset: u8,
    /// Задержка между инъекциями (мкс)
    #[serde(default = "default_inject_delay")]
    pub inject_delay_us: u64,
    /// Техники (пусто = default set: FakeSni + MultiSplit + BadChecksum)
    #[serde(default)]
    pub techniques: Vec<String>,
    /// TTL значение для TtlManipulation
    #[serde(default = "default_ttl_value")]
    pub ttl_value: u8,
    /// Разрешить TtlManipulation на реальных пакетах
    #[serde(default)]
    pub allow_real_ttl_manipulation: bool,
    /// Разрешить BadChecksum на реальных пакетах (разрушительная манипуляция)
    #[serde(default)]
    pub allow_destructive_manipulation: bool,
    /// Политика фолбэка для QUIC
    #[serde(default)]
    pub quic_fallback_policy: crate::desync::QuicFallbackPolicy,
}

fn default_ttl_value() -> u8 {
    64
}

fn default_fake_sni() -> String {
    "www.google.com".to_string()
}
fn default_split_count() -> usize {
    3
}
fn default_fake_ttl_offset() -> u8 {
    1
}
fn default_inject_delay() -> u64 {
    1000
}

impl Default for DesyncSection {
    fn default() -> Self {
        Self {
            fake_sni: default_fake_sni(),
            split_size: 1,
            split_count: default_split_count(),
            fake_ttl_offset: default_fake_ttl_offset(),
            inject_delay_us: default_inject_delay(),
            techniques: Vec::new(),
            ttl_value: default_ttl_value(),
            allow_real_ttl_manipulation: false,
            allow_destructive_manipulation: false,
            quic_fallback_policy: crate::desync::QuicFallbackPolicy::default(),
        }
    }
}

fn default_data_dir() -> PathBuf {
    let path = PathBuf::from("data");
    // Try to find data dir relative to executable
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let exe_path = parent.join("data");
            if exe_path.exists() {
                return exe_path;
            }
        }
    }
    path
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: AppMode::Service,
            split_mode: SplitModeConfig::BlacklistOnly,
            dns: DnsConfig::default(),
            api: ApiConfig::default(),
            windivert: WindivertConfig::default(),
            data_dir: default_data_dir(),
            cpu_threads: 0,
            desync: DesyncSection::default(),
            strategies: Vec::new(),
            proxy: ProxyConfig::default(),
            adaptive_router: crate::routing::adaptive_router::AdaptiveRouterConfig::default(),
            zero_config: ZeroConfigConfig::default(),
            awg: AwgConfig::default(),
            network_tuning: NetworkTuningConfig::default(),
        }
    }
}

impl Config {
    /// Конвертирует Config в ProcessingConfig для engine.
    pub fn to_processing_config(&self) -> crate::engine::ProcessingConfig {
        use crate::desync::{DesyncConfig, DesyncTechnique};

        let desync_config = DesyncConfig {
            fake_sni: std::sync::Arc::from(self.desync.fake_sni.as_str()),
            split_size: self.desync.split_size,
            split_count: self.desync.split_count,
            max_seg_size: 10,
            bad_checksum: false,
            fake_ttl_offset: self.desync.fake_ttl_offset,
            inject_delay_us: self.desync.inject_delay_us,
            inter_delay_us: 0,
            reseed_interval: 8192,
            ttl_value: self.desync.ttl_value,
            allow_real_ttl_manipulation: self.desync.allow_real_ttl_manipulation,
            allow_destructive_manipulation: self.desync.allow_destructive_manipulation,
            quic_fallback_policy: self.desync.quic_fallback_policy,
            ..Default::default()
        };

        let techniques: Vec<DesyncTechnique> = self
            .desync
            .techniques
            .iter()
            .filter_map(|name| parse_technique(name))
            .collect();

        crate::engine::ProcessingConfig {
            seq_spoof_enabled: true,
            fake_sni: std::sync::Arc::from(self.desync.fake_sni.as_str()),
            hop_tab_enabled: true,
            geo_routing_enabled: true,
            desync_port: 443,
            only_outbound: true,
            stats_print_interval: std::time::Duration::from_secs(60),
            desync: desync_config,
            techniques,
            strategies: self.strategies.clone(),
            proxy_config: self.proxy.clone(),
            dns_config: self.dns.clone(),
            adaptive_router_config: self.adaptive_router.clone(),
            zero_config: self.zero_config.clone(),
            awg: self.awg.clone(),
            network_tuning: self.network_tuning.clone(),
            capture_budget: crate::capture_budget::CaptureBudgetConfig::default(),
        }
    }
}

fn parse_technique(name: &str) -> Option<crate::desync::DesyncTechnique> {
    parse_technique_name(name)
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            doh_url: default_doh_url(),
            dot_addr: default_dot_addr(),
            cache_ttl: default_cache_ttl(),
            doh_persistent: true,
            dns_ip_overrides: Vec::new(),
            doh_pins: Vec::new(),
        }
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            port: default_api_port(),
            api_key: default_api_key(),
            enabled: true,
        }
    }
}

impl Default for WindivertConfig {
    fn default() -> Self {
        Self {
            filter: default_filter(),
            queue_length: default_queue_len(),
            queue_time: default_queue_time(),
        }
    }
}

impl Config {
    /// Загружает конфигурацию из файла.
    /// Если файл не существует — создаёт с настройками по умолчанию.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            let config: Config = toml::from_str(&content)?;
            debug!("Config loaded from {}", path.display());
            Ok(config)
        } else {
            let config = Config::default();
            config.save(path)?;
            debug!("Default config saved to {}", path.display());
            Ok(config)
        }
    }

    /// Сохраняет конфигурацию в файл.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        debug!("Config saved to {}", path.display());
        Ok(())
    }

    /// Создаёт конфиг из TOML строки (для тестов).
    pub fn from_toml(toml_str: &str) -> anyhow::Result<Self> {
        Ok(toml::from_str(toml_str)?)
    }
}

/// T57: Пользовательский профиль стратегии из TOML [[strategies]] секции.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyProfileConfig {
    /// Имя профиля (уникальное).
    pub name: String,
    /// Протокол: "tls", "http", "quic", "dns", "tcp".
    pub protocol: String,
    /// Список техник по имени (строка → DesyncTechnique).
    /// Пустой список = routing-only профиль (dns_doh, socks5_fallback).
    #[serde(default)]
    pub techniques: Vec<String>,
    /// Параметры по умолчанию.
    #[serde(default)]
    pub split_size: Option<usize>,
    #[serde(default)]
    pub split_count: Option<usize>,
    #[serde(default)]
    pub fake_ttl_offset: Option<u8>,
    #[serde(default)]
    pub max_seg_size: Option<usize>,
    /// Устанавливает данный профиль как дефолтный для категории.
    #[serde(default)]
    pub default: Option<bool>,
    /// Предварительно активирует профиль при запуске.
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// T57: Парсит строку в DesyncTechnique.
/// Возвращает None если имя не распознано.
#[allow(deprecated)]
pub fn parse_technique_name(name: &str) -> Option<crate::desync::DesyncTechnique> {
    let upper = name.to_lowercase().replace('_', "");
    match upper.as_str() {
        "multisplit" => Some(crate::desync::DesyncTechnique::MultiSplit),
        "multidisorder" => Some(crate::desync::DesyncTechnique::MultiDisorder),
        "hostfakesplit" => Some(crate::desync::DesyncTechnique::HostFakeSplit),
        "fakedatasplit" => Some(crate::desync::DesyncTechnique::FakeDataSplit),
        "fakedatadisorder" => Some(crate::desync::DesyncTechnique::FakeDataDisorder),
        "tcpseg" => Some(crate::desync::DesyncTechnique::TcpSeg),
        "syndata" => Some(crate::desync::DesyncTechnique::SynData),
        "synacksplit" => Some(crate::desync::DesyncTechnique::SynAckSplit),
        "winsize" => Some(crate::desync::DesyncTechnique::WinSize),
        "synhide" => Some(crate::desync::DesyncTechnique::SynHide),
        "fakesni" => Some(crate::desync::DesyncTechnique::FakeSni),
        "oobinjection" => Some(crate::desync::DesyncTechnique::OobInjection),
        "tcppreopen" => Some(crate::desync::DesyncTechnique::TcpPreopen),
        "mssclamp" => Some(crate::desync::DesyncTechnique::MssClamp),
        "acksuppress" => Some(crate::desync::DesyncTechnique::AckSuppress),
        "pktreorder" => Some(crate::desync::DesyncTechnique::PktReorder),
        "rstselective" => Some(crate::desync::DesyncTechnique::RstSelective),
        "synflooddecoy" => Some(crate::desync::DesyncTechnique::SynFloodDecoy),
        "winscalemanip" => Some(crate::desync::DesyncTechnique::WinScaleManip),
        "disorder" => Some(crate::desync::DesyncTechnique::Disorder),
        "multidisordernew" => Some(crate::desync::DesyncTechnique::MultidisorderNew),
        "disoob" => Some(crate::desync::DesyncTechnique::Disoob),
        "hostfake" => Some(crate::desync::DesyncTechnique::HostFake),
        "fakerst" => Some(crate::desync::DesyncTechnique::FakeRst),
        "bytebybyte" => Some(crate::desync::DesyncTechnique::ByteByByte),
        "unidirfrag" => Some(crate::desync::DesyncTechnique::UnidirFrag),
        "portshuffle" => Some(crate::desync::DesyncTechnique::PortShuffle),
        "wclamp" => Some(crate::desync::DesyncTechnique::Wclamp),
        "tsmd5" => Some(crate::desync::DesyncTechnique::TsMd5),
        "seqspoof" => Some(crate::desync::DesyncTechnique::SeqSpoof),
        "fragoverlap" => Some(crate::desync::DesyncTechnique::FragOverlap),
        "badchecksum" => Some(crate::desync::DesyncTechnique::BadChecksum),
        "ttlmanipulation" => Some(crate::desync::DesyncTechnique::TtlManipulation),
        "ipfragprimitives" => Some(crate::desync::DesyncTechnique::IpFragPrimitives),
        "rstdropipid" => Some(crate::desync::DesyncTechnique::RstDropIpId),
        "dscprandom" => Some(crate::desync::DesyncTechnique::DscpRandom),
        "mutualspoof" => Some(crate::desync::DesyncTechnique::MutualSpoof),
        "tlsrecordfrag" => Some(crate::desync::DesyncTechnique::TlsRecordFrag),
        "tlsrecordpad" => Some(crate::desync::DesyncTechnique::TlsRecordPad),
        "snimasking" => Some(crate::desync::DesyncTechnique::SniMasking),
        "snimicrofrag" => Some(crate::desync::DesyncTechnique::SniMicrofrag),
        "tlsrecordrewrap" => Some(crate::desync::DesyncTechnique::TlsRecordRewrap),
        "tlsversionspoof" => Some(crate::desync::DesyncTechnique::TlsVersionSpoof),
        "snirecordfrag" => Some(crate::desync::DesyncTechnique::SniRecordFrag),
        "h2settingsflood" => Some(crate::desync::DesyncTechnique::H2SettingsFlood),
        "h2rstpadding" => Some(crate::desync::DesyncTechnique::H2RstPadding),
        "h2windowupdateflood" => Some(crate::desync::DesyncTechnique::H2WindowUpdateFlood),
        "h2priorityabuse" => Some(crate::desync::DesyncTechnique::H2PriorityAbuse),
        "h2goaway" => Some(crate::desync::DesyncTechnique::H2Goaway),
        "chunkobfuscation" => Some(crate::desync::DesyncTechnique::ChunkObfuscation),
        "h2frameordering" => Some(crate::desync::DesyncTechnique::H2FrameOrdering),
        "http11pipeline" => Some(crate::desync::DesyncTechnique::Http11Pipeline),
        "contentlengthfuzz" => Some(crate::desync::DesyncTechnique::ContentLengthFuzz),
        "httpupgradeabuse" => Some(crate::desync::DesyncTechnique::HttpUpgradeAbuse),
        "httpcasemix" => Some(crate::desync::DesyncTechnique::HttpCaseMix),
        "quicblocking" => Some(crate::desync::DesyncTechnique::QuicBlocking),
        "quicversiondowngrade" => Some(crate::desync::DesyncTechnique::QuicVersionDowngrade),
        "quicretryinject" => Some(crate::desync::DesyncTechnique::QuicRetryInject),
        "quicconnectionclose" => Some(crate::desync::DesyncTechnique::QuicConnectionClose),
        "quicstreamreset" => Some(crate::desync::DesyncTechnique::QuicStreamReset),
        "quicmaxstreams" => Some(crate::desync::DesyncTechnique::QuicMaxStreams),
        "quicinitialinject" => Some(crate::desync::DesyncTechnique::QuicInitialInject),
        "quicshortheaderpoison" => Some(crate::desync::DesyncTechnique::QuicShortHeaderPoison),
        "quicpaddingflood" => Some(crate::desync::DesyncTechnique::QuicPaddingFlood),
        "doppelgangergrease" => Some(crate::desync::DesyncTechnique::DoppelgangerGrease),
        "quiclongheaderdrop" => Some(crate::desync::DesyncTechnique::QuicLongHeaderDrop),
        "quicnormalizer" => Some(crate::desync::DesyncTechnique::QuicNormalizer),
        "udpcoalescing" => Some(crate::desync::DesyncTechnique::UdpCoalescing),
        "udp2icmp" => Some(crate::desync::DesyncTechnique::Udp2Icmp),
        "xorfirst" => Some(crate::desync::DesyncTechnique::XorFirst),
        "wgobfs" => Some(crate::desync::DesyncTechnique::WgObfs),
        "chacha20" => Some(crate::desync::DesyncTechnique::ChaCha20),
        "reversefragmentorder" => Some(crate::desync::DesyncTechnique::ReverseFragmentOrder),
        _ => None,
    }
}

/// T57: Преобразует StrategyProfileConfig → StrategyProfile.
/// Валидирует имена техник, возвращает Err при нераспознанном имени.
pub fn profile_config_to_profile(
    config: &StrategyProfileConfig,
    strategy_id: u32,
    base_config: &crate::desync::DesyncConfig,
) -> Result<crate::adaptive::strategy_profile::StrategyProfile, String> {
    use crate::adaptive::auto_tune::TuneParams;
    use crate::adaptive::strategy::StrategyCategory;
    use crate::adaptive::strategy_profile::StrategyProfile;
    use crate::desync::group::DesyncGroup;

    let category = match config.protocol.to_lowercase().as_str() {
        "tls" => StrategyCategory::Tls,
        "http" => StrategyCategory::Http,
        "quic" => StrategyCategory::Quic,
        "dns" => StrategyCategory::Dns,
        "tcp" => StrategyCategory::Tcp,
        "ip" => StrategyCategory::Ip,
        "obfs" => StrategyCategory::Obfs,
        "general" => StrategyCategory::General,
        other => {
            return Err(format!(
                "Unknown protocol '{}' in strategy '{}'",
                other, config.name
            ))
        }
    };

    let mut techniques = Vec::new();
    for tech_name in &config.techniques {
        match parse_technique_name(tech_name) {
            Some(t) => techniques.push(t),
            None => {
                return Err(format!(
                    "Unknown technique '{}' in strategy '{}'",
                    tech_name, config.name
                ))
            }
        }
    }

    let mut group = DesyncGroup::new(base_config.clone());
    for t in &techniques {
        group.add(*t);
    }
    if let Err(e) = group.validate() {
        return Err(format!(
            "Invalid technique composition in strategy '{}': {}",
            config.name, e
        ));
    }

    Ok(StrategyProfile {
        id: crate::adaptive::strategy_profile::ProfileId(0),
        name: config.name.clone(),
        category,
        techniques,
        default_params: TuneParams {
            split_size: config.split_size,
            split_count: config.split_count,
            fake_ttl_offset: config.fake_ttl_offset,
            max_seg_size: config.max_seg_size,
        },
        description: "User-defined profile from config.toml".to_string(),
        strategy_id,
        desync_group: std::sync::Arc::new(group),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.api.port, 11337);
        assert!(config.api.enabled);
        assert!(config.dns.cache_ttl >= 60);
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        assert!(toml_str.contains("doh_url"));
        assert!(toml_str.contains("api_key"));
    }

    #[test]
    fn test_config_deserialization() {
        let toml_str = r#"
[api]
port = 12345
enabled = true

[dns]
cache_ttl = 600

[windivert]
queue_length = 4096
"#;
        let config = Config::from_toml(toml_str).unwrap();
        assert_eq!(config.api.port, 12345);
        assert_eq!(config.dns.cache_ttl, 600);
        assert_eq!(config.windivert.queue_length, 4096);
    }

    #[test]
    fn test_api_key_generation() {
        let config1 = Config::default();
        let config2 = Config::default();
        // Each instance generates a unique key
        assert_ne!(config1.api.api_key, config2.api.api_key);
    }

    #[test]
    fn test_parse_technique_name_known() {
        assert_eq!(
            parse_technique_name("FakeSni"),
            Some(crate::desync::DesyncTechnique::FakeSni)
        );
        assert_eq!(
            parse_technique_name("fakesni"),
            Some(crate::desync::DesyncTechnique::FakeSni)
        );
        assert_eq!(
            parse_technique_name("fake_sni"),
            Some(crate::desync::DesyncTechnique::FakeSni)
        );
        assert_eq!(
            parse_technique_name("MultiSplit"),
            Some(crate::desync::DesyncTechnique::MultiSplit)
        );
        assert_eq!(
            parse_technique_name("SeqSpoof"),
            Some(crate::desync::DesyncTechnique::SeqSpoof)
        );
        assert_eq!(
            parse_technique_name("QuicBlocking"),
            Some(crate::desync::DesyncTechnique::QuicBlocking)
        );
    }

    #[test]
    fn test_parse_technique_name_unknown() {
        assert_eq!(parse_technique_name("Nonexistent"), None);
        assert_eq!(parse_technique_name(""), None);
    }

    #[test]
    fn test_profile_config_to_profile_valid() {
        let cfg = StrategyProfileConfig {
            name: "custom_tls".into(),
            protocol: "tls".into(),
            techniques: vec!["FakeSni".into(), "BadChecksum".into()],
            split_size: Some(1),
            split_count: Some(3),
            fake_ttl_offset: Some(1),
            max_seg_size: None,
            default: None,
            enabled: None,
        };
        let profile =
            profile_config_to_profile(&cfg, 200, &crate::desync::DesyncConfig::default()).unwrap();
        assert_eq!(profile.name, "custom_tls");
        assert_eq!(
            profile.category,
            crate::adaptive::strategy::StrategyCategory::Tls
        );
        assert_eq!(profile.techniques.len(), 2);
        assert_eq!(
            profile.techniques[0],
            crate::desync::DesyncTechnique::FakeSni
        );
    }

    #[test]
    fn test_profile_config_unknown_technique() {
        let cfg = StrategyProfileConfig {
            name: "bad".into(),
            protocol: "tls".into(),
            techniques: vec!["NonexistentTechnique".into()],
            split_size: None,
            split_count: None,
            fake_ttl_offset: None,
            max_seg_size: None,
            default: None,
            enabled: None,
        };
        assert!(
            profile_config_to_profile(&cfg, 200, &crate::desync::DesyncConfig::default()).is_err()
        );
    }

    #[test]
    fn test_profile_config_unknown_protocol() {
        let cfg = StrategyProfileConfig {
            name: "bad".into(),
            protocol: "icmp".into(),
            techniques: vec![],
            split_size: None,
            split_count: None,
            fake_ttl_offset: None,
            max_seg_size: None,
            default: None,
            enabled: None,
        };
        assert!(
            profile_config_to_profile(&cfg, 200, &crate::desync::DesyncConfig::default()).is_err()
        );
    }

    #[test]
    fn test_toml_parsing_strategies_section() {
        let toml_str = r#"
mode = "service"
[[strategies]]
name = "test_profile"
protocol = "tls"
techniques = ["FakeSni", "BadChecksum"]
split_size = 1
split_count = 3
fake_ttl_offset = 1
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.strategies.len(), 1);
        assert_eq!(config.strategies[0].name, "test_profile");
        assert_eq!(
            config.strategies[0].techniques,
            vec!["FakeSni", "BadChecksum"]
        );
    }

    #[test]
    fn filter_includes_syn_when_mss_enabled() {
        let features = FilterFeatures {
            tls_desync: true,
            quic_desync: true,
            dns_proxy: true,
            mss_clamp: true,
            win_size_clamp: false,
            socks_redirect: false,
            fakeip_redirect: false,
            target_ports: smallvec::smallvec![443],
        };
        let filter = build_windivert_filter(&features);
        assert!(filter.contains("tcp.Syn"));
        assert!(filter.contains("tcp.DstPort == 443"));
    }

    #[test]
    fn filter_excludes_syn_when_no_syn_features_enabled() {
        let features = FilterFeatures {
            tls_desync: true,
            quic_desync: true,
            dns_proxy: true,
            mss_clamp: false,
            win_size_clamp: false,
            socks_redirect: false,
            fakeip_redirect: false,
            target_ports: smallvec::smallvec![443],
        };
        let filter = build_windivert_filter(&features);
        assert!(!filter.contains("tcp.Syn"));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CustomProxyConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default = "default_true")]
    pub use_opera_fallback: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxyConfig {
    /// Включить Opera SOCKS5 proxy routing вообще.
    #[serde(default)]
    pub enabled: bool,
    /// Домены прямо в TOML (маленький список / override).
    #[serde(default)]
    pub proxy_domains: Vec<String>,
    /// Путь к внешнему файлу со списком доменов (один домен на строку).
    #[serde(default)]
    pub proxy_domains_file: Option<String>,
    /// Автоматически определять заблокированные домены через probe.
    #[serde(default = "default_true")]
    pub auto_probe: bool,
    pub max_connections: Option<usize>,
    pub idle_timeout_secs: Option<u64>,
    /// Пользовательский кастомный прокси с авторизацией
    #[serde(default)]
    pub custom_proxy: CustomProxyConfig,
}

/// T60: Читает домены из файла, игнорируя пустые строки и комментарии (#...).
pub fn load_domains_from_file(path: &str) -> anyhow::Result<Vec<String>> {
    if !std::path::Path::new(path).exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(path)?;

    let domains: Vec<String> = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_lowercase())
        .collect();

    tracing::info!("T60: loaded {} domains from {path}", domains.len());
    Ok(domains)
}

/// T63: Конфигурация Zero-Config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroConfigConfig {
    /// Включить Zero-Config движок.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Включить автоматическое определение режима белых списков.
    #[serde(default)]
    pub auto_detect: bool,
    /// Путь к файлу со списком канареек.
    #[serde(default = "default_canary_domains_path")]
    pub canary_domains_path: String,
    /// Интервал проверки в секундах.
    #[serde(default = "default_detection_interval_secs")]
    pub detection_interval_secs: u64,
    /// Путь к файлу кэша Opera credentials.
    #[serde(default = "default_opera_cache_path")]
    pub opera_cache_path: String,
    /// SNI для маскировки Opera over TCP.
    #[serde(default = "default_opera_masquerade_sni")]
    pub opera_masquerade_sni: String,
    /// SNI для маскировки DoH запросов к Google.
    #[serde(default = "default_doh_google_masquerade_sni")]
    pub doh_google_masquerade_sni: String,
    /// SNI для маскировки DoH запросов к Cloudflare.
    #[serde(default = "default_doh_cloudflare_masquerade_sni")]
    pub doh_cloudflare_masquerade_sni: String,
}

fn default_canary_domains_path() -> String {
    "canary_domains.txt".into()
}
fn default_detection_interval_secs() -> u64 {
    600
}
fn default_opera_cache_path() -> String {
    "opera_credentials.json".into()
}
fn default_opera_masquerade_sni() -> String {
    "gosuslugi.ru".into()
}
fn default_doh_google_masquerade_sni() -> String {
    "translate.google.com".into()
}
fn default_doh_cloudflare_masquerade_sni() -> String {
    "gosuslugi.ru".into()
}

impl Default for ZeroConfigConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_detect: false,
            canary_domains_path: default_canary_domains_path(),
            detection_interval_secs: default_detection_interval_secs(),
            opera_cache_path: default_opera_cache_path(),
            opera_masquerade_sni: default_opera_masquerade_sni(),
            doh_google_masquerade_sni: default_doh_google_masquerade_sni(),
            doh_cloudflare_masquerade_sni: default_doh_cloudflare_masquerade_sni(),
        }
    }
}

/// T63: AmneziaWG configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwgConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_awg_endpoint")]
    pub endpoint: String,
    #[serde(default)]
    pub private_key: String,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub address: String, // e.g. "10.0.0.2/32"
    #[serde(default = "default_awg_jc")]
    pub jc: usize,
    #[serde(default = "default_awg_jmin")]
    pub jmin: usize,
    #[serde(default = "default_awg_jmax")]
    pub jmax: usize,
    #[serde(default = "default_awg_s1")]
    pub s1: usize,
    #[serde(default = "default_awg_s2")]
    pub s2: usize,
    #[serde(default)]
    pub s3: usize,
    #[serde(default)]
    pub s4: usize,
    #[serde(default = "default_awg_h1")]
    pub h1: u32,
    #[serde(default = "default_awg_h2")]
    pub h2: u32,
    #[serde(default = "default_awg_h3")]
    pub h3: u32,
    #[serde(default = "default_awg_h4")]
    pub h4: u32,
}

fn default_awg_endpoint() -> String {
    "engage.cloudflareclient.com:2408".to_string()
}
fn default_awg_jc() -> usize {
    4
}
fn default_awg_jmin() -> usize {
    40
}
fn default_awg_jmax() -> usize {
    1000
}
fn default_awg_s1() -> usize {
    120
}
fn default_awg_s2() -> usize {
    60
}
fn default_awg_h1() -> u32 {
    512345
}
fn default_awg_h2() -> u32 {
    512346
}
fn default_awg_h3() -> u32 {
    512347
}
fn default_awg_h4() -> u32 {
    512348
}

impl Default for AwgConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_awg_endpoint(),
            private_key: String::new(),
            public_key: String::new(),
            address: "10.0.0.2/32".to_string(),
            jc: default_awg_jc(),
            jmin: default_awg_jmin(),
            jmax: default_awg_jmax(),
            s1: default_awg_s1(),
            s2: default_awg_s2(),
            s3: 0,
            s4: 0,
            h1: default_awg_h1(),
            h2: default_awg_h2(),
            h3: default_awg_h3(),
            h4: default_awg_h4(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FilterFeatures {
    pub tls_desync: bool,
    pub quic_desync: bool,
    pub dns_proxy: bool,
    pub mss_clamp: bool,
    pub win_size_clamp: bool,
    pub socks_redirect: bool,
    pub fakeip_redirect: bool,
    pub target_ports: smallvec::SmallVec<[u16; 8]>,
}

fn render_port_predicate(field: &str, ports: &[u16]) -> String {
    if ports.is_empty() {
        return "false".to_string();
    }
    if ports.len() == 1 {
        return format!("{} == {}", field, ports[0]);
    }
    let parts: Vec<String> = ports
        .iter()
        .map(|p| format!("{} == {}", field, p))
        .collect();
    format!("({})", parts.join(" or "))
}

pub fn build_windivert_filter(features: &FilterFeatures) -> String {
    let mut terms = Vec::new();

    if features.mss_clamp
        || features.win_size_clamp
        || features.socks_redirect
        || features.fakeip_redirect
    {
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

impl Config {
    pub fn get_filter_features(&self) -> FilterFeatures {
        let target_ports = smallvec::smallvec![443];

        let has_technique = |name: &str| {
            self.desync
                .techniques
                .iter()
                .any(|t| t.to_lowercase().replace('_', "") == name)
                || self.strategies.iter().any(|s| {
                    s.techniques
                        .iter()
                        .any(|t| t.to_lowercase().replace('_', "") == name)
                })
        };

        let mss_clamp = has_technique("mssclamp");
        let win_size_clamp =
            has_technique("winsize") || has_technique("wclamp") || has_technique("winscalemanip");
        let socks_redirect = self.proxy.enabled;
        let fakeip_redirect = self.zero_config.enabled;

        FilterFeatures {
            tls_desync: true,
            quic_desync: true,
            dns_proxy: true,
            mss_clamp,
            win_size_clamp,
            socks_redirect,
            fakeip_redirect,
            target_ports,
        }
    }
}
