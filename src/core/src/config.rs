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

fn default_filter() -> String {
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
) -> Result<crate::adaptive::strategy_profile::StrategyProfile, String> {
    use crate::adaptive::auto_tune::TuneParams;
    use crate::adaptive::strategy::StrategyCategory;
    use crate::adaptive::strategy_profile::StrategyProfile;
    use crate::desync::group::DesyncGroup;
    use crate::desync::DesyncConfig;

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

    Ok(StrategyProfile {
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
        desync_group: std::sync::Arc::new(DesyncGroup::new(DesyncConfig::default())),
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
        };
        let profile = profile_config_to_profile(&cfg, 200).unwrap();
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
        };
        assert!(profile_config_to_profile(&cfg, 200).is_err());
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
        };
        assert!(profile_config_to_profile(&cfg, 200).is_err());
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
}
