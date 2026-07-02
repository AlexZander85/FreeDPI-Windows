//! Strategy Profile Registry — связывающий probe-рекомендации (`strategy_id`),
//! наборы `DesyncTechnique` и AutoTune-метрики в единую систему профилей.

use crate::adaptive::auto_tune::TuneParams;
use crate::adaptive::strategy::StrategyCategory;
use crate::desync::group::DesyncGroup;
use crate::desync::{DesyncConfig, DesyncTechnique};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error};

/// Стратегия обхода — связывает имя с набором техник и параметрами.
#[derive(Debug, Clone)]
pub struct StrategyProfile {
    /// Уникальное имя профиля — ключ в `AutoTune` и в `StrategyProfileRegistry`.
    pub name: String,
    /// Категория трафика (переиспользует `adaptive::strategy::StrategyCategory`).
    pub category: StrategyCategory,
    /// Набор техник — порядок важен, `DesyncGroup` применяет последовательно.
    pub techniques: Vec<DesyncTechnique>,
    /// Параметры по умолчанию.
    pub default_params: TuneParams,
    /// Человеко-читаемое описание (для API/UI).
    pub description: String,
    /// ID стратегии.
    pub strategy_id: u32,
    /// Собранная и провалидированная `DesyncGroup`.
    pub desync_group: Arc<DesyncGroup>,
}

impl StrategyProfile {
    /// Объединяет `default_params` с override.
    pub fn merged_params(&self, override_params: &TuneParams) -> TuneParams {
        TuneParams {
            split_size: override_params.split_size.or(self.default_params.split_size),
            split_count: override_params.split_count.or(self.default_params.split_count),
            fake_ttl_offset: override_params
                .fake_ttl_offset
                .or(self.default_params.fake_ttl_offset),
            max_seg_size: override_params.max_seg_size.or(self.default_params.max_seg_size),
        }
    }
}

/// Реестр профилей стратегий.
pub struct StrategyProfileRegistry {
    profiles: HashMap<String, StrategyProfile>,
    category_defaults: HashMap<StrategyCategory, String>,
    id_map: HashMap<u32, String>,
}

impl StrategyProfileRegistry {
    /// Создаёт реестр со стандартными профилями.
    pub fn with_defaults(base_config: &DesyncConfig, user_techniques: &[DesyncTechnique]) -> Self {
        let mut registry = Self {
            profiles: HashMap::new(),
            category_defaults: HashMap::new(),
            id_map: HashMap::new(),
        };

        let outbound_tls_techniques = if user_techniques.is_empty() {
            vec![DesyncTechnique::FakeSni, DesyncTechnique::BadChecksum]
        } else {
            user_techniques.to_vec()
        };

        // === 1: outbound_tls ===
        registry.register(
            base_config,
            "outbound_tls",
            StrategyCategory::Tls,
            outbound_tls_techniques,
            TuneParams {
                split_size: Some(1),
                split_count: Some(3),
                fake_ttl_offset: Some(1),
                max_seg_size: Some(10),
            },
            "TLS ClientHello desync: default (config.techniques если задан, иначе FakeSni+BadChecksum)",
            1,
        );
        registry.category_defaults.insert(StrategyCategory::Tls, "outbound_tls".into());

        // === 2: outbound_tls_split ===
        registry.register(
            base_config,
            "outbound_tls_split",
            StrategyCategory::Tls,
            vec![DesyncTechnique::MultiSplit, DesyncTechnique::BadChecksum],
            TuneParams {
                split_size: Some(1),
                split_count: Some(3),
                fake_ttl_offset: Some(1),
                max_seg_size: Some(10),
            },
            "TLS split-only: MultiSplit + BadChecksum (без FakeSni)",
            2,
        );

        // === 3: outbound_tls_disorder ===
        registry.register(
            base_config,
            "outbound_tls_disorder",
            StrategyCategory::Tls,
            vec![DesyncTechnique::Disorder, DesyncTechnique::BadChecksum],
            TuneParams {
                split_size: Some(1),
                split_count: Some(2),
                fake_ttl_offset: Some(1),
                max_seg_size: Some(10),
            },
            "TLS disorder: Disorder + BadChecksum",
            7,
        );

        // === 4: outbound_tls_tlsfrag ===
        registry.register(
            base_config,
            "outbound_tls_tlsfrag",
            StrategyCategory::Tls,
            vec![DesyncTechnique::TlsRecordFrag, DesyncTechnique::BadChecksum],
            TuneParams {
                split_size: Some(5),
                split_count: Some(2),
                fake_ttl_offset: Some(1),
                max_seg_size: Some(10),
            },
            "TLS record fragmentation: TlsRecordFrag + BadChecksum",
            15,
        );

        // === 5: outbound_tls_hostfake ===
        registry.register(
            base_config,
            "outbound_tls_hostfake",
            StrategyCategory::Tls,
            vec![DesyncTechnique::HostFake, DesyncTechnique::BadChecksum],
            TuneParams {
                split_size: Some(1),
                split_count: Some(2),
                fake_ttl_offset: Some(1),
                max_seg_size: Some(10),
            },
            "TLS hostfake: HostFake + BadChecksum",
            4,
        );

        // === 6: outbound_http ===
        registry.register(
            base_config,
            "outbound_http",
            StrategyCategory::Http,
            vec![DesyncTechnique::HttpCaseMix, DesyncTechnique::ChunkObfuscation],
            TuneParams {
                split_size: Some(1),
                split_count: Some(2),
                fake_ttl_offset: Some(1),
                max_seg_size: Some(10),
            },
            "HTTP desync: HttpCaseMix + ChunkObfuscation",
            20,
        );
        registry.category_defaults.insert(StrategyCategory::Http, "outbound_http".into());

        // === 7: outbound_quic ===
        registry.register(
            base_config,
            "outbound_quic",
            StrategyCategory::Quic,
            vec![DesyncTechnique::QuicBlocking],
            TuneParams {
                split_size: Some(1),
                split_count: Some(2),
                fake_ttl_offset: Some(1),
                max_seg_size: Some(10),
            },
            "QUIC desync: QuicBlocking",
            30,
        );
        registry.category_defaults.insert(StrategyCategory::Quic, "outbound_quic".into());

        // === 8: outbound_quic_downgrade ===
        registry.register(
            base_config,
            "outbound_quic_downgrade",
            StrategyCategory::Quic,
            vec![DesyncTechnique::QuicVersionDowngrade],
            TuneParams {
                split_size: Some(1),
                split_count: Some(2),
                fake_ttl_offset: Some(1),
                max_seg_size: Some(10),
            },
            "QUIC version downgrade: QuicVersionDowngrade",
            31,
        );

        // === 9: dns_doh ===
        registry.register(
            base_config,
            "dns_doh",
            StrategyCategory::Dns,
            vec![],
            TuneParams::default(),
            "DNS DoH resolver routing",
            100,
        );

        // === 10: socks5_fallback ===
        registry.register(
            base_config,
            "socks5_fallback",
            StrategyCategory::Tcp,
            vec![],
            TuneParams::default(),
            "SOCKS5 proxy fallback routing",
            35,
        );

        // === 11: tcp_mss_clamp ===
        registry.register(
            base_config,
            "tcp_mss_clamp",
            StrategyCategory::Tcp,
            vec![DesyncTechnique::MssClamp, DesyncTechnique::PktReorder],
            TuneParams {
                split_size: Some(1),
                split_count: Some(2),
                fake_ttl_offset: Some(1),
                max_seg_size: Some(536),
            },
            "TCP MSS clamp + reorder: для data-volume cutoff DPI",
            9,
        );

        // === 12: tcp_window_clamp ===
        registry.register(
            base_config,
            "tcp_window_clamp",
            StrategyCategory::Tcp,
            vec![DesyncTechnique::Wclamp, DesyncTechnique::MssClamp],
            TuneParams {
                split_size: Some(1),
                split_count: Some(2),
                fake_ttl_offset: Some(1),
                max_seg_size: Some(536),
            },
            "TCP window clamp + MSS: для HTTP cutoff DPI",
            8,
        );

        // === 13: outbound_tls_seqspoof ===
        registry.register(
            base_config,
            "outbound_tls_seqspoof",
            StrategyCategory::Tls,
            vec![DesyncTechnique::SeqSpoof, DesyncTechnique::BadChecksum],
            TuneParams {
                split_size: Some(1),
                split_count: Some(2),
                fake_ttl_offset: Some(1),
                max_seg_size: Some(10),
            },
            "TLS SEQ Spoof: fake ClientHello with out-of-window SEQ + dynamic TTL",
            6,
        );

        debug!(
            "StrategyProfileRegistry initialized with {} profiles",
            registry.profiles.len()
        );
        registry
    }

    #[allow(clippy::too_many_arguments)]
    fn register(
        &mut self,
        base_config: &DesyncConfig,
        name: &str,
        category: StrategyCategory,
        techniques: Vec<DesyncTechnique>,
        default_params: TuneParams,
        description: &str,
        strategy_id: u32,
    ) {
        let desync_group = Arc::new(Self::build_validated_group(base_config, &techniques, name));
        let profile = StrategyProfile {
            name: name.to_string(),
            category,
            techniques,
            default_params,
            description: description.to_string(),
            strategy_id,
            desync_group,
        };
        self.id_map.insert(strategy_id, name.to_string());
        self.profiles.insert(name.to_string(), profile);
    }

    fn build_validated_group(
        base_config: &DesyncConfig,
        techniques: &[DesyncTechnique],
        profile_name: &str,
    ) -> DesyncGroup {
        let mut group = DesyncGroup::new(base_config.clone());
        for t in techniques {
            group.add(*t);
        }
        if let Err(e) = group.validate() {
            error!(
                "StrategyProfileRegistry: профиль '{}' — невалидная композиция техник ({}) — используем [FakeSni, BadChecksum]",
                profile_name, e
            );
            let mut safe = DesyncGroup::new(base_config.clone());
            safe.add(DesyncTechnique::FakeSni);
            safe.add(DesyncTechnique::BadChecksum);
            return safe;
        }
        group
    }

    pub fn get(&self, name: &str) -> Option<&StrategyProfile> {
        self.profiles.get(name)
    }

    pub fn get_default_for_category(&self, category: StrategyCategory) -> Option<&StrategyProfile> {
        self.category_defaults
            .get(&category)
            .and_then(|name| self.profiles.get(name))
    }

    pub fn get_by_id(&self, strategy_id: u32) -> Option<&StrategyProfile> {
        self.id_map.get(&strategy_id).and_then(|name| self.profiles.get(name))
    }

    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }
}

impl Default for StrategyProfileRegistry {
    fn default() -> Self {
        Self::with_defaults(&DesyncConfig::default(), &[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_has_13_profiles() {
        let registry = StrategyProfileRegistry::default();
        assert_eq!(registry.len(), 13);
    }

    #[test]
    fn test_category_defaults() {
        let registry = StrategyProfileRegistry::default();
        assert_eq!(
            registry.get_default_for_category(StrategyCategory::Tls).unwrap().name,
            "outbound_tls"
        );
        assert_eq!(
            registry.get_default_for_category(StrategyCategory::Http).unwrap().name,
            "outbound_http"
        );
        assert_eq!(
            registry.get_default_for_category(StrategyCategory::Quic).unwrap().name,
            "outbound_quic"
        );
        assert!(registry.get_default_for_category(StrategyCategory::Dns).is_none());
    }

    #[test]
    fn test_id_mapping() {
        let registry = StrategyProfileRegistry::default();
        assert_eq!(registry.get_by_id(1).unwrap().name, "outbound_tls");
        assert_eq!(registry.get_by_id(7).unwrap().name, "outbound_tls_disorder");
        assert_eq!(registry.get_by_id(100).unwrap().name, "dns_doh");
        assert_eq!(registry.get_by_id(35).unwrap().name, "socks5_fallback");
        assert!(registry.get_by_id(9999).is_none());
    }

    #[test]
    fn test_all_registered_groups_are_valid() {
        let registry = StrategyProfileRegistry::default();
        let outbound_tls = registry.get("outbound_tls").unwrap();
        assert_eq!(
            outbound_tls.desync_group.techniques(),
            &[DesyncTechnique::FakeSni, DesyncTechnique::BadChecksum]
        );
        let split = registry.get("outbound_tls_split").unwrap();
        assert_eq!(
            split.desync_group.techniques(),
            &[DesyncTechnique::MultiSplit, DesyncTechnique::BadChecksum]
        );
    }

    #[test]
    fn test_user_techniques_override_outbound_tls_only() {
        let custom = vec![DesyncTechnique::Disorder, DesyncTechnique::MssClamp];
        let registry = StrategyProfileRegistry::with_defaults(&DesyncConfig::default(), &custom);
        assert_eq!(registry.get("outbound_tls").unwrap().techniques, custom);
        assert_eq!(
            registry.get("outbound_tls_split").unwrap().techniques,
            vec![DesyncTechnique::MultiSplit, DesyncTechnique::BadChecksum]
        );
    }

    #[test]
    fn test_merged_params_override_priority() {
        let registry = StrategyProfileRegistry::default();
        let profile = registry.get("outbound_tls").unwrap();

        let empty_override = TuneParams::default();
        let merged = profile.merged_params(&empty_override);
        assert_eq!(merged.split_count, Some(3));

        let override_params = TuneParams {
            split_count: Some(5),
            ..Default::default()
        };
        let merged = profile.merged_params(&override_params);
        assert_eq!(merged.split_size, Some(1));
        assert_eq!(merged.split_count, Some(5));
    }
}
