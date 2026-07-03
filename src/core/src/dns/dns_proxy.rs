use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

use super::dns_utils::{build_dns_response, parse_dns_query, DnsQuery};
use crate::dns::fakeip::FakeIpManager;
use crate::routing::geo::GeoRouter;
use crate::routing::GeoRegion;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsResolveMode {
    AdBlock,
    FakeIp,
    SecureDoh,
    SystemDns,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsProxyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub adblock_enabled: bool,
    #[serde(default = "default_doh_servers")]
    pub doh_servers: Vec<String>,
    #[serde(default = "default_system_dns")]
    pub system_dns_servers: Vec<String>,
    #[serde(default)]
    pub censored_domains: Vec<String>,
    #[serde(default)]
    pub adblock_domains: Vec<String>,
    #[serde(default = "default_ttl")]
    pub ttl: u32,
}

fn default_true() -> bool {
    true
}
fn default_ttl() -> u32 {
    60
}
fn default_doh_servers() -> Vec<String> {
    vec![
        "https://cloudflare-dns.com/dns-query".into(),
        "https://dns.google/resolve".into(),
    ]
}
fn default_system_dns() -> Vec<String> {
    vec!["8.8.8.8".into()]
}

impl Default for DnsProxyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            adblock_enabled: false,
            doh_servers: default_doh_servers(),
            system_dns_servers: default_system_dns(),
            censored_domains: Vec::new(),
            adblock_domains: vec![
                "doubleclick.net".into(),
                "googlesyndication.com".into(),
                "googleadservices.com".into(),
                "google-analytics.com".into(),
            ],
            ttl: default_ttl(),
        }
    }
}

pub struct DnsProxyEngine {
    pub config: std::sync::RwLock<DnsProxyConfig>,
    pub fake_ip_manager: Arc<FakeIpManager>,
    pub geo_router: Arc<GeoRouter>,
    pub cache: DashMap<String, (IpAddr, Instant)>,
    pub doh_client: reqwest::Client,
    pub system_resolver: Option<trust_dns_resolver::TokioAsyncResolver>,
}

impl DnsProxyEngine {
    pub fn new(
        config: DnsProxyConfig,
        fake_ip_manager: Arc<FakeIpManager>,
        geo_router: Arc<GeoRouter>,
    ) -> Self {
        let doh_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();

        let (sys_cfg, sys_opts) = match trust_dns_resolver::system_conf::read_system_conf() {
            Ok(res) => res,
            Err(_) => (
                trust_dns_resolver::config::ResolverConfig::google(),
                trust_dns_resolver::config::ResolverOpts::default(),
            ),
        };
        let system_resolver = Some(trust_dns_resolver::TokioAsyncResolver::tokio(
            sys_cfg, sys_opts,
        ));

        Self {
            config: std::sync::RwLock::new(config),
            fake_ip_manager,
            geo_router,
            cache: DashMap::new(),
            doh_client,
            system_resolver,
        }
    }

    pub fn classify_domain(&self, domain: &str) -> DnsResolveMode {
        let lower = domain.to_lowercase();
        let config = self.config.read().unwrap();

        // 1. AdBlock Check
        if config.adblock_enabled
            && config
                .adblock_domains
                .iter()
                .any(|d| lower == *d || lower.ends_with(&format!(".{}", d)))
        {
            return DnsResolveMode::AdBlock;
        }

        // 2. Geoblock Check (EU / US -> SOCKS5 proxy)
        let region = self.geo_router.classify(domain, None);
        if matches!(region, GeoRegion::Europe | GeoRegion::UnitedStates) {
            return DnsResolveMode::FakeIp;
        }

        // 3. Censored check (RKN / blocked) -> DoH
        if config
            .censored_domains
            .iter()
            .any(|d| lower == *d || lower.ends_with(&format!(".{}", d)))
        {
            return DnsResolveMode::SecureDoh;
        }

        DnsResolveMode::SystemDns
    }

    pub async fn handle_dns_query(&self, query_packet: &[u8]) -> Option<Vec<u8>> {
        let dns_query = parse_dns_query(query_packet)?;
        debug!(
            "DNS proxy query: {} (type={})",
            dns_query.domain, dns_query.query_type
        );

        let mode = self.classify_domain(&dns_query.domain);

        // AAAA for AdBlock/FakeIp: return empty NOERROR (ANCOUNT=0) to force IPv4
        if dns_query.query_type == 28
            && matches!(mode, DnsResolveMode::AdBlock | DnsResolveMode::FakeIp)
        {
            let ttl = self.config.read().unwrap().ttl;
            return build_dns_response(query_packet, &dns_query, None, ttl, 0).ok();
        }

        let ttl = self.config.read().unwrap().ttl;
        match mode {
            DnsResolveMode::AdBlock => {
                // Return NXDOMAIN (rcode=3)
                build_dns_response(query_packet, &dns_query, None, ttl, 3).ok()
            }
            DnsResolveMode::FakeIp => {
                let fake_ip = self.fake_ip_manager.allocate(&dns_query.domain)?;
                build_dns_response(query_packet, &dns_query, Some(IpAddr::V4(fake_ip)), ttl, 0).ok()
            }
            DnsResolveMode::SecureDoh => {
                match self
                    .resolve_via_doh(&dns_query.domain, dns_query.query_type)
                    .await
                {
                    Some(ip) => build_dns_response(query_packet, &dns_query, Some(ip), ttl, 0).ok(),
                    None => None,
                }
            }
            DnsResolveMode::SystemDns => {
                match self
                    .resolve_via_system(&dns_query.domain, dns_query.query_type)
                    .await
                {
                    Some(ip) => build_dns_response(query_packet, &dns_query, Some(ip), ttl, 0).ok(),
                    None => {
                        // System resolve failed, fallback to DoH
                        match self
                            .resolve_via_doh(&dns_query.domain, dns_query.query_type)
                            .await
                        {
                            Some(ip) => {
                                build_dns_response(query_packet, &dns_query, Some(ip), ttl, 0).ok()
                            }
                            None => None,
                        }
                    }
                }
            }
        }
    }

    async fn resolve_via_doh(&self, domain: &str, query_type: u16) -> Option<IpAddr> {
        let cache_key = format!("{}:{}", domain, query_type);
        if let Some(entry) = self.cache.get(&cache_key) {
            if entry.1 > Instant::now() {
                return Some(entry.0);
            }
        }

        let (doh_servers, ttl_fallback) = {
            let config = self.config.read().unwrap();
            (config.doh_servers.clone(), config.ttl)
        };

        for url in &doh_servers {
            let full_url = if url.contains('?') {
                format!(
                    "{}&name={}&type={}",
                    url,
                    domain,
                    if query_type == 28 { "AAAA" } else { "A" }
                )
            } else {
                format!(
                    "{}?name={}&type={}",
                    url,
                    domain,
                    if query_type == 28 { "AAAA" } else { "A" }
                )
            };

            match self
                .doh_client
                .get(&full_url)
                .header("accept", "application/dns-json")
                .send()
                .await
            {
                Ok(resp) => {
                    if let Ok(body) = resp.json::<serde_json::Value>().await {
                        if let Some(answer) = body["Answer"].as_array() {
                            for entry in answer {
                                let etype = entry["type"].as_i64().unwrap_or(0) as u16;
                                if etype == query_type {
                                    if let Some(ip_str) = entry["data"].as_str() {
                                        let ip_clean = ip_str.trim_end_matches('.');
                                        if let Ok(ip) = ip_clean.parse::<IpAddr>() {
                                            let ttl =
                                                entry["TTL"].as_u64().unwrap_or(ttl_fallback as u64);
                                            self.cache.insert(
                                                cache_key.clone(),
                                                (ip, Instant::now() + Duration::from_secs(ttl)),
                                            );
                                            return Some(ip);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("DoH request failed for {} via {}: {}", domain, url, e);
                }
            }
        }
        None
    }

    async fn resolve_via_system(&self, domain: &str, query_type: u16) -> Option<IpAddr> {
        let cache_key = format!("{}:{}", domain, query_type);
        if let Some(entry) = self.cache.get(&cache_key) {
            if entry.1 > Instant::now() {
                return Some(entry.0);
            }
        }

        let resolver = self.system_resolver.as_ref()?;
        if query_type == 28 {
            let lookup = resolver.ipv6_lookup(domain).await.ok()?;
            if let Some(record) = lookup.iter().next() {
                let ip = IpAddr::V6(record.0);
                self.cache.insert(
                    cache_key,
                    (
                        ip,
                        Instant::now()
                            + Duration::from_secs(self.config.read().unwrap().ttl as u64),
                    ),
                );
                return Some(ip);
            }
        } else {
            let lookup = resolver.ipv4_lookup(domain).await.ok()?;
            if let Some(record) = lookup.iter().next() {
                let ip = IpAddr::V4(record.0);
                self.cache.insert(
                    cache_key,
                    (
                        ip,
                        Instant::now()
                            + Duration::from_secs(self.config.read().unwrap().ttl as u64),
                    ),
                );
                return Some(ip);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::geo::GeoRouterConfig;

    #[test]
    fn test_dns_proxy_engine_classify() {
        let fake_ip = Arc::new(FakeIpManager::new(100));
        let geo = Arc::new(GeoRouter::new_default());
        geo.add_user_domain("netflix.com");

        let config = DnsProxyConfig {
            adblock_enabled: true,
            adblock_domains: vec!["adserver.com".to_string()],
            censored_domains: vec!["blocked.com".to_string()],
            ..Default::default()
        };

        let engine = DnsProxyEngine::new(config, fake_ip, geo);

        assert_eq!(
            engine.classify_domain("adserver.com"),
            DnsResolveMode::AdBlock
        );
        assert_eq!(
            engine.classify_domain("netflix.com"),
            DnsResolveMode::FakeIp
        );
        assert_eq!(
            engine.classify_domain("blocked.com"),
            DnsResolveMode::SecureDoh
        );
        assert_eq!(
            engine.classify_domain("yandex.ru"),
            DnsResolveMode::SystemDns
        );
    }
}
