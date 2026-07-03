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
    pub zero_config: Arc<crate::proxy::zero_config::ZeroConfigEngine>,
}

impl DnsProxyEngine {
    pub fn new(
        config: DnsProxyConfig,
        fake_ip_manager: Arc<FakeIpManager>,
        geo_router: Arc<GeoRouter>,
        zero_config: Arc<crate::proxy::zero_config::ZeroConfigEngine>,
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
            zero_config,
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

        // 1. Попытка обычного DoH
        if let Some(ip) = self.resolve_via_doh_normal(domain, query_type).await {
            return Some(ip);
        }

        // 2. Если обычный DoH заблокирован, пробуем DoH с маскировкой через Opera CONNECT
        if self.zero_config.is_active() {
            debug!(
                "T63: Normal DoH failed, trying masqueraded DoH over Opera tunnel for {}...",
                domain
            );
            if let Some(ip) = self.resolve_via_doh_masqueraded(domain, query_type).await {
                let ttl = { self.config.read().unwrap().ttl as u64 };
                self.cache
                    .insert(cache_key, (ip, Instant::now() + Duration::from_secs(ttl)));
                return Some(ip);
            }
        }

        None
    }

    async fn resolve_via_doh_normal(&self, domain: &str, query_type: u16) -> Option<IpAddr> {
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
                                            let ttl = entry["TTL"]
                                                .as_u64()
                                                .unwrap_or(ttl_fallback as u64);
                                            let cache_key = format!("{}:{}", domain, query_type);
                                            self.cache.insert(
                                                cache_key,
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

    async fn resolve_via_doh_masqueraded(&self, domain: &str, query_type: u16) -> Option<IpAddr> {
        let tunnel = self.zero_config.get_tunnel()?;

        // CONNECT к IP 8.8.8.8 на порт 443 через туннель Opera с fake SNI
        let opera_stream = match tunnel.connect("8.8.8.8", 443).await {
            Ok(s) => s,
            Err(e) => {
                warn!("DoH masquerade: CONNECT to 8.8.8.8:443 failed: {e:#}");
                return None;
            }
        };

        // Вложенный TLS-хэндшейк с dns.google
        let connector = crate::proxy::http_tunnel::build_tls_connector();
        let server_name = match rustls::pki_types::ServerName::try_from("dns.google") {
            Ok(name) => name.to_owned(),
            Err(_) => return None,
        };
        let mut tls_stream = match connector.connect(server_name, opera_stream).await {
            Ok(s) => s,
            Err(e) => {
                warn!("DoH masquerade: Inner TLS handshake with 'dns.google' failed: {e:#}");
                return None;
            }
        };

        let dns_query = self.build_dns_wire_query(domain, query_type);

        let http_request = format!(
            "POST /dns-query HTTP/1.1\r\n\
             Host: dns.google\r\n\
             Content-Type: application/dns-message\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            dns_query.len()
        );

        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        if tls_stream.write_all(http_request.as_bytes()).await.is_err() {
            return None;
        }
        if tls_stream.write_all(&dns_query).await.is_err() {
            return None;
        }

        let mut response = Vec::with_capacity(1024);
        if tls_stream.read_to_end(&mut response).await.is_err() {
            return None;
        }

        let header_end = response.windows(4).position(|w| w == b"\r\n\r\n")?;
        let body = &response[header_end + 4..];

        if body.len() < 12 {
            return None;
        }

        let ancount = u16::from_be_bytes([body[6], body[7]]) as usize;
        if ancount == 0 {
            return None;
        }

        // Skip header (12) + question section
        let mut pos = 12;
        while pos < body.len() && body[pos] != 0 {
            pos += 1 + body[pos] as usize;
        }
        pos += 1; // null terminator
        pos += 4; // QTYPE + QCLASS

        // Parse first answer NAME (handles compression pointers correctly)
        loop {
            if pos >= body.len() {
                return None;
            }
            let len = body[pos];
            if len == 0 {
                pos += 1;
                break;
            } else if (len & 0xC0) == 0xC0 {
                pos += 2; // Pointer terminates the name
                break;
            } else {
                pos += 1 + len as usize;
            }
        }

        if pos + 10 > body.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let rdlength = u16::from_be_bytes([body[pos + 8], body[pos + 9]]) as usize;
        pos += 10;

        if rtype == 1 && rdlength == 4 && pos + 4 <= body.len() {
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                body[pos],
                body[pos + 1],
                body[pos + 2],
                body[pos + 3],
            ));
            return Some(ip);
        } else if rtype == 28 && rdlength == 16 && pos + 16 <= body.len() {
            let mut ipv6_bytes = [0u8; 16];
            ipv6_bytes.copy_from_slice(&body[pos..pos + 16]);
            let ip = IpAddr::V6(std::net::Ipv6Addr::from(ipv6_bytes));
            return Some(ip);
        }

        None
    }

    fn build_dns_wire_query(&self, domain: &str, query_type: u16) -> Vec<u8> {
        let mut query = Vec::with_capacity(12 + domain.len() + 6);
        let txn_id = (crate::desync::rand::random_u32() & 0xFFFF) as u16;
        query.extend_from_slice(&txn_id.to_be_bytes()); // Transaction ID
        query.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: standard query, RD=1
        query.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        query.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
        query.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
        query.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

        for label in domain.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0); // Root label

        query.extend_from_slice(&query_type.to_be_bytes()); // QTYPE
        query.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

        query
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

        let zero_config = Arc::new(crate::proxy::zero_config::ZeroConfigEngine::new(
            crate::config::ZeroConfigConfig {
                enabled: false,
                ..Default::default()
            },
        ));
        let engine = DnsProxyEngine::new(config, fake_ip, geo, zero_config);

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
