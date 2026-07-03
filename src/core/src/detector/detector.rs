use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::{debug, info, warn};

use super::types::{CanaryDomain, CanaryRole, ProbeOutcome, ProbeResult, WhitelistState};
use crate::proxy::zero_config::ZeroConfigEngine;

pub struct WhitelistDetector {
    canaries: Vec<CanaryDomain>,
    state_tag: AtomicU8, // 0 = Unknown, 1 = Inactive, 2 = Active
    state_detail: RwLock<WhitelistState>,
    zero_config: Arc<ZeroConfigEngine>,
    interval: Duration,
}

impl WhitelistDetector {
    pub fn new(
        canaries: Vec<CanaryDomain>,
        zero_config: Arc<ZeroConfigEngine>,
        interval_secs: u64,
    ) -> Self {
        Self {
            canaries,
            state_tag: AtomicU8::new(0),
            state_detail: RwLock::new(WhitelistState::Unknown),
            zero_config,
            interval: Duration::from_secs(interval_secs),
        }
    }

    pub fn current_state(&self) -> WhitelistState {
        *self.state_detail.read().unwrap()
    }

    pub fn start_loop(self: &Arc<Self>) {
        let detector = self.clone();
        tokio::spawn(async move {
            info!("T63: Whitelist detector background thread started.");
            loop {
                detector.run_detection_pass().await;
                sleep(detector.interval).await;
            }
        });
    }

    pub async fn run_detection_pass(&self) {
        if self.canaries.is_empty() {
            debug!("T63: Canary list is empty, skipping whitelist detection pass.");
            return;
        }

        let mut positive_ok = 0usize;
        let mut positive_total = 0usize;
        let mut negative_blocked = 0usize;
        let mut negative_total = 0usize;
        let mut l7_signal = 0usize;

        for canary in &self.canaries {
            // Resolve domain
            let ip = match tokio::net::lookup_host(format!("{}:443", canary.domain)).await {
                Ok(mut addrs) => addrs.next().map(|a| a.ip()),
                Err(_) => None,
            };

            let Some(resolved_ip) = ip else {
                debug!("T63: Failed to resolve canary domain: {}", canary.domain);
                match canary.role {
                    CanaryRole::Positive => {
                        positive_total += 1;
                    }
                    CanaryRole::Negative => {
                        negative_total += 1;
                        negative_blocked += 1; // Unresolvable under whitelist drop-all
                    }
                }
                continue;
            };

            let result = self.probe_domain(&canary.domain, resolved_ip).await;
            match canary.role {
                CanaryRole::Positive => {
                    positive_total += 1;
                    if result.outcome == ProbeOutcome::Success {
                        positive_ok += 1;
                    }
                }
                CanaryRole::Negative => {
                    negative_total += 1;
                    if matches!(
                        result.outcome,
                        ProbeOutcome::ResetByPeer
                            | ProbeOutcome::Timeout
                            | ProbeOutcome::TlsFailure
                    ) {
                        negative_blocked += 1;
                        if result.tcp_success
                            && matches!(
                                result.outcome,
                                ProbeOutcome::ResetByPeer | ProbeOutcome::TlsFailure
                            )
                        {
                            l7_signal += 1;
                        }
                    }
                }
            }
        }

        let new_state = self.aggregate(
            positive_ok,
            positive_total,
            negative_blocked,
            negative_total,
            l7_signal,
        );
        let old_state = *self.state_detail.read().unwrap();

        if new_state != old_state {
            info!(
                "T63: Whitelist state changed from {:?} to {:?}",
                old_state, new_state
            );
            *self.state_detail.write().unwrap() = new_state;

            let tag = match new_state {
                WhitelistState::Unknown => 0,
                WhitelistState::Inactive => 1,
                WhitelistState::Active { .. } => 2,
            };
            self.state_tag.store(tag, Ordering::Relaxed);

            // Dynamically notify ZeroConfigEngine
            match new_state {
                WhitelistState::Active { .. } => {
                    info!("T63: Whitelist Drop-All active! Triggering auto-activation of Zero-Config...");
                    self.zero_config.set_auto_active(true);
                }
                _ => {
                    self.zero_config.set_auto_active(false);
                }
            }
        } else {
            debug!("T63: Whitelist state remains {:?}", old_state);
        }
    }

    async fn probe_domain(&self, domain: &str, ip: IpAddr) -> ProbeResult {
        let start = Instant::now();
        let target = SocketAddr::new(ip, 443);

        // Stage 1: TCP Connect
        let tcp_result = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::TcpStream::connect(target),
        )
        .await;

        let mut stream = match tcp_result {
            Ok(Ok(s)) => s,
            Ok(Err(ref e)) => {
                let err_str = e.to_string();
                let outcome = if err_str.contains("connection reset") || err_str.contains("Reset") {
                    ProbeOutcome::ResetByPeer
                } else {
                    ProbeOutcome::Error
                };
                return ProbeResult {
                    domain: domain.to_string(),
                    ip,
                    outcome,
                    tcp_success: false,
                    rtt: start.elapsed(),
                    timestamp: Instant::now(),
                };
            }
            Err(_) => {
                return ProbeResult {
                    domain: domain.to_string(),
                    ip,
                    outcome: ProbeOutcome::Timeout,
                    tcp_success: false,
                    rtt: start.elapsed(),
                    timestamp: Instant::now(),
                };
            }
        };

        // Stage 2: TLS SNI Probe
        let outcome = self.probe_tls_sni(&mut stream, domain).await;

        ProbeResult {
            domain: domain.to_string(),
            ip,
            outcome,
            tcp_success: true,
            rtt: start.elapsed(),
            timestamp: Instant::now(),
        }
    }

    async fn probe_tls_sni(
        &self,
        stream: &mut tokio::net::TcpStream,
        domain: &str,
    ) -> ProbeOutcome {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let hello = build_minimal_client_hello(domain);
        if stream.write_all(&hello).await.is_err() {
            return ProbeOutcome::ResetByPeer;
        }

        let mut buf = [0u8; 5]; // TLS record header (Content Type, Version, Length)
        match tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut buf)).await {
            Ok(Ok(_)) => {
                if buf[0] == 0x16 {
                    ProbeOutcome::Success // Handshake (ServerHello)
                } else {
                    ProbeOutcome::TlsFailure // Alert or garbage
                }
            }
            Ok(Err(ref e)) => {
                let err_str = e.to_string();
                if err_str.contains("connection reset") || err_str.contains("Reset") {
                    ProbeOutcome::ResetByPeer
                } else {
                    ProbeOutcome::Error
                }
            }
            Err(_) => ProbeOutcome::Timeout,
        }
    }

    fn aggregate(
        &self,
        positive_ok: usize,
        positive_total: usize,
        negative_blocked: usize,
        negative_total: usize,
        l7_signal: usize,
    ) -> WhitelistState {
        if positive_total == 0 || negative_total < 3 {
            return WhitelistState::Unknown;
        }

        let positive_rate = positive_ok as f32 / positive_total as f32;
        let negative_block_rate = negative_blocked as f32 / negative_total as f32;

        // If less than 70% of whitelist/positive sites work, internet is likely down entirely
        if positive_rate < 0.7 {
            return WhitelistState::Unknown;
        }

        if negative_block_rate >= 0.7 {
            WhitelistState::Active {
                confidence: negative_block_rate,
                l7_sni_based: (l7_signal as f32 / negative_blocked.max(1) as f32) > 0.5,
            }
        } else {
            WhitelistState::Inactive
        }
    }
}

fn build_minimal_client_hello(sni: &str) -> Vec<u8> {
    let mut random = [0u8; 32];
    for (i, b) in random.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(37).wrapping_add(11);
    }

    let mut hello_body = Vec::new();
    hello_body.extend_from_slice(&[0x03, 0x03]); // legacy_version = TLS 1.2
    hello_body.extend_from_slice(&random);
    hello_body.push(0x00); // session_id length = 0

    let ciphers: &[u16] = &[0x1301, 0x1302, 0x1303, 0xc02f, 0xc030];
    hello_body.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
    for c in ciphers {
        hello_body.extend_from_slice(&c.to_be_bytes());
    }

    hello_body.push(0x01); // compression methods length
    hello_body.push(0x00); // null compression

    let mut extensions = Vec::new();

    // SNI (server_name, extension type 0x0000)
    let sni_bytes = sni.as_bytes();
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&((sni_bytes.len() + 3) as u16).to_be_bytes());
    sni_ext.push(0x00); // name_type = host_name
    sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(sni_bytes);
    extensions.extend_from_slice(&0x0000u16.to_be_bytes());
    extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_ext);

    // supported_versions = TLS 1.3
    let sv_ext: &[u8] = &[0x03, 0x04];
    extensions.extend_from_slice(&0x002bu16.to_be_bytes());
    extensions.extend_from_slice(&((1 + sv_ext.len()) as u16).to_be_bytes());
    extensions.push(sv_ext.len() as u8);
    extensions.extend_from_slice(sv_ext);

    hello_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello_body.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(0x01); // ClientHello
    let len = hello_body.len() as u32;
    handshake.extend_from_slice(&len.to_be_bytes()[1..]); // 3-byte length
    handshake.extend_from_slice(&hello_body);

    let mut record = Vec::new();
    record.push(0x16); // Content Type = Handshake
    record.extend_from_slice(&[0x03, 0x01]); // record version = TLS 1.0 (compatibility)
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ZeroConfigConfig;

    #[test]
    fn test_aggregate_logic() {
        let config = ZeroConfigConfig::default();
        let zero_config = Arc::new(ZeroConfigEngine::new(config));
        let detector = WhitelistDetector::new(Vec::new(), zero_config, 600);

        // Test Case 1: Positive rate is too low (likely offline)
        let state = detector.aggregate(1, 3, 3, 3, 2);
        assert_eq!(state, WhitelistState::Unknown);

        // Test Case 2: Positive rate OK, negative blocked rate low (ordinary internet)
        let state = detector.aggregate(3, 3, 0, 3, 0);
        assert_eq!(state, WhitelistState::Inactive);

        // Test Case 3: Whitelist drop-all active (high negative block, positive works)
        let state = detector.aggregate(3, 3, 3, 3, 2);
        assert!(
            matches!(state, WhitelistState::Active { confidence, l7_sni_based: true } if confidence >= 0.9)
        );
    }
}
