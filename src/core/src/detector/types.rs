use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Role of a canary domain in detecting whitelist drop-all censorship.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanaryRole {
    /// Domestically whitelisted (e.g. gosuslugi.ru) - must succeed if internet is up.
    Positive,
    /// International/neutral site - will fail if drop-all whitelist is active.
    Negative,
}

/// A canary domain configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryDomain {
    pub domain: String,
    pub role: CanaryRole,
}

/// Outcome of a connection probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    Success,
    ResetByPeer,
    Timeout,
    TlsFailure,
    Error,
}

/// Result of a single domain connection probe.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub domain: String,
    pub ip: IpAddr,
    pub outcome: ProbeOutcome,
    pub tcp_success: bool, // True if TCP connected before TLS stage
    pub rtt: Duration,
    pub timestamp: Instant,
}

/// Whitelist state.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WhitelistState {
    Unknown,
    Inactive,
    Active { confidence: f32, l7_sni_based: bool },
}
