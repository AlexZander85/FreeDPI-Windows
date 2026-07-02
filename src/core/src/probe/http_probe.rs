//! HTTP Probe — проверка HTTP application layer.
//!
//! Методика (из Ladon + dpi-detector):
//! 1. GET / → read up to 32KB
//! 2. Verdict: ok / cutoff / http_451 / redirect / timeout
//! 3. Redirect check: same domain = ok, foreign = ISP page
//! 4. RKN stub detection
//!
//! Источники:
//! - [Ladon](https://github.com/nickspaargaren/ladon): HTTP cutoff detection (32KB)
//! - [dpi-detector](https://github.com/Runnin4ik/dpi-detector): HTTP 451 + redirect + stub

use crate::probe::classifier::HttpFailureCode;
use crate::probe::config::ProbeConfig;
use crate::probe::rkn_stub::is_rkn_stub;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use tracing::debug;

/// Результат HTTP probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpProbeResult {
    pub verdict: HttpFailureCode,
    pub bytes_read: u64,
    pub redirect_url: Option<String>,
    pub latency_us: u64,
    // T50.2: expanded timing & metadata
    /// HTTP status code (200, 451, 302, etc.)
    pub status_code: u16,
    /// Total size of HTTP response headers in bytes
    pub headers_size: u64,
    /// Time to first byte of HTTP response (ms), 0 if failed
    pub first_byte_rtt_ms: f64,
    /// Total HTTP response time (ms), 0 if failed
    pub total_rtt_ms: f64,
}

// === T54.5: Default implementation ===
impl Default for HttpProbeResult {
    fn default() -> Self {
        Self {
            verdict: HttpFailureCode::Ok,
            bytes_read: 0,
            redirect_url: None,
            latency_us: 0,
            status_code: 0,
            headers_size: 0,
            first_byte_rtt_ms: 0.0,
            total_rtt_ms: 0.0,
        }
    }
}

/// Compute approximate HTTP response headers wire size.
fn compute_headers_size(headers: &reqwest::header::HeaderMap) -> u64 {
    let mut size: u64 = 15; // approximate "HTTP/1.1 200 OK\r\n"
    for (name, value) in headers {
        size += name.as_str().len() as u64 + 2; // ": "
        size += value.len() as u64 + 2; // value + "\r\n"
    }
    size += 2; // final \r\n
    size
}

/// HTTP Probe — GET request + response analysis.
pub struct HttpProbe {
    config: ProbeConfig,
    client: reqwest::Client,
}

impl HttpProbe {
    pub fn new(config: &ProbeConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(config.http_read_timeout)
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config: config.clone(),
            client,
        }
    }

    /// HTTP probe: GET / + response analysis.
    pub async fn probe(&self, _ip: Ipv4Addr, domain: &str) -> HttpProbeResult {
        let start = std::time::Instant::now();
        let url = format!("https://{}/", domain);

        match tokio::time::timeout(
            self.config.http_read_timeout,
            self.client.get(&url).header("Host", domain).send(),
        )
        .await
        {
            Ok(Ok(resp)) => {
                let first_byte_us = start.elapsed().as_micros() as u64;
                let first_byte_rtt_ms = first_byte_us as f64 / 1000.0;
                let status = resp.status().as_u16();
                let headers_size = compute_headers_size(resp.headers());

                // HTTP 451: legal block
                if status == 451 {
                    debug!("HTTP 451 for {}", domain);
                    return HttpProbeResult {
                        verdict: HttpFailureCode::Http451,
                        bytes_read: 0,
                        redirect_url: None,
                        latency_us: first_byte_us,
                        status_code: 451,
                        headers_size,
                        first_byte_rtt_ms,
                        total_rtt_ms: first_byte_rtt_ms,
                    };
                }

                // Check redirect
                if (300..400).contains(&status) {
                    let redirect_url = resp
                        .headers()
                        .get("location")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());

                    if let Some(ref redir) = redirect_url {
                        let is_same = redir.contains(domain)
                            || domain.ends_with(
                                &redir
                                    .split("://")
                                    .nth(1)
                                    .unwrap_or("")
                                    .split('/')
                                    .next()
                                    .unwrap_or(""),
                            );

                        return HttpProbeResult {
                            verdict: if is_same {
                                HttpFailureCode::RedirectSame
                            } else {
                                HttpFailureCode::RedirectForeign
                            },
                            bytes_read: 0,
                            redirect_url: Some(redir.clone()),
                            latency_us: first_byte_us,
                            status_code: status,
                            headers_size,
                            first_byte_rtt_ms,
                            total_rtt_ms: first_byte_rtt_ms,
                        };
                    }
                }

                // Read response body
                match resp.bytes().await {
                    Ok(body) => {
                        let total_rtt_ms = start.elapsed().as_micros() as f64 / 1000.0;
                        let bytes_read = body.len() as u64;

                        // Check for RKN stub (configurable substrings)
                        if is_rkn_stub(&body, &self.config) {
                            debug!("RKN stub detected for {}", domain);
                            return HttpProbeResult {
                                verdict: HttpFailureCode::StubPage,
                                bytes_read,
                                redirect_url: None,
                                latency_us: first_byte_us,
                                status_code: status,
                                headers_size,
                                first_byte_rtt_ms,
                                total_rtt_ms,
                            };
                        }

                        // Check for cutoff (response too small)
                        if bytes_read < 1000 && status == 200 {
                            debug!("HTTP cutoff for {}: only {} bytes", domain, bytes_read);
                            return HttpProbeResult {
                                verdict: HttpFailureCode::Cutoff,
                                bytes_read,
                                redirect_url: None,
                                latency_us: first_byte_us,
                                status_code: status,
                                headers_size,
                                first_byte_rtt_ms,
                                total_rtt_ms,
                            };
                        }

                        HttpProbeResult {
                            verdict: HttpFailureCode::Ok,
                            bytes_read,
                            redirect_url: None,
                            latency_us: first_byte_us,
                            status_code: status,
                            headers_size,
                            first_byte_rtt_ms,
                            total_rtt_ms,
                        }
                    }
                    Err(e) => {
                        debug!("HTTP read error for {}: {}", domain, e);
                        let failed_total_ms = start.elapsed().as_micros() as f64 / 1000.0;
                        HttpProbeResult {
                            verdict: HttpFailureCode::Cutoff,
                            bytes_read: 0,
                            redirect_url: None,
                            latency_us: first_byte_us,
                            status_code: status,
                            headers_size,
                            first_byte_rtt_ms,
                            total_rtt_ms: failed_total_ms,
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                debug!("HTTP request error for {}: {}", domain, e);
                HttpProbeResult {
                    verdict: HttpFailureCode::Timeout,
                    bytes_read: 0,
                    redirect_url: None,
                    latency_us: start.elapsed().as_micros() as u64,
                    status_code: 0,
                    headers_size: 0,
                    first_byte_rtt_ms: 0.0,
                    total_rtt_ms: 0.0,
                }
            }
            Err(_) => {
                debug!("HTTP timeout for {}", domain);
                HttpProbeResult {
                    verdict: HttpFailureCode::Timeout,
                    bytes_read: 0,
                    redirect_url: None,
                    latency_us: self.config.http_read_timeout.as_micros() as u64,
                    status_code: 0,
                    headers_size: 0,
                    first_byte_rtt_ms: 0.0,
                    total_rtt_ms: 0.0,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_probe_result_serialization() {
        let result = HttpProbeResult {
            verdict: HttpFailureCode::Cutoff,
            bytes_read: 500,
            redirect_url: Some("https://other.com".into()),
            latency_us: 12000,
            status_code: 200,
            headers_size: 128,
            first_byte_rtt_ms: 45.0,
            total_rtt_ms: 120.0,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: HttpProbeResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.verdict, HttpFailureCode::Cutoff);
        assert_eq!(back.bytes_read, 500);
        assert_eq!(back.status_code, 200);
        assert_eq!(back.headers_size, 128);
        assert!((back.first_byte_rtt_ms - 45.0).abs() < 0.001);
        assert!((back.total_rtt_ms - 120.0).abs() < 0.001);
    }

    #[test]
    fn test_compute_headers_size_empty() {
        let headers = reqwest::header::HeaderMap::new();
        assert_eq!(compute_headers_size(&headers), 17); // status line + final \r\n
    }

    #[test]
    fn test_compute_headers_size_with_values() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("content-type", "text/html".parse().unwrap());
        headers.insert("content-length", "1234".parse().unwrap());
        let size = compute_headers_size(&headers);
        // 15 (status) + (12+2+9+2) "content-type: text/html\r\n" + (14+2+4+2) "content-length: 1234\r\n" + 2 (final \r\n)
        // = 15 + 25 + 22 + 2 = 64
        assert_eq!(size, 64);
    }
}
