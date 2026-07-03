//! SurfEasy API client — регистрация анонимного сеанса Opera VPN,
//! получение списка HTTPS-прокси и credentials для Proxy-Authorization.

use crate::proxy::base64_encode_no_pad;
use anyhow::{Context, Result};
use md5::{Digest, Md5};
use rand_core::RngCore;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::sync::Mutex;

const API_BASE: &str = "https://api2.sec-tunnel.com/v4";
const CLIENT_VERSION: &str = "Stable 114.0.5282.21";
const CLIENT_TYPE: &str = "se0316";
const OPERATING_SYSTEM: &str = "Windows";
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0";

#[derive(Debug, Deserialize)]
struct SeResponse<T> {
    data: T,
    #[serde(rename = "return_code")]
    return_code: SeReturnCode,
}

#[derive(Debug, Deserialize)]
struct SeReturnCode {
    code: i64,
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SeRegisterDeviceData {
    device_id: String,
}

#[derive(Debug, Deserialize)]
struct SeDevicePasswordData {
    device_password: String,
}

#[derive(Debug, Deserialize)]
struct SeGeoListData {
    geos: Vec<SeGeoEntry>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SeGeoEntry {
    pub country: Option<String>,
    pub country_code: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SeIpEntry {
    pub geo: Option<SeGeoEntry>,
    pub host: Option<String>,
    pub ip: String,
    pub ports: Vec<u16>,
}

#[derive(Debug, Deserialize)]
struct SeDiscoverData {
    ips: Vec<SeIpEntry>,
}

impl SeIpEntry {
    pub fn endpoint(&self) -> String {
        let port = self.ports.first().copied().unwrap_or(443);
        let host = self.host.as_deref().unwrap_or(&self.ip);
        format!("{host}:{port}")
    }
}

struct DigestState {
    realm: Option<String>,
    nonce: Option<String>,
    opaque: Option<String>,
    nc: u32,
}

pub struct SurfEasyClient {
    http: reqwest::Client,
    subscriber_email: String,
    subscriber_password: String,
    device_id: String,
    device_password: String,
    digest: Mutex<DigestState>,
}

impl Default for SurfEasyClient {
    fn default() -> Self {
        Self::new()
    }
}

impl SurfEasyClient {
    pub fn new() -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(
            "SE-Client-Version",
            HeaderValue::from_static(CLIENT_VERSION),
        );
        headers.insert(
            "SE-Operating-System",
            HeaderValue::from_static(OPERATING_SYSTEM),
        );
        headers.insert("User-Agent", HeaderValue::from_static(USER_AGENT));
        headers.insert("Accept", HeaderValue::from_static("application/json"));

        let http = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .expect("Failed to build reqwest client");

        let email = random_email_local_part();
        let password = random_hex_string(20);

        Self {
            http,
            subscriber_email: email,
            subscriber_password: password,
            device_id: String::new(),
            device_password: String::new(),
            digest: Mutex::new(DigestState {
                realm: None,
                nonce: None,
                opaque: None,
                nc: 0,
            }),
        }
    }

    pub async fn init(&mut self) -> Result<()> {
        self.anon_register().await?;
        self.login().await?;
        self.register_device().await?;
        self.device_generate_password().await?;
        Ok(())
    }

    pub async fn geo_list(&self) -> Result<Vec<SeGeoEntry>> {
        let params = vec![("device_id", self.device_id.as_str())];
        let data: SeGeoListData = self.rpc_call("geo_list", &params).await?;
        Ok(data.geos)
    }

    pub async fn discover(&self, country: &str) -> Result<Vec<SeIpEntry>> {
        let hash = capital_hex_sha1(&self.device_id);
        let params: Vec<(&str, &str)> =
            vec![("serial_no", hash.as_str()), ("requested_geo", country)];
        let data: SeDiscoverData = self.rpc_call("discover", &params).await?;
        Ok(data.ips)
    }

    pub fn proxy_credentials(&self) -> (&str, &str) {
        (&self.device_id, &self.device_password)
    }

    async fn anon_register(&self) -> Result<()> {
        let params = vec![
            ("email", self.subscriber_email.as_str()),
            ("password", self.subscriber_password.as_str()),
        ];
        self.rpc_call::<serde_json::Value>("register_subscriber", &params)
            .await?;
        Ok(())
    }

    async fn login(&self) -> Result<()> {
        let params = vec![
            ("login", self.subscriber_email.as_str()),
            ("password", self.subscriber_password.as_str()),
            ("client_type", CLIENT_TYPE),
        ];
        self.rpc_call::<serde_json::Value>("subscriber_login", &params)
            .await?;
        Ok(())
    }

    async fn register_device(&mut self) -> Result<()> {
        let device_hash = capital_hex_sha1(&self.subscriber_email);
        let params = vec![
            ("client_type", CLIENT_TYPE),
            ("device_hash", &device_hash),
            ("device_name", "Opera-Browser-Client"),
        ];
        let data: SeRegisterDeviceData = self.rpc_call("register_device", &params).await?;
        self.device_id = data.device_id;
        Ok(())
    }

    async fn device_generate_password(&mut self) -> Result<()> {
        let params = vec![("device_id", self.device_id.as_str())];
        let data: SeDevicePasswordData = self.rpc_call("device_generate_password", &params).await?;
        self.device_password = data.device_password;
        Ok(())
    }

    async fn rpc_call<T: DeserializeOwned>(
        &self,
        method: &str,
        params: &[(&str, &str)],
    ) -> Result<T> {
        let url = format!("{API_BASE}/{method}");
        let body = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, urlencode(v)))
            .collect::<Vec<_>>()
            .join("&");

        let auth_header = {
            let d = self.digest.lock().unwrap();
            if d.realm.is_some() {
                Some(self.make_digest_header("POST", &url, &d))
            } else {
                None
            }
        };

        match self
            .do_request::<T>(&url, method, &body, auth_header.as_deref())
            .await
        {
            Ok(data) => return Ok(data),
            Err(e) => {
                let err_msg = format!("{e:#}");
                if !err_msg.contains("HTTP 401") {
                    anyhow::bail!("SurfEasy API {method} failed: {err_msg}");
                }
            }
        }

        let challenge = self.get_digest_challenge(&url, &body).await?;

        {
            let mut d = self.digest.lock().unwrap();
            d.realm = Some(challenge.0);
            d.nonce = Some(challenge.1);
            d.opaque = challenge.2;
            d.nc = 0;
        }

        let auth_header = {
            let d = self.digest.lock().unwrap();
            self.make_digest_header("POST", &url, &d)
        };

        self.do_request::<T>(&url, method, &body, Some(&auth_header))
            .await
            .with_context(|| format!("SurfEasy API {method} failed with Digest auth"))
    }

    async fn do_request<T: DeserializeOwned>(
        &self,
        url: &str,
        _method: &str,
        body: &str,
        auth: Option<&str>,
    ) -> Result<T> {
        let mut req = self
            .http
            .post(url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body.to_owned());

        if let Some(auth_val) = auth {
            req = req.header("Authorization", auth_val);
        }

        let resp = req.send().await?;
        let status = resp.status();

        if !status.is_success() && status != 401 {
            let text = resp.text().await?;
            anyhow::bail!("HTTP {status}: {text}");
        }

        if status == 401 {
            anyhow::bail!("HTTP 401 Unauthorized");
        }

        let text = resp.text().await?;
        let se_resp: SeResponse<T> = serde_json::from_str(&text)
            .with_context(|| format!("Failed to parse response: {text:.100}"))?;

        if se_resp.return_code.code != 0 {
            anyhow::bail!(
                "API error {}: {}",
                se_resp.return_code.code,
                se_resp.return_code.message.as_deref().unwrap_or("unknown")
            );
        }

        Ok(se_resp.data)
    }

    async fn get_digest_challenge(
        &self,
        url: &str,
        body: &str,
    ) -> Result<(String, String, Option<String>)> {
        let resp = self
            .http
            .post(url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body.to_owned())
            .send()
            .await?;

        let status = resp.status();
        if status != 401 {
            let text = resp.text().await?;
            anyhow::bail!("Expected 401 for Digest challenge, got {status}: {text}");
        }

        let www_auth = resp
            .headers()
            .get("www-authenticate")
            .context("401 without WWW-Authenticate")?
            .to_str()
            .map_err(|e| anyhow::anyhow!("Invalid WWW-Authenticate header: {e}"))?;

        let realm = extract_digest_param(www_auth, "realm")
            .ok_or_else(|| anyhow::anyhow!("Missing realm in WWW-Authenticate"))?
            .to_string();
        let nonce = extract_digest_param(www_auth, "nonce")
            .ok_or_else(|| anyhow::anyhow!("Missing nonce in WWW-Authenticate"))?
            .to_string();
        let opaque = extract_digest_param(www_auth, "opaque").map(String::from);

        Ok((realm, nonce, opaque))
    }

    fn make_digest_header(&self, method: &str, uri: &str, state: &DigestState) -> String {
        let realm = state.realm.as_deref().unwrap_or("");
        let nonce = state.nonce.as_deref().unwrap_or("");
        let nc = state.nc + 1;
        let cnonce = random_hex_string(8);

        let ha1 = format!(
            "{:x}",
            Md5::digest(format!(
                "{}:{}:{}",
                self.subscriber_email, realm, self.subscriber_password
            ))
        );
        let ha2 = format!("{:x}", Md5::digest(format!("{method}:{uri}")));

        let qop = "auth";
        let response_input = format!("{ha1}:{nonce}:{nc:08x}:{cnonce}:{qop}:{ha2}");
        let response = format!("{:x}", Md5::digest(response_input));

        let mut auth = format!(
            r#"Digest username="{}", realm="{}", nonce="{}", uri="{}", qop={}, nc={:08x}, cnonce="{}", response="{}""#,
            self.subscriber_email, realm, nonce, uri, qop, nc, cnonce, response
        );
        if let Some(ref opaque) = state.opaque {
            auth.push_str(&format!(r#", opaque="{}""#, opaque));
        }
        auth
    }
}

fn capital_hex_sha1(input: &str) -> String {
    use sha1::Digest;
    format!("{:X}", sha1::Sha1::digest(input.as_bytes()))
}

fn random_email_local_part() -> String {
    let mut buf = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut buf);
    base64_encode_no_pad(&buf)
}

fn random_hex_string(byte_len: usize) -> String {
    let mut buf = vec![0u8; byte_len];
    rand_core::OsRng.fill_bytes(&mut buf);
    hex::encode(&buf)
}

fn urlencode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(b as char);
            }
            _ => {
                result.push_str(&format!("%{b:02X}"));
            }
        }
    }
    result
}

fn extract_digest_param<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    let pattern = format!(r#"{name}="#);
    let start = header.find(&pattern)?;
    let value_start = start + pattern.len();
    let rest = &header[value_start..];
    if let Some(stripped) = rest.strip_prefix('"') {
        let end = stripped.find('"')?;
        Some(&stripped[..end])
    } else {
        let end = rest
            .find([',', ' ', '\n'])
            .unwrap_or(rest.len());
        Some(&rest[..end])
    }
}
