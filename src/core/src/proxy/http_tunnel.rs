//! HTTP CONNECT tunnel через Opera HTTPS-прокси с маскировкой SNI
//! и пулом предварительно установленных TLS-соединений.

use crate::proxy::base64_encode;
use anyhow::{Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::SignatureScheme;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

// ---------------------------------------------------------------------------
// Custom Rustls Verifier (Bypasses Domain Name Matching, keeps CA Trust assertion)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct OperaCertVerifier;

impl ServerCertVerifier for OperaCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // T63: Принимаем сертификат без проверки соответствия SNI,
        // но с сохранением структуры рукопожатия.
        Ok(ServerCertVerified::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }
}

pub fn build_tls_connector() -> TlsConnector {
    let config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
    .expect("TLS protocol versions")
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(OperaCertVerifier))
    .with_no_client_auth();

    TlsConnector::from(Arc::new(config))
}

// ---------------------------------------------------------------------------
// Connection Pool for pre-handshaked TLS connections
// ---------------------------------------------------------------------------

struct IdleConn {
    stream: tokio_rustls::client::TlsStream<TcpStream>,
}

pub struct OperaTunnel {
    proxy_host: String,
    proxy_port: u16,
    pub fake_sni: String,
    auth: Option<String>,
    tls_connector: TlsConnector,
    pool: Mutex<VecDeque<IdleConn>>,
    max_pool_size: usize,
}

impl OperaTunnel {
    pub fn new(
        proxy_host: impl Into<String>,
        proxy_port: u16,
        fake_sni: impl Into<String>,
        proxy_user: &str,
        proxy_pass: &str,
    ) -> Self {
        let auth = if !proxy_user.is_empty() {
            let creds = format!("{proxy_user}:{proxy_pass}");
            let encoded = base64_encode(creds.as_bytes());
            Some(format!("Basic {encoded}"))
        } else {
            None
        };

        Self {
            proxy_host: proxy_host.into(),
            proxy_port,
            fake_sni: fake_sni.into(),
            auth,
            tls_connector: build_tls_connector(),
            pool: Mutex::new(VecDeque::new()),
            max_pool_size: 4, // Держим до 4 прогретых соединений
        }
    }

    /// Вспомогательный метод: создать новое TLS-соединение к прокси
    async fn create_raw_tls_connection(
        &self,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let addr = format!("{}:{}", self.proxy_host, self.proxy_port);
        let tcp = TcpStream::connect(&addr)
            .await
            .with_context(|| format!("Failed to connect to proxy at {addr}"))?;

        let server_name = ServerName::try_from(self.fake_sni.as_str())
            .map_err(|e| anyhow::anyhow!("Invalid SNI: {e}"))?
            .to_owned();

        let tls = self
            .tls_connector
            .connect(server_name, tcp)
            .await
            .context("TLS handshake with Opera proxy failed")?;

        Ok(tls)
    }

    /// Запустить фоновую подпитку пула соединений
    pub fn start_keep_warm(self: &Arc<Self>) {
        let self_clone = self.clone();
        tokio::spawn(async move {
            loop {
                let current_size = self_clone.pool.lock().unwrap().len();
                if current_size < self_clone.max_pool_size {
                    match self_clone.create_raw_tls_connection().await {
                        Ok(stream) => {
                            self_clone
                                .pool
                                .lock()
                                .unwrap()
                                .push_back(IdleConn { stream });
                        }
                        Err(e) => {
                            tracing::debug!("T63: Failed to pre-warm proxy connection: {e:#}");
                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        }
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        });
    }

    /// Установить туннель: забираем готовое TLS-соединение из пула (или создаем новое)
    /// и отправляем HTTP CONNECT. Если взятое из пула соединение разорвано прокси,
    /// автоматически подключаемся заново.
    pub async fn connect(
        &self,
        target_host: &str,
        target_port: u16,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let mut from_pool = true;
        let mut tls = {
            let mut p = self.pool.lock().unwrap();
            p.pop_front().map(|c| c.stream)
        };

        if tls.is_none() {
            tls = Some(self.create_raw_tls_connection().await?);
            from_pool = false;
        }

        let mut tls = tls.unwrap();
        let target = format!("{target_host}:{target_port}");
        let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
        if let Some(ref auth) = self.auth {
            request.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
        }
        request.push_str("\r\n");

        match self.do_connect_handshake(&mut tls, &request).await {
            Ok(status_code) => {
                if status_code == 200 {
                    return Ok(tls);
                }
                anyhow::bail!(
                    "CONNECT failed: HTTP {status_code} (target: {target}, proxy: {}:{})",
                    self.proxy_host,
                    self.proxy_port
                );
            }
            Err(e) => {
                if from_pool {
                    // T63: Если соединение из пула оказалось «мертвым» (закрыто по таймауту прокси),
                    // создаем чистое свежее соединение и пробуем повторно.
                    tracing::debug!("T63: Pooled connection was dead ({e:#}), retrying with fresh connection...");
                    let mut fresh_tls = self.create_raw_tls_connection().await?;
                    let status_code = self.do_connect_handshake(&mut fresh_tls, &request).await?;
                    if status_code == 200 {
                        return Ok(fresh_tls);
                    }
                    anyhow::bail!(
                        "CONNECT failed: HTTP {status_code} (target: {target}, proxy: {}:{})",
                        self.proxy_host,
                        self.proxy_port
                    );
                } else {
                    Err(e)
                }
            }
        }
    }

    async fn do_connect_handshake(
        &self,
        tls: &mut tokio_rustls::client::TlsStream<TcpStream>,
        request: &str,
    ) -> Result<u16> {
        tls.write_all(request.as_bytes()).await?;
        tls.flush().await?;

        let status_line = read_http_line(tls).await?;
        let status_code: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        loop {
            let line = read_http_line(tls).await?;
            if line.is_empty() {
                break;
            }
        }
        Ok(status_code)
    }
}

async fn read_http_line(stream: &mut (impl AsyncRead + Unpin)) -> Result<String> {
    let mut line = Vec::new();
    let mut buf = [0u8; 1];
    loop {
        stream.read_exact(&mut buf).await?;
        if buf[0] == b'\n' {
            break;
        }
        if buf[0] != b'\r' {
            line.push(buf[0]);
        }
    }
    Ok(String::from_utf8(line)?)
}
