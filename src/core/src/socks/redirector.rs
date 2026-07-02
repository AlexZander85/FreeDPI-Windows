use crate::desync::redirect_table::{RedirectEntry, RedirectTable};
use crate::routing::opera::OperaVpnProvider;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

pub struct SocksRedirector {
    table: Arc<RedirectTable>,
    proxy_provider: Arc<Mutex<OperaVpnProvider>>,
}

impl SocksRedirector {
    pub fn new(table: Arc<RedirectTable>) -> Self {
        // Default runtime blocks on temp thread in Default impl of OperaVpnProvider
        let provider = OperaVpnProvider::default();
        Self {
            table,
            proxy_provider: Arc::new(Mutex::new(provider)),
        }
    }

    /// Запуск SOCKS5 редиректора и фонового пинга прокси.
    pub async fn run(self: Arc<Self>, port: u16) -> std::io::Result<()> {
        // 1. Запуск фоновой проверки здоровья прокси
        let provider_clone = self.proxy_provider.clone();
        tokio::spawn(async move {
            info!("SocksRedirector: background proxy health checker started");
            loop {
                {
                    let mut provider = provider_clone.lock().await;
                    debug!("SocksRedirector: checking Opera proxy health...");
                    provider.check_health().await;
                }
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });

        // 2. Биндинг TCP-слушателя
        let listener = TcpListener::bind(("0.0.0.0", port)).await?;
        info!("SocksRedirector listening on 0.0.0.0:{}", port);

        loop {
            match listener.accept().await {
                Ok((inbound, peer_addr)) => {
                    let this = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = this.handle(inbound, peer_addr.port()).await {
                            debug!("SocksRedirector session error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("SocksRedirector accept failed: {}", e);
                }
            }
        }
    }

    async fn handle(&self, mut inbound: TcpStream, client_src_port: u16) -> anyhow::Result<()> {
        // Извлекаем оригинальный адрес из таблицы
        let entry = self.table.get(client_src_port).ok_or_else(|| {
            anyhow::anyhow!(
                "No redirect entry found for client port {}",
                client_src_port
            )
        })?;

        let target_host = entry
            .domain
            .clone()
            .unwrap_or_else(|| entry.orig_dst_ip.to_string());

        // 1. Выбираем лучший живой прокси
        let proxy_opt = {
            let provider = self.proxy_provider.lock().await;
            let alive = provider.alive_proxies();
            if !alive.is_empty() {
                // Выбираем первый живой
                Some((alive[0].host.clone(), alive[0].port))
            } else {
                None
            }
        };

        let mut outbound = if let Some((proxy_host, proxy_port)) = proxy_opt {
            debug!(
                "SocksRedirector: routing connection to {}:{} via SOCKS5 proxy {}:{}",
                target_host, entry.orig_dst_port, proxy_host, proxy_port
            );

            match TcpStream::connect((proxy_host.as_str(), proxy_port)).await {
                Ok(mut proxy_conn) => {
                    // SOCKS5 Handshake
                    if let Err(e) = socks5_handshake_noauth(&mut proxy_conn).await {
                        warn!("SocksRedirector: SOCKS5 handshake with proxy failed: {}", e);
                        // Fallback: connect direct
                        self.connect_direct(&target_host, entry.orig_dst_port)
                            .await?
                    } else if let Err(e) =
                        socks5_connect(&mut proxy_conn, &target_host, entry.orig_dst_port).await
                    {
                        warn!("SocksRedirector: SOCKS5 connect request failed: {}", e);
                        // Fallback: connect direct
                        self.connect_direct(&target_host, entry.orig_dst_port)
                            .await?
                    } else {
                        proxy_conn
                    }
                }
                Err(e) => {
                    warn!("SocksRedirector: failed to connect to proxy: {}. Trying direct connection.", e);
                    self.connect_direct(&target_host, entry.orig_dst_port)
                        .await?
                }
            }
        } else {
            warn!("SocksRedirector: no alive Opera SOCKS5 proxies found. Falling back to direct connection.");
            self.connect_direct(&target_host, entry.orig_dst_port)
                .await?
        };

        // 2. Запускаем copy_bidirectional
        let (from_client, from_target) = copy_bidirectional(&mut inbound, &mut outbound).await?;
        debug!(
            "SocksRedirector: connection to {}:{} closed (sent: {} bytes, received: {} bytes)",
            target_host, entry.orig_dst_port, from_client, from_target
        );

        // Очищаем таблицу после завершения
        self.table.remove(client_src_port);
        Ok(())
    }

    async fn connect_direct(&self, host: &str, port: u16) -> anyhow::Result<TcpStream> {
        debug!("SocksRedirector: connecting directly to {}:{}", host, port);
        let stream = TcpStream::connect((host, port)).await?;
        Ok(stream)
    }
}

/// SOCKS5 handshake без аутентификации (RFC 1928, метод 0x00).
async fn socks5_handshake_noauth(s: &mut TcpStream) -> anyhow::Result<()> {
    // Write SOCKS5 greeting: Version (0x05), NumMethods (0x01), Method NoAuth (0x00)
    s.write_all(&[0x05, 0x01, 0x00]).await?;

    // Read SOCKS5 response: Version, ChosenMethod
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await?;
    if resp[0] != 0x05 || resp[1] != 0x00 {
        anyhow::bail!("SOCKS5 handshake failed or authentication required");
    }
    Ok(())
}

/// SOCKS5 CONNECT по доменному имени (ATYP=0x03) или IP.
async fn socks5_connect(s: &mut TcpStream, host: &str, port: u16) -> anyhow::Result<()> {
    let mut req = Vec::new();
    req.extend_from_slice(&[0x05, 0x01, 0x00]); // Version, CMD Connect (0x01), Reserved (0x00)

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(ipv4) => {
                req.push(0x01); // ATYP IPv4 (0x01)
                req.extend_from_slice(&ipv4.octets());
            }
            std::net::IpAddr::V6(ipv6) => {
                req.push(0x04); // ATYP IPv6 (0x04)
                req.extend_from_slice(&ipv6.octets());
            }
        }
    } else {
        req.push(0x03); // ATYP Domain (0x03)
        req.push(host.len() as u8);
        req.extend_from_slice(host.as_bytes());
    }
    req.extend_from_slice(&port.to_be_bytes());

    s.write_all(&req).await?;

    // Read Connect Response
    let mut resp_header = [0u8; 4];
    s.read_exact(&mut resp_header).await?;
    if resp_header[0] != 0x05 || resp_header[1] != 0x00 {
        anyhow::bail!(
            "SOCKS5 connect request failed with code: {}",
            resp_header[1]
        );
    }

    // Read remaining address/port bytes based on ATYP to clear the buffer
    let atyp = resp_header[3];
    let skip_len = match atyp {
        0x01 => 4 + 2, // IPv4 + Port
        0x03 => {
            let mut len_byte = [0u8; 1];
            s.read_exact(&mut len_byte).await?;
            len_byte[0] as usize + 2 // Domain Length + Port
        }
        0x04 => 16 + 2, // IPv6 + Port
        _ => anyhow::bail!("Unsupported SOCKS5 ATYP: {}", atyp),
    };
    let mut skip_buf = vec![0u8; skip_len];
    s.read_exact(&mut skip_buf).await?;

    Ok(())
}
