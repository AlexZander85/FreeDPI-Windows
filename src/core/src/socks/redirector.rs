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
    pub custom_proxy: Arc<std::sync::RwLock<crate::config::CustomProxyConfig>>,
}

impl SocksRedirector {
    pub fn new(table: Arc<RedirectTable>, custom_proxy: crate::config::CustomProxyConfig) -> Self {
        // Default runtime blocks on temp thread in Default impl of OperaVpnProvider
        let provider = OperaVpnProvider::default();
        Self {
            table,
            proxy_provider: Arc::new(Mutex::new(provider)),
            custom_proxy: Arc::new(std::sync::RwLock::new(custom_proxy)),
        }
    }

    /// Обновляет параметры кастомного прокси.
    pub fn update_custom_proxy(&self, cfg: crate::config::CustomProxyConfig) {
        let mut w = self.custom_proxy.write().unwrap();
        *w = cfg;
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

        let custom = { self.custom_proxy.read().unwrap().clone() };

        let mut outbound = if custom.enabled {
            debug!(
                "SocksRedirector: routing connection to {}:{} via custom SOCKS5 proxy {}:{}",
                target_host, entry.orig_dst_port, custom.host, custom.port
            );
            match TcpStream::connect((custom.host.as_str(), custom.port)).await {
                Ok(mut conn) => {
                    let u = custom.username.as_deref();
                    let p = custom.password.as_deref();
                    if let Err(e) = socks5_handshake_auth(&mut conn, u, p).await {
                        warn!("SocksRedirector: custom SOCKS5 handshake failed: {}", e);
                        self.fallback_or_direct(&target_host, entry.orig_dst_port, &custom)
                            .await?
                    } else if let Err(e) =
                        socks5_connect(&mut conn, &target_host, entry.orig_dst_port).await
                    {
                        warn!("SocksRedirector: custom SOCKS5 connect failed: {}", e);
                        self.fallback_or_direct(&target_host, entry.orig_dst_port, &custom)
                            .await?
                    } else {
                        conn
                    }
                }
                Err(e) => {
                    warn!(
                        "SocksRedirector: failed to connect to custom proxy: {}. Trying fallback.",
                        e
                    );
                    self.fallback_or_direct(&target_host, entry.orig_dst_port, &custom)
                        .await?
                }
            }
        } else {
            self.connect_via_opera(&target_host, entry.orig_dst_port)
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

    async fn fallback_or_direct(
        &self,
        host: &str,
        port: u16,
        custom: &crate::config::CustomProxyConfig,
    ) -> anyhow::Result<TcpStream> {
        if custom.use_opera_fallback {
            debug!("SocksRedirector: falling back to Opera SOCKS5 proxies");
            self.connect_via_opera(host, port).await
        } else {
            debug!("SocksRedirector: no fallback configured, trying direct connection");
            self.connect_direct(host, port).await
        }
    }

    async fn connect_via_opera(&self, host: &str, port: u16) -> anyhow::Result<TcpStream> {
        let proxy_opt = {
            let provider = self.proxy_provider.lock().await;
            let alive = provider.alive_proxies();
            if !alive.is_empty() {
                Some((alive[0].host.clone(), alive[0].port))
            } else {
                None
            }
        };

        if let Some((proxy_host, proxy_port)) = proxy_opt {
            debug!(
                "SocksRedirector: routing connection to {}:{} via Opera SOCKS5 proxy {}:{}",
                host, port, proxy_host, proxy_port
            );

            match TcpStream::connect((proxy_host.as_str(), proxy_port)).await {
                Ok(mut proxy_conn) => {
                    if let Err(e) = socks5_handshake_noauth(&mut proxy_conn).await {
                        warn!("SocksRedirector: Opera SOCKS5 handshake failed: {}", e);
                        self.connect_direct(host, port).await
                    } else if let Err(e) = socks5_connect(&mut proxy_conn, host, port).await {
                        warn!("SocksRedirector: Opera SOCKS5 connect failed: {}", e);
                        self.connect_direct(host, port).await
                    } else {
                        Ok(proxy_conn)
                    }
                }
                Err(e) => {
                    warn!(
                        "SocksRedirector: failed to connect to Opera proxy: {}. Trying direct connection.",
                        e
                    );
                    self.connect_direct(host, port).await
                }
            }
        } else {
            warn!("SocksRedirector: no alive Opera SOCKS5 proxies found. Falling back to direct connection.");
            self.connect_direct(host, port).await
        }
    }

    async fn connect_direct(&self, host: &str, port: u16) -> anyhow::Result<TcpStream> {
        debug!("SocksRedirector: connecting directly to {}:{}", host, port);
        let stream = TcpStream::connect((host, port)).await?;
        Ok(stream)
    }
}

/// SOCKS5 handshake с поддержкой аутентификации (RFC 1928 / RFC 1929).
async fn socks5_handshake_auth(
    s: &mut TcpStream,
    username: Option<&str>,
    password: Option<&str>,
) -> anyhow::Result<()> {
    if let (Some(u), Some(p)) = (username, password) {
        // Отправляем greeting: версия 5, 2 метода: без аутентификации (0x00) и User/Pass (0x02)
        s.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;

        let mut resp = [0u8; 2];
        s.read_exact(&mut resp).await?;
        if resp[0] != 0x05 {
            anyhow::bail!("SOCKS5 handshake failed");
        }

        if resp[1] == 0x02 {
            // Аутентификация User/Pass
            let mut req = Vec::new();
            req.push(0x01); // Версия субдоговора
            req.push(u.len() as u8);
            req.extend_from_slice(u.as_bytes());
            req.push(p.len() as u8);
            req.extend_from_slice(p.as_bytes());
            s.write_all(&req).await?;

            let mut auth_resp = [0u8; 2];
            s.read_exact(&mut auth_resp).await?;
            if auth_resp[0] != 0x01 || auth_resp[1] != 0x00 {
                anyhow::bail!("SOCKS5 authentication failed");
            }
        } else if resp[1] != 0x00 {
            anyhow::bail!("SOCKS5 proxy rejected authentication methods");
        }
    } else {
        socks5_handshake_noauth(s).await?;
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_socks5_handshake_noauth() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Spawn mock server
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            socket.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting[0], 0x05); // Version 5
            socket.write_all(&[0x05, 0x00]).await.unwrap(); // ChosenMethod NoAuth
        });

        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let res = socks5_handshake_auth(&mut client, None, None).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_socks5_handshake_auth_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Spawn mock server
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            // greeting (Version, NumMethods, Method1, Method2)
            let mut greeting = [0u8; 4];
            socket.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting[0], 0x05);
            socket.write_all(&[0x05, 0x02]).await.unwrap(); // ChosenMethod User/Pass (0x02)

            // Auth request
            let mut sub_ver = [0u8; 1];
            socket.read_exact(&mut sub_ver).await.unwrap();
            assert_eq!(sub_ver[0], 0x01);

            let mut ulen = [0u8; 1];
            socket.read_exact(&mut ulen).await.unwrap();
            let mut uname = vec![0u8; ulen[0] as usize];
            socket.read_exact(&mut uname).await.unwrap();
            assert_eq!(uname, b"user");

            let mut plen = [0u8; 1];
            socket.read_exact(&mut plen).await.unwrap();
            let mut pword = vec![0u8; plen[0] as usize];
            socket.read_exact(&mut pword).await.unwrap();
            assert_eq!(pword, b"pass");

            // Write auth response (success)
            socket.write_all(&[0x01, 0x00]).await.unwrap();
        });

        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let res = socks5_handshake_auth(&mut client, Some("user"), Some("pass")).await;
        assert!(res.is_ok());
    }
}
