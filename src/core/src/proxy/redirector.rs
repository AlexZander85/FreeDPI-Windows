use std::sync::Arc;
use std::time::Duration;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use super::socks5_client::{socks5_connect, socks5_handshake_auth};
use super::types::{OperaProxyPool, REDIRECTOR_PORT_RANGE};
use crate::desync::redirect_table::RedirectTable;

pub struct SocksRedirector {
    pub table: Arc<RedirectTable>,
    pub proxy_pool: Arc<OperaProxyPool>,
    pub custom_proxy: Arc<std::sync::RwLock<crate::config::CustomProxyConfig>>,
}

impl SocksRedirector {
    pub fn new(
        table: Arc<RedirectTable>,
        proxy_pool: Arc<OperaProxyPool>,
        custom_proxy: crate::config::CustomProxyConfig,
    ) -> Self {
        Self {
            table,
            proxy_pool,
            custom_proxy: Arc::new(std::sync::RwLock::new(custom_proxy)),
        }
    }

    pub fn update_custom_proxy(&self, cfg: crate::config::CustomProxyConfig) {
        let mut w = self.custom_proxy.write().unwrap();
        *w = cfg;
    }

    /// Пытается забиндить порт из диапазона 17650-17659 и запустить accept loop.
    pub async fn bind_and_run(self: Arc<Self>) -> anyhow::Result<u16> {
        let mut last_err = None;
        for port in REDIRECTOR_PORT_RANGE {
            match TcpListener::bind(("0.0.0.0", port)).await {
                Ok(listener) => {
                    info!("SocksRedirector listening on 0.0.0.0:{port}");
                    let this = self.clone();
                    tokio::spawn(async move {
                        this.accept_loop(listener).await;
                    });
                    return Ok(port);
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(anyhow::anyhow!(
            "failed to bind SocksRedirector on any port in 17650-17659: {:?}",
            last_err
        ))
    }

    async fn accept_loop(self: Arc<Self>, listener: TcpListener) {
        loop {
            match listener.accept().await {
                Ok((inbound, peer_addr)) => {
                    let this = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = this.handle(inbound, peer_addr.port()).await {
                            debug!("socks redirect session error: {e}");
                        }
                    });
                }
                Err(e) => {
                    warn!("SocksRedirector accept error: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    async fn handle(&self, mut inbound: TcpStream, client_src_port: u16) -> anyhow::Result<()> {
        let entry = self
            .table
            .get(client_src_port)
            .ok_or_else(|| anyhow::anyhow!("no redirect entry for port {client_src_port}"))?;

        let target_host = entry
            .domain
            .clone()
            .unwrap_or_else(|| entry.orig_dst_ip.to_string());

        let custom = { self.custom_proxy.read().unwrap().clone() };

        let mut outbound = if custom.enabled {
            // Try Custom Proxy first
            debug!(
                "SocksRedirector: routing via custom SOCKS5 proxy {}:{}",
                custom.host, custom.port
            );
            match TcpStream::connect((custom.host.as_str(), custom.port)).await {
                Ok(mut conn) => {
                    let u = custom.username.as_deref();
                    let p = custom.password.as_deref();
                    if let Err(e) = socks5_handshake_auth(&mut conn, u, p).await {
                        warn!("SocksRedirector: custom SOCKS5 handshake failed: {e}");
                        self.fallback_or_direct(&target_host, entry.orig_dst_port, &custom)
                            .await?
                    } else if let Err(e) =
                        socks5_connect(&mut conn, &target_host, entry.orig_dst_port).await
                    {
                        warn!("SocksRedirector: custom SOCKS5 connect failed: {e}");
                        self.fallback_or_direct(&target_host, entry.orig_dst_port, &custom)
                            .await?
                    } else {
                        conn
                    }
                }
                Err(e) => {
                    warn!(
                        "SocksRedirector: failed to connect to custom proxy: {e}. Trying fallback."
                    );
                    self.fallback_or_direct(&target_host, entry.orig_dst_port, &custom)
                        .await?
                }
            }
        } else {
            // Try Opera Proxy pool
            self.connect_via_opera(&target_host, entry.orig_dst_port)
                .await?
        };

        let bridge_result = copy_bidirectional(&mut inbound, &mut outbound).await;
        self.table.remove(client_src_port);

        match bridge_result {
            Ok((up, down)) => {
                debug!(
                    "bridge {target_host}:{} closed: {up}B up / {down}B down",
                    entry.orig_dst_port
                );
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
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
        let proxy_addr = self
            .proxy_pool
            .select_best()
            .ok_or_else(|| anyhow::anyhow!("no healthy opera proxy"))?;

        match TcpStream::connect(proxy_addr).await {
            Ok(mut conn) => {
                if let Err(e) = socks5_handshake_auth(&mut conn, None, None).await {
                    warn!("SocksRedirector: Opera SOCKS5 handshake failed: {e}");
                    self.proxy_pool.mark_result(proxy_addr, false);
                    self.connect_direct(host, port).await
                } else if let Err(e) = socks5_connect(&mut conn, host, port).await {
                    warn!("SocksRedirector: Opera SOCKS5 connect failed: {e}");
                    self.proxy_pool.mark_result(proxy_addr, false);
                    self.connect_direct(host, port).await
                } else {
                    self.proxy_pool.mark_result(proxy_addr, true);
                    Ok(conn)
                }
            }
            Err(e) => {
                warn!("SocksRedirector: failed to connect to Opera proxy {proxy_addr}: {e}. Trying direct connection.");
                self.proxy_pool.mark_result(proxy_addr, false);
                self.connect_direct(host, port).await
            }
        }
    }

    async fn connect_direct(&self, host: &str, port: u16) -> anyhow::Result<TcpStream> {
        debug!("SocksRedirector: connecting directly to {host}:{port}");
        let stream = TcpStream::connect((host, port)).await?;
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::desync::redirect_table::RedirectEntry;
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_socks_redirector_integration() {
        // 1. Start a mock SOCKS5 server that acts as an echo server after greeting/connect
        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = socks_listener.local_addr().unwrap().port();
        let socks_addr = socks_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = socks_listener.accept().await.unwrap();
            // Read greeting (Version, NMethods, Methods...)
            let mut greeting = [0u8; 3];
            socket.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting[0], 0x05);
            // Write greeting response (Version, SelectedMethod=NoAuth)
            socket.write_all(&[0x05, 0x00]).await.unwrap();

            // Read connect request
            let mut req_hdr = [0u8; 4];
            socket.read_exact(&mut req_hdr).await.unwrap();
            assert_eq!(req_hdr[0], 0x05); // Version
            assert_eq!(req_hdr[1], 0x01); // Connect command
            let atyp = req_hdr[3];
            // Read domain or IP
            let skip_len = match atyp {
                0x01 => 4 + 2,
                0x03 => {
                    let mut len = [0u8; 1];
                    socket.read_exact(&mut len).await.unwrap();
                    len[0] as usize + 2
                }
                _ => panic!("unsupported ATYP"),
            };
            let mut skip = vec![0u8; skip_len];
            socket.read_exact(&mut skip).await.unwrap();

            // Write connect response (Version=5, Success=0, Reserved=0, ATYP=1, IP=0.0.0.0, Port=0)
            socket
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();

            // Now echo back any received data
            let mut buf = [0u8; 1024];
            loop {
                match socket.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        socket.write_all(&buf[..n]).await.unwrap();
                    }
                    Err(_) => break,
                }
            }
        });

        // 2. Setup redirect table and proxy pool with the mock SOCKS5 address
        let table = Arc::new(RedirectTable::new());
        let pool = Arc::new(OperaProxyPool::new(vec![socks_addr]));

        let custom_cfg = crate::config::CustomProxyConfig {
            enabled: false,
            ..Default::default()
        };

        let redirector = Arc::new(SocksRedirector::new(table.clone(), pool, custom_cfg));
        // Bind to a random port in REDIRECTOR_PORT_RANGE
        let redirector_port = redirector.bind_and_run().await.unwrap();

        // 3. Populate RedirectTable with client port mapping
        let client_socket = tokio::net::TcpSocket::new_v4().unwrap();
        client_socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let client_port = client_socket.local_addr().unwrap().port();

        table.insert(
            client_port,
            RedirectEntry {
                orig_dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
                orig_dst_port: 80,
                domain: Some("test.com".to_string()),
                created_at: Instant::now(),
            },
        );

        // Connect client to redirector, pretending it was rewritten
        let redirector_addr = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            redirector_port,
        );
        let mut client_conn = client_socket.connect(redirector_addr).await.unwrap();

        // Write test data
        client_conn.write_all(b"hello world").await.unwrap();

        // Read response
        let mut response = [0u8; 11];
        client_conn.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"hello world");
    }
}
