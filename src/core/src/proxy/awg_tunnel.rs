use dashmap::DashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use wireguard_sans_io::{
    Config, Encapsulated, EntropyError, EntropySource, Now, PollOutput, Received, SendReason,
    StaticSecret, Tunnel,
};

use crate::config::AwgConfig;
use crate::packet_engine::PacketEngine;
use crate::proxy::awg_obfuscator::{AwgObfuscationConfig, AwgObfuscator};

/// Standard IPv4 checksum implementation
fn ipv4_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for i in (0..data.len()).step_by(2) {
        if i + 1 < data.len() {
            let word = u16::from_be_bytes([data[i], data[i + 1]]) as u32;
            sum += word;
        } else {
            let word = u16::from_be_bytes([data[i], 0]) as u32;
            sum += word;
        }
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

struct OsEntropy;
impl EntropySource for OsEntropy {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), EntropyError> {
        use rand::RngCore;
        rand::thread_rng()
            .try_fill_bytes(buf)
            .map_err(|_| EntropyError)
    }
}

struct ParsedUdp {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    _payload_offset: usize,
}

fn parse_ipv4_udp(data: &[u8]) -> Option<ParsedUdp> {
    if data.len() < 28 {
        return None;
    }
    let ver_ihl = data[0];
    let version = ver_ihl >> 4;
    let ihl = (ver_ihl & 0x0f) as usize * 4;
    if version != 4 || data.len() < ihl + 8 {
        return None;
    }
    let protocol = data[9];
    if protocol != 17 {
        // UDP
        return None;
    }
    let mut src_ip_bytes = [0u8; 4];
    src_ip_bytes.copy_from_slice(&data[12..16]);
    let src_ip = Ipv4Addr::from(src_ip_bytes);

    let mut dst_ip_bytes = [0u8; 4];
    dst_ip_bytes.copy_from_slice(&data[16..20]);
    let dst_ip = Ipv4Addr::from(dst_ip_bytes);

    let src_port = u16::from_be_bytes([data[ihl], data[ihl + 1]]);
    let dst_port = u16::from_be_bytes([data[ihl + 2], data[ihl + 3]]);

    Some(ParsedUdp {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        _payload_offset: ihl + 8,
    })
}

fn rewrite_ipv4_udp(
    data: &mut [u8],
    new_src_ip: Ipv4Addr,
    new_src_port: u16,
    new_dst_ip: Ipv4Addr,
    new_dst_port: u16,
) {
    let ver_ihl = data[0];
    let ihl = (ver_ihl & 0x0f) as usize * 4;

    data[12..16].copy_from_slice(&new_src_ip.octets());
    data[16..20].copy_from_slice(&new_dst_ip.octets());

    data[ihl..ihl + 2].copy_from_slice(&new_src_port.to_be_bytes());
    data[ihl + 2..ihl + 4].copy_from_slice(&new_dst_port.to_be_bytes());

    // Recalculate IPv4 header checksum
    data[10] = 0;
    data[11] = 0;
    let cksum = ipv4_checksum(&data[0..ihl]);
    data[10..12].copy_from_slice(&cksum.to_be_bytes());

    // Clear UDP checksum (optional in IPv4, prevents recalculation)
    data[ihl + 6] = 0;
    data[ihl + 7] = 0;
}

fn base64_decode(input: &str) -> Option<[u8; 32]> {
    let input = input.trim();
    if input.is_empty() {
        return None;
    }
    let mut bytes = Vec::new();
    let mut current = 0u32;
    let mut bits = 0;
    for c in input.chars() {
        if c == '=' {
            break;
        }
        let val = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            _ => continue,
        };
        current = (current << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((current >> bits) as u8);
        }
    }
    if bytes.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[0..32]);
        Some(arr)
    } else {
        None
    }
}

pub struct AwgTunnel {
    socket: Arc<UdpSocket>,
    tunnel: Arc<Mutex<Tunnel>>,
    obfuscator: Arc<AwgObfuscator>,
    nat_table: Arc<DashMap<u16, (Ipv4Addr, u16)>>,
    virtual_ip: Ipv4Addr,
    endpoint: SocketAddr,
    start_time: std::time::Instant,
}

impl std::fmt::Debug for AwgTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwgTunnel")
            .field("virtual_ip", &self.virtual_ip)
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

impl AwgTunnel {
    pub async fn start(
        config: AwgConfig,
        packet_engine: Arc<PacketEngine>,
    ) -> anyhow::Result<Self> {
        let mut config = config;
        if config.private_key.trim().is_empty() || config.public_key.trim().is_empty() {
            info!("AWG: Private or public key not set, initiating auto-registration...");
            match auto_register_warp_device().await {
                Ok((priv_key, pub_key, v4_ip)) => {
                    info!("AWG: Auto-registration successful!");
                    info!("AWG: Assigned Virtual IP: {v4_ip}");
                    info!("AWG: Peer Public Key: {pub_key}");
                    config.private_key = priv_key;
                    config.public_key = pub_key;
                    config.address = v4_ip;
                }
                Err(e) => {
                    anyhow::bail!("AWG auto-registration failed: {e:#}");
                }
            }
        }

        let private_bytes = base64_decode(&config.private_key)
            .ok_or_else(|| anyhow::anyhow!("Invalid base64 private key"))?;
        let public_bytes = base64_decode(&config.public_key)
            .ok_or_else(|| anyhow::anyhow!("Invalid base64 public key"))?;

        let local_static = StaticSecret::from(private_bytes);
        let peer_public = wireguard_sans_io::PublicKey::from(public_bytes);

        let virtual_ip: Ipv4Addr = config
            .address
            .split('/')
            .next()
            .unwrap_or("10.0.0.2")
            .parse()?;

        // Bind socket on local ephemeral port
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let endpoint: SocketAddr = config.endpoint.parse()?;
        socket.connect(endpoint).await?;
        let socket = Arc::new(socket);

        let tunnel_config = Config::new(local_static, peer_public);
        let tunnel = Arc::new(Mutex::new(Tunnel::new(tunnel_config)?));

        let obf_config = AwgObfuscationConfig {
            jc: config.jc,
            jmin: config.jmin,
            jmax: config.jmax,
            s1: config.s1,
            s2: config.s2,
            s3: config.s3,
            s4: config.s4,
            h1: config.h1,
            h2: config.h2,
            h3: config.h3,
            h4: config.h4,
        };
        let obfuscator = Arc::new(AwgObfuscator::new(obf_config));
        let nat_table = Arc::new(DashMap::<u16, (Ipv4Addr, u16)>::new());

        let start_time = std::time::Instant::now();

        // Spawn read and timer tasks
        let socket_clone = Arc::clone(&socket);
        let tunnel_clone = Arc::clone(&tunnel);
        let obf_clone = Arc::clone(&obfuscator);
        let nat_clone = Arc::clone(&nat_table);
        let engine_clone = Arc::clone(&packet_engine);

        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let mut decap_buf = vec![0u8; 2048];
            let mut rng = OsEntropy;

            loop {
                match socket_clone.recv(&mut buf).await {
                    Ok(len) => {
                        let packet_slice = &mut buf[0..len];
                        let packet_len = match obf_clone.deobfuscate_slice(packet_slice) {
                            Some(new_len) => new_len,
                            None => continue, // Discard invalid/junk packet
                        };
                        let deobf_packet = &packet_slice[..packet_len];

                        let mono_nanos = start_time.elapsed().as_nanos() as u64;
                        let system_time = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default();
                        let now = Now::new(
                            mono_nanos,
                            system_time.as_secs(),
                            system_time.subsec_nanos(),
                        );

                        let mut tunnel_guard = tunnel_clone.lock().await;
                        match tunnel_guard.decapsulate(
                            now,
                            &[],
                            false,
                            deobf_packet,
                            &mut decap_buf,
                            &mut rng,
                        ) {
                            Ok(Received::Data(plain)) => {
                                // Decrypted IP packet!
                                if let Some(parsed) = parse_ipv4_udp(plain) {
                                    if let Some(entry) = nat_clone.get(&parsed.dst_port) {
                                        let (client_ip, client_port) = *entry;
                                        let plain_len = plain.len();
                                        let mut plain_buf = [0u8; 2048];
                                        if plain_len <= 2048 {
                                            plain_buf[..plain_len].copy_from_slice(plain);
                                            let slice = &mut plain_buf[..plain_len];
                                            rewrite_ipv4_udp(
                                                slice,
                                                parsed.src_ip,
                                                parsed.src_port,
                                                client_ip,
                                                client_port,
                                            );
                                            let _ = engine_clone.inject_raw_udp(slice);
                                        } else {
                                            let mut plain_packet = plain.to_vec();
                                            rewrite_ipv4_udp(
                                                &mut plain_packet,
                                                parsed.src_ip,
                                                parsed.src_port,
                                                client_ip,
                                                client_port,
                                            );
                                            let _ = engine_clone.inject_raw_udp(&plain_packet);
                                        }
                                    }
                                }
                            }
                            Ok(Received::Reply(reply_bytes)) => {
                                let reply_len = reply_bytes.len();
                                let mut reply_buf = [0u8; 512];
                                if reply_len <= 512 {
                                    reply_buf[..reply_len].copy_from_slice(reply_bytes);
                                    if let (_, Some(new_len)) =
                                        obf_clone.obfuscate_slice(&mut reply_buf, reply_len)
                                    {
                                        let _ = socket_clone.send(&reply_buf[..new_len]).await;
                                    }
                                } else {
                                    let mut reply_vec = reply_bytes.to_vec();
                                    obf_clone.obfuscate(&mut reply_vec);
                                    let _ = socket_clone.send(&reply_vec).await;
                                }
                            }
                            Ok(Received::HandshakeComplete) => {
                                info!("AWG: Handshake complete!");
                            }
                            Err(e) => {
                                debug!("AWG decapsulate error: {e}");
                            }
                            _ => {}
                        }
                    }
                    Err(e) => {
                        error!("AWG socket recv error: {e}");
                        break;
                    }
                }
            }
        });

        // Spawn retransmission/keepalive timer task
        let socket_clone = Arc::clone(&socket);
        let tunnel_clone = Arc::clone(&tunnel);
        let obf_clone = Arc::clone(&obfuscator);
        tokio::spawn(async move {
            let mut poll_buf = vec![0u8; 2048];
            let mut rng = OsEntropy;

            loop {
                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

                let mono_nanos = start_time.elapsed().as_nanos() as u64;
                let system_time = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                let now = Now::new(
                    mono_nanos,
                    system_time.as_secs(),
                    system_time.subsec_nanos(),
                );

                let mut tunnel_guard = tunnel_clone.lock().await;
                if let Ok(PollOutput::Send(wire_bytes, reason)) =
                    tunnel_guard.poll(now, &mut poll_buf, &mut rng)
                {
                    let wire_len = wire_bytes.len();
                    let mut wire_buf = [0u8; 2048];
                    if wire_len <= 2048 {
                        wire_buf[..wire_len].copy_from_slice(wire_bytes);
                        if matches!(
                            reason,
                            SendReason::HandshakeInitiation | SendReason::HandshakeRetransmit
                        ) {
                            let _ = obf_clone.inject_junk_packets(&socket_clone, endpoint).await;
                        }
                        if let (_, Some(new_len)) =
                            obf_clone.obfuscate_slice(&mut wire_buf, wire_len)
                        {
                            let _ = socket_clone.send(&wire_buf[..new_len]).await;
                        }
                    } else {
                        let mut wire_vec = wire_bytes.to_vec();
                        if matches!(
                            reason,
                            SendReason::HandshakeInitiation | SendReason::HandshakeRetransmit
                        ) {
                            let _ = obf_clone.inject_junk_packets(&socket_clone, endpoint).await;
                        }
                        obf_clone.obfuscate(&mut wire_vec);
                        let _ = socket_clone.send(&wire_vec).await;
                    }
                }
            }
        });

        Ok(Self {
            socket,
            tunnel,
            obfuscator,
            nat_table,
            virtual_ip,
            endpoint,
            start_time,
        })
    }

    /// Tunnels a raw IP packet via AWG
    pub async fn send_ip_packet(&self, ip_packet: bytes::Bytes) -> anyhow::Result<()> {
        let parsed = parse_ipv4_udp(&ip_packet)
            .ok_or_else(|| anyhow::anyhow!("Invalid IPv4 UDP packet for AWG tunnel"))?;

        // Record NAT table mapping
        self.nat_table
            .insert(parsed.src_port, (parsed.src_ip, parsed.src_port));

        // Rewrite source address to virtual IP
        let len = ip_packet.len();
        let mut local_buf = [0u8; 2048];
        let mut local_vec;
        let ip_packet_mut = if len <= 2048 {
            local_buf[..len].copy_from_slice(&ip_packet);
            &mut local_buf[..len]
        } else {
            local_vec = ip_packet.to_vec();
            &mut local_vec[..]
        };

        rewrite_ipv4_udp(
            ip_packet_mut,
            self.virtual_ip,
            parsed.src_port,
            parsed.dst_ip,
            parsed.dst_port,
        );

        let mono_nanos = self.start_time.elapsed().as_nanos() as u64;
        let system_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let now = Now::new(
            mono_nanos,
            system_time.as_secs(),
            system_time.subsec_nanos(),
        );

        let mut encap_buf = [0u8; 2048];
        let mut rng = OsEntropy;

        let mut tunnel_guard = self.tunnel.lock().await;
        match tunnel_guard.encapsulate(now, ip_packet_mut, &mut encap_buf, &mut rng) {
            Ok(Encapsulated::Transport(wire_bytes)) => {
                let wire_len = wire_bytes.len();
                let mut wire_buf = [0u8; 2048];
                if wire_len <= 2048 {
                    wire_buf[..wire_len].copy_from_slice(wire_bytes);
                    if let (_, Some(new_len)) =
                        self.obfuscator.obfuscate_slice(&mut wire_buf, wire_len)
                    {
                        self.socket.send(&wire_buf[..new_len]).await?;
                    }
                } else {
                    let mut wire_vec = wire_bytes.to_vec();
                    self.obfuscator.obfuscate(&mut wire_vec);
                    self.socket.send(&wire_vec).await?;
                }
            }
            Ok(Encapsulated::HandshakeInitiation(wire_bytes)) => {
                let wire_len = wire_bytes.len();
                let mut wire_buf = [0u8; 2048];
                if wire_len <= 2048 {
                    wire_buf[..wire_len].copy_from_slice(wire_bytes);
                    let _ = self
                        .obfuscator
                        .inject_junk_packets(&self.socket, self.endpoint)
                        .await;
                    if let (_, Some(new_len)) =
                        self.obfuscator.obfuscate_slice(&mut wire_buf, wire_len)
                    {
                        self.socket.send(&wire_buf[..new_len]).await?;
                    }
                } else {
                    let mut wire_vec = wire_bytes.to_vec();
                    let _ = self
                        .obfuscator
                        .inject_junk_packets(&self.socket, self.endpoint)
                        .await;
                    self.obfuscator.obfuscate(&mut wire_vec);
                    self.socket.send(&wire_vec).await?;
                }
            }
            Err(e) => {
                anyhow::bail!("AWG encapsulate error: {e}");
            }
        }

        Ok(())
    }
}

async fn auto_register_warp_device() -> anyhow::Result<(String, String, String)> {
    let mut private_bytes = [0u8; 32];
    {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut private_bytes);
    }

    // Clamp Curve25519 private key
    private_bytes[0] &= 248;
    private_bytes[31] &= 127;
    private_bytes[31] |= 64;

    let local_static = StaticSecret::from(private_bytes);
    let public_key = local_static.public_key();

    let local_private_b64 = crate::proxy::base64_encode(&private_bytes);
    let local_public_b64 = crate::proxy::base64_encode(public_key.as_bytes());

    let client = reqwest::Client::builder()
        .user_agent("okhttp/3.12.1")
        .build()?;

    let payload = serde_json::json!({
        "key": local_public_b64,
        "install_id": "",
        "fcm_token": "",
        "tos": "2024-06-11T00:00:00Z",
        "model": "PC",
        "locale": "en_US"
    });

    let resp = client
        .post("https://api.cloudflareclient.com/v0a3121/reg")
        .json(&payload)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let err_text = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "Cloudflare WARP registration failed: Status {}, Body: {}",
            status,
            err_text
        );
    }

    let resp_json: serde_json::Value = resp.json().await?;

    let peer_public = resp_json["config"]["peers"][0]["public_key"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing peer public_key in response"))?
        .to_string();

    let virtual_ip = resp_json["config"]["interface"]["addresses"]["v4"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing interface v4 address in response"))?
        .to_string();

    Ok((local_private_b64, peer_public, virtual_ip))
}

#[cfg(test)]
mod registration_tests {
    use super::*;

    #[tokio::test]
    async fn test_auto_register_warp_device() {
        match auto_register_warp_device().await {
            Ok((priv_key, pub_key, v4_ip)) => {
                println!("Registration successful!");
                println!("Private key: {priv_key}");
                println!("Peer Public key: {pub_key}");
                println!("Virtual IP: {v4_ip}");
                assert!(!priv_key.is_empty());
                assert!(!pub_key.is_empty());
                assert!(v4_ip.contains('.'));
            }
            Err(e) => {
                println!("Registration failed/skipped (expected if offline): {e}");
            }
        }
    }
}
