use anyhow::{bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// SOCKS5 handshake с поддержкой аутентификации (RFC 1928 / RFC 1929).
pub async fn socks5_handshake_auth(
    s: &mut TcpStream,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<()> {
    if let (Some(u), Some(p)) = (username, password) {
        // Отправляем greeting: версия 5, 2 метода: без аутентификации (0x00) и User/Pass (0x02)
        s.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;

        let mut resp = [0u8; 2];
        s.read_exact(&mut resp).await?;
        if resp[0] != 0x05 {
            bail!("SOCKS5 handshake failed");
        }

        if resp[1] == 0x02 {
            // Аутентификация User/Pass (RFC 1929)
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
                bail!("SOCKS5 authentication failed");
            }
        } else if resp[1] != 0x00 {
            bail!("SOCKS5 proxy rejected authentication methods");
        }
    } else {
        socks5_handshake_noauth(s).await?;
    }
    Ok(())
}

/// SOCKS5 handshake без аутентификации (RFC 1928, метод 0x00).
pub async fn socks5_handshake_noauth(s: &mut TcpStream) -> Result<()> {
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await?;
    if resp[0] != 0x05 || resp[1] != 0x00 {
        bail!(
            "SOCKS5 handshake failed or authentication required (method={})",
            resp[1]
        );
    }
    Ok(())
}

/// SOCKS5 CONNECT. Если host — доменное имя, шлёт ATYP=0x03.
pub async fn socks5_connect(s: &mut TcpStream, host: &str, port: u16) -> Result<()> {
    let mut req = Vec::new();
    req.extend_from_slice(&[0x05, 0x01, 0x00]);

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(ipv4) => {
                req.push(0x01);
                req.extend_from_slice(&ipv4.octets());
            }
            std::net::IpAddr::V6(ipv6) => {
                req.push(0x04);
                req.extend_from_slice(&ipv6.octets());
            }
        }
    } else {
        if host.len() > 255 {
            bail!("domain name too long for SOCKS5: {} bytes", host.len());
        }
        req.push(0x03);
        req.push(host.len() as u8);
        req.extend_from_slice(host.as_bytes());
    }
    req.extend_from_slice(&port.to_be_bytes());

    s.write_all(&req).await?;

    let mut resp_header = [0u8; 4];
    s.read_exact(&mut resp_header).await?;
    if resp_header[0] != 0x05 || resp_header[1] != 0x00 {
        bail!("SOCKS5 CONNECT failed, REP={}", resp_header[1]);
    }

    // Дочитываем BND.ADDR/BND.PORT по фактическому ATYP
    let atyp = resp_header[3];
    let skip_len = match atyp {
        0x01 => 4 + 2,
        0x03 => {
            let mut len_byte = [0u8; 1];
            s.read_exact(&mut len_byte).await?;
            len_byte[0] as usize + 2
        }
        0x04 => 16 + 2,
        _ => bail!("unsupported SOCKS5 ATYP in response: {atyp}"),
    };
    let mut skip_buf = vec![0u8; skip_len];
    s.read_exact(&mut skip_buf).await?;

    Ok(())
}
