pub mod http_tunnel;
pub mod redirector;
pub mod rewrite;
pub mod socks5_client;
pub mod surfeasy;
pub mod types;
pub mod zero_config;

pub fn base64_encode(data: &[u8]) -> String {
    const CHARSET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as usize;
        let b1 = if i + 1 < data.len() {
            data[i + 1] as usize
        } else {
            0
        };
        let b2 = if i + 2 < data.len() {
            data[i + 2] as usize
        } else {
            0
        };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        let c0 = CHARSET[(triple >> 18) & 63];
        let c1 = CHARSET[(triple >> 12) & 63];
        let c2 = CHARSET[(triple >> 6) & 63];
        let c3 = CHARSET[triple & 63];

        result.push(c0 as char);
        result.push(c1 as char);
        if i + 1 < data.len() {
            result.push(c2 as char);
        } else {
            result.push('=');
        }
        if i + 2 < data.len() {
            result.push(c3 as char);
        } else {
            result.push('=');
        }
        i += 3;
    }
    result
}

pub fn base64_encode_no_pad(data: &[u8]) -> String {
    let s = base64_encode(data);
    if let Some(truncated) = s.split('=').next() {
        truncated.to_string()
    } else {
        s
    }
}
