use rand::{Rng, RngCore};
use std::net::SocketAddr;
use tokio::net::UdpSocket;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AwgObfuscationConfig {
    pub jc: usize,
    pub jmin: usize,
    pub jmax: usize,
    pub s1: usize,
    pub s2: usize,
    pub s3: usize,
    pub s4: usize,
    pub h1: u32,
    pub h2: u32,
    pub h3: u32,
    pub h4: u32,
}

impl Default for AwgObfuscationConfig {
    fn default() -> Self {
        Self {
            jc: 4,
            jmin: 40,
            jmax: 1000,
            s1: 120,
            s2: 60,
            s3: 0,
            s4: 0,
            h1: 0x01000000, // Standard little-endian 1
            h2: 0x02000000, // Standard little-endian 2
            h3: 0x03000000, // Standard little-endian 3
            h4: 0x04000000, // Standard little-endian 4
        }
    }
}

pub struct AwgObfuscator {
    config: AwgObfuscationConfig,
}

impl AwgObfuscator {
    pub fn new(config: AwgObfuscationConfig) -> Self {
        Self { config }
    }

    /// Obfuscates a standard WireGuard packet to match the AmneziaWG format.
    /// Returns whether the packet is a Handshake Initiation (which triggers junk packet injection).
    pub fn obfuscate(&self, packet: &mut Vec<u8>) -> bool {
        if packet.len() < 4 {
            return false;
        }

        let mut header_bytes = [0u8; 4];
        header_bytes.copy_from_slice(&packet[0..4]);
        let msg_type = u32::from_le_bytes(header_bytes);

        let mut is_initiation = false;

        match msg_type {
            1 => {
                // Handshake Initiation
                packet[0..4].copy_from_slice(&self.config.h1.to_le_bytes());
                if self.config.s1 > 0 {
                    let mut junk = vec![0u8; self.config.s1];
                    rand::thread_rng().fill_bytes(&mut junk);
                    packet.extend_from_slice(&junk);
                }
                is_initiation = true;
            }
            2 => {
                // Handshake Response
                packet[0..4].copy_from_slice(&self.config.h2.to_le_bytes());
                if self.config.s2 > 0 {
                    let mut junk = vec![0u8; self.config.s2];
                    rand::thread_rng().fill_bytes(&mut junk);
                    packet.extend_from_slice(&junk);
                }
            }
            3 => {
                // Cookie Reply
                packet[0..4].copy_from_slice(&self.config.h3.to_le_bytes());
                if self.config.s3 > 0 {
                    let mut junk = vec![0u8; self.config.s3];
                    rand::thread_rng().fill_bytes(&mut junk);
                    packet.extend_from_slice(&junk);
                }
            }
            4 => {
                // Transport Data
                packet[0..4].copy_from_slice(&self.config.h4.to_le_bytes());
                if self.config.s4 > 0 {
                    let mut junk = vec![0u8; self.config.s4];
                    rand::thread_rng().fill_bytes(&mut junk);
                    packet.extend_from_slice(&junk);
                }
            }
            _ => {}
        }

        is_initiation
    }

    /// De-obfuscates an incoming AmneziaWG packet to standard WireGuard format.
    /// Returns true if the packet was successfully de-obfuscated, or false if it is invalid/junk.
    pub fn deobfuscate(&self, packet: &mut Vec<u8>) -> bool {
        if packet.len() < 4 {
            return false;
        }

        let mut header_bytes = [0u8; 4];
        header_bytes.copy_from_slice(&packet[0..4]);
        let msg_type = u32::from_le_bytes(header_bytes);

        if msg_type == self.config.h1 {
            if packet.len() < 4 + self.config.s1 {
                return false;
            }
            packet[0..4].copy_from_slice(&1u32.to_le_bytes());
            packet.truncate(packet.len() - self.config.s1);
            true
        } else if msg_type == self.config.h2 {
            if packet.len() < 4 + self.config.s2 {
                return false;
            }
            packet[0..4].copy_from_slice(&2u32.to_le_bytes());
            packet.truncate(packet.len() - self.config.s2);
            true
        } else if msg_type == self.config.h3 {
            if packet.len() < 4 + self.config.s3 {
                return false;
            }
            packet[0..4].copy_from_slice(&3u32.to_le_bytes());
            packet.truncate(packet.len() - self.config.s3);
            true
        } else if msg_type == self.config.h4 {
            if packet.len() < 4 + self.config.s4 {
                return false;
            }
            packet[0..4].copy_from_slice(&4u32.to_le_bytes());
            packet.truncate(packet.len() - self.config.s4);
            true
        } else {
            // Unrecognized magic header, likely a standalone junk packet or garbled data
            false
        }
    }

    /// Injects Jc junk packets before the Handshake Initiation packet is sent.
    pub async fn inject_junk_packets(
        &self,
        socket: &UdpSocket,
        target: SocketAddr,
    ) -> std::io::Result<()> {
        if self.config.jc == 0 || self.config.jmax == 0 {
            return Ok(());
        }

        for _ in 0..self.config.jc {
            let size = rand::thread_rng().gen_range(self.config.jmin..=self.config.jmax);
            let mut junk = vec![0u8; size];
            rand::thread_rng().fill_bytes(&mut junk);
            let _ = socket.send_to(&junk, target).await;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_obfuscate_deobfuscate_initiation() {
        let config = AwgObfuscationConfig {
            jc: 2,
            jmin: 10,
            jmax: 20,
            s1: 50,
            s2: 30,
            s3: 0,
            s4: 0,
            h1: 0x11111111,
            h2: 0x22222222,
            h3: 0x33333333,
            h4: 0x44444444,
        };
        let obfuscator = AwgObfuscator::new(config);

        // Handshake Initiation starts with 1 u32
        let mut packet = 1u32.to_le_bytes().to_vec();
        packet.extend_from_slice(b"sample handshake data");
        let orig_len = packet.len();

        let is_init = obfuscator.obfuscate(&mut packet);
        assert!(is_init);
        assert_eq!(packet.len(), orig_len + 50);
        let header = u32::from_le_bytes([packet[0], packet[1], packet[2], packet[3]]);
        assert_eq!(header, 0x11111111);

        let valid = obfuscator.deobfuscate(&mut packet);
        assert!(valid);
        assert_eq!(packet.len(), orig_len);
        let restored_header = u32::from_le_bytes([packet[0], packet[1], packet[2], packet[3]]);
        assert_eq!(restored_header, 1);
    }
}
