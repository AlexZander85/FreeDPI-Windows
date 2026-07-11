use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Ethernet,
    RawIp,
    Unsupported(u32),
}

#[derive(Debug)]
pub struct PcapPacket {
    pub ts_sec: u32,
    pub ts_frac: u32,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct PcapFile {
    pub link_type: LinkType,
    pub packets: Vec<PcapPacket>,
}

pub fn read_pcap(path: impl AsRef<Path>) -> io::Result<PcapFile> {
    let mut bytes = Vec::new();
    File::open(path)?.read_to_end(&mut bytes)?;

    if bytes.len() < 24 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "pcap header too short",
        ));
    }

    let magic_le = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let big_endian = match magic_le {
        0xa1b2c3d4 | 0xa1b23c4d => false,
        0xd4c3b2a1 | 0x4d3cb2a1 => true,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "bad pcap magic")),
    };

    let rd_u16 = |s: &[u8]| -> u16 {
        if big_endian {
            u16::from_be_bytes(s.try_into().unwrap())
        } else {
            u16::from_le_bytes(s.try_into().unwrap())
        }
    };
    let rd_u32 = |s: &[u8]| -> u32 {
        if big_endian {
            u32::from_be_bytes(s.try_into().unwrap())
        } else {
            u32::from_le_bytes(s.try_into().unwrap())
        }
    };

    let major = rd_u16(&bytes[4..6]);
    let _minor = rd_u16(&bytes[6..8]);
    if major != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported pcap version",
        ));
    }

    let snaplen = rd_u32(&bytes[16..20]) as usize;
    let network = rd_u32(&bytes[20..24]);
    let link_type = match network {
        1 => LinkType::Ethernet,
        101 => LinkType::RawIp,
        x => LinkType::Unsupported(x),
    };

    let mut pos = 24;
    let mut packets = Vec::new();

    while pos + 16 <= bytes.len() {
        let ts_sec = rd_u32(&bytes[pos..pos + 4]);
        let ts_frac = rd_u32(&bytes[pos + 4..pos + 8]);
        let incl_len = rd_u32(&bytes[pos + 8..pos + 12]) as usize;
        let orig_len = rd_u32(&bytes[pos + 12..pos + 16]) as usize;
        pos += 16;

        if incl_len > snaplen || incl_len > orig_len || pos + incl_len > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid or truncated pcap packet",
            ));
        }

        packets.push(PcapPacket {
            ts_sec,
            ts_frac,
            data: bytes[pos..pos + incl_len].to_vec(),
        });
        pos += incl_len;
    }

    Ok(PcapFile { link_type, packets })
}

pub fn network_packet(link: LinkType, frame: &[u8]) -> Option<&[u8]> {
    match link {
        LinkType::RawIp => Some(frame),
        LinkType::Ethernet => {
            if frame.len() < 14 {
                return None;
            }
            match u16::from_be_bytes([frame[12], frame[13]]) {
                0x0800 | 0x86dd => Some(&frame[14..]),
                0x8100 if frame.len() >= 18 => match u16::from_be_bytes([frame[16], frame[17]]) {
                    0x0800 | 0x86dd => Some(&frame[18..]),
                    _ => None,
                },
                _ => None,
            }
        }
        LinkType::Unsupported(_) => None,
    }
}
