use std::net::{IpAddr, Ipv4Addr};

use super::flow::{Direction, Endpoint, FlowKey, L4Proto};

#[derive(Debug, Clone, Copy)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
}

#[derive(Debug)]
pub struct PacketEvent<'a> {
    pub ts_ms: u128,

    pub flow: FlowKey,
    pub dir: Direction,
    pub proto: L4Proto,

    pub src_port: u16,
    pub dst_port: u16,

    pub tcp_flags: Option<TcpFlags>,

    pub payload: &'a [u8],
}

// !! Duplicate code as to not have merge conflicts, refactoring parser later
/// Decode only what needed for flow tracking
/// FOR NOW: Returns None if it's not Eth+IPv4+TCP
pub fn decode_ipv4_l4<'a>(ts_ms: u128, data: &'a [u8], datalink: i32) -> Option<PacketEvent<'a>> {
    
    // Picking where the IPv4 header starts depending on link type
    let ip: &'a [u8] = match datalink {
        // Ethernet
        1 => {
            /*
            data[..6]   : dest MAC
            data[6..12] : src MAC
            data[12..14]: EtherType
            */
            if data.len() < 14 { return None; }
            let ether_type = u16::from_be_bytes([data[12], data[13]]);
            if ether_type != 0x0800 { return None; } // IPv4 only
            &data[14..]
        }

        // DLT_NULL (0) / DLT_LOOP (often 12): 4-byte family header then IP.
        // Family is typically AF_INET = 2, often host-endian in DLT_NULL.
        0 | 12 => {
            if data.len() < 4 { return None; }
            let fam_ne = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
            let fam_swapped = fam_ne.swap_bytes();
            let is_ipv4 = fam_ne == 2 || fam_swapped == 2;
            if !is_ipv4 { return None; }
            &data[4..]
        }

        // DLT_RAW (often 101): packet begins with IP header
        101 => data,

        // Unknown: try a best-effort fallback:
        // - if looks like IPv4 header (version nibble == 4), treat as raw
        // - else if looks like Ethernet+IPv4, treat as Ethernet
        _ => {
            if data.len() >= 1 && (data[0] >> 4) == 4 {
                data
            } else if data.len() >= 14 {
                let ether_type = u16::from_be_bytes([data[12], data[13]]);
                if ether_type == 0x0800 {
                    &data[14..]
                } else {
                    return None;
                }
            } else {
                return None;
            }
        }
    };

    // IPv4 Header: >= 20 bytes
    if ip.len() < 20 {
        return None;
    }

    // IP Version check -> High nibble
    let version = ip[0] >> 4;
    if version != 4 {
        return None;
    }

    // Internet Header Length -> Low nibble
    let ihl = ip[0] & 0x0F;
    let ip_header_len = (ihl as usize) * 4;
    if ip.len() < ip_header_len {
        return None;
    }

    let proto = ip[9];

    let src_ip = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst_ip = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);

    let l4 = &ip[ip_header_len..];


    match proto {
        // TCP 
        6 => {
            // TCP Header >= 20 bytes
            if l4.len() < 20 { return None; }

            let src_port = u16::from_be_bytes([l4[0], l4[1]]);
            let dst_port = u16::from_be_bytes([l4[2], l4[3]]);

            // Check TCP header length is in data offset field: high nibble of byte 12
            let data_offset_words = (l4[12] >> 4) as usize;
            let tcp_header_len = data_offset_words * 4;
            if l4.len() < tcp_header_len { return None; }

            let flags = l4[13];
            let tcp_flags = TcpFlags {
                fin: flags & 0x01 != 0,
                syn: flags & 0x02 != 0,
                rst: flags & 0x04 != 0,
                psh: flags & 0x08 != 0,
                ack: flags & 0x10 != 0,
            };

            // Everything after the TCP header is application data 
            let payload = &l4[tcp_header_len..];

            let src = Endpoint { ip: IpAddr::V4(src_ip), port: src_port };
            let dst = Endpoint { ip: IpAddr::V4(dst_ip), port: dst_port };
            let (flow, dir) = FlowKey::new(L4Proto::Tcp, src, dst);

            Some(PacketEvent {
                ts_ms,
                flow,
                dir,
                proto: L4Proto::Tcp,
                src_port,
                dst_port,
                tcp_flags: Some(tcp_flags),
                payload,
            })
        }

        17 => {
            // UDP
            if l4.len() < 8 { return None; }

            let src_port = u16::from_be_bytes([l4[0], l4[1]]);
            let dst_port = u16::from_be_bytes([l4[2], l4[3]]);

            // UDP header is fixed 8 bytes
            let payload = &l4[8..];

            let src = Endpoint { ip: IpAddr::V4(src_ip), port: src_port };
            let dst = Endpoint { ip: IpAddr::V4(dst_ip), port: dst_port };
            let (flow, dir) = FlowKey::new(L4Proto::Udp, src, dst);

            Some(PacketEvent {
                ts_ms,
                flow,
                dir,
                proto: L4Proto::Udp,
                src_port,
                dst_port,
                tcp_flags: None, // important
                payload,
            })
        }

        1 => {
            // ICMP (ping)
            if l4.len() < 4 { return None; } // type, code, checksum...
            let src = Endpoint { ip: IpAddr::V4(src_ip), port: 0 };
            let dst = Endpoint { ip: IpAddr::V4(dst_ip), port: 0 };
            let (flow, dir) = FlowKey::new(L4Proto::Icmp, src, dst);

            Some(PacketEvent {
                ts_ms,
                flow,
                dir,
                proto: L4Proto::Icmp,
                src_port: 0,
                dst_port: 0,
                tcp_flags: None,
                payload: l4, // or &l4[4..] if you prefer
            })
        }

        _ => None,
    }
}