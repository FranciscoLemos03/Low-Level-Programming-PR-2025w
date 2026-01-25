use crate::parser::{tcp, udp};
use std::net::Ipv6Addr;

pub fn parse(data: &[u8]) {
    if data.len() < 40 { return; }

    let version = data[0] >> 4;

    let next_header = data[6];
    let hop_limit = data[7]; // IPv6 equivalent of TTL


    let src_ip = &data[8..24];
    let dst_ip = &data[24..40];

    let src_addr = Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).unwrap());
    let dst_addr = Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).unwrap());

    println!(
        "  [IPv6] {} -> {} | Next: {} | Hop: {}",
        src_addr,
        dst_addr,
        next_header,
        hop_limit
    );

    let payload = &data[40..];
    if !payload.is_empty() {
        match next_header {
            6 => tcp::parse(payload, hop_limit),
            17 => udp::parse(payload),
            _ => {}
        }
    }
}