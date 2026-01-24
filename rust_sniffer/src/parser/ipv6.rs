use crate::parser::{tcp, udp};

pub fn parse(data: &[u8]) {
    if data.len() < 40 { return; }

    let version = data[0] >> 4;

    let next_header = data[6];
    let hop_limit = data[7]; // IPv6 equivalent of TTL


    let src_ip = &data[8..24];
    let dst_ip = &data[24..40];

    println!(
        "  [IPv6] {:02x}{:02x}:{:02x}{:02x}... -> {:02x}{:02x}:{:02x}{:02x}... | Next: {} | Hop: {}",
        src_ip[0], src_ip[1], src_ip[14], src_ip[15],
        dst_ip[0], dst_ip[1], dst_ip[14], dst_ip[15],
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