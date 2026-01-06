use crate::parser::{tcp, udp};

pub fn parse(data: &[u8]) {
    if data.len() < 20 { return; }

    // First byte: Version (4 bits) and IHL (4 bits)
    let version = data[0] >> 4;
    let ihl = data[0] & 0x0F;
    let header_len = (ihl * 4) as usize;

    // Byte 9: Protocol (6 = TCP, 17 = UDP)
    let protocol = data[9];

    // Bytes 12-15: Source IP, 16-19: Destination IP
    let src_ip = &data[12..16];
    let dst_ip = &data[16..20];

    println!("  [IPv4] {}.{}.{}.{} -> {}.{}.{}.{} | Proto: {}",
             src_ip[0], src_ip[1], src_ip[2], src_ip[3],
             dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3],
             protocol
    );

    // Peeling further: The payload starts after 'header_len'
    if data.len() > header_len {
        let payload = &data[header_len..];
        match protocol {
            6 => tcp::parse(payload),
            17 => udp::parse(payload),
            _ => {}
        }
    }
}