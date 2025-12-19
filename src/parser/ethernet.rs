use crate::parser::{arp, ipv4};

pub fn parse(data: &[u8]) {
    if data.len() < 14 { return; }

    let dest_mac = &data[0..6];
    let src_mac = &data[6..12];
    let ether_type = u16::from_be_bytes([data[12], data[13]]);

    println!("[Ethernet] {} -> {} | Type: {:#06X}",
             format_mac(src_mac), format_mac(dest_mac), ether_type);

    // The Payload is everything after byte 14
    let payload = &data[14..];

    match ether_type {
        0x0800 => ipv4::parse(payload),
        0x0806 => arp::parse(payload),
        _ => {} // Ignore or log unknown types
    }
}


fn format_mac(mac: &[u8]) -> String {
    mac.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<String>>()
        .join(":")
}