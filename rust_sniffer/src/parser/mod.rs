pub mod ethernet;
mod arp;
mod ipv4;
mod tcp;
mod udp;
mod dns;
mod icmp;
mod smtp;
mod http;
mod ipv6;
mod https;

pub fn handle_packet(data: &[u8]) {
    ethernet::parse(data);
}

pub fn get_ips(data: &[u8]) -> (Option<String>, Option<String>) {
    if data.len() < 14 { return (None, None); }

    let ether_type = u16::from_be_bytes([data[12], data[13]]);
    let payload = &data[14..];

    match ether_type {
        0x0800 => get_ipv4_ips(payload),
        _ => (None, None),
    }
}

fn get_ipv4_ips(data: &[u8]) -> (Option<String>, Option<String>) {
    if data.len() < 20 { return (None, None); }

    let src_ip = &data[12..16];
    let dst_ip = &data[16..20];

    let src_ip_str = format!("{}.{}.{}.{}", src_ip[0], src_ip[1], src_ip[2], src_ip[3]);
    let dst_ip_str = format!("{}.{}.{}.{}", dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]);

    (Some(src_ip_str), Some(dst_ip_str))
}

pub fn get_protocol(data: &[u8]) -> Option<String> {
    if data.len() < 14 { return None; }

    let ether_type = u16::from_be_bytes([data[12], data[13]]);

    let payload = &data[14..];

    match ether_type {
        0x0800 => get_ipv4_protocol(payload),
        0x0806 => Some("arp".to_string()),
        0x86DD => Some("ipv6".to_string()),
        _ => None,
    }
}

fn get_ipv4_protocol(data: &[u8]) -> Option<String> {
    if data.len() < 20 { return None; }

    let protocol = data[9];

    let header_len = ((data[0] & 0x0F) * 4) as usize;

    if data.len() > header_len {
        let payload = &data[header_len..];
        match protocol {
            1 => Some("icmp".to_string()),
            6 => get_tcp_protocol(payload),
            17 => get_udp_protocol(payload),
            _ => None,
        }
    } else {
        None
    }
}

fn get_tcp_protocol(data: &[u8]) -> Option<String> {
    if data.len() < 20 { return None; }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);

    let data_offset = ((data[12] >> 4) as usize) * 4;

    if data.len() > data_offset {
        match (src_port, dst_port) {
            (80, _) | (_, 80) => Some("http".to_string()),
            (443, _) | (_, 443) => Some("https".to_string()),
            (25, _) | (_, 25) | (587, _) | (_, 587) => Some("smtp".to_string()),
            (53, _) | (_, 53) => Some("dns".to_string()),
            _ => Some("tcp".to_string()),
        }
    } else {
        Some("tcp".to_string())
    }
}

fn get_udp_protocol(data: &[u8]) -> Option<String> {
    if data.len() < 8 { return None; }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);

    match (src_port, dst_port) {
        (53, _) | (_, 53) => Some("dns".to_string()),
        _ => Some("udp".to_string()),
    }
}