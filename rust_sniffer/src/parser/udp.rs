pub fn parse(data: &[u8]) {
    // Safety Check: Minimum UDP header is 8 bytes
    if data.len() < 8 { return; }

    // Decode Header (Standard Network Byte Order)
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let length = u16::from_be_bytes([data[4], data[5]]);

    println!("    [UDP] {} -> {} | Length: {}", src_port, dst_port, length);

    let payload_len = (length as usize).saturating_sub(8);
    let available_data = data.len().saturating_sub(8);
    let actual_payload_len = std::cmp::min(payload_len, available_data);

    let payload_start = 8;
    let payload_end = payload_start + actual_payload_len;

    if actual_payload_len > 0 {
        let payload = &data[payload_start..payload_end];
        identify_udp_application(src_port, dst_port, payload);
    }
}

fn identify_udp_application(src: u16, dst: u16, payload: &[u8]) {
    match (src, dst) {
        (53, _) | (_, 53) => {
            crate::parser::dns::parse(payload);
        },
        (67, 68) | (68, 67) => println!("      [DHCP] IP Assignment Protocol"),
        (123, _) | (_, 123) => println!("      [NTP] Network Time Protocol"),
        _ => {
            let preview: String = payload.iter()
                .take(32)
                .map(|&b| if b >= 32 && b <= 126 { b as char } else { '.' })
                .collect();
            println!("      [Data] Preview: \"{}\"...", preview);
        }
    }
}