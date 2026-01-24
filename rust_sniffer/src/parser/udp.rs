use crate::parser::dns;

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

    if src == 53 || dst == 53 {
        dns::parse(payload);
        return;
    }

    // Fallback: heuristic DNS detection (catches randomized source port responses)
    if payload.len() >= 12 {
        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        let qr = (flags & 0x8000) != 0;          // QR bit = 1 for response
        let opcode = (flags >> 11) & 0x0F;       // usually 0 (standard query)

        let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
        let ancount = u16::from_be_bytes([payload[6], payload[7]]);

        // Typical response pattern
        if qr && opcode == 0 && qdcount == 1 && ancount >= 1 {
            println!("      [DNS Response (heuristic match) — src port randomized?]");
            dns::parse(payload);
            return;
        }
    }

    match (src, dst) {
        (67, 68) | (68, 67) => println!("      [DHCP] IP Assignment Protocol"),
        (123, _) | (_, 123) => println!("      [NTP] Network Time Protocol"),
        (443, _) | (_, 443) => {
            // We identify this as QUIC/HTTP3 based on the port and transport layer
            println!("      [QUIC/HTTP3] Encrypted Connection");
        },
        _ => {
            println!("      [UDP Data] {} bytes", payload.len());
        }
    }
}