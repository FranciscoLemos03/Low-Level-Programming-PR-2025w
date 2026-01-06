pub fn parse(data: &[u8]) {
    if data.len() < 20 { return; }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);

    // The first 4 bits of byte 12 tell us how many 32-bit words are in the header
    let data_offset = ((data[12] >> 4) as usize) * 4;

    if data.len() > data_offset {
        let payload = &data[data_offset..];

        // 1. Identify the Application
        if src_port == 443 || dst_port == 443 {
            println!("    [HTTPS] Encrypted Data ({} bytes)", payload.len());
        } else if src_port == 80 || dst_port == 80 {
            println!("    [HTTP] Potential Plaintext!");
            preview_content(payload);
        } else {
            println!("    [Data] {} bytes", payload.len());
        }
    }
}

fn preview_content(payload: &[u8]) {
    if payload.is_empty() { return; }

    let text: String = payload.iter()
        .map(|&b| if b >= 32 && b <= 126 { b as char } else { '.' })
        .collect(); // Show the whole payload for now

    if text.contains("HTTP/1.1 200") || text.contains("<html") {
        println!("      [HTTP RESPONSE DETECTED]");
        println!("      Content: {}", text);
    } else if text.contains("GET") {
        println!("      [HTTP REQUEST DETECTED]");
        println!("      Content: {}", text);
    }
}