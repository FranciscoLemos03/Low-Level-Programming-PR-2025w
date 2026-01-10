pub fn parse(data: &[u8]) {
    if data.len() < 8 { return; }

    let icmp_type = data[0];
    let icmp_code = data[1];

    match icmp_type {
        8 => println!("    [ICMP] Echo Request (Ping) | Code: {}", icmp_code),
        0 => println!("    [ICMP] Echo Reply (Pong) | Code: {}", icmp_code),
        3 => println!("    [ICMP] Destination Unreachable"),
        11 => println!("    [ICMP] Time Exceeded (used by Traceroute)"),
        _ => println!("    [ICMP] Other Type: {}", icmp_type),
    }

    // Payload
    if data.len() > 8 {
        let payload = &data[8..];
        preview_icmp_content(payload);
    }
}

fn preview_icmp_content(payload: &[u8]) {
    let text: String = payload.iter()
        .take(32) // Let's look at the first 32 bytes
        .map(|&b| if b >= 32 && b <= 126 { b as char } else { '.' })
        .collect();

    println!("      Payload Content: \"{}\"...", text);
}