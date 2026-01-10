pub fn parse(data: &[u8]) {
    // ARP for IPv4 on Ethernet is exactly 28 bytes
    if data.len() < 28 {
        println!("  [ARP] Error: Packet too short");
        return;
    }

    // Operation: bytes 6-7 (index 20-21 in global packet)
    let opcode = u16::from_be_bytes([data[6], data[7]]);

    // Sender IP: bytes 14-17 (index 28-31 in global)
    let src_ip = &data[14..18];

    // Target IP: bytes 24-27 (index 38-41 in global)
    let dst_ip = &data[24..28];

    let op_name = match opcode {
        1 => "Request",
        2 => "Reply",
        _ => "Unknown",
    };

    println!("  [ARP {}] Sender: {}.{}.{}.{} | Target: {}.{}.{}.{}",
             op_name,
             src_ip[0], src_ip[1], src_ip[2], src_ip[3],
             dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]
    );
}