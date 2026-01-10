const DNS_HEADER_SIZE: usize = 12;
const DNS_QR_MASK: u16 = 0x8000; // Mask for the 1st bit (Query/Response)


pub fn parse(data: &[u8]) {
    if data.len() < 12 { return; }

    // DNS Header is exactly 12 bytes
    let transaction_id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let question_count = u16::from_be_bytes([data[4], data[5]]);

    let is_response = (flags & DNS_QR_MASK) != 0;
    let type_str = if is_response { "Response" } else { "Query" };

    println!("      [DNS {}] ID: {:#06X} | Qs: {}", type_str, transaction_id, question_count);

    if question_count > 0 && data.len() > DNS_HEADER_SIZE {
        // We pass everything starting at index 12 to the name decoder
        decode_dns_name(&data[DNS_HEADER_SIZE..]);
    }
}

fn decode_dns_name(payload: &[u8]) {
    let mut domain = String::new();
    let mut cursor = 0;

    // DNS Names end with a 0-length byte
    while cursor < payload.len() && payload[cursor] != 0 {
        let length = payload[cursor] as usize;
        cursor += 1;

        if cursor + length > payload.len() { break; }

        if !domain.is_empty() { domain.push('.'); }

        let label = String::from_utf8_lossy(&payload[cursor..cursor + length]);
        domain.push_str(&label);
        cursor += length;
    }

    if !domain.is_empty() {
        println!("      [DNS Detail] Target: {}", domain);
    }
}