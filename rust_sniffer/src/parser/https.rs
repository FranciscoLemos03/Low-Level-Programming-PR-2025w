pub fn parse(payload: &[u8]) {
    if payload.len() < 5 {
        return;
    }

    let content_type = payload[0];
    let ver_major = payload[1];
    let ver_minor = payload[2];
    let rec_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;

    let record_version_str = match (ver_major, ver_minor) {
        (0x03, 0x00) => "SSLv3",
        (0x03, 0x01) => "TLS 1.0",
        (0x03, 0x02) => "TLS 1.1",
        (0x03, 0x03) => "TLS 1.2",
        (0x03, 0x04) => "TLS 1.3 (record)",
        _ => "Unknown/Invalid",
    };

    if ver_major != 0x03 || ver_minor > 0x04 || rec_len == 0 || rec_len > 16384 + 2048 {
        return;
    }

    let record_name = match content_type {
        0x14 => "ChangeCipherSpec",
        0x15 => "Alert",
        0x16 => "Handshake",
        0x17 => "Application Data",
        _    => "Unknown TLS Record",
    };

    println!(
        "    [HTTPS/TLS] Record: {}  ver: {}  len: {}  (payload: {} bytes)",
        record_name, record_version_str, rec_len, payload.len() - 5
    );

    if content_type == 0x16 {
        parse_handshake(&payload[5..]);
    }
}

fn parse_handshake(data: &[u8]) {
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let hs_type = data[pos];
        let hs_len = ((data[pos+1] as usize) << 16) | ((data[pos+2] as usize) << 8) | (data[pos+3] as usize);

        if pos + 4 + hs_len > data.len() { break; }

        if hs_type == 0x01 {
            println!("      → Handshake: ClientHello");
            if let Some(sni) = extract_sni(&data[pos + 4 .. pos + 4 + hs_len]) {
                println!("      [TLS Detail] SNI (Target Domain): {}", sni);
            }
        } else if hs_type == 0x02 {
            println!("      → Handshake: ServerHello");
        }

        pos += 4 + hs_len;
    }
}


fn extract_sni(payload: &[u8]) -> Option<String> {
    let mut cursor = 34; // Skip Version (2b) and Random (32b)

    // 1. Skip Session ID
    if cursor >= payload.len() { return None; }
    let session_id_len = payload[cursor] as usize;
    cursor += 1 + session_id_len;

    // 2. Skip Cipher Suites
    if cursor + 2 > payload.len() { return None; }
    let cipher_len = u16::from_be_bytes([payload[cursor], payload[cursor+1]]) as usize;
    cursor += 2 + cipher_len;

    // 3. Skip Compression Methods
    if cursor >= payload.len() { return None; }
    let comp_len = payload[cursor] as usize;
    cursor += 1 + comp_len;

    // 4. Extensions
    if cursor + 2 > payload.len() { return None; }
    let ext_total_len = u16::from_be_bytes([payload[cursor], payload[cursor+1]]) as usize;
    cursor += 2;

    let extensions_end = cursor + ext_total_len;
    while cursor + 4 <= extensions_end && cursor + 4 <= payload.len() {
        let ext_type = u16::from_be_bytes([payload[cursor], payload[cursor+1]]);
        let ext_len = u16::from_be_bytes([payload[cursor+2], payload[cursor+3]]) as usize;
        cursor += 4;

        if ext_type == 0x0000 { // Server Name Indication Type
            if cursor + 5 <= payload.len() {
                let list_len = u16::from_be_bytes([payload[cursor], payload[cursor+1]]) as usize;
                let name_type = payload[cursor+2]; // 0 = host_name
                let name_len = u16::from_be_bytes([payload[cursor+3], payload[cursor+4]]) as usize;

                if name_type == 0 && cursor + 5 + name_len <= payload.len() {
                    let name_bytes = &payload[cursor+5 .. cursor+5+name_len];
                    return Some(String::from_utf8_lossy(name_bytes).into_owned());
                }
            }
        }
        cursor += ext_len;
    }
    None
}