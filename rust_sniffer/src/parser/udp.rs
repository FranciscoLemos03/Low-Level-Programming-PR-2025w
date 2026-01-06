pub fn parse(data: &[u8]) {
    if data.len() < 8 { return; }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let length = u16::from_be_bytes([data[4], data[5]]);

    println!("    [UDP] Port: {} -> {} | Len: {}", src_port, dst_port, length);

    // If you wanted to see DNS (Port 53), you'd peel again here!
}