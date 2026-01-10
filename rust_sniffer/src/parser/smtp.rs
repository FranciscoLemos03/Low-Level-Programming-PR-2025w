pub fn parse(payload: &[u8]) {
    if payload.is_empty() { return; }

    let text = String::from_utf8_lossy(payload);

    // SMTP commands are usually 4 letters followed by a space
    if text.starts_with("220") || text.starts_with("HELO") || text.starts_with("MAIL") {
        println!("    [SMTP] Found Email Traffic:");
        for line in text.lines().take(3) { // Just show first 3 lines
            println!("      > {}", line.trim());
        }
    }
}