pub fn parse(payload: &[u8]) {
    if payload.is_empty() { return; }

    let text = String::from_utf8_lossy(payload);
    let mut lines = text.lines();
    let mut body_started = false;

    if let Some(first_line) = lines.next() {
        if first_line.contains("HTTP") {
            println!("      [HTTP Header] {}", first_line);

            for line in lines {
                if !body_started {
                    // If we hit an empty line, the headers are done
                    if line.trim().is_empty() {
                        body_started = true;
                        println!("      [HTTP] --- End of Headers / Start of Body ---");
                        continue;
                    }

                    if line.starts_with("Host:") || line.starts_with("Content-Type:") || line.starts_with("Server:") {
                        println!("      [HTTP Header] {}", line);
                    }
                } else {
                    if !line.trim().is_empty() {
                        let preview = if line.len() > 80 { &line[..80] } else { line };
                        println!("      [HTTP Content] {}", preview);
                    }
                }
            }
        }
    }
}