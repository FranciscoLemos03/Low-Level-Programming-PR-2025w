use super::flow::{HttpRequestSummary, HttpResponseSummary};


fn is_printable_ascii(b: u8) -> bool {
    (0x20..=0x7E).contains(&b) || b == b'\r' || b == b'\n' || b == b'\t'
}


pub fn try_parse_http(ts_ms: u128, payload: &[u8]) -> (Option<HttpRequestSummary>, Option<HttpResponseSummary>) {
    if payload.is_empty() {
        return (None, None);
    }

    // Only parse if it looks like text.
    let sample_len = payload.len().min(64);
    if payload[..sample_len].iter().any(|&b| !is_printable_ascii(b)) {
        return (None, None);
    }

    let text = String::from_utf8_lossy(payload);

    // First line ends at \r\n or \n
    let mut lines = text.lines();
    let first = match lines.next() {
        Some(l) => l.trim(),
        None => return (None, None),
    };

    // Req line ex: "GET /path HTTP/1.1"
    // Resp line ex: "HTTP/1.1 200 OK"
    let upper = first.to_ascii_uppercase();

    // Request detection
    for m in ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"] {
        if upper.starts_with(m) && upper.contains("HTTP/") {
            // crude split
            let parts: Vec<&str> = first.split_whitespace().collect();
            if parts.len() >= 2 {
                // Try to grab Host header
                let host = text
                    .lines()
                    .find_map(|l| {
                        let l = l.trim();
                        if l.to_ascii_lowercase().starts_with("host:") {
                            Some(l[5..].trim().to_string())
                        } else {
                            None
                        }
                    });

                return (
                    Some(HttpRequestSummary {
                        at_time_ms: ts_ms,
                        method: parts[0].to_string(),
                        path: parts[1].to_string(),
                        host,
                    }),
                    None,
                );
            }
        }
    }

    // Response detection
    if upper.starts_with("HTTP/") {
        let parts: Vec<&str> = first.split_whitespace().collect();
        if parts.len() >= 2 {
            if let Ok(code) = parts[1].parse::<u16>() {
                return (
                    None,
                    Some(HttpResponseSummary {
                        at_time_ms: ts_ms,
                        status: code,
                    }),
                );
            }
        }
    }

    (None, None)
}