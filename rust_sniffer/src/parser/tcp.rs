use crate::parser::{http, smtp};

pub fn parse(data: &[u8]) {
    if data.len() < 20 {
        return;
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);

    let data_offset = ((data[12] >> 4) as usize) * 4;

    if data.len() > data_offset {
        let payload = &data[data_offset..];

        match (src_port, dst_port) {
            (80, _) | (_, 80) => {
                http::parse(payload);
            }
            (25, _) | (_, 25) | (587, _) | (_, 587) => {
                smtp::parse(payload);
            }
            (443, _) | (_, 443) => {
                println!("    [HTTPS] Encrypted Data ({} bytes)", payload.len());
            }
            (3389, _) | (_, 3389) => {
                println!("    [RDP] Remote Desktop Traffic");
            }
            _ => println!("    [TCP Data] {} bytes", payload.len()),
        }
    }
}
