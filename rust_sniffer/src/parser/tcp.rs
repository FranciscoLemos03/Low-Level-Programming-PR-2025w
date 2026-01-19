use crate::parser::{http, https, smtp};

pub fn parse(data: &[u8]) {
    if data.len() < 20 {
        return;
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);

    let data_offset = ((data[12] >> 4) as usize) * 4;
    let window_size = u16::from_be_bytes([data[14], data[15]]);

    let flags = data[13];
    let mut f = Vec::new();
    if flags & 0x02 != 0 { f.push("SYN"); }
    if flags & 0x10 != 0 { f.push("ACK"); }
    if flags & 0x01 != 0 { f.push("FIN"); }
    if flags & 0x04 != 0 { f.push("RST"); }
    if flags & 0x08 != 0 { f.push("PSH"); }

    // Print the TCP summary for EVERY packet
    println!(
        "    [TCP] Port: {} -> {} | Win: {} | Flags: {:?}",
        src_port, dst_port, window_size, f
    );


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
                https::parse(payload);
            }
            (3389, _) | (_, 3389) => {
                println!("    [RDP] Remote Desktop Traffic");
            }
            _ => println!("    [TCP Data] {} bytes", payload.len()),
        }
    }
}
