pub mod ethernet;
mod arp;
mod ipv4;

pub fn handle_packet(data: &[u8]) {
    ethernet::parse(data);
}