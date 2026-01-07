pub mod ethernet;
mod arp;
mod ipv4;
mod tcp;
mod udp;
mod dns;

pub fn handle_packet(data: &[u8]) {
    ethernet::parse(data);
}