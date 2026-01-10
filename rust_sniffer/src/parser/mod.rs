pub mod ethernet;
mod arp;
mod ipv4;
mod tcp;
mod udp;
mod dns;
mod icmp;
mod smtp;
mod http;
mod ipv6;

pub fn handle_packet(data: &[u8]) {
    ethernet::parse(data);
}