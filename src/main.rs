mod menu;
mod parser;

use pcap::{Capture, Device};
fn main() {
    println!("Welcome to the Packet Sniffer Configuration Interface.");

    // println!(r"cargo:rustc-link-search=native=F:/Programme/npcap-sdk-1.15/Lib/x64");

    // // Now receiving five values
    // let (protocol, type1, ip1, type2, ip2) = menu::menu();
    //
    // println!("\nInitial Sniffer configuration complete.");
    // print!("Ready to start sniffing for Protocol: {}", protocol);
    //
    // // Conditional printing based on whether a secondary filter exists
    // if type2.is_empty() {
    //     println!(" with filter: {} on IP: {}", type1, ip1);
    // } else {
    //     println!(" with filters: {} ({}) AND {} ({})", type1, ip1, type2, ip2);
    // }

    use pcap::{Capture, Device};

    let devices = Device::list().expect("Error listing devices");
    println!("Devices: {:?}", devices);

    let main_device = devices.into_iter().find(|d| {
        let desc = d.desc.as_deref().unwrap_or("");

        let is_physical = !desc.contains("Hyper-V") &&
            !desc.contains("Virtual") &&
            !desc.contains("Loopback");

        let is_connected = d.flags.connection_status == pcap::ConnectionStatus::Connected;

        is_physical && is_connected
    }).expect("No physical network card found!");


    println!("Starting capture on: {}", main_device.name);


    let mut cap = Capture::from_device(main_device)
        .unwrap()
        .promisc(true) // Capture all traffic in the LAN, not just yours
        .snaplen(65535) // Maximum packet size
        .immediate_mode(true)
        .open()
        .unwrap();

    println!("Waiting for packets...");
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                // Your existing logic here
                parser::handle_packet(&packet.data);
            }
            Err(pcap::Error::TimeoutExpired) => {
                // might happen that timeout occurs when many packets are received
                continue;
            }
            Err(e) => {
                eprintln!("PCAP Error: {:?}", e);
            }
        }
    }

}
