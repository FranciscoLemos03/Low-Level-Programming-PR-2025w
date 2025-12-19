mod menu;
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

    let main_device = devices.first().expect("No device found").clone();
    println!("Starting capture on: {}", main_device.name);

    // 2. Open the device for sniffing [cite: 15]
    let mut cap = Capture::from_device(main_device)
        .unwrap()
        .promisc(true) // Capture all traffic in the LAN, not just yours
        .snaplen(65535) // Maximum packet size
        .immediate_mode(true)
        .open()
        .unwrap();

    println!("Waiting for packets...");
    while let Ok(packet) = cap.next_packet() {
        println!("Packet received! Length: {} bytes", packet.header.len);
        println!("{:?}", packet);
        println!("Hex Data: {:02X?}", &packet.data[0..14]);
        // parse_ethernet(packet.data);
    }

    println!("Ending program");
}
