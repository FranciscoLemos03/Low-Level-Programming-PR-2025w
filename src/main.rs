mod menu; 

fn main() {
    println!("Welcome to the Packet Sniffer Configuration Interface.");
    
    // Now receiving five values
    let (protocol, type1, ip1, type2, ip2) = menu::menu();

    println!("\nInitial Sniffer configuration complete.");
    print!("Ready to start sniffing for Protocol: {}", protocol);
    
    // Conditional printing based on whether a secondary filter exists
    if type2.is_empty() {
        println!(" with filter: {} on IP: {}", type1, ip1);
    } else {
        println!(" with filters: {} ({}) AND {} ({})", type1, ip1, type2, ip2);
    }
}