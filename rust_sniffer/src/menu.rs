use std::io::{self, Write};
use std::fs::File;

use crate::sniffer;

/// Reads user input from stdin
fn read_input(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");

    input.trim().to_string()
}

/// Lets the user choose a network adapter
pub fn choose_adapter() -> usize {
    let adapters = sniffer::list_adapters();

    if adapters.is_empty() {
        println!("❌ No network adapters found.");
        std::process::exit(1);
    }

    loop {
        println!("\n--- Available Network Adapters ---");
        for (i, adapter) in adapters.iter().enumerate() {
            println!("{} - {}", i, adapter);
        }

        let choice = read_input("Choose adapter index: ");

        if let Ok(index) = choice.parse::<usize>() {
            if index < adapters.len() {
                return index;
            }
        }

        println!("❌ Invalid adapter index. Try again.");
    }
}

/// Saves adapter choice to a file (filename chosen by user)
pub fn save_adapter_choice(adapter_index: usize, adapter_name: &str) {
    let config = format!(
        "Selected Adapter Index: {}\nSelected Adapter Name: {}",
        adapter_index, adapter_name
    );

    save_configuration(&config);
}

/* ---------------- FILTER / PROTOCOL MENU ---------------- */

pub fn menu() -> sniffer::FilterConfig {
    let protocol = choose_protocol();
    let (src_ip, dst_ip) = choose_ip_filters();
    
    sniffer::FilterConfig {
        protocol,
        src_ip,
        dst_ip,
    }
}

fn choose_protocol() -> &'static str {
    loop {
        println!("\n--- Choose Protocol Filter ---");
        println!("0 - All traffic");
        println!("1 - HTTP");
        println!("2 - HTTPS");
        println!("3 - DNS");
        println!("4 - ICMP");
        println!("5 - ARP");

        let choice = read_input("Choose protocol (0-5): ");

        match choice.as_str() {
            "0" => return "all",
            "1" => return "http",
            "2" => return "https",
            "3" => return "dns",
            "4" => return "icmp",
            "5" => return "arp",
            _ => println!("❌ Invalid choice. Try again."),
        }
    }
}

fn choose_ip_filters() -> (Option<String>, Option<String>) {
    loop {
        println!("\n--- IP Filters ---");
        println!("Do you want to filter by IP address? (y/n)");
        
        let choice = read_input("Choice: ").to_lowercase();
        
        match choice.as_str() {
            "y" | "yes" => {
                let src_ip = choose_ip("source");
                let dst_ip = choose_ip("destination");
                return (src_ip, dst_ip);
            }
            "n" | "no" => return (None, None),
            _ => println!("❌ Please enter 'y' or 'n'."),
        }
    }
}

fn choose_ip(ip_type: &str) -> Option<String> {
    loop {
        println!("\n--- {} IP Filter ---", ip_type);
        println!("Enter {} IP address (or 'none' to skip): ", ip_type);
        
        let ip = read_input("IP: ");
        
        if ip.to_lowercase() == "none" {
            return None;
        }
        
        // Basic IP validation
        if is_valid_ipv4(&ip) {
            return Some(ip);
        } else {
            println!("❌ Invalid IPv4 address. Try again.");
        }
    }
}

fn is_valid_ipv4(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    
    for part in parts {
        match part.parse::<u8>() {
            Ok(_) => {},
            Err(_) => return false,
        }
    }
    true
}

/* ---------------- END MENU ---------------- */

/// Writes configuration text to a user-chosen file
fn save_configuration(config: &str) {
    let filename =
        read_input("\nEnter the filename to save the configuration (e.g., config.txt): ");

    match File::create(&filename) {
        Ok(mut file) => {
            if let Err(e) = file.write_all(config.as_bytes()) {
                eprintln!("❌ Error writing to file: {}", e);
            } else {
                println!("✅ Configuration saved to '{}'", filename);
            }
        }
        Err(e) => eprintln!("❌ Error creating file: {}", e),
    }
}