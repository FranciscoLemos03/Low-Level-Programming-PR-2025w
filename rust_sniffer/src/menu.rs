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

/* ---------------- FILTER / PROTOCOL MENU (DISABLED FOR NOW) ----------------

pub fn menu() -> (String, String, String, String, String) {
    let chosen_protocol = choose_protocol();
    let (ip_filter_type_1, filtering_ip_1, ip_filter_type_2, filtering_ip_2) =
        request_ip_filter();

    let filter_details_2 = if ip_filter_type_2.is_empty() {
        "".to_string()
    } else {
        format!(
            "\nIP Filter Type 2: {}\nFiltering IP Address 2: {}",
            ip_filter_type_2, filtering_ip_2
        )
    };

    let configuration = format!(
        "Selected Protocol: {}\nIP Filter Type 1: {}\nFiltering IP Address 1: {}{}",
        chosen_protocol,
        ip_filter_type_1,
        filtering_ip_1,
        filter_details_2
    );

    save_configuration(&configuration);

    (
        chosen_protocol,
        ip_filter_type_1,
        filtering_ip_1,
        ip_filter_type_2,
        filtering_ip_2,
    )
}

fn choose_protocol() -> String {
    unimplemented!()
}

fn request_ip_filter() -> (String, String, String, String) {
    unimplemented!()
}

------------------------------------------------------------------------ */

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