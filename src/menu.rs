use std::io::{self, Write};
use std::fs::File;

// The layers and their associated protocols defined as a constant array.
const PROTOCOLS_BY_LAYER: [(&str, &[&str]); 4] = [
    ("1. Physical Layer", &["Ethernet", "Wifi"]),
    ("2. Internet Layer", &["IPv4", "ICMP", "IPv6"]),
    ("3. Transport Layer", &["TCP", "UDP"]),
    ("4. Application Layer", &["DNS", "HTTP", "HTTPS", "SMTP"]),
];

// Encapsulate repetitive user interaction logic in the console into a single call, making the main code cleaner and more readable.
fn read_input(prompt: &str) -> String {
    print!("{}", prompt);
    // Ensure the prompt is shown immediately
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read line.");
    input.trim().to_string()
}

/// Runs the menu flow.
/// Returns (protocol_name, filter_type_1, ip_address_1, filter_type_2, ip_address_2).
pub fn menu() -> (String, String, String, String, String) {
    // 1. Display protocol options and get the user's choice
    let chosen_protocol = choose_protocol();

    // 2. Get the filtering IP addresses and types (can be up to two pairs)
    let (ip_filter_type_1, filtering_ip_1, ip_filter_type_2, filtering_ip_2) = request_ip_filter();

    // 3. Format the choices for file saving
    let filter_details_2 = if ip_filter_type_2.is_empty() {
        "".to_string()
    } else {
        format!("\nIP Filter Type 2: {}\nFiltering IP Address 2: {}", ip_filter_type_2, filtering_ip_2)
    };
    
    let configuration = format!(
        "Selected Protocol: {}\nIP Filter Type 1: {}\nFiltering IP Address 1: {}{}",
        chosen_protocol,
        ip_filter_type_1,
        filtering_ip_1,
        filter_details_2
    );

    println!("\n--- Current Configuration ---");
    println!("{}", configuration);
    println!("--------------------------\n");

    // 4. Save the choices to a file
    save_configuration(&configuration);
    
    println!("\n✅ Process completed.");

    // Return the configuration for use in the main sniffer logic later
    (chosen_protocol, ip_filter_type_1, filtering_ip_1, ip_filter_type_2, filtering_ip_2)
}

/// Presents a hierarchical menu (Layer -> Protocol) and gets a valid protocol choice.
fn choose_protocol() -> String {
    loop {
        // --- STEP 1: CHOOSE LAYER ---
        println!("\n--- Choose Protocol Layer ---");
        for (index, (layer, _)) in PROTOCOLS_BY_LAYER.iter().enumerate() {
            println!("{}", layer);
        }
        let layer_input = read_input("Enter the number corresponding to the layer: ");

        if let Ok(layer_index) = layer_input.parse::<usize>() {
            if layer_index > 0 && layer_index <= PROTOCOLS_BY_LAYER.len() {
                // Adjust for 0-based indexing
                let (layer_name, protocols) = PROTOCOLS_BY_LAYER[layer_index - 1];

                // --- STEP 2: CHOOSE PROTOCOL WITHIN THE SELECTED LAYER ---
                // Extract only the name (e.g., "Physical Layer") from the indexed string (e.g., "1. Physical Layer")
                let layer_name_clean = layer_name.split(". ").nth(1).unwrap_or(layer_name);

                println!("\n--- Choose Protocol for {} ---", layer_name_clean);
                
                for (index, protocol) in protocols.iter().enumerate() {
                    println!("{}. {}", index + 1, protocol);
                }
                let protocol_input = read_input("Enter the number corresponding to the protocol: ");

                if let Ok(protocol_index) = protocol_input.parse::<usize>() {
                    if protocol_index > 0 && protocol_index <= protocols.len() {
                        // Return the chosen protocol name
                        return protocols[protocol_index - 1].to_string();
                    }
                }
                
                // If protocol choice is invalid, the loop continues to the layer selection
            }
        }

        println!("\n❌ Invalid choice. Please start again by selecting a valid layer.");
    }
}

/// Requests the user to choose the type of IP filter(s) and the IP address(es).
/// Returns (Filter_Type_1, IP_Value_1, Filter_Type_2, IP_Value_2).
fn request_ip_filter() -> (String, String, String, String) {
    let filter_options = vec![
        "1. Source IP",
        "2. Destination IP",
        "3. Any IP",
    ];

    let mut filter_type_1: String = String::new();
    let mut ip_value_1: String = String::new();
    let mut filter_type_2: String = String::new();
    let mut ip_value_2: String = String::new();
    let mut primary_choice: u8 = 0;

    // --- STEP 1: CHOOSE PRIMARY FILTER ---
    loop {
        println!("\n--- Choose Primary IP Filter Type ---");
        for option in &filter_options {
            println!("{}", option);
        }
        let choice = read_input("Enter the number corresponding to the filter type: ");

        if let Ok(num) = choice.parse::<u8>() {
            primary_choice = num;
            match num {
                1 => { 
                    filter_type_1 = "Source IP".to_string(); 
                    ip_value_1 = read_input("Enter the Source IP address: ");
                    break;
                }
                2 => { 
                    filter_type_1 = "Destination IP".to_string(); 
                    ip_value_1 = read_input("Enter the Destination IP address: ");
                    break;
                }
                3 => { 
                    filter_type_1 = "Any IP".to_string(); 
                    ip_value_1 = read_input("Enter the Any IP address: ");
                    return (filter_type_1, ip_value_1, filter_type_2, ip_value_2);
                }
                _ => println!("\n❌ Invalid choice. Please try again."),
            }
        } else {
            println!("\n❌ Invalid input. Please enter a number.");
        }
    }

    // --- STEP 2: CHOOSE SECONDARY FILTER (Only if Primary was Source or Destination) ---
    loop {
        let secondary_prompt = if primary_choice == 1 {
            // Primary was Source IP (1), so offer Destination IP (2)
            "Do you want to add a Destination IP filter? (y/n): "
        } else {
            // Primary was Destination IP (2), so offer Source IP (1)
            "Do you want to add a Source IP filter? (y/n): "
        };
        
        let add_secondary = read_input(secondary_prompt).to_lowercase();
        
        if add_secondary == "y" {
            if primary_choice == 1 {
                // User choose Source IP first, now add Destination IP
                filter_type_2 = "Destination IP".to_string();
                ip_value_2 = read_input("Enter the Destination IP address: ");
            } else {
                // User choose Destination IP first, now add Source IP
                filter_type_2 = "Source IP".to_string();
                ip_value_2 = read_input("Enter the Source IP address: ");
            }
            break; // Exit secondary loop after adding filter
        } else if add_secondary == "n" {
            break; // Exit secondary loop without adding filter
        } else {
            println!("\n❌ Invalid input. Please enter 'y' or 'n'.");
        }
    }

    (filter_type_1, ip_value_1, filter_type_2, ip_value_2)
}

/// Saves the configuration string to a file with the name specified by the user.
fn save_configuration(config: &str) {
    let filename = read_input("\nEnter the filename to save the configurations (e.g., config.txt): ");
    
    match File::create(filename.clone()) {
        Ok(mut file) => {
            match file.write_all(config.as_bytes()) {
                Ok(_) => println!("\n✅ Configuration successfully saved to '{}'.", filename),
                Err(e) => eprintln!("\n❌ Error writing to file: {}", e),
            }
        }
        Err(e) => eprintln!("\n❌ Error creating file: {}", e),
    }
}