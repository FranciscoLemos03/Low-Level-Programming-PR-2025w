mod sniffer;
mod menu;
mod parser;
mod analyzer;

fn main() {
    println!("Started");

    // Step 1: user chooses adapter
    let adapter_index = menu::choose_adapter();

    sniffer::read_packets(adapter_index as u8);


    /****************************************/
    // To-Do : save packets to the file     
    /****************************************/

    /* 

    // Step 2: get adapter name (for saving)
    let adapters = sniffer::list_adapters();
    let adapter_name = &adapters[adapter_index];

    // Step 3: save selection to file
    menu::save_adapter_choice(adapter_index, adapter_name);

    */

    println!("Finished");
}