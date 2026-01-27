mod sniffer;
mod menu;
mod parser;
mod analyzer;

fn main() {
    println!("Started");

    // Step 1: user chooses adapter
    let adapter_index = menu::choose_adapter();

    // Step 2: choose filter
    let filter_config = menu::menu();

    // Step 3: choose to create dump file
    let createDump = menu::dump_file_dialog();

    sniffer::read_packets(adapter_index as u8, Some(filter_config), createDump);

    /*
    // Step 3: get adapter name (for saving)
    let adapters = sniffer::list_adapters();
    let adapter_name = &adapters[adapter_index];

    // Step 4: save selection to file
    menu::save_adapter_choice(adapter_index, adapter_name);
    */

    println!("Finished");
}