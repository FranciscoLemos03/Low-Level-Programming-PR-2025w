use bindings::{pcap_if_t, pcap_findalldevs_ex, PCAP_SRC_IF_STRING, pcap_freealldevs };

use std::ffi::CStr;

// println!("MIDDLE");


fn print_adapters() {
    let mut a = [0 as ::std::os::raw::c_char; 256];
    let errbuf:*mut ::std::os::raw::c_char = a.as_mut_ptr(); // mut???

    
    let pcap_src_if_string_as_ptr: *const i8 = PCAP_SRC_IF_STRING.as_ptr() as *const i8;

    let mut alldevs: *mut pcap_if_t = std::ptr::null_mut();

    let findalldevs_out = unsafe {
        pcap_findalldevs_ex(
            pcap_src_if_string_as_ptr,
            std::ptr::null_mut(),
            &mut alldevs,
            errbuf, // TODO: not sure whether anything can be actually written to this buffer.
        )
    };

    if findalldevs_out == -1 {
        println!("Error in pcap_findalldevs_ex: {:?}", unsafe {CStr::from_ptr(errbuf)});
        panic!();
    }

    let mut current_dev_p = alldevs;
    let mut i = 0;
    while !current_dev_p.is_null() {
        let current_dev = unsafe{ *current_dev_p};
        println!("{} - {:?}", i, unsafe { CStr::from_ptr(current_dev.description)});

        current_dev_p = current_dev.next; 
        i += 1;
    }


    unsafe {
        pcap_freealldevs(alldevs);
    }
}

fn main() {
    println!("Started");

    print_adapters();

    println!("Finished");
}