use bindings::{pcap_if_t, pcap_findalldevs_ex, PCAP_SRC_IF_STRING, PCAP_ERRBUF_SIZE, pcap_remoteact_cleanup as aaa};

use std::ptr::null_mut;

// println!("MIDDLE");

fn main() {
    println!("NOT EVEN HERE");
    // let mut _alldevs: *mut pcap_if_t = null_mut();
    // let alldevs = &raw mut _alldevs;

    // let mut _s = String::with_capacity(256);
    let mut a = [0 as ::std::os::raw::c_char; 256];
    let mut errbuf:*mut ::std::os::raw::c_char = a.as_mut_ptr();

    println!("MIDDLE");

    // a[2] = 127 as ::std::os::raw::c_char;

    // println!("{:?}", unsafe {*errbuf.add(2)});
    
    let pcap_src_if_string_as_ptr: *const i8 = PCAP_SRC_IF_STRING.as_ptr() as *const i8;

    println!("STR is -{:?}-", PCAP_SRC_IF_STRING);

    let mut alldevs: *mut pcap_if_t = std::ptr::null_mut();

    let findalldevs_out = unsafe {
        pcap_findalldevs_ex(
            pcap_src_if_string_as_ptr,
            std::ptr::null_mut(),
            &mut alldevs,
            errbuf,
        )
    };
    println!("Result is -{}-", findalldevs_out);
    // unsafe {pcap_remoteact_cleanup();}
    // println!("{:p}", aaa as *const ());

    // unsafe {
    //     aaa();
    // }

    println!("DONE");

    // if findalldevs_out == -1 {
    //     println!("Error in pcap_findalldevs_ex: ");
    //     // exit(1);
    // }
}