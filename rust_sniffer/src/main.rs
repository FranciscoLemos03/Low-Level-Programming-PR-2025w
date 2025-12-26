use bindings::{
    pcap_if_t, 
    pcap_findalldevs_ex, 
    PCAP_SRC_IF_STRING, 
    pcap_freealldevs, 
    PCAP_OPENFLAG_PROMISCUOUS, 
    pcap_open, 
    pcap_loop, 
    pcap_pkthdr,
    u_char
};

use std::{ffi::CStr, ptr::null, ptr::null_mut, slice};

// println!("MIDDLE");

// /* Callback function invoked by libpcap for every incoming packet */
// void packet_handler(u_char *param,
//   const struct pcap_pkthdr *header,
//   const u_char *pkt_data)
// {
//   struct tm ltime;
//   char timestr[16];
//   time_t local_tv_sec;

//   /*
//    * unused variables
//    */
//   (VOID)(param);
//   (VOID)(pkt_data);

//   /* convert the timestamp to readable format */
//   local_tv_sec = header->ts.tv_sec;
//   localtime_s(&ltime, &local_tv_sec);
//   strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);
  
//   printf("%s,%.6d len:%d\n",
//     timestr, header->ts.tv_usec, header->len);
// }

pub struct TimeVal {
    sec: u32,
    usec: u32
}

pub struct Packet {
    data: Vec<u8>,
    ts: TimeVal 
}

unsafe extern "C" fn packet_handler(
    param: *mut u_char, 
    header: *const pcap_pkthdr, 
    pkt_data: *const u_char
) {
    if header.is_null() || pkt_data.is_null() {
        println!("Header or Data pointers were NULL!!!");
        return;
    }
    // Always check pointers before dereferencing
    let packet_vec = unsafe {
        slice::from_raw_parts(pkt_data, (*header).len as usize).to_vec() 
    };

    // TODO: somehow pass this packet var into other functions
    let packet = unsafe {
        Packet {
            data: packet_vec,
            ts: TimeVal {
                sec: (*header).ts.tv_sec as u32,
                usec: (*header).ts.tv_usec as u32
            }
        }
    };

    println!("[{}, {}, {}]", packet.ts.sec, packet.ts.usec, packet.data.len());
}

fn read_packets(adapter_index: u8) {
    let mut a = [0 as ::std::os::raw::c_char; 256];
    let errbuf:*mut ::std::os::raw::c_char = a.as_mut_ptr(); // mut???

    
    let pcap_src_if_string_as_ptr: *const i8 = PCAP_SRC_IF_STRING.as_ptr() as *const i8;

    let mut alldevs: *mut pcap_if_t = null_mut();

    let findalldevs_out = unsafe {
        pcap_findalldevs_ex(
            pcap_src_if_string_as_ptr,
            null_mut(),
            &mut alldevs,
            errbuf, // TODO: not sure whether anything can be actually written to this buffer.
        )
    };

    if findalldevs_out == -1 {
        println!("Error in pcap_findalldevs_ex: {:?}", unsafe {CStr::from_ptr(errbuf)});
        panic!();
    }

    let mut next_dev_p = alldevs;
    let mut i = 0;
    while !next_dev_p.is_null() && i != adapter_index {
        let current_dev = unsafe{ *next_dev_p};
        
        next_dev_p = current_dev.next; 
        i += 1;
    }

    let chosen_dev = unsafe{ *next_dev_p};

    println!("Chose {} - {:?}", i, unsafe { CStr::from_ptr(chosen_dev.description)});

    let adapter_handle = unsafe {
        pcap_open(
            chosen_dev.name, 
            65536 as ::std::os::raw::c_int,
            PCAP_OPENFLAG_PROMISCUOUS as ::std::os::raw::c_int,
            2 as ::std::os::raw::c_int,
            null_mut(),
            errbuf
        )
    };

    if adapter_handle.is_null() {
        println!("Error in pcap_open {:?}", unsafe {CStr::from_ptr(errbuf)});
        // panic!();
    } else {
        println!("Starting listening on the adapter.");
    }

    unsafe {
        pcap_freealldevs(alldevs);
        pcap_loop(
            adapter_handle, 
            0, 
            Some(packet_handler),
            null_mut()
        );
    }

}

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

    read_packets(6);

    println!("Finished");
}