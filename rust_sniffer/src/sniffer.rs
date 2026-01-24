use std::{ffi::CStr, ptr::null_mut, slice};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use crossterm::event::{read, Event, KeyCode, KeyEvent, KeyModifiers};
use bindings::{
    pcap_if_t,
    pcap_findalldevs_ex,
    PCAP_SRC_IF_STRING,
    pcap_freealldevs,
    PCAP_OPENFLAG_PROMISCUOUS,
    pcap_open,
    pcap_pkthdr,
    u_char,
    pcap_breakloop,
    pcap_dispatch};
use crate::parser;

#[derive(Debug)]
pub struct FilterConfig {
    pub protocol: &'static str,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
}

static mut FILTER: Option<FilterConfig> = None;

/// Timestamp (seconds + microseconds)
pub struct TimeVal {
    pub sec: u32,
    pub usec: u32,
}

/// Captured packet (Rust-owned)
pub struct Packet {
    pub data: Vec<u8>,
    pub ts: TimeVal,
}

/* ------------------------------------------------------------------------- */
/*                               RAII HELPERS                                 */
/* ------------------------------------------------------------------------- */

struct DeviceList {
    ptr: *mut pcap_if_t,
}

impl Drop for DeviceList {
    fn drop(&mut self) {
        unsafe {
            if !self.ptr.is_null() {
                pcap_freealldevs(self.ptr);
            }
        }
    }
}

/* ------------------------------------------------------------------------- */
/*                          LOW-LEVEL HELPER FUNCTIONS                         */
/* ------------------------------------------------------------------------- */

/// # Safety
/// `data` must point to at least `len` valid bytes
unsafe fn copy_packet_data(data: *const u_char, len: usize) -> Vec<u8> {
    slice::from_raw_parts(data, len).to_vec()
}

fn ipv4_to_string(bytes: &[u8]) -> String {
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

fn protocol_to_string(proto: u8) -> &'static str {
    match proto {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        _ => "OTHER",
    }
}

/* ------------------------------------------------------------------------- */
/*                              PCAP CALLBACK                                  */
/* ------------------------------------------------------------------------- */

/// # Safety
/// - pointers provided by libpcap
/// - packet data valid for header.len bytes
unsafe extern "C" fn packet_handler(
    param: *mut u_char,
    header: *const pcap_pkthdr,
    pkt_data: *const u_char,
) {
    if header.is_null() || pkt_data.is_null() {
        return;
    }

    // Read datalink value (passed from read_packets)
    let dl: i32 = if !param.is_null() {
        *(param as *const i32)
    } else {
        // assuming Ethernet if not provided
        1 
    };

    let len = (*header).len as usize;
    let data_slice = unsafe { slice::from_raw_parts(pkt_data, len) };

    let sec = (*header).ts.tv_sec as u32;
    let usec = (*header).ts.tv_usec as u32;

    let proto = parser::get_protocol(data_slice);
    let (src_ip, dst_ip) = parser::get_ips(data_slice);
    let print = unsafe {
        let f = &raw const FILTER;
        match *f {
            None => true,
            Some(ref fc) => {
                let proto_match = fc.protocol == "all" || proto.as_ref().map(|p| p == fc.protocol).unwrap_or(false);
                let src_match = fc.src_ip.as_ref().map(|filter_ip| src_ip.as_ref() == Some(filter_ip)).unwrap_or(true);
                let dst_match = fc.dst_ip.as_ref().map(|filter_ip| dst_ip.as_ref() == Some(filter_ip)).unwrap_or(true);
                proto_match && src_match && dst_match
            }
        }
    };

    if print {
        print!("[Time: {}.{}] ", sec, usec);
        parser::handle_packet(data_slice);
    }
}

/* ------------------------------------------------------------------------- */
/*                              PUBLIC API                                     */
/* ------------------------------------------------------------------------- */

pub fn list_adapters() -> Vec<String> {
    let mut adapters : Vec<String> = Vec::new();

    let mut errbuf = [0 as ::std::os::raw::c_char; 256];
    let errbuf_ptr = errbuf.as_mut_ptr();

    let mut alldevs: *mut pcap_if_t = null_mut();
    let src = PCAP_SRC_IF_STRING.as_ptr() as *const i8;

    let result = unsafe {
        pcap_findalldevs_ex(src, null_mut(), &mut alldevs, errbuf_ptr)
    };

    if result == -1 {
        return adapters;
    }

    let devices = DeviceList { ptr: alldevs };
    let mut current = devices.ptr;

    while !current.is_null() {
        let dev = unsafe { &*current };

        if !dev.description.is_null() {
            let desc = unsafe { CStr::from_ptr(dev.description) }
                .to_string_lossy()
                .to_string();
            adapters.push(desc);
        }

        current = dev.next;
    }

    adapters
}

pub fn print_adapters() {
    for (i, adapter) in list_adapters().iter().enumerate() {
        println!("{} - {}", i, adapter);
    }
}

pub fn read_packets(adapter_index: u8, filter: Option<FilterConfig>) {
    let mut errbuf = [0 as ::std::os::raw::c_char; 256];
    let errbuf_ptr = errbuf.as_mut_ptr();

    let mut alldevs: *mut pcap_if_t = null_mut();
    let src = PCAP_SRC_IF_STRING.as_ptr() as *const i8;

    let result = unsafe {
        pcap_findalldevs_ex(src, null_mut(), &mut alldevs, errbuf_ptr)
    };

    if result == -1 {
        println!(
            "Error in pcap_findalldevs_ex: {:?}",
            unsafe { CStr::from_ptr(errbuf_ptr) }
        );
        return;
    }

    let devices = DeviceList { ptr: alldevs };
    let mut current = devices.ptr;
    let mut i = 0;

    while !current.is_null() && i != adapter_index {
        let dev = unsafe { &*current };
        current = dev.next;
        i += 1;
    }

    if current.is_null() {
        println!("Invalid adapter index.");
        return;
    }

    let chosen_dev = unsafe { &*current };

    println!(
        "Chose {} - {:?}",
        i,
        unsafe { CStr::from_ptr(chosen_dev.description) }
    );

    let handle = unsafe {
        pcap_open(
            chosen_dev.name,
            65536,
            PCAP_OPENFLAG_PROMISCUOUS as i32,
            2,
            null_mut(),
            errbuf_ptr,
        )
    };

    if handle.is_null() {
        println!(
            "Error in pcap_open {:?}",
            unsafe { CStr::from_ptr(errbuf_ptr) }
        );
        return;
    }

    unsafe { FILTER = filter; }

    println!("Starting listening on the adapter.");

    let running = Arc::new(AtomicBool::new(true));
    let running_key = running.clone();

    println!("Press Crtl+Q to stop listening.");
    thread::spawn(move || {
        while running_key.load(Ordering::Relaxed) {
            if let Ok(Event::Key(KeyEvent { code, modifiers, .. })) = read() {
                if code == KeyCode::Char('q') && modifiers.contains(KeyModifiers::CONTROL) {
                    println!("Ctrl+Q pressed!");
                    running_key.store(false, Ordering::Relaxed);
                }
            }
        }
    });

    while running.load(Ordering::Relaxed) {
        unsafe {
            pcap_dispatch(handle, 0, Some(packet_handler), null_mut());
        }
    }

    unsafe {
        pcap_breakloop(handle);
        println!("Stopping listening on the adapter.");
    }
}