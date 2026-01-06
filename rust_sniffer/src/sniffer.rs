use std::{ffi::CStr, ptr::null_mut, slice};

use bindings::{
    pcap_if_t,
    pcap_findalldevs_ex,
    PCAP_SRC_IF_STRING,
    pcap_freealldevs,
    PCAP_OPENFLAG_PROMISCUOUS,
    pcap_open,
    pcap_loop,
    pcap_pkthdr,
    u_char,
};

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
    _param: *mut u_char,
    header: *const pcap_pkthdr,
    pkt_data: *const u_char,
) {
    if header.is_null() || pkt_data.is_null() {
        return;
    }

    let packet_vec = unsafe {
        copy_packet_data(pkt_data, (*header).len as usize)
    };

    let packet = Packet {
        data: packet_vec,
        ts: TimeVal {
            sec: (*header).ts.tv_sec as u32,
            usec: (*header).ts.tv_usec as u32,
        },
    };

    // Ethernet (14) + IPv4 minimum (20)
    if packet.data.len() < 34 {
        return;
    }

    // EtherType (bytes 12..14)
    let ethertype = u16::from_be_bytes([packet.data[12], packet.data[13]]);
    if ethertype != 0x0800 {
        return; // not IPv4
    }

    // IPv4 header length (IHL * 4)
    let ihl = packet.data[14] & 0x0F;
    let ip_header_len = (ihl as usize) * 4;

    let transport_offset = 14 + ip_header_len;
    if packet.data.len() < transport_offset + 4 {
        return;
    }

    // IP addresses
    let src_ip = ipv4_to_string(&packet.data[26..30]);
    let dst_ip = ipv4_to_string(&packet.data[30..34]);

    let protocol_num = packet.data[23];
    let protocol = protocol_to_string(protocol_num);

    // Default ports (for non TCP/UDP)
    let mut src_port = "-".to_string();
    let mut dst_port = "-".to_string();

    // TCP or UDP → extract ports
    if protocol_num == 6 || protocol_num == 17 {
        let sp = u16::from_be_bytes([
            packet.data[transport_offset],
            packet.data[transport_offset + 1],
        ]);
        let dp = u16::from_be_bytes([
            packet.data[transport_offset + 2],
            packet.data[transport_offset + 3],
        ]);

        src_port = sp.to_string();
        dst_port = dp.to_string();
    }

    println!(
        "[{}, {}, {}, {}, {}, {}, {}, {}]",
        packet.ts.sec,
        packet.ts.usec,
        packet.data.len(),
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port
    );
}

/* ------------------------------------------------------------------------- */
/*                              PUBLIC API                                     */
/* ------------------------------------------------------------------------- */

pub fn list_adapters() -> Vec<String> {
    let mut adapters = Vec::new();

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

pub fn read_packets(adapter_index: u8) {
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

    println!("Starting listening on the adapter.");

    unsafe {
        pcap_loop(handle, 0, Some(packet_handler), null_mut());
    }
}