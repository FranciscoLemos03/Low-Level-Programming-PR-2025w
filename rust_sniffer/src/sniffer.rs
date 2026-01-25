use std::{ffi::CStr, ptr::null_mut, slice};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
    mpsc
};
use std::thread;
use crossterm::event::{poll, read, Event, KeyCode, KeyEvent, KeyModifiers, KeyEventKind};
use crossterm::terminal::{enable_raw_mode, disable_raw_mode};
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
    pcap_dispatch,
    pcap_datalink};
use crate::parser;
use crate::analyzer;
use std::time::Duration;

enum UiCmd {
    ToggleMode,
    PrintTable,
    ToggleHttpOnly,
    ToggleEstablishedOnly,
    Clear,
    Help,
    Quit,
    CycleSort,
    ToggleSortReverse,
}

#[repr(C)]
struct CaptureCtx {
    datalink: i32,
    filter: Option<FilterConfig>,
    print_packets: AtomicBool,
}

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

    // Read context passed from read_packets()
    /* let datalink: i32 = if !param.is_null() {
        let ctx = &*(param as *const CaptureCtx);
        ctx.datalink
    } else {
        1 // fallback: assume Ethernet
    }; */
    let ctx = &*(param as *const CaptureCtx);
    let do_print = ctx.print_packets.load(Ordering::Relaxed);
    let datalink = ctx.datalink;
    let filter = &ctx.filter;

    let len = (*header).len as usize;
    let data_slice = unsafe { slice::from_raw_parts(pkt_data, len) };

    let sec_u128 = (*header).ts.tv_sec as u128;
    let usec_u128 = (*header).ts.tv_usec as u128;
    let ts_ms = sec_u128 * 1000 + (usec_u128 / 1000);

    // Analyzer Connection tracking
    /* if let Some(ev) = analyzer::decode::decode_ipv4_tcp(ts_ms, data_slice, datalink) {
        if let Ok(mut a) = analyzer::GLOBAL.lock() {
            a.on_packet(ev);
        }
    } */

    let sec = (*header).ts.tv_sec as u32;
    let usec = (*header).ts.tv_usec as u32;


    let proto = parser::get_protocol(data_slice);
    let (src_ip, dst_ip) = parser::get_ips(data_slice);

    let pass = match filter {
        None => true,
        Some(fc) => matches_filter(fc, &proto, &src_ip, &dst_ip),
    };

    if pass {
        if do_print {
            // Always allow printing for protocols the parser supports
            print!("[Time: {}.{}] ", sec, usec);
            parser::handle_packet(data_slice);
        }

        // Only update analyzer if we can decode TCP flow events
        if let Some(ev) = analyzer::decode::decode_ipv4_l4(ts_ms, data_slice, datalink) {
            if let Ok(mut a) = analyzer::GLOBAL.lock() {
                a.on_packet(ev);
            }
        }
    }
}

fn matches_filter(
    fc: &FilterConfig,
    proto: &Option<String>,
    src_ip: &Option<String>,
    dst_ip: &Option<String>,
) -> bool {
    // IP filters (IPv4 only, since get_ips ignores IPv6/ARP)
    let src_match = fc
        .src_ip
        .as_ref()
        .map(|f| src_ip.as_ref() == Some(f))
        .unwrap_or(true);

    let dst_match = fc
        .dst_ip
        .as_ref()
        .map(|f| dst_ip.as_ref() == Some(f))
        .unwrap_or(true);

    if !(src_match && dst_match) {
        return false;
    }

    // Protocol filter
    if fc.protocol == "all" {
        return true;
    }

    // Compare against parser protocol labels
    proto.as_deref() == Some(fc.protocol)
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

    // Changing filtering to directly have filtering for the analyzer
    // unsafe { FILTER = filter; }

    let dl = unsafe { pcap_datalink(handle) };
    println!("pcap_datalink = {}", dl);

    let mut ctx = Box::new(CaptureCtx { datalink: dl, filter, print_packets: AtomicBool::new(true) });
    let user_ptr = (&mut *ctx as *mut CaptureCtx) as *mut u_char;

    println!("Starting listening on the adapter.");

    enable_raw_mode().ok();

    let (tx, rx) = mpsc::channel::<UiCmd>();

    let running = Arc::new(AtomicBool::new(true));
    let running_key = running.clone();

    println!("Keys: m=mode, t=table, s=sort, r=reverse, w=web-view, e=established-only, c=clear, ?=help, Ctrl+Q=quit");
    let tx_key = tx.clone();
    thread::spawn(move || {
        while running_key.load(Ordering::Relaxed) {
            if poll(Duration::from_millis(50)).unwrap_or(false) {
                if let Ok(Event::Key(KeyEvent { code, modifiers, kind, .. })) = read() {
                    if kind != KeyEventKind::Press {
                        continue;
                    }
                    
                    // Quit
                    if code == KeyCode::Char('q') && modifiers.contains(KeyModifiers::CONTROL) {
                        let _ = tx_key.send(UiCmd::Quit);
                        running_key.store(false, Ordering::Relaxed);
                        continue;
                    }

                    // Single-key commands
                    match code {
                        KeyCode::Char('m') => { let _ = tx_key.send(UiCmd::ToggleMode); }
                        KeyCode::Char('t') => { let _ = tx_key.send(UiCmd::PrintTable); }
                        KeyCode::Char('w') => { let _ = tx_key.send(UiCmd::ToggleHttpOnly); }
                        KeyCode::Char('e') => { let _ = tx_key.send(UiCmd::ToggleEstablishedOnly); }
                        KeyCode::Char('c') => { let _ = tx_key.send(UiCmd::Clear); }
                        KeyCode::Char('?') => { let _ = tx_key.send(UiCmd::Help); }
                        KeyCode::Char('s') => { let _ = tx_key.send(UiCmd::CycleSort); }
                        KeyCode::Char('r') => { let _ = tx_key.send(UiCmd::ToggleSortReverse); }
                        _ => {}
                    }
                }
            }
        }
    });

    while running.load(Ordering::Relaxed) {
        unsafe {
            pcap_dispatch(handle, 0, Some(packet_handler), user_ptr);
        }

        while let Ok(cmd) = rx.try_recv() {
                match cmd {
                    UiCmd::ToggleMode => {
                        let old = ctx.print_packets.load(Ordering::Relaxed);
                        ctx.print_packets.store(!old, Ordering::Relaxed);
                        println!("Mode: {}", if old { "FLOWS" } else { "PACKETS" });
                    }
                    UiCmd::PrintTable => {
                        if let Ok(a) = analyzer::GLOBAL.lock() {
                            a.print_now();
                        }
                    }
                    UiCmd::ToggleHttpOnly => {
                        if let Ok(mut a) = analyzer::GLOBAL.lock() {
                            a.toggle_http_only();
                        }
                    }
                    UiCmd::ToggleEstablishedOnly => {
                        if let Ok(mut a) = analyzer::GLOBAL.lock() {
                            a.toggle_established_only();
                        }
                    }
                    UiCmd::Clear => {
                        if let Ok(mut a) = analyzer::GLOBAL.lock() {
                            a.clear();
                            println!("🧽 Cleared flows");
                        }
                    }
                    UiCmd::Help => {
                        println!("Keys: m=mode, t=table, s=sort, r=reverse, w=web-view, e=established-only, c=clear, ?=help, Ctrl+Q=quit");
                    }
                    UiCmd::Quit => {
                        running.store(false, Ordering::Relaxed);
                    }
                    UiCmd::CycleSort => {
                        if let Ok(mut a) = analyzer::GLOBAL.lock() {
                            a.cycle_sort_mode();
                            a.print_now();
                        }
                    }
                    UiCmd::ToggleSortReverse => {
                        if let Ok(mut a) = analyzer::GLOBAL.lock() {
                            a.toggle_sort_reverse();
                            a.print_now();
                        }
                    }
                }
            }
    }

    unsafe {
        disable_raw_mode().ok();
        pcap_breakloop(handle);
        println!("Stopping listening on the adapter.");
    }
}