use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

pub mod decode;
pub mod flow;
mod http_min;

use decode::PacketEvent;
use flow::{Direction, FlowKey, FlowState, TcpConnState, L4Proto};

const IDLE_TIMEOUT_MS: u128 = 120_000;      // 120s
const HARD_TIMEOUT_MS: u128 = 5 * 60_000;   // 5 min
const EVICT_EVERY_N_PACKETS: u64 = 500;     // Evict every 500 packets

pub static GLOBAL: LazyLock<Mutex<Analyzer>> = LazyLock::new(|| Mutex::new(Analyzer::new()));


#[derive(Debug, Clone, Copy)]
pub enum SortMode {
    Recent,
    Bytes,
    Packets,
    Duration,
}

pub struct Analyzer {
    flows: HashMap<FlowKey, FlowState>,
    packet_count: u64,
    last_evict_at_packet: u64,

    // View toggle for printing
    view_http_only: bool,
    view_established_only: bool,

    sort_mode: SortMode,
    sort_reverse: bool,
}

impl Analyzer {
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
            packet_count: 0,
            last_evict_at_packet: 0,
            view_http_only: false,
            view_established_only: false,
            sort_mode: SortMode::Recent,
            sort_reverse: false,
        }
    }

    pub fn on_packet(&mut self, ev: PacketEvent) {
        self.packet_count += 1;

        let flow = self.flows.entry(ev.flow.clone()).or_insert_with(|| FlowState {
            state: TcpConnState::New,
            first_seen_ms: ev.ts_ms,
            last_seen_ms: ev.ts_ms,
            packets_a2b: 0,
            packets_b2a: 0,
            bytes_a2b: 0,
            bytes_b2a: 0,
            syn_count: 0,
            fin_count: 0,
            rst_count: 0,
            http_requests: Vec::new(),
            http_responses: Vec::new(),
            syn_dir: None,
            synack_seen: false,
        });

        // update timestamps
        flow.last_seen_ms = ev.ts_ms;

        // update counters
        let payload_len = ev.payload.len() as u64;
        match ev.dir {
            Direction::AToB => {
                flow.packets_a2b += 1;
                flow.bytes_a2b += payload_len;
            }
            Direction::BToA => {
                flow.packets_b2a += 1;
                flow.bytes_b2a += payload_len;
            }
        }
        
        // TCP state tracking
        if let Some(flags) = ev.tcp_flags {
            Self::update_tcp_state(flow, ev.dir, flags);
            Self::maybe_track_http(flow, ev.ts_ms, ev.src_port, ev.dst_port, ev.payload);

            // Fallback: if we missed SYN/SYNACK but see data, infer Established.
            // This makes Established-only usable in real captures.
            if flow.state == TcpConnState::New && flags.ack && !ev.payload.is_empty() {
                flow.state = TcpConnState::Established;
            }
        }

        /* // print occasional summary -> Every 200 packets
        if self.packet_count % 200 == 0 {
            self.print_flow_summary(10);
        } */

        // Periodic eviction
        if self.packet_count - self.last_evict_at_packet >= EVICT_EVERY_N_PACKETS {
            self.last_evict_at_packet = self.packet_count;
            let removed = self.evict_old_flows(ev.ts_ms);
            if removed > 0 {
                println!("🧹 Evicted {} stale flows (remaining: {})", removed, self.flows.len());
            }
        }

    }

    fn evict_old_flows(&mut self, now_ms: u128) -> usize {
        let before = self.flows.len();

        self.flows.retain(|_k, st| {
            let idle = now_ms.saturating_sub(st.last_seen_ms);
            let age  = now_ms.saturating_sub(st.first_seen_ms);

            // Keep flow only if it's not idle-expired and not hard-expired
            idle <= IDLE_TIMEOUT_MS && age <= HARD_TIMEOUT_MS
        });

        before - self.flows.len()
    }


    fn update_tcp_state(flow: &mut FlowState, dir: Direction, f: decode::TcpFlags) {
        // RST always wins
        if f.rst {
            flow.rst_count += 1;
            flow.state = TcpConnState::Reset;
            // reset handshake tracking (optional)
            flow.syn_dir = None;
            flow.synack_seen = false;
            return;
        }

        if f.syn { flow.syn_count += 1; }
        if f.fin { flow.fin_count += 1; }

        // A simple but useful state machine:
        flow.state = match flow.state {
            TcpConnState::New => {
                // Initial SYN from initiator (SYN set, ACK not set)
                if f.syn && !f.ack {
                    flow.syn_dir = Some(dir);
                    flow.synack_seen = false;
                    TcpConnState::SynSeen
                } else {
                    TcpConnState::New
                }
            }

            TcpConnState::SynSeen => {
                // If we never recorded syn_dir (edge case), learn it
                if flow.syn_dir.is_none() && f.syn && !f.ack {
                    flow.syn_dir = Some(dir);
                }

                // We want SYN+ACK from the opposite direction
                if f.syn && f.ack {
                    if let Some(init_dir) = flow.syn_dir {
                        if dir == init_dir.opposite() {
                            flow.synack_seen = true;
                        }
                    }
                    TcpConnState::SynSeen
                }
                // Final ACK from initiator direction after SYN+ACK
                else if f.ack && !f.syn {
                    if let Some(init_dir) = flow.syn_dir {
                        if flow.synack_seen && dir == init_dir {
                            TcpConnState::Established
                        } else {
                            TcpConnState::SynSeen
                        }
                    } else {
                        TcpConnState::SynSeen
                    }
                } else {
                    TcpConnState::SynSeen
                }
            }

            TcpConnState::Established => {
                if f.fin {
                    TcpConnState::FinSeen
                } else {
                    TcpConnState::Established
                }
            }

            TcpConnState::FinSeen => {
                // You can optionally require FIN from both directions;
                // but for demo purposes this is good enough.
                if f.ack {
                    TcpConnState::Closed
                } else {
                    TcpConnState::FinSeen
                }
            }

            TcpConnState::Closed => TcpConnState::Closed,
            TcpConnState::Reset => TcpConnState::Reset,
        };
    }


    fn maybe_track_http(flow: &mut FlowState, ts_ms: u128, src_port: u16, dst_port: u16, payload: &[u8]) {
        // treat port 80 or 8080 as HTTP
        let is_http = src_port == 80 || dst_port == 80 || src_port == 8080 || dst_port == 8080;
        if !is_http {
            return;
        }

        let (req, resp) = http_min::try_parse_http(ts_ms, payload);
        if let Some(r) = req {
            flow.http_requests.push(r);
        }
        if let Some(r) = resp {
            flow.http_responses.push(r);
        }
    }

    pub fn print_flow_summary(&self, max: usize) {
        println!(
            "\n===== Flow table (top {}) [sort={:?} {}] [web-view only={}] [established_only={}] =====",
            max,
            self.sort_mode,
            if self.sort_reverse { "asc" } else { "desc" },
            self.view_http_only,
            self.view_established_only
        );

        // Sort flows
        let mut flows: Vec<_> = self.flows.iter().collect();

        flows.sort_by(|a, b| {
            let (_ka, sa) = a;
            let (_kb, sb) = b;

            let key_a = match self.sort_mode {
                SortMode::Recent => sb.last_seen_ms.cmp(&sa.last_seen_ms), // note: default desc
                SortMode::Bytes => {
                    let ta = sa.bytes_a2b + sa.bytes_b2a;
                    let tb = sb.bytes_a2b + sb.bytes_b2a;
                    tb.cmp(&ta)
                }
                SortMode::Packets => {
                    let ta = sa.packets_a2b + sa.packets_b2a;
                    let tb = sb.packets_a2b + sb.packets_b2a;
                    tb.cmp(&ta)
                }
                SortMode::Duration => {
                    let da = sa.last_seen_ms.saturating_sub(sa.first_seen_ms);
                    let db = sb.last_seen_ms.saturating_sub(sb.first_seen_ms);
                    db.cmp(&da)
                }
            };

            if self.sort_reverse { key_a.reverse() } else { key_a }
        });

        for (i, (k, st)) in flows.into_iter()
            .filter(|(k, st)| {
                // Established-only: TCP only
                if self.view_established_only {
                    if k.proto != L4Proto::Tcp { return false; }
                    if !(st.state == TcpConnState::Established || st.state == TcpConnState::SynSeen) {
                        return false;
                    }
                }

                // HTTP-only: show flows that look like HTTP (by port) or have parsed HTTP
                if self.view_http_only {
                    let is_web_port =
                    matches!(k.a.port, 80 | 8080 | 443) || matches!(k.b.port, 80 | 8080 | 443);

                    let has_http = !st.http_requests.is_empty() || !st.http_responses.is_empty();

                    if self.view_http_only && !(is_web_port || has_http) {
                        return false;
                    }
                }

                true
            })
            .take(max)
            .enumerate() 
        {
            let state_str = match k.proto {
                L4Proto::Tcp => format!("{:?}", st.state),
                L4Proto::Udp => "UDP".to_string(),
                L4Proto::Icmp => "ICMP".to_string(),
            };

            let dur_ms = st.last_seen_ms.saturating_sub(st.first_seen_ms);
            let dur_s = dur_ms as f64 / 1000.0;

            println!(
                "{}. {:?}  {}:{} <-> {}:{}  state={}  dur={:.1}s  pkts(A->B/B->A)={}/{}  bytes={}/{}  HTTP(req/resp)={}/{}",
                i + 1,
                k.proto,
                k.a.ip, k.a.port,
                k.b.ip, k.b.port,
                state_str,
                dur_s,
                st.packets_a2b, st.packets_b2a,
                st.bytes_a2b, st.bytes_b2a,
                st.http_requests.len(), st.http_responses.len()
            );

            // Show last request line if present
            if let Some(last_req) = st.http_requests.last() {
                println!("    last HTTP request: {} {} host={:?}", last_req.method, last_req.path, last_req.host);
            }
            if let Some(last_resp) = st.http_responses.last() {
                println!("    last HTTP response: {}", last_resp.status);
            }
        }

        println!("===== End flow table =====\n");
    }



    // Public methods for keybinds
    pub fn print_now(&self) {
        self.print_flow_summary(10);
    }

    pub fn clear(&mut self) {
        self.flows.clear();
        self.packet_count = 0;
        self.last_evict_at_packet = 0;
    }

    pub fn toggle_http_only(&mut self) {
        self.view_http_only = !self.view_http_only;
        println!("🔎 HTTP-only view: {}", self.view_http_only);
    }

    pub fn toggle_established_only(&mut self) {
        self.view_established_only = !self.view_established_only;
        println!("🔒 Established-only view: {}", self.view_established_only);
    }


    // Sorting
    pub fn cycle_sort_mode(&mut self) {
        self.sort_mode = match self.sort_mode {
            SortMode::Recent => SortMode::Bytes,
            SortMode::Bytes => SortMode::Packets,
            SortMode::Packets => SortMode::Duration,
            SortMode::Duration => SortMode::Recent,
        };
        println!("↕️ sort mode: {:?}", self.sort_mode);
    }

    pub fn toggle_sort_reverse(&mut self) {
        self.sort_reverse = !self.sort_reverse;
        println!("↕️ sort reverse: {}", self.sort_reverse);
    }
}