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

pub struct Analyzer {
    flows: HashMap<FlowKey, FlowState>,
    packet_count: u64,
    last_evict_at_packet: u64,
}

impl Analyzer {
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
            packet_count: 0,
            last_evict_at_packet: 0,
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
            Self::update_tcp_state(flow, flags);
            Self::maybe_track_http(flow, ev.ts_ms, ev.src_port, ev.dst_port, ev.payload);
        }

        // print occasional summary -> Every 200 packets
        if self.packet_count % 200 == 0 {
            self.print_flow_summary(10);
        }

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

    fn update_tcp_state(flow: &mut FlowState, f: decode::TcpFlags) {
        if f.rst {
            flow.rst_count += 1;
            flow.state = TcpConnState::Reset;
            return;
        }

        if f.syn {
            flow.syn_count += 1;
        }
        if f.fin {
            flow.fin_count += 1;
        }

        // A simple but useful state machine:
        flow.state = match flow.state {
            TcpConnState::New => {
                if f.syn && !f.ack {
                    TcpConnState::SynSeen // first SYN
                } else {
                    TcpConnState::New
                }
            }
            TcpConnState::SynSeen => {
                // SYN+ACK or ACK indicates handshake completion
                if (f.syn && f.ack) || f.ack {
                    TcpConnState::Established
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
                if f.fin {
                    TcpConnState::Closed
                } else {
                    TcpConnState::FinSeen
                }
            }
            other => other,
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
        println!("\n===== Flow table (top {}) =====", max);

        // Print a few flows, sorted by last_seen (most recent)
        let mut flows: Vec<_> = self.flows.iter().collect();
        flows.sort_by_key(|(_, st)| st.last_seen_ms);
        flows.reverse();

        for (i, (k, st)) in flows.into_iter().take(max).enumerate() {
            let state_str = match k.proto {
                L4Proto::Tcp => format!("{:?}", st.state),
                L4Proto::Udp => "UDP".to_string(),
            };

            println!(
                "{}. {:?}  {}:{} <-> {}:{}  state={}  pkts(A->B/B->A)={}/{}  bytes={}/{}  HTTP(req/resp)={}/{}",
                i + 1,
                k.proto,
                k.a.ip, k.a.port,
                k.b.ip, k.b.port,
                state_str,
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
}