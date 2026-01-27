use std::net::IpAddr;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum L4Proto {
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    AToB,
    BToA,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    // Canonical ordering: (a,b) is sorted so both directions share one entry.
    pub a: Endpoint,
    pub b: Endpoint,
    pub proto: L4Proto,
}

impl Direction {
    pub fn opposite(self) -> Direction {
        match self {
            Direction::AToB => Direction::BToA,
            Direction::BToA => Direction::AToB,
        }
    }
}

impl FlowKey {
    /// Build a canonical flow key and return the packet direction.
    /// Use Direction to tell which way the packet went
    pub fn new(proto: L4Proto, src: Endpoint, dst: Endpoint) -> (Self, Direction) {
        // Define an ordering for endpoints (IP, port). This is used only for canonicalization.
        if (src.ip, src.port) <= (dst.ip, dst.port) {
            (
                FlowKey { a: src, b: dst, proto },
                Direction::AToB,
            )
        } else {
            (
                FlowKey { a: dst, b: src, proto },
                Direction::BToA,
            )
        }
    }   
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpConnState {
    New,
    SynSeen,
    Established,
    FinSeen,
    Closed,
    Reset,
}

#[derive(Debug, Clone)]
pub struct HttpRequestSummary {
    pub at_time_ms: u128,
    pub method: String,
    pub path: String,
    pub host: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HttpResponseSummary {
    pub at_time_ms: u128,
    pub status: u16,
}

#[derive(Debug)]
pub struct FlowState {
    pub state: TcpConnState,

    pub first_seen_ms: u128,
    pub last_seen_ms: u128,

    pub packets_a2b: u64,
    pub packets_b2a: u64,
    pub bytes_a2b: u64,
    pub bytes_b2a: u64,

    pub syn_count: u32,
    pub fin_count: u32,
    pub rst_count: u32,

    // Minimal HTTP tracking:
    pub http_requests: Vec<HttpRequestSummary>,
    pub http_responses: Vec<HttpResponseSummary>,

    // Direction-aware handshake tracking (TCP only)
    pub syn_dir: Option<Direction>, // direction of the initial SYN (no ACK)
    pub synack_seen: bool,          // did we see SYN+ACK in the opposite direction?
}