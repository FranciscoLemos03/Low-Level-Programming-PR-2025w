# Low-Level-Programming-PR-2025w
Packet Sniffer / Traffic Analyzer

A packet sniffer written in Rust that captures and analyzes network traffic in real-time, with support for protocol-based filters.

## Features

- Real-time packet capture using WinPcap/Npcap
- Network protocol analysis (Ethernet, IPv4, TCP, UDP, HTTP, HTTPS, DNS, ICMP, ARP)
- Protocol filters (HTTP, HTTPS, DNS, ICMP, ARP or all traffic)
- IP address filters (source and/or destination IP)
- Simple command-line interface
- Support for multiple network adapters

## How to Run

### Prerequisites

- Rust (installed via rustup)
- WinPcap or Npcap (for packet capture on Windows)
- Administrator permissions (for network adapter access)

### Build and Run

1. Navigate to the project directory:
   ```bash
   cd C:/Users/franc/Desktop/Low-Level-Programming-PR-2025w
   ```

2. Build the project:
   ```bash
   cargo build --release
   ```

3. Run as administrator:
   ```bash
   cargo run
   ```

### Usage

1. The program will list available network adapters
2. Choose the desired adapter index
3. Select the protocol filter:
   - 0: All traffic
   - 1: HTTP only
   - 2: HTTPS only
   - 3: DNS only
   - 4: ICMP only
   - 5: ARP only
4. Choose whether to filter by IP address (y/n)
5. If yes, enter source IP (or 'none' to skip)
6. If yes, enter destination IP (or 'none' to skip)
7. Press Ctrl+Q to stop capturing

## Architecture and Program Logic

### Execution Flow

```
main.rs -> menu.rs -> sniffer.rs -> parser/
```

1. **main.rs**: Entry point, coordinates adapter and filter selection
2. **menu.rs**: Interface for adapter and protocol filter selection
3. **sniffer.rs**: Manages packet capture using libpcap
4. **parser/**: Modules for network protocol analysis

### Capture and Filtering Logic

```
+----------------+     +-----------------+     +-----------------+
|   Packet       | --> |  get_protocol() | --> |   Filter        |
|   Capture      |     |   (parse)       |     |   Check         |
+----------------+     +-----------------+     +-----------------+
        |                       |                       |
        v                       v                       v
+----------------+     +-----------------+     +-----------------+
|   pcap_dispatch| --> | Ethernet -> IP  | --> | Display if     |
|   (raw data)   |     | -> TCP/UDP ->   |     | matches filter  |
|                |     | Application     |     +-----------------+
+----------------+     +-----------------+
```

#### Technical Details

- **Capture**: Uses `pcap_findalldevs_ex` to list adapters and `pcap_open` to start capture
- **Parsing**: Hierarchical packet analysis:
  - Ethernet (frame type)
  - IPv4/IPv6 (IP addresses)
  - TCP/UDP (ports and flags)
  - Application (HTTP headers, etc.)
- **Filtering**: Before displaying, determines packet protocol and IP addresses, then compares with selected filters
- **Interruption**: Separate thread monitors Ctrl+Q to stop capture

### Supported Protocols

| Protocol | Detection | IP Filtering |
|----------|-----------|--------------|
| HTTP     | TCP port 80 + "HTTP" in payload | Yes |
| HTTPS    | TCP port 443 | Yes |
| DNS      | UDP/TCP port 53 | Yes |
| ICMP     | IP protocol 1 | Yes |
| ARP      | EtherType 0x0806 | No (Layer 2) |
| TCP/UDP  | IP protocols 6/17 | Yes |

## Building `bindings`

If you want to build fresh bindings.rs:

On Linux:
```sh
bindgen Include/pcap.h -- -target x86_64-pc-windows-gnu -I[FULL-PATH]/Include
```

On Windows:
```sh
bindgen Include/pcap.h -- -I ./Include
```