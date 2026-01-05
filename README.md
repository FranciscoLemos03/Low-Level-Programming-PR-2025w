# Low-Level-Programming-PR-2025w
Packet Sniffer / Traffic Analyzer


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