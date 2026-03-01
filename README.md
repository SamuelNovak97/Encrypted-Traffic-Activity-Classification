# Encrypted Traffic Activity Classification (Wi‑Fi/LAN) using Real‑Time Heuristics

## Abstract
This project infers user activity from **encrypted** Wi‑Fi/LAN traffic in real time using **metadata-only heuristics** (no ML). It classifies traffic into **video_streaming**, **gaming**, and **idle** with strong practical accuracy; **browsing** is supported but remains difficult due to QUIC/HTTP3 multiplexing, caching, and background traffic. The script also reports **cumulative direction dominance** (AP→Device vs Device→AP) in bytes and packets.

## Requirements
- Linux (tested on Ubuntu/Kali)
- `tshark` (Wireshark CLI)
- Python 3

Install:
```bash
sudo apt update
sudo apt install -y tshark python3
```

## Run
1) List interfaces:
```bash
tshark -D
```

2) Find your device IP on that interface:
```bash
ip addr show <iface>
```

3) Start the classifier (recommended: isolate your device traffic):
```bash
sudo ./categorize.py -i <iface> --local-ip <your_ip> --target-ip <your_ip>
```

### Optional flags
- Change window length:
```bash
sudo ./categorize.py -i <iface> --local-ip <your_ip> --target-ip <your_ip> --window 5
```

- Control printing strictness:
```bash
sudo ./categorize.py -i <iface> --local-ip <your_ip> --target-ip <your_ip> --conf-threshold 0.7
```

- Debug scoring:
```bash
sudo ./categorize.py -i <iface> --local-ip <your_ip> --target-ip <your_ip> --show-scores
```

Stop with `Ctrl+C`. The script prints a **Direction dominance (cumulative)** summary on exit.
