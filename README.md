# Personal_firewall_filters_traffic
 a lightweight personal firewall that filters traffic based on rules.

## Project Overview
This project implements a lightweight personal firewall that monitors live network traffic and blocks packets based on rules defined by the user. It features a GUI for control and logs suspicious packets to a file.

## Features
- Rule-based filtering for IPs, Ports, Protocols
- Packet sniffing using Scapy
- Logs blocked packets with timestamp and reason
- Simple GUI to Start/Stop the firewall
- Easy customization via `rules.json`

## 🛠Tools & Libraries
- Python 3
- Scapy
- Tkinter
- JSON

## How to Run

### 1. Install dependencies
```bash
""pip install scapy ""
```
### 2. Navigate to Project Folder
```bash
"" cd path/personal_firewall ""
```
### 3. Start Firewall With GUI
```bash
"" Python gui.py ""
```
🖥️ A window will open: (Screenshot Attached)
- Click Start Firewall → Sniffing begins
- Click Stop Firewall → Graceful stop, thread ends

### 4. Defile Rules to include IPs, ports, or protocols you want to block
```rules.json file
{
  "block": {
    "ip": ["192.168.1.1"],
    "port": [80],
    "protocol": ["ICMP"]
  }
}
```
### 5. View logs to see all blocked packets
Saves in log.json file

## Note
- Requires admin/root privileges to sniff packets.
- Educational use only. Not a replacement for real firewalls.
