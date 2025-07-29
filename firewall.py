from scapy.all import sniff, IP, TCP, UDP, ICMP
import json
from datetime import datetime

running = True  # Global flag to control sniffing

with open("rules.json", "r") as f:
    rules = json.load(f)

log = []

def log_packet(pkt, reason):
    log_entry = {
        "time": str(datetime.now()),
        "src": pkt[IP].src,
        "dst": pkt[IP].dst,
        "reason": reason
    }
    print(f"Blocked: {log_entry}")
    log.append(log_entry)
    with open("log.json", "w") as f:
        json.dump(log, f, indent=2)

def process_packet(pkt):
    if not running:
        return False  # Stop sniffing

    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst

        if src in rules["block"]["ip"] or dst in rules["block"]["ip"]:
            log_packet(pkt, "IP blocked")
            return

        if TCP in pkt and pkt[TCP].dport in rules["block"]["port"]:
            log_packet(pkt, "TCP port blocked")
            return

        if UDP in pkt and pkt[UDP].dport in rules["block"]["port"]:
            log_packet(pkt, "UDP port blocked")
            return

        if ICMP in pkt and "ICMP" in rules["block"]["protocol"]:
            log_packet(pkt, "ICMP blocked")
            return

def start_firewall():
    global running
    running = True
    sniff(prn=process_packet, stop_filter=lambda x: not running)

def stop_firewall():
    global running
    running = False
