from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from datetime import datetime

def print_fill(char="-", width=60):
    """Returns a horizontal line string."""
    return char * width + "\n"

def read_pcap(pcap_path):
    """Reads a .pcap file and returns tree-style formatted packet info as a string."""

    strst = ""
    print("[*] Parsing Pcap file.")

    packets = rdpcap(pcap_path)
    strst += print_fill("=")
    strst += f"[+] Total packets: {len(packets)}\n"
    strst += print_fill("=")
    strst += "\n\n"

    # Loop through packets
    for i, pkt in enumerate(packets, start=1):
        time_str = datetime.fromtimestamp(float(pkt.time)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        layers = " > ".join([layer.__class__.__name__ for layer in pkt.layers()])

        # Header section
        strst += print_fill("-")
        strst += f"[{i:04}] {time_str}\n"
        strst += f"└── Layers: {layers}\n"
        strst += f"    └── Length: {len(pkt)} bytes\n"

        # IP layer info
        if IP in pkt:
            ip = pkt[IP]
            strst += "        ├── IP Layer:\n"
            strst += f"        │   ├── Source IP : {ip.src}\n"
            strst += f"        │   └── Dest IP   : {ip.dst}\n"

        # Transport layer
        if TCP in pkt:
            tcp = pkt[TCP]
            strst += "        ├── TCP Layer:\n"
            strst += f"        │   ├── Src Port : {tcp.sport}\n"
            strst += f"        │   ├── Dst Port : {tcp.dport}\n"
            strst += f"        │   └── Flags    : {tcp.flags}\n"
        elif UDP in pkt:
            udp = pkt[UDP]
            strst += "        ├── UDP Layer:\n"
            strst += f"        │   ├── Src Port : {udp.sport}\n"
            strst += f"        │   └── Dst Port : {udp.dport}\n"
        elif ICMP in pkt:
            icmp = pkt[ICMP]
            strst += "        ├── ICMP Layer:\n"
            strst += f"        │   ├── Type : {icmp.type}\n"
            strst += f"        │   └── Code : {icmp.code}\n"

        # Payload preview
        try:
            raw_bytes = bytes(pkt.payload.payload)
            if raw_bytes:
                hex_data = raw_bytes.hex()[:64]
                strst += "        └── Payload:\n"
                strst += f"            └── {hex_data}...\n"
        except Exception:
            pass

    strst += print_fill("=")
    strst += "[✓] Network Trace Analysis Done.\n"
    strst += print_fill("=")
    
    print("[*] Done reading PCAP.\n")
    return strst

