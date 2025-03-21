from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        payload = packet[Raw].load if Raw in packet else "No Payload"
        
        print(f"[+] Source IP: {src_ip} -> Destination IP: {dst_ip} | Protocol: {protocol}")
        if payload != "No Payload":
            print(f"    Payload: {payload[:100]}")  # Display first 100 bytes of payload

if __name__ == "__main__":
    print("[*] Starting packet sniffer. Press Ctrl+C to stop.")
    sniff(prn=packet_callback, store=False)