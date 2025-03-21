Network Packet Sniffer in Python using Scapy 🚀

Overview
This Python script is a simple yet powerful packet sniffer that captures and analyzes network packets in real-time. It provides details such as source and destination IP addresses, protocols, and payload data. The tool is designed for educational and ethical purposes to help developers and cybersecurity enthusiasts understand network traffic.

Features
✅ Captures network packets in real-time
✅ Displays IP addresses, protocols, and payload data
✅ Supports command-line arguments for interface selection
✅ Exception handling for permission errors
✅ Uses Scapy, a powerful network packet manipulation library

Code Explanation
1️⃣ Import Required Modules

from scapy.all import sniff, IP, TCP, UDP, Raw

Scapy is used to capture and analyze network packets.
The required classes (IP, TCP, UDP, Raw) help extract specific packet details.

2️⃣ Define the Packet Processing Function

def packet_callback(packet):
    """Callback function to process captured packets."""
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        payload = packet[Raw].load if Raw in packet else "No Payload"
        print(f"[+] Source: {src_ip} -> Destination: {dst_ip} | Protocol: {protocol}")
        if payload != "No Payload":
            print(f"    Payload (truncated): {payload[:100]}") 
      

This function extracts and displays:
Source & Destination IP Addresses
Protocol type (TCP, UDP, or Other)
First 100 bytes of the Payload (if available)

3️⃣ Start the Sniffer

def start_sniffer(interface=None):
    """Starts packet sniffing on the specified network interface."""
    print("[*] Starting packet sniffer. Press Ctrl+C to stop.")
    try:
        sniff(prn=packet_callback, store=False, iface=interface)
    except PermissionError:
        print("[!] Permission denied. Run the script with administrative privileges.")
    except Exception as e:
        print(f"[!] Error: {e}")

sniff() starts capturing packets.
Handles permission errors, ensuring the user runs the script as an administrator.

4️⃣ Add Command-Line Arguments

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Simple Network Packet Sniffer")
    parser.add_argument("-i", "--interface", type=str, help="Network interface to sniff on", required=False)
    args = parser.parse_args()
    start_sniffer(interface=args.interface)
    
Allows users to specify a network interface using:

python packet_sniffer.py -i Wi-Fi

If no interface is provided, it sniffs on the default interface.

How to Use the Packet Sniffer
1️⃣ Install Dependencies

pip install scapy

2️⃣ Run the Script
With a specific network interface:

python packet_sniffer.py -i Wi-Fi

Without specifying an interface (default):

python packet_sniffer.py

3️⃣ Stop the Sniffer
Press Ctrl + C to stop.
