# Network Packet Analyzer
import scapy.all as scapy
from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    """
    Callback function to process captured packets.
    """
    try:
        # Display basic packet details
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            
            print(f"\n[+] Packet Captured:")
            print(f"    Source IP: {src_ip}")
            print(f"    Destination IP: {dst_ip}")
            print(f"    Protocol: {protocol}")
            
            # If the packet contains TCP or UDP, extract port information
            if TCP in packet:
                print(f"    Source Port: {packet[TCP].sport}")
                print(f"    Destination Port: {packet[TCP].dport}")
            elif UDP in packet:
                print(f"    Source Port: {packet[UDP].sport}")
                print(f"    Destination Port: {packet[UDP].dport}")
            
            # If there's payload data, show it
            if Raw in packet:
                print(f"    Payload Data: {packet[Raw].load[:50]}...")  # Display first 50 bytes
    except Exception as e:
        print(f"Error processing packet: {e}")

def start_sniffer(interface=None, packet_count=0):
    """
    Start the packet sniffer.
    """
    print(f"[*] Starting packet sniffer on interface: {interface or 'default'}...")
    sniff(iface=interface, prn=packet_callback, count=packet_count)

if __name__ == "__main__":
    # User can define the interface and packet count here.
    interface = input("Enter the network interface (e.g., eth0, wlan0, or leave blank for default): ").strip()
    packet_count = input("Enter the number of packets to capture (0 for unlimited): ").strip()
    packet_count = int(packet_count) if packet_count.isdigit() else 0
    
    start_sniffer(interface if interface else None, packet_count)
