from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from datetime import datetime

packet_count = 0

def packet_analyzer(packet):
    global packet_count

    if IP in packet:
        packet_count += 1
        print("\n========== Packet", packet_count, "==========")
        print("Time           :", datetime.now().strftime("%H:%M:%S"))
        print("Source IP      :", packet[IP].src)
        print("Destination IP :", packet[IP].dst)

        if TCP in packet:
            print("Protocol       : TCP")
        elif UDP in packet:
            print("Protocol       : UDP")
        elif ICMP in packet:
            print("Protocol       : ICMP")
        else:
            print("Protocol       : Other")

print("Network Sniffer Started...")
print("Capturing packets for 1 minute...\n")

sniff(
    iface="Wi-Fi",      
    prn=packet_analyzer,
    store=False,
    timeout=60
)

print("\nSniffing stopped.")
print("Total packets captured:", packet_count)
