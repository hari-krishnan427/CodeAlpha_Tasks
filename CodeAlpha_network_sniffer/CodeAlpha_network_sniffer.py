from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_analyzer(packet):
    print("\n========== New Packet ==========")

    if IP in packet:
        print("Source IP      :", packet[IP].src)
        print("Destination IP :", packet[IP].dst)

        if TCP in packet:
            print("Protocol       : TCP")
        elif UDP in packet:
            print("Protocol       : UDP")
        elif ICMP in packet:
            print("Protocol       : ICMP")

print("Network Sniffer Started... Capturing 10 packets only")
sniff(prn=packet_analyzer, store=False, count=10)
print("Sniffing completed.")
