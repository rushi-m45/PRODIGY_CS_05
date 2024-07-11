from scapy.all import sniff, IP, TCP, wrpcap, rdpcap

# Function to process captured packets
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"IP Source: {ip_src} -> IP Destination: {ip_dst}")
        
    if TCP in packet:
        tcp_sport = packet[TCP].sport
        tcp_dport = packet[TCP].dport
        print(f"TCP Source Port: {tcp_sport} -> TCP Destination Port: {tcp_dport}")

# Capture packets and save to file
packets = sniff(filter="tcp", prn=packet_callback, count=10)
wrpcap('captured_packets.pcap', packets)

# Read packets from file
saved_packets = rdpcap('captured_packets.pcap')

for packet in saved_packets:
    print(packet.show())
