from scapy.all import rdpcap

packets = rdpcap("dns&tcp_Packets.pcap")

for packet in packets:
    print(packet.summary())