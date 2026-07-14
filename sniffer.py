from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def packet_callback(packet):
    print("=" * 60)

    if packet.haslayer(IP):
        print(f"Source IP      : {packet[IP].src}")
        print(f"Destination IP : {packet[IP].dst}")

        if packet.haslayer(TCP):
            print("Protocol       : TCP")
        elif packet.haslayer(UDP):
            print("Protocol       : UDP")
        elif packet.haslayer(ICMP):
            print("Protocol       : ICMP")
        else:
            print("Protocol       : Other")

        if packet.haslayer(Raw):
            try:
                print("Payload:")
                print(packet[Raw].load.decode(errors="ignore"))
            except:
                print("Payload: Binary Data")

print("Network Sniffer Started...")
print("Press Ctrl + C to Stop.\n")

sniff(prn=packet_callback, store=False)

