from scapy.all import sniff, conf, IP, TCP, UDP, ARP, ICMP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        # Check for protocol type
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        elif ARP in packet:
            protocol = "ARP"
        else:
            protocol = "Other"

        # Print packet details
        print(f"Protocol: {protocol}")
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Payload: {bytes(packet[IP].payload)}")
        print("-" * 50)

def main():
    # Use layer 3 socket for sniffing
    conf.L3socket
    # Start sniffing
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
