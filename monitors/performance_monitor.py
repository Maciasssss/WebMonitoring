from datetime import datetime
from scapy.all import sniff, ICMP, IP

class PerformanceMonitor:
    def __init__(self):
        self.previous_timestamps = {}

    def monitor_traffic(self, packet):
        if packet.haslayer(ICMP) and packet[ICMP].type == 8:  # ICMP Echo Request
            src_ip = packet[IP].src
            timestamp = datetime.now()

            if src_ip in self.previous_timestamps:
                rtt = (timestamp - self.previous_timestamps[src_ip]).total_seconds() * 1000  # RTT w milisekundach
                print(f"RTT for {src_ip}: {rtt:.2f} ms")
            self.previous_timestamps[src_ip] = timestamp
