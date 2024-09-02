from collections import defaultdict
from datetime import datetime, timedelta
from scapy.all import IP

class DDoSDetector:
    def __init__(self, time_window=60, packet_threshold=1000):
        self.time_window = time_window
        self.packet_threshold = packet_threshold
        self.packet_count = defaultdict(list)

    def monitor_traffic(self, packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            timestamp = datetime.now()

            # Usuwanie pakietów starszych niż time_window
            self.packet_count[src_ip] = [ts for ts in self.packet_count[src_ip] if ts > timestamp - timedelta(seconds=self.time_window)]
            self.packet_count[src_ip].append(timestamp)

            # Wykrywanie ataku DDoS
            if len(self.packet_count[src_ip]) > self.packet_threshold:
                print(f"Potential DDoS attack detected from {src_ip} - {len(self.packet_count[src_ip])} packets in {self.time_window} seconds")
