from collections import defaultdict
from datetime import datetime, timedelta
from scapy.all import IP

from .detector_strategy import DetectorStrategy

class DDoSDetector(DetectorStrategy):
    def __init__(self, time_window=60, packet_threshold=1000):
        self.time_window = time_window
        self.packet_threshold = packet_threshold
        self.packet_count = defaultdict(list)

    def monitor_traffic(self, packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            timestamp = datetime.now()
            self.packet_count[src_ip] = [ts for ts in self.packet_count[src_ip] if ts > timestamp - timedelta(seconds=self.time_window)]
            self.packet_count[src_ip].append(timestamp)

            if len(self.packet_count[src_ip]) > self.packet_threshold:
                return {"ip": src_ip, "details": "Potential DDoS attack detected"}
        return None  # No alert if no DDoS detected
