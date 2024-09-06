from collections import defaultdict
from datetime import datetime, timedelta  # Correct import for timedelta
from scapy.all import TCP, IP
from .detector_strategy import DetectorStrategy

class SynFloodDetector(DetectorStrategy):
    def __init__(self, time_window=60, syn_threshold=100):
        self.time_window = time_window
        self.syn_threshold = syn_threshold
        self.syn_requests = defaultdict(list)

    def monitor_traffic(self, packet):
        if packet.haslayer(TCP) and packet[TCP].flags == 'S':  # SYN packet
            src_ip = packet[IP].src
            timestamp = datetime.now()

            # Remove old requests outside the time window
            self.syn_requests[src_ip] = [ts for ts in self.syn_requests[src_ip] if ts > timestamp - timedelta(seconds=self.time_window)]
            self.syn_requests[src_ip].append(timestamp)

            # Detect potential SYN flood
            if len(self.syn_requests[src_ip]) > self.syn_threshold:
                return {
                    "ip": src_ip,
                    "type": "SYN Flood",
                    "details": f"Potential SYN flood attack detected from {src_ip} - {len(self.syn_requests[src_ip])} SYN requests in {self.time_window} seconds",
                    "timestamp": timestamp
                }
        return None  # No alert if nothing is detected
