from collections import defaultdict
import datetime
from scapy.all import TCP, IP

class SynFloodDetector:
    def __init__(self, time_window=60, syn_threshold=100):
        self.time_window = time_window
        self.syn_threshold = syn_threshold
        self.syn_requests = defaultdict(list)

    def monitor_traffic(self, packet):
        if packet.haslayer(TCP):
            if packet[TCP].flags == 'S':  # SYN packet
                src_ip = packet[IP].src
                timestamp = datetime.now()

                self.syn_requests[src_ip] = [ts for ts in self.syn_requests[src_ip] if ts > timestamp - datetime.timedelta(seconds=self.time_window)]
                self.syn_requests[src_ip].append(timestamp)

                if len(self.syn_requests[src_ip]) > self.syn_threshold:
                    print(f"Potential SYN flood attack detected from {src_ip} - {len(self.syn_requests[src_ip])} SYN requests in {self.time_window} seconds")
