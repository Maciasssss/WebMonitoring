from collections import defaultdict
from datetime import datetime, timedelta
from scapy.all import TCP, IP
from .detector_strategy import DetectorStrategy

class SynFloodDetector(DetectorStrategy):
    def __init__(self, time_window=60, syn_threshold=100):
        self.time_window = time_window
        self.syn_threshold = syn_threshold
        self.syn_requests = defaultdict(list)

    def monitor_traffic(self, packet):
        if packet.haslayer(TCP) and packet[TCP].flags == 'S':  
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport  
            protocol = "TCP"
            timestamp = datetime.now()

            # Remove old SYN requests that are outside the time window
            self.syn_requests[src_ip] = [ts for ts in self.syn_requests[src_ip] if ts > timestamp - timedelta(seconds=self.time_window)]
            self.syn_requests[src_ip].append(timestamp)

            if len(self.syn_requests[src_ip]) > self.syn_threshold:
                severity = "High" if len(self.syn_requests[src_ip]) > 200 else "Medium"
                return {
                    "ip": src_ip,
                    "type": "SYN_Flood",
                    "details": f"Potential SYN flood attack detected from {src_ip} - {len(self.syn_requests[src_ip])} SYN requests in {self.time_window} seconds",
                    "timestamp": timestamp,
                    "severity": severity,
                    "port": dst_port,
                    "protocol": protocol,
                    "possible_fixes": "Consider enabling SYN cookies, rate limiting, or using firewall rules to mitigate SYN flood attacks."
                }
        return None  
