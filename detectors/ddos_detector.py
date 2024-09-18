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
            dst_port = packet[IP].dport if packet.haslayer('TCP') or packet.haslayer('UDP') else "Multiple"
            protocol = "IP"  
            timestamp = datetime.now()

            # Clean up older packets outside the time window
            self.packet_count[src_ip] = [ts for ts in self.packet_count[src_ip]
                                         if ts > timestamp - timedelta(seconds=self.time_window)]
            self.packet_count[src_ip].append(timestamp)

            if len(self.packet_count[src_ip]) > self.packet_threshold:
                severity = "High" if len(self.packet_count[src_ip]) > 2000 else "Medium"
                return {
                    "ip": src_ip,
                    "type": "DDoS_Attack",
                    "details": f"Potential DDoS attack detected with {len(self.packet_count[src_ip])} packets from {src_ip} in the last {self.time_window} seconds.",
                    "timestamp": timestamp,
                    "severity": severity,
                    "port": dst_port,
                    "protocol": protocol,
                    "possible_fixes": "Consider implementing rate limiting, using a web application firewall, or blocking suspicious IPs."
                }
        return None  
