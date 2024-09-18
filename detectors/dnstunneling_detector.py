from collections import defaultdict
from datetime import datetime, timedelta
from scapy.all import IP, UDP, DNS, DNSQR

from .detector_strategy import DetectorStrategy

class DNSTunnelingDetector(DetectorStrategy):
    def __init__(self, time_window=60, query_threshold=50):
        self.time_window = time_window  # Time window in seconds to track DNS requests
        self.query_threshold = query_threshold  # Number of DNS queries in the time window considered suspicious
        self.dns_queries = defaultdict(list)  # Track DNS queries by source IP

    def monitor_traffic(self, packet):
        if packet.haslayer(DNS) and packet.haslayer(IP) and packet.haslayer(UDP):
            dns_layer = packet.getlayer(DNS)
            if dns_layer.qr == 0:  
                src_ip = packet[IP].src
                dst_port = packet[UDP].dport  
                protocol = "UDP"
                timestamp = datetime.now()

                # Track the DNS query timestamp for the source IP
                self.dns_queries[src_ip] = [ts for ts in self.dns_queries[src_ip] if ts > timestamp - timedelta(seconds=self.time_window)]
                self.dns_queries[src_ip].append(timestamp)

                if len(self.dns_queries[src_ip]) > self.query_threshold:
                    severity = "High" if len(self.dns_queries[src_ip]) > 100 else "Medium"
                    return {
                        "ip": src_ip,
                        "type": "DNS_Tunneling",
                        "details": f"{len(self.dns_queries[src_ip])} DNS queries in {self.time_window} seconds",
                        "timestamp": timestamp,
                        "severity": severity,
                        "port": dst_port,
                        "protocol": protocol,
                        "possible_fixes": "Consider using DNS filtering, inspecting DNS queries more closely, or blocking suspicious DNS requests."
                    }
        return None  
