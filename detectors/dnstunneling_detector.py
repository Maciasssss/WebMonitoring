from collections import defaultdict
from datetime import datetime, timedelta
from scapy.all import IP, UDP, DNS, DNSQR

class DNSTunnelingDetector:
    def __init__(self, time_window=60, query_threshold=50):
        self.time_window = time_window  # Time window in seconds to track DNS requests
        self.query_threshold = query_threshold  # Number of DNS queries in the time window considered suspicious
        self.dns_queries = defaultdict(list)  # Track DNS queries by source IP

    def monitor_traffic(self, packet):
        if packet.haslayer(DNS) and packet.haslayer(IP) and packet.haslayer(UDP):
            dns_layer = packet.getlayer(DNS)
            if dns_layer.qr == 0:  # This is a DNS query (not a response)
                src_ip = packet[IP].src
                timestamp = datetime.now()

                # Track the DNS query timestamp for the source IP
                self.dns_queries[src_ip] = [ts for ts in self.dns_queries[src_ip] if ts > timestamp - timedelta(seconds=self.time_window)]
                self.dns_queries[src_ip].append(timestamp)

                # If the number of DNS queries from this IP exceeds the threshold, trigger an alert
                if len(self.dns_queries[src_ip]) > self.query_threshold:
                    print(f"Potential DNS tunneling detected from {src_ip} - {len(self.dns_queries[src_ip])} DNS queries in {self.time_window} seconds")

