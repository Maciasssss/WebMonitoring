from collections import defaultdict
from datetime import datetime, timedelta
from scapy.all import IP, TCP

class PortScanDetector:
    def __init__(self, time_window=10, port_threshold=10):
        self.time_window = time_window
        self.port_threshold = port_threshold
        self.scan_activity = defaultdict(lambda: defaultdict(list))

    def monitor_traffic(self, packet):
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            timestamp = datetime.now()

            # Usuwanie starych zapisów
            self.scan_activity[src_ip][dst_port] = [ts for ts in self.scan_activity[src_ip][dst_port] if ts > timestamp - timedelta(seconds=self.time_window)]
            self.scan_activity[src_ip][dst_port].append(timestamp)

            # Liczenie różnych portów, które były skanowane
            if len(self.scan_activity[src_ip]) > self.port_threshold:
                print(f"Potential port scan detected from {src_ip} - {len(self.scan_activity[src_ip])} ports in {self.time_window} seconds")
