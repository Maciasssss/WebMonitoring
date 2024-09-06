from collections import defaultdict
from datetime import datetime, timedelta
from scapy.all import IP, TCP

from .detector_strategy import DetectorStrategy

class PortScanDetector(DetectorStrategy):
    def __init__(self, time_window=10, port_threshold=10):
        self.time_window = time_window
        self.port_threshold = port_threshold
        self.scan_activity = defaultdict(lambda: defaultdict(list))

    def monitor_traffic(self, packet):
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            timestamp = datetime.now()

            # Remove old entries
            self.scan_activity[src_ip][dst_port] = [ts for ts in self.scan_activity[src_ip][dst_port]
                                                    if ts > timestamp - timedelta(seconds=self.time_window)]
            self.scan_activity[src_ip][dst_port].append(timestamp)

            # Count the number of different ports scanned
            if len(self.scan_activity[src_ip]) > self.port_threshold:
                return {
                    "ip": src_ip,
                    "type": "Port Scan",
                    "details": f"Potential port scan detected from {src_ip} - {len(self.scan_activity[src_ip])} ports in {self.time_window} seconds",
                    "timestamp": timestamp
                }
        return None  # No alert if nothing is detected
