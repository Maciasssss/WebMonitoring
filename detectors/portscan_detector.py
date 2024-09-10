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
            protocol = "TCP"  # The protocol for port scanning in this case is TCP
            timestamp = datetime.now()

            # Clean up old entries for this source IP and port
            self.scan_activity[src_ip][dst_port] = [ts for ts in self.scan_activity[src_ip][dst_port]
                                                    if ts > timestamp - timedelta(seconds=self.time_window)]
            self.scan_activity[src_ip][dst_port].append(timestamp)

            # Count the number of different ports scanned within the time window
            if len(self.scan_activity[src_ip]) > self.port_threshold:
                severity = "High" if len(self.scan_activity[src_ip]) > 20 else "Medium"  # More than 20 ports is "High"

                return {
                    "ip": src_ip,
                    "type": "Port_Scan",
                    "details": f"Potential port scan detected from {src_ip} - {len(self.scan_activity[src_ip])} ports in {self.time_window} seconds",
                    "timestamp": timestamp,
                    "severity": severity,
                    "port": dst_port,  # The most recently scanned port
                    "protocol": protocol,
                    "possible_fixes": "Consider blocking the IP address, limiting rate of requests, or using an Intrusion Prevention System (IPS)."
                }
        return None  # No alert if no suspicious activity is detected
