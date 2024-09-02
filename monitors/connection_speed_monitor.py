from datetime import datetime
from scapy.all import sniff, TCP, IP

class ConnectionSpeedMonitor:
    def __init__(self):
        self.connection_start_times = {}

    def monitor_traffic(self, packet):
        if packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            tcp_flags = packet[TCP].flags

            if tcp_flags == "S":  # SYN
                self.connection_start_times[(src_ip, dst_ip)] = datetime.now()

            elif tcp_flags == "SA":  # SYN-ACK
                if (dst_ip, src_ip) in self.connection_start_times:
                    start_time = self.connection_start_times.pop((dst_ip, src_ip))
                    connection_time = (datetime.now() - start_time).total_seconds() * 1000  # w ms
                    print(f"Connection established between {src_ip} and {dst_ip} in {connection_time:.2f} ms")
