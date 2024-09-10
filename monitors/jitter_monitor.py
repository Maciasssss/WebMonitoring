from datetime import datetime
from collections import defaultdict
from .monitor_strategy import MonitorStrategy
from scapy.all import IP

class JitterMonitor(MonitorStrategy):
    def __init__(self):
        self.flows = defaultdict(lambda: {'packets': []})

    def monitor_traffic(self, packet):
     if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        flow_key = (src_ip, dst_ip)
        timestamp = datetime.now()
        self.flows[flow_key]['packets'].append(timestamp)

    def get_metric(self, flow_key):
        flow = self.flows[flow_key]
        if len(flow['packets']) < 2:
            return 0

        delays = []
        previous_packet_time = flow['packets'][0]
        for packet_time in flow['packets'][1:]:
            delay = (packet_time - previous_packet_time).total_seconds() * 1000  # ms
            delays.append(delay)
            previous_packet_time = packet_time

        if len(delays) > 1:
            avg_delay = sum(delays) / len(delays)
            return sum((d - avg_delay) ** 2 for d in delays) / len(delays)
        return 0
