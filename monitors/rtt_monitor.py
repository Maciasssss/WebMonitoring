from datetime import datetime
from collections import defaultdict
from .monitor_strategy import MonitorStrategy
from scapy.all import IP

class RTTMonitor(MonitorStrategy):
    def __init__(self):
        self.flows = defaultdict(lambda: {'packets': []})

    def monitor_traffic(self, packet):
     if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        flow_key = (src_ip, dst_ip)
        self.flows[flow_key]['packets'].append(datetime.now())

    def get_metric(self, flow_key):
        flow = self.flows[flow_key]
        if len(flow['packets']) >= 2:
            rtt = (flow['packets'][-1] - flow['packets'][0]).total_seconds() * 1000  
            return rtt
        return 0
