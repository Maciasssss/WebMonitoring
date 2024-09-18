from datetime import datetime
from collections import defaultdict
from .monitor_strategy import MonitorStrategy
from scapy.all import IP

class ThroughputMonitor(MonitorStrategy):
    def __init__(self):
        self.flows = defaultdict(lambda: {'total_bytes': 0, 'start_time': None, 'end_time': None})

    def monitor_traffic(self, packet):
     if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        flow_key = (src_ip, dst_ip)
        packet_size = len(packet)
        timestamp = datetime.now()

        if self.flows[flow_key]['start_time'] is None:
            self.flows[flow_key]['start_time'] = timestamp
        
        self.flows[flow_key]['end_time'] = timestamp
        self.flows[flow_key]['total_bytes'] += packet_size

    def get_metric(self, flow_key):
        flow = self.flows[flow_key]
        duration = (flow['end_time'] - flow['start_time']).total_seconds()
        if duration > 0:
            return flow['total_bytes'] / duration  
        return 0
