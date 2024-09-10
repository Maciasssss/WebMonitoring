from datetime import datetime
from collections import defaultdict
from .monitor_strategy import MonitorStrategy
from scapy.all import IP

class PacketDelayMonitor(MonitorStrategy):
    def __init__(self):
        self.flows = defaultdict(lambda: {'start_time': None, 'end_time': None})

    def monitor_traffic(self, packet):
     if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        flow_key = (src_ip, dst_ip)
        timestamp = datetime.now()

        if self.flows[flow_key]['start_time'] is None:
            self.flows[flow_key]['start_time'] = timestamp

        self.flows[flow_key]['end_time'] = timestamp

    def get_metric(self, flow_key):
        flow = self.flows[flow_key]
        if flow['start_time'] and flow['end_time']:
            return (flow['end_time'] - flow['start_time']).total_seconds() * 1000  # Delay in ms
        return 0
