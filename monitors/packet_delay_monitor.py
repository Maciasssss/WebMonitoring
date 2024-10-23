from datetime import datetime
from collections import defaultdict
from .monitor_strategy import MonitorStrategy
from scapy.all import IP

class PacketDelayMonitor(MonitorStrategy):
    def __init__(self):
        self.flows = defaultdict(lambda: {'last_time': None, 'delays': []})

    def monitor_traffic(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            flow_key = (src_ip, dst_ip)
            timestamp = datetime.now()

            flow = self.flows[flow_key]

            if flow['last_time'] is not None:
                delay = (timestamp - flow['last_time']).total_seconds() * 1000  
                flow['delays'].append(delay)
                MAX_DELAYS = 100
                if len(flow['delays']) > MAX_DELAYS:
                    flow['delays'].pop(0)

            flow['last_time'] = timestamp

    def get_metric(self, flow_key):
        flow = self.flows[flow_key]
        if flow['delays']:
            avg_delay = sum(flow['delays']) / len(flow['delays'])
            return avg_delay
        else:
            return 0
