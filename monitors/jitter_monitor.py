from datetime import datetime
from collections import defaultdict
from .monitor_strategy import MonitorStrategy
from scapy.all import IP

class JitterMonitor(MonitorStrategy):
    def __init__(self):
        self.flows = defaultdict(lambda: {'last_timestamp': None, 'last_delay': 0, 'jitter': 0})

    def monitor_traffic(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            flow_key = (src_ip, dst_ip)
            timestamp = datetime.now()

            flow = self.flows[flow_key]
            if flow['last_timestamp'] is not None:
                delay = (timestamp - flow['last_timestamp']).total_seconds() * 1000  # ms
                delay_variation = delay - flow['last_delay']
                flow['jitter'] += (abs(delay_variation) - flow['jitter']) / 16
                flow['last_delay'] = delay
            else:
                flow['last_delay'] = 0
            flow['last_timestamp'] = timestamp

    def get_metric(self, flow_key):
        flow = self.flows[flow_key]
        return flow.get('jitter', 0)
