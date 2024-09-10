from scapy.all import IP
from collections import defaultdict
from .monitor_strategy import MonitorStrategy

class TTLMonitor(MonitorStrategy):
    def __init__(self):
        self.flows = defaultdict(lambda: {'ttl_values': []})

    def monitor_traffic(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            flow_key = (src_ip, dst_ip)

            ttl_value = packet[IP].ttl
            self.flows[flow_key]['ttl_values'].append(ttl_value)

    def get_metric(self, flow_key):
        flow = self.flows.get(flow_key)
        if flow and flow['ttl_values']:
            # Return the most recent TTL value (or could calculate average)
            return flow['ttl_values'][-1]
        return 'N/A'
