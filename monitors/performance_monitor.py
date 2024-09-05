from datetime import datetime
from collections import defaultdict
from scapy.all import IP

class FlowMonitor:
    def __init__(self):
        self.flows = defaultdict(lambda: {'start_time': None, 'end_time': None, 'total_bytes': 0, 'packets': []})

    def monitor_flow(self, packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            flow_key = f"{src_ip}->{dst_ip}"
            packet_size = len(packet)
            timestamp = datetime.now()

            # Initialize flow data if not present
            if self.flows[flow_key]['start_time'] is None:
                self.flows[flow_key]['start_time'] = timestamp

            # Update flow data
            self.flows[flow_key]['end_time'] = timestamp
            self.flows[flow_key]['total_bytes'] += packet_size
            self.flows[flow_key]['packets'].append(timestamp)

    def calculate_throughput(self, flow_key):
        flow = self.flows[flow_key]
        duration = (flow['end_time'] - flow['start_time']).total_seconds()
        if duration > 0:
            return flow['total_bytes'] / duration  # Bytes per second
        return 0

    def calculate_packet_delay(self, flow_key):
        flow = self.flows[flow_key]
        if flow['start_time'] and flow['end_time']:
            return (flow['end_time'] - flow['start_time']).total_seconds() * 1000  # In milliseconds
        return 0

    def calculate_jitter(self, flow_key):
        flow = self.flows[flow_key]
        if len(flow['packets']) < 2:
            return 0

        delays = []
        previous_packet_time = flow['packets'][0]
        for packet_time in flow['packets'][1:]:
            delay = (packet_time - previous_packet_time).total_seconds() * 1000  # Milliseconds
            delays.append(delay)
            previous_packet_time = packet_time

        # Calculate jitter as the variance in delay
        if len(delays) > 1:
            avg_delay = sum(delays) / len(delays)
            return sum((d - avg_delay) ** 2 for d in delays) / len(delays)
        return 0

    def get_flow_stats(self):
        flow_stats = {}
        for flow_key in self.flows:
            flow_stats[flow_key] = {
                'throughput': self.calculate_throughput(flow_key),
                'packet_delay': self.calculate_packet_delay(flow_key),
                'jitter': self.calculate_jitter(flow_key),
            }
        return flow_stats
