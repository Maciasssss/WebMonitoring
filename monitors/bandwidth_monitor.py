from datetime import datetime
from collections import defaultdict
from scapy.all import IP
from .monitor_strategy import MonitorStrategy

class BandwidthUtilizationMonitor(MonitorStrategy):
    def __init__(self, capacity_bandwidth_bps=1_000_000_000):  
        # Flow data structure to store total bytes and timestamps
        self.flows = defaultdict(lambda: {
            'total_bytes': 0, 
            'start_time': None, 
            'end_time': None
        })
        self.capacity_bandwidth_bps = capacity_bandwidth_bps  

    def monitor_traffic(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            flow_key = (src_ip, dst_ip)
            packet_size = len(packet) * 8  
            timestamp = datetime.now()

            # Initialize flow data if this is the first packet for the flow
            if self.flows[flow_key]['start_time'] is None:
                self.flows[flow_key]['start_time'] = timestamp

            self.flows[flow_key]['end_time'] = timestamp
            self.flows[flow_key]['total_bytes'] += packet_size  # Total bytes in bits

    def calculate_utilization(self, flow_key):
        flow = self.flows[flow_key]
        if flow['start_time'] and flow['end_time']:
            duration = (flow['end_time'] - flow['start_time']).total_seconds()
            if duration > 0:
                throughput_bps = flow['total_bytes'] / duration
                # Calculate utilization as a percentage of the total bandwidth
                utilization = (throughput_bps / self.capacity_bandwidth_bps) * 100
                return utilization
        return 0

    def get_metric(self, flow_key):
        return self.calculate_utilization(flow_key)
