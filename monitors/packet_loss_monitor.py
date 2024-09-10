from collections import defaultdict
from .monitor_strategy import MonitorStrategy
from scapy.all import IP

class PacketLossMonitor(MonitorStrategy):
    def __init__(self):
        self.flows = defaultdict(lambda: {'packets': []})
        self.expected_packet_counts = defaultdict(int)

    def monitor_traffic(self, packet):
     if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        flow_key = (src_ip, dst_ip)
        self.flows[flow_key]['packets'].append(packet)
        self.expected_packet_counts[flow_key] += 1

    def get_metric(self, flow_key):
        flow = self.flows[flow_key]
        received_packets = len(flow['packets'])
        expected_packets = self.expected_packet_counts[flow_key]
        if expected_packets > 0:
            return (expected_packets - received_packets) / expected_packets * 100  # Packet loss %
        return 0
