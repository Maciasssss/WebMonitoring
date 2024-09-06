from datetime import datetime
from collections import defaultdict
from scapy.all import IP
#seperate to diffrent monitor classes
class PerformanceMonitor:
    def __init__(self):
        self.flows = defaultdict(lambda: {
            'start_time': None, 
            'end_time': None, 
            'total_bytes': 0, 
            'packets': [], 
            'packet_loss': 0,  # To monitor packet loss
            'rtt': 0,  # To monitor Round Trip Time
            'ttl': 0  # To monitor TTL
        })
        self.expected_packet_counts = defaultdict(int)  # Track expected packet count for each flow
        self.total_observed_bytes = 0  # Track total bytes for calculating bandwidth
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
            self.total_observed_bytes += packet_size  # Track total observed bytes
            # Monitor additional metrics
            self.flows[flow_key]['ttl'] = packet[IP].ttl
            self.flows[flow_key]['rtt'] = self.calculate_rtt(flow_key)
            self.expected_packet_counts[flow_key] += 1

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

    def calculate_packet_loss(self, flow_key):
        # Calculate the packet loss percentage based on expected vs actual received packets
        flow = self.flows[flow_key]
        received_packets = len(flow['packets'])
        expected_packets = self.expected_packet_counts[flow_key]
        if expected_packets > 0:
            return (expected_packets - received_packets) / expected_packets * 100  # Packet loss percentage
        return 0

    def calculate_rtt(self, flow_key):
        # Estimate Round Trip Time (RTT) for a flow if applicable
        flow = self.flows[flow_key]
        if len(flow['packets']) >= 2:
            rtt = (flow['packets'][-1] - flow['packets'][0]).total_seconds() * 1000  # RTT in milliseconds
            return rtt
        return 0

    def calculate_bandwidth_utilization(self, flow_key):
        # Get the total bandwidth
        total_bandwidth = self.get_total_bandwidth()
        
        # Calculate the flow's throughput
        throughput = self.calculate_throughput(flow_key)

        # Calculate and return the utilization percentage
        utilization = (throughput / total_bandwidth) * 100  # Bandwidth utilization percentage
        return utilization

    def get_flow_stats(self):
        total_bandwidth = self.get_total_bandwidth()
        flow_stats = {}
        for flow_key in self.flows:
            flow_stats[flow_key] = {
                'throughput': self.calculate_throughput(flow_key),
                'packet_delay': self.calculate_packet_delay(flow_key),
                'jitter': self.calculate_jitter(flow_key),
                'packet_loss': self.calculate_packet_loss(flow_key),
                'rtt': self.calculate_rtt(flow_key),
                'ttl': self.flows[flow_key]['ttl'],
                'bandwidth_utilization': self.calculate_bandwidth_utilization(flow_key)
            }
        return flow_stats
    
    def get_total_bandwidth(self):
        # Define a fixed capacity bandwidth (e.g., 1 Gbps)
        capacity_bandwidth = 1_000_000_000 / 8  # Convert 1 Gbps to bytes per second

        # Alternatively, calculate bandwidth based on observed traffic in a specific time frame
        total_duration = sum(
            (flow['end_time'] - flow['start_time']).total_seconds() 
            for flow in self.flows.values() if flow['start_time'] and flow['end_time']
        )

        if total_duration > 0:
            observed_bandwidth = self.total_observed_bytes / total_duration  # Bytes per second
            return min(observed_bandwidth, capacity_bandwidth)  # Return the smaller value (realistic bandwidth)
        
        return capacity_bandwidth  # Default if no data is available
