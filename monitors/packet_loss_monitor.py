from collections import defaultdict
from .monitor_strategy import MonitorStrategy
from scapy.all import IP, TCP, UDP, ICMP, DNS, ARP

class PacketLossMonitor(MonitorStrategy):
    def __init__(self):
        super().__init__()
        # Initialize flows
        self.flows = defaultdict(lambda: {
            'protocol': None,
            'packets': set(),
            'sent': set(),
            'received': set(),
            'expected_count': 0,
            'last_seq': None,
        })

    def monitor_traffic(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            flow_key = (src_ip, dst_ip)
            flow = self.flows[flow_key]

            # Handle TCP packets
            if TCP in packet:
                flow['protocol'] = 'tcp'
                seq = packet[TCP].seq
                flow['packets'].add(seq)

                # Update expected packet count based on sequence numbers
                last_seq = flow['last_seq']
                if last_seq is not None:
                    expected_packets = seq - last_seq
                    flow['expected_count'] += expected_packets
                else:
                    flow['expected_count'] += 1  
                flow['last_seq'] = seq

            # Handle UDP packets 
            elif UDP in packet:
                flow['protocol'] = 'udp'
                payload = bytes(packet[UDP].payload)
                if len(payload) >= 4:
                    seq = int.from_bytes(payload[:4], byteorder='big')
                    flow['packets'].add(seq)

                    last_seq = flow['last_seq']
                    if last_seq is not None:
                        expected_packets = seq - last_seq
                        flow['expected_count'] += expected_packets
                    else:
                        flow['expected_count'] += 1  # First packet
                    flow['last_seq'] = seq

            # Handle ICMP packets
            elif ICMP in packet:
                flow['protocol'] = 'icmp'
                icmp_type = packet[ICMP].type
                icmp_seq = packet[ICMP].seq
                if icmp_type == 8:  # Echo Request
                    flow['sent'].add(icmp_seq)
                    flow['expected_count'] += 1
                elif icmp_type == 0:  # Echo Reply
                    flow['received'].add(icmp_seq)

            # Handle DNS packets
            elif DNS in packet:
                flow['protocol'] = 'dns'
                dns_id = packet[DNS].id
                if packet[DNS].qr == 0:  # Query
                    flow['sent'].add(dns_id)
                    flow['expected_count'] += 1
                else:  # Response
                    flow['received'].add(dns_id)

        # Handle ARP packets
        elif ARP in packet:
            src_ip = packet[ARP].psrc
            dst_ip = packet[ARP].pdst
            flow_key = (src_ip, dst_ip)
            flow = self.flows[flow_key]
            flow['protocol'] = 'arp'

            arp_op = packet[ARP].op
            if arp_op == 1:  # ARP Request
                flow['sent'].add(packet[ARP].hwsrc)
                flow['expected_count'] += 1
            elif arp_op == 2:  # ARP Reply
                flow['received'].add(packet[ARP].hwsrc)

    def get_metric(self, flow_key):
        flow = self.flows.get(flow_key)
        if not flow or not flow['protocol']:
            return None 

        protocol = flow['protocol']
        expected_packets = flow['expected_count']

        if protocol in ['tcp', 'udp']:
            received_packets = len(flow['packets'])
            if expected_packets > 0:
                lost_packets = expected_packets - received_packets
                packet_loss = (lost_packets / expected_packets) * 100
                return packet_loss
            return 0

        elif protocol in ['icmp', 'dns', 'arp']:
            total_sent = len(flow['sent'])
            total_received = len(flow['received'])
            if total_sent > 0:
                lost_packets = total_sent - total_received
                packet_loss = (lost_packets / total_sent) * 100
                return packet_loss
            return 0

        else:
            return None
