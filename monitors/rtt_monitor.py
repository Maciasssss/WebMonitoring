# rtt_monitor.py
from datetime import datetime
from collections import defaultdict
from scapy.all import IP, TCP, ICMP, ARP, UDP, DNS, IPv6, Ether
from .monitor_strategy import MonitorStrategy

class RTTMonitor(MonitorStrategy):
    def __init__(self):
        self.sent_packets = defaultdict(dict)
        self.rtt_records = defaultdict(list)

    def monitor_traffic(self, packet):
        try:
            # Handle ARP packets
            if packet.haslayer(ARP):
                self._handle_arp(packet)
            
            # Handle IPv6 Neighbor Discovery (generic handling)
            elif packet.haslayer(IPv6) and packet.haslayer(ICMP):
                self._handle_ipv6_neighbor_discovery(packet)
            
            # Handle ICMP packets (including ICMPv4)
            elif packet.haslayer(ICMP):
                self._handle_icmp(packet)
            
            # Handle TCP packets
            elif packet.haslayer(TCP):
                self._handle_tcp(packet)
            
            # Handle UDP packets (specifically DNS)
            elif packet.haslayer(UDP):
                self._handle_udp(packet)
            
        except Exception as e:
            print(f"Error in RTTMonitor.monitor_traffic: {e}")

    def _handle_arp(self, packet):
        arp_layer = packet[ARP]
        protocol = 'ARP'
        src_ip = arp_layer.psrc
        dst_ip = arp_layer.pdst
        opcode = arp_layer.op 
        identifier = (arp_layer.hwsrc, arp_layer.pdst)  

        if opcode == 1:  # ARP Request
            flow_key = (src_ip, dst_ip, protocol, identifier)
            self.sent_packets[flow_key] = datetime.now()
        elif opcode == 2:  # ARP Reply
            flow_key = (dst_ip, src_ip, protocol, identifier)
            if flow_key in self.sent_packets:
                rtt = (datetime.now() - self.sent_packets.pop(flow_key)).total_seconds() * 1000  # in ms
                flow_key_metric = (dst_ip, src_ip, protocol)
                self.rtt_records[flow_key_metric].append(rtt)

    def _handle_ipv6_neighbor_discovery(self, packet):
        icmpv6_layer = packet[ICMP]
        protocol = 'IPv6_ND'
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst

        if icmpv6_layer.type == 135:  # Neighbor Solicitation
            identifier = getattr(icmpv6_layer, 'id', getattr(icmpv6_layer, 'nsid', None))
            flow_key = (src_ip, dst_ip, protocol, identifier)
            self.sent_packets[flow_key] = datetime.now()
        elif icmpv6_layer.type == 136:  # Neighbor Advertisement
            identifier = getattr(icmpv6_layer, 'id', getattr(icmpv6_layer, 'nsid', None))
            flow_key = (dst_ip, src_ip, protocol, identifier)
            if flow_key in self.sent_packets:
                rtt = (datetime.now() - self.sent_packets.pop(flow_key)).total_seconds() * 1000  # in ms
                flow_key_metric = (dst_ip, src_ip, protocol)
                self.rtt_records[flow_key_metric].append(rtt)

    def _handle_icmp(self, packet):
        icmp_layer = packet[ICMP]
        protocol = 'ICMP'
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        if icmp_layer.type == 8:  # Echo Request
            identifier = icmp_layer.id
            sequence = icmp_layer.seq
            flow_key = (src_ip, dst_ip, protocol, identifier, sequence)
            self.sent_packets[flow_key] = datetime.now()
        elif icmp_layer.type == 0:  # Echo Reply
            identifier = icmp_layer.id
            sequence = icmp_layer.seq
            flow_key = (dst_ip, src_ip, protocol, identifier, sequence)
            if flow_key in self.sent_packets:
                rtt = (datetime.now() - self.sent_packets.pop(flow_key)).total_seconds() * 1000  # in ms
                flow_key_metric = (dst_ip, src_ip, protocol)
                self.rtt_records[flow_key_metric].append(rtt)

    def _handle_tcp(self, packet):
        tcp_layer = packet[TCP]
        protocol = 'TCP'
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        flags = tcp_layer.flags
        identifier = tcp_layer.seq  

        flow_key = (src_ip, dst_ip, protocol, identifier)

        if flags & 0x02:  # SYN flag
            self.sent_packets[flow_key] = datetime.now()
        elif flags & 0x12:  # SYN-ACK flags
            request_key = (dst_ip, src_ip, protocol, tcp_layer.ack - 1)
            if request_key in self.sent_packets:
                rtt = (datetime.now() - self.sent_packets.pop(request_key)).total_seconds() * 1000  # in ms
                flow_key_metric = (dst_ip, src_ip, protocol)
                self.rtt_records[flow_key_metric].append(rtt)

    def _handle_udp(self, packet):
        udp_layer = packet[UDP]
        protocol = 'UDP'
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        src_port = udp_layer.sport
        dst_port = udp_layer.dport

        # Check if UDP is being used for DNS
        if packet.haslayer(DNS):
            dns_layer = packet[DNS]
            dns_id = dns_layer.id
            dns_qd = dns_layer.qd.qname.decode() if dns_layer.qdcount > 0 else ""
            identifier = dns_id  
            flow_key = (src_ip, dst_ip, protocol, identifier)

            if dns_layer.qr == 0:  # DNS Query
                self.sent_packets[flow_key] = datetime.now()
            elif dns_layer.qr == 1:  # DNS Response
                flow_key_response = (dst_ip, src_ip, protocol, identifier)
                if flow_key_response in self.sent_packets:
                    rtt = (datetime.now() - self.sent_packets.pop(flow_key_response)).total_seconds() * 1000  # in ms
                    flow_key_metric = (dst_ip, src_ip, protocol)
                    self.rtt_records[flow_key_metric].append(rtt)


    def get_flow_stats(self):
        return self.rtt_records

    def get_metric(self, flow_key):
        if flow_key in self.rtt_records and self.rtt_records[flow_key]:
            return sum(self.rtt_records[flow_key]) / len(self.rtt_records[flow_key])
        return 0.0

    @property
    def flows(self):
        return self.rtt_records.keys()
