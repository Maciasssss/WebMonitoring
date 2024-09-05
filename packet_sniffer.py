import csv
from datetime import datetime
import threading
import time
from colorama import Fore, Style
from scapy.all import sniff, IP
from scapy.utils import wrpcap
from sniffers.arp_handler import ARPHandler
from sniffers.icmp_handler import ICMPHandler
from sniffers.tcp_handler import TCPHandler
from sniffers.udp_handler import UDPHandler
from sniffers.http_handler import HTTPHandler
from sniffers.dns_handler import DNSHandler
from sniffers.ip_handler import IPHandler
from sniffers.ipv6_handler import IPv6Handler
from detectors.ddos_detector import DDoSDetector
from detectors.portscan_detector import PortScanDetector
from detectors.spoofing_detector import SpoofingDetector
from monitors.bandwidth_monitor import BandwidthMonitor
from monitors.connection_speed_monitor import ConnectionSpeedMonitor
from monitors.performance_monitor import FlowMonitor
import queue


class SnifferConfig:
    def __init__(self, interface, verbose, timeout, output, use_db, capture_file):
        self.handlers = {...}
        self.interface = interface
        self.verbose = verbose
        self.timeout = timeout
        self.output = output
        self.use_db = use_db
        self.capture_file = capture_file
        self.total_packets = 0
        self.echo_request_count = 0
        self.echo_reply_count = 0
        self.packets = []
        self.statistics_queue = queue.Queue()  

# packet_sniffer.py
class PacketSniffer:
    def __init__(self, config):
        self.config = config
        self.packets_info = [] 
        self.handlers = {
            "ARP": ARPHandler(self),
            "ICMP": ICMPHandler(self),
            "TCP": TCPHandler(self),
            "UDP": UDPHandler(self),
            "HTTP": HTTPHandler(self),
            "DNS": DNSHandler(self),
            "IP": IPHandler(self),
            "IPv6": IPv6Handler(self)
        }
        self.ddos_detector = DDoSDetector()
        self.portscan_detector = PortScanDetector()
        self.spoofing_detector = SpoofingDetector()
        self.bandwidth_monitor = BandwidthMonitor()
        self.connection_speed_monitor = ConnectionSpeedMonitor()
        self.flow_monitor = FlowMonitor()
        self.capture_file = config.capture_file
        self.total_packets = 0
        self.echo_request_count = 0
        self.echo_reply_count = 0
        self.arp_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.http_count = 0
        self.dns_count = 0
        self.ip_count = 0
        self.ipv6_count = 0
        self.total_bytes_sent = 0
        self.total_bytes_received = 0
        self.icmp_count = 0 
        self.lock = threading.Lock()
        self.sniffing = True
        self.packets = {}

    def handle_packet(self, packet):
        with self.lock:
            if not self.sniffing:
                return
            for handler_key, handler in self.handlers.items():
                handler.handle_packet(packet)
            self.ddos_detector.monitor_traffic(packet)
            self.portscan_detector.monitor_traffic(packet)
            self.spoofing_detector.monitor_traffic(packet)
            self.bandwidth_monitor.monitor_traffic(packet)
            self.connection_speed_monitor.monitor_traffic(packet)
            self.flow_monitor.monitor_flow(packet)
            time.sleep(0.5)
            self.total_packets += 1
            self.start_capture(self.packets_info)
            self.update_statistics()
            
    def get_flow_statistics(self):
        return self.flow_monitor.get_flow_stats()
    def get_recent_packets(self):
        with self.lock:
            return self.packets_info[-10:]  # Return the last 10 packets for display

    def update_statistics(self):
        statistics = {
            'total_packets': self.total_packets,
            'echo_request_count': self.echo_request_count,
            'echo_reply_count': self.echo_reply_count,
            'arp_count': self.arp_count,
            'tcp_count': self.tcp_count,
            'udp_count': self.udp_count,
            'http_count': self.http_count,
            'dns_count': self.dns_count,
            'icmp_count' : self.icmp_count,
            'ip_count': self.ip_count,
            'ipv6_count': self.ipv6_count,
            'total_bytes_sent': self.total_bytes_sent,
            'total_bytes_received': self.total_bytes_received,
        }
        self.config.statistics_queue.put(statistics)

    def start_sniffing(self):
        if not self.config.interface:
            raise ValueError("No valid network interface provided.")
        self.sniffing = True
        sniff(iface=self.config.interface, prn=self.handle_packet, store=False, timeout=self.config.timeout, stop_filter=lambda x: not self.sniffing)

    def stop_sniffing(self):
        self.sniffing = False

    def start_capture(self, packets_to_capture):
        if self.packets_info and self.config.capture_file:
            with open(self.config.capture_file, 'w', newline='', encoding='utf-8') as csvfile:
                # Expanded fieldnames for advanced details
                fieldnames = [
                    "Source IP", "Destination IP", "Source MAC", "Destination MAC", "IP Version", "TTL",
                    "Checksum", "Packet Size", "Passing Time", "Protocol", "Identifier", "Sequence",
                    "ICMP Type", "ICMP Code", "HTTP Method", "Flow Label", "Traffic Class", "Hop Limit",
                    "Next Header", "Fragment Offset", "Flags"
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                writer.writeheader()
                for packet in packets_to_capture:
                    # Write detailed packet information, using `.get()` to avoid KeyError for non-applicable fields
                    writer.writerow({
                        "Source IP": packet.get('src_ip', 'N/A'),
                        "Destination IP": packet.get('dst_ip', 'N/A'),
                        "Source MAC": packet.get('src_mac', 'N/A'),
                        "Destination MAC": packet.get('dst_mac', 'N/A'),
                        "IP Version": packet.get('ip_version', 'N/A'),
                        "TTL": packet.get('ttl', 'N/A'),
                        "Checksum": packet.get('checksum', 'N/A'),
                        "Packet Size": packet.get('packet_size', 'N/A'),
                        "Passing Time": packet.get('passing_time', 'N/A'),
                        "Protocol": packet.get('protocol', 'N/A'),
                        "Identifier": packet.get('identifier', 'N/A'),
                        "Sequence": packet.get('sequence', 'N/A'),
                        "ICMP Type": packet.get('icmp_type', 'N/A'),
                        "ICMP Code": packet.get('icmp_code', 'N/A'),
                        "HTTP Method": packet.get('http_method', 'N/A'),
                        "Flow Label": packet.get('flow_label', 'N/A'),
                        "Traffic Class": packet.get('traffic_class', 'N/A'),
                        "Hop Limit": packet.get('hop_limit', 'N/A'),
                        "Next Header": packet.get('next_header', 'N/A'),
                        "Fragment Offset": packet.get('fragment_offset', 'N/A'),
                        "Flags": packet.get('flags', 'N/A')
                    })



    def get_statistics(self):
        if not self.config.statistics_queue.empty():
            return self.config.statistics_queue.get()
        return {}
