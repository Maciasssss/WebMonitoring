import csv
from datetime import datetime
import threading
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
from monitors.performance_monitor import PerformanceMonitor
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
        self.performance_monitor = PerformanceMonitor()
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
            self.performance_monitor.monitor_traffic(packet)
            self.total_packets += 1
            self.start_capture(self.packets_info)
            self.update_statistics()

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
                fieldnames = ["Source IP", "Destination IP", "Source MAC", "Destination MAC", "IP Version", "TTL", "Checksum", "Packet Size", "Passing Time", "Protocol", "Identifier", "Sequence"]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                writer.writeheader()
                for packet in packets_to_capture:
                    writer.writerow({
                        "Source IP": packet['src_ip'],
                        "Destination IP": packet['dst_ip'],
                        "Source MAC": packet['src_mac'],
                        "Destination MAC": packet['dst_mac'],
                        "IP Version": packet['ip_version'],
                        "TTL": packet['ttl'],
                        "Checksum": packet['checksum'],
                        "Packet Size": packet['packet_size'],
                        "Passing Time": packet['passing_time'],
                        "Protocol": packet['protocol'],
                        "Identifier": packet['identifier'],
                        "Sequence": packet['sequence']
                    })


    def get_statistics(self):
        if not self.config.statistics_queue.empty():
            return self.config.statistics_queue.get()
        return {}
