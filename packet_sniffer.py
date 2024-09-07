#packet_sniffer.py
import csv
from datetime import datetime
import threading
import time
from colorama import Fore, Style
from scapy.all import sniff, IP,TCP
from scapy.utils import wrpcap
from detectors.alert_manager import AlertManager
from detectors.bruteforcelogin_detector import BruteForceLoginDetector
from detectors.dnstunneling_detector import DNSTunnelingDetector
from detectors.passwordfiltration_detector import PasswordExfiltrationDetector
from detectors.synflood_detector import SynFloodDetector
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
    def __init__(self, interface, verbose, timeout, use_db, capture_file):
        self.handlers = {...}
        self.interface = interface
        self.verbose = verbose
        self.timeout = timeout
        self.use_db = use_db
        self.capture_file = capture_file
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
        self.detectors = {
            "DDoS": DDoSDetector(),
            "PortScan" : PortScanDetector(),
            "BruteForce" : BruteForceLoginDetector(),
            "DNStunneling" : DNSTunnelingDetector(),
            "Passfiltration" : PasswordExfiltrationDetector(),
            "Spoofing" : SpoofingDetector(),
            "Synflood" : SynFloodDetector(),
        }
        self.monitors = {
            "Bandwidth": BandwidthMonitor(),
            "Performance": PerformanceMonitor(),
            "Connection" : ConnectionSpeedMonitor(),
        }
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
        self.alert_manager = AlertManager()    

    def handle_packet(self, packet):
        with self.lock:
            if not self.sniffing:
                return
            # Process packet through handlers
            for handler in self.handlers.values():
                handler.handle_packet(packet)
            
            # Run packet through all detectors and check for alerts
            for detector_key, detector in self.detectors.items():
                alert = detector.monitor_traffic(packet)
                if alert:
                    # Pass the correct type to the alert manager
                    if detector_key == "DDoS":
                        self.alert_manager.add_alert(alert["ip"], alert["details"], "ddos")
                    elif detector_key == "PortScan":
                        self.alert_manager.add_alert(alert["ip"], alert["details"], "port_scan")
                    elif detector_key == "BruteForce":
                        self.alert_manager.add_alert(alert["ip"], alert["details"], "brute_force")
                    elif detector_key == "DNStunneling":
                        self.alert_manager.add_alert(alert["ip"], alert["details"], "dns_tunneling")
                    elif detector_key == "Passfiltration":
                        self.alert_manager.add_alert(alert["ip"], alert["details"], "password_exfiltration")
                    elif detector_key == "Spoofing":
                        self.alert_manager.add_alert(alert["ip"], alert["details"], "spoofing")
                    elif detector_key == "Synflood":
                        self.alert_manager.add_alert(alert["ip"], alert["details"], "synflood")

            # Monitor traffic
            for monitor in self.monitors.values():
                monitor.monitor_traffic(packet)
            self.total_packets += 1
            self.start_capture(self.packets_info)
            self.update_statistics()
            pass

    def get_flow_statistics(self):
        # Gather flow statistics from your monitors
        flow_stats = self.monitors["Performance"].get_flow_stats()

        # Create a new dictionary to store filtered flow statistics
        filtered_flow_stats = {}

        for flow, stats in flow_stats.items():
            src_ip = flow[0]  # Assuming flow is a tuple like (src_ip, dst_ip)
            dst_ip = flow[1]

            # Check if the flow involves your app's IP and exclude it
            if not (src_ip == "192.168.55.103" or dst_ip == "192.168.55.103"):
                filtered_flow_stats[flow] = stats  # Only add non-app traffic to flow stats

        return filtered_flow_stats

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
        sniff(iface=self.config.interface, prn=self.handle_packet, store=False,
                filter="not (host 192.168.55.103 and (tcp port 80 or tcp port 443))", 
                timeout=self.config.timeout, stop_filter=lambda x: not self.sniffing)


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
