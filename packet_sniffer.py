from colorama import Fore, Style
from scapy.all import sniff
from scapy.utils import wrpcap
from sniffers.arp_handler import ARPHandler
from sniffers.icmp_handler import ICMPHandler
from sniffers.tcp_handler import TCPHandler
from sniffers.udp_handler import UDPHandler
from sniffers.http_handler import HTTPHandler       # Nowe
from sniffers.dns_handler import DNSHandler         # Nowe
from sniffers.ip_handler import IPHandler           # Nowe
from sniffers.ipv6_handler import IPv6Handler       # Nowe
from detectors.ddos_detector import DDoSDetector
from detectors.portscan_detector import PortScanDetector
from detectors.spoofing_detector import SpoofingDetector
from monitors.bandwidth_monitor import BandwidthMonitor
from monitors.connection_speed_monitor import ConnectionSpeedMonitor
from monitors.performance_monitor import PerformanceMonitor
from web import socketio

class PacketSniffer:
    def __init__(self):
        self.handlers = {
            "ARP": ARPHandler(),
            "ICMP": ICMPHandler(),
            "TCP": TCPHandler(),
            "UDP": UDPHandler(),
            "HTTP": HTTPHandler(),         # Nowe
            "DNS": DNSHandler(),           # Nowe
            "IP": IPHandler(),             # Nowe
            "IPv6": IPv6Handler()          # Nowe
        }

        self.ddos_detector = DDoSDetector()
        self.portscan_detector = PortScanDetector()
        self.spoofing_detector = SpoofingDetector()
        self.bandwidth_monitor = BandwidthMonitor()
        self.connection_speed_monitor = ConnectionSpeedMonitor()
        self.performance_monitor = PerformanceMonitor()

    def handle_packet(self, packet):
        for handler_key, handler in self.handlers.items():
            handler.handle_packet(packet)
        self.ddos_detector.monitor_traffic(packet)
        self.portscan_detector.monitor_traffic(packet)
        self.spoofing_detector.monitor_traffic(packet)
        self.bandwidth_monitor.monitor_traffic(packet)
        self.connection_speed_monitor.monitor_traffic(packet)
        self.performance_monitor.monitor_traffic(packet)
        self.total_packets += 1
        self.packets.append(packet)
        for handler_key, handler in self.handlers.items():
            handler.handle_packet(packet)
        self.start_capture(self.packets)
        socketio.emit('new_packet', {'data': str(packet.summary())})

    def start_sniffing(self, iface=None):
        sniff(iface=iface, prn=self.handle_packet, store=False)
    
    def start_capture(self, packets_to_capture):
        if self.capture_file:
            wrpcap(self.capture_file, packets_to_capture)

    def print_statistics(self):
        print(f"{Fore.YELLOW}\tPacket Sniffing Statistics:{Style.RESET_ALL}")
        print(f"Total Packets       : {self.total_packets}")
        print(f"Echo Request Packets: {self.echo_request_count}")
        print(f"Echo Reply Packets  : {self.echo_reply_count}")
        print(f"ARP Packets         : {self.arp_count}")
        print(f"TCP Packets         : {self.tcp_count}")
        print(f"UDP Packets         : {self.udp_count}")
        print(f"HTTP Packets        : {self.http_count}")  # Dodaj do handlera HTTP
        print(f"DNS Packets         : {self.dns_count}")   # Dodaj do handlera DNS
        print(f"IP Packets          : {self.ip_count}")    # Dodaj do handlera IP
        print(f"IPv6 Packets        : {self.ipv6_count}")  # Dodaj do handlera IPv6
        print(f"Total Bytes Sent    : {self.total_bytes_sent} bytes")
        print(f"Total Bytes Received: {self.total_bytes_received} bytes")
    
    def save_packets(self):
        wrpcap(self.capture_file, self.packets)
        print(f"Saved {len(self.packets)} packets to {self.capture_file}")
