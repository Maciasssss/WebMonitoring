import threading
from scapy.all import sniff

from detectors.alert_manager import AlertManager
from detectors.bruteforcelogin_detector import BruteForceLoginDetector
from detectors.dnstunneling_detector import DNSTunnelingDetector
from detectors.passwordfiltration_detector import PasswordExfiltrationDetector
from detectors.synflood_detector import SynFloodDetector
from detectors.ddos_detector import DDoSDetector
from detectors.portscan_detector import PortScanDetector
from detectors.spoofing_detector import SpoofingDetector

from sniffers.arp_handler import ARPHandler
from sniffers.icmp_handler import ICMPHandler
from sniffers.tcp_handler import TCPHandler
from sniffers.udp_handler import UDPHandler
from sniffers.http_handler import HTTPHandler
from sniffers.dns_handler import DNSHandler
from sniffers.ip_handler import IPHandler
from sniffers.ipv6_handler import IPv6Handler

from monitors.throughput_monitor import ThroughputMonitor
from monitors.packet_delay_monitor import PacketDelayMonitor
from monitors.jitter_monitor import JitterMonitor
from monitors.packet_loss_monitor import PacketLossMonitor
from monitors.rtt_monitor import RTTMonitor
from monitors.ttl_monitor import TTLMonitor
from monitors.bandwidth_monitor import BandwidthUtilizationMonitor

from utils.packet_capture import PacketCapture


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
            "throughput" : ThroughputMonitor(),
            "packet_delay" : PacketDelayMonitor(),
            "jitter" : JitterMonitor(),
            "packet_loss" : PacketLossMonitor(),
            "rtt" : RTTMonitor(),
            "ttl" : TTLMonitor(),
            "bandwidth_utilization" : BandwidthUtilizationMonitor()
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
        self.sniffing = False
        self.packets = {}
        self.alert_manager = AlertManager()
        self.packet_capture = PacketCapture(self.capture_file)

    def handle_packet(self, packet):
        with self.lock:
            if not self.sniffing:
                return
            for handler in self.handlers.values():
                handler.handle_packet(packet)
            
            for detector_key, detector in self.detectors.items():
                alert = detector.monitor_traffic(packet)
                if alert:
                    self.alert_manager.add_alert(alert)

                for monitor in self.monitors.values():
                 monitor.monitor_traffic(packet)
                self.total_packets += 1
                self.packet_capture.start_capture(self.packets_info)
                self.update_statistics()
                pass

    def get_flow_statistics(self):
        flow_stats = self.get_flow_stats()

        filtered_flow_stats = {}

        for flow, stats in flow_stats.items():
            src_ip = flow[0]  
            dst_ip = flow[1]

            if not (src_ip == "192.168.55.103" or dst_ip == "192.168.55.103"):
                filtered_flow_stats[flow] = stats  

        return filtered_flow_stats
    
    def get_flow_stats(self):
        flow_stats = {}
        for monitor_name, monitor in self.monitors.items():
            for flow_key in monitor.flows:
                # Convert tuple (src_ip, dst_ip) to string
                flow_key_str = f"{flow_key[0]}->{flow_key[1]}"
                
                if flow_key_str not in flow_stats:
                    flow_stats[flow_key_str] = {}
                
                flow_stats[flow_key_str][monitor_name] = monitor.get_metric(flow_key)
        
        return flow_stats
    
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

    def build_filter_string(self,filter_options):
        filters = []

        if filter_options.get('protocol'):
            filters.append(f"{filter_options['protocol']}")

        if filter_options.get('src_ip'):
            filters.append(f"src host {filter_options['src_ip']}")

        if filter_options.get('dst_ip'):
            filters.append(f"dst host {filter_options['dst_ip']}")

        if filter_options.get('src_port'):
            filters.append(f"src port {filter_options['src_port']}")

        if filter_options.get('dst_port'):
            filters.append(f"dst port {filter_options['dst_port']}")

        if filter_options.get('custom_filter'):
            filters.append(f"{filter_options['custom_filter']}")

        return " and ".join(filters)

    def start_sniffing(self):
        if not self.config.interface:
            raise ValueError("No valid network interface provided.")
        self.sniffing = True

        filter_string = self.build_filter_string(self.config.filter_options)
        
        sniff(iface=self.config.interface, prn=self.handle_packet, store=False,
            filter=filter_string, 
            timeout=self.config.timeout, stop_filter=lambda x: not self.sniffing)


    def stop_sniffing(self):
        self.sniffing = False

    def get_statistics(self):
        return {
            'total_packets': self.total_packets,
            'echo_request_count': self.echo_request_count,
            'echo_reply_count': self.echo_reply_count,
            'arp_count': self.arp_count,
            'tcp_count': self.tcp_count,
            'udp_count': self.udp_count,
            'http_count': self.http_count,
            'dns_count': self.dns_count,
            'icmp_count': self.icmp_count,
            'ip_count': self.ip_count,
            'ipv6_count': self.ipv6_count,
            'total_bytes_sent': self.total_bytes_sent,
            'total_bytes_received': self.total_bytes_received,
        }
