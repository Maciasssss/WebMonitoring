import os
import threading
import logging
from packet_sniffer import PacketSniffer
from sniffer_config import SnifferConfig
from scapy.arch.windows import get_windows_if_list
from utils.packet_capture import PacketCapture

class SnifferService:
    def __init__(self):
        self.sniffer = None
        self.sniffer_thread = None
        self.lock = threading.Lock()

    def start_sniffer(self, interface_guid,interface_ip, timeout, capture_file,filter_options):
        """Start the packet sniffer on a specific interface."""
        capture_directory = os.path.join(os.getcwd(), "captures")
        if not os.path.exists(capture_directory):
            os.makedirs(capture_directory)

        capture_file_path = os.path.join(capture_directory, capture_file) if capture_file else None

        config = SnifferConfig(
            interface=interface_guid, 
            interface_ip=interface_ip,
            timeout=timeout,
            use_db=False,
            capture_file=capture_file_path,
            filter_options= filter_options
        )

        try:
            self.sniffer = PacketSniffer(config)
            self.sniffer_thread = threading.Thread(target=self.sniffer.start_sniffing)
            self.sniffer_thread.start()
        except Exception as e:
            logging.error(f"Error starting sniffer: {e}")
            raise

    def stop_sniffer(self):
        """Stop the packet sniffer and wait for the thread to finish."""
        with self.lock:
            if self.sniffer and self.sniffer_thread:
                self.sniffer.stop_sniffing()
                self.sniffer = None
                self.sniffer_thread = None

    def get_statistics(self):
        with self.lock:
            if self.sniffer:
                return self.sniffer.get_statistics()
            return {}

    def get_packets(self):
        with self.lock:
            if self.sniffer:
                return self.sniffer.packets_info
            return []

    def get_flow_statistics(self):
        with self.lock:
            if self.sniffer:
                return self.sniffer.get_flow_statistics()
            return None

    def get_detector_alerts(self):
        if not self.sniffer:
            return {}
        
        try:
            return {
                'DNS_Tunneling': self.sniffer.alert_manager.get_alerts_by_type('DNS_Tunneling'),
                'Brute_Force_Login': self.sniffer.alert_manager.get_alerts_by_type('Brute_Force_Login'),
                'DDoS_Attack': self.sniffer.alert_manager.get_alerts_by_type('DDoS_Attack'),
                'Port_Scan': self.sniffer.alert_manager.get_alerts_by_type('Port_Scan'),
                'Spoofing': self.sniffer.alert_manager.get_alerts_by_type('Spoofing'),
                'Password_Exfiltration': self.sniffer.alert_manager.get_alerts_by_type('Password_Exfiltration'),
                'SYN_Flood': self.sniffer.alert_manager.get_alerts_by_type('SYN_Flood')
            }
        except Exception as e:
            logging.error(f"Error fetching detector alerts: {e}")
            return None


    def get_capture_file(self):
        if self.sniffer and self.sniffer.capture_file and os.path.exists(self.sniffer.capture_file):
            return self.sniffer.capture_file
        return None

    @staticmethod
    def get_sniffable_interfaces():
        """Returns a list of sniffable interfaces."""
        interfaces = []
        for iface in get_windows_if_list():
            try:
                friendly_name = iface['name']
                guid = iface['guid']
                ips = iface.get('ips', [])
                ip_address = next((ip for ip in ips if '.' in ip), ips[0] if ips else None)

                if ip_address:
                    interfaces.append({
                        'name': friendly_name,
                        'guid': guid,
                        'ip': ip_address
                    })
            except Exception as e:
                logging.error(f"Error processing interface {iface}: {e}")
        return interfaces

    @staticmethod
    def get_friendly_to_guid_mapping():
        """Returns a dictionary mapping friendly interface names to GUIDs."""
        mapping = {}
        for iface in get_windows_if_list():
            try:
                friendly_name = iface['name']
                guid = iface['guid']
                mapping[friendly_name] = guid
            except Exception as e:
                logging.error(f"Error processing interface {iface}: {e}")
        return mapping
