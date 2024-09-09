import datetime
from scapy.all import IP, Ether

from .detector_strategy import DetectorStrategy

class SpoofingDetector(DetectorStrategy):
    def __init__(self):
        self.ip_mac_mapping = {}  # Map IP to MAC

    def monitor_traffic(self, packet):
        if packet.haslayer(IP) and packet.haslayer(Ether):
            src_ip = packet[IP].src
            src_mac = packet[Ether].src
            protocol = "IP"  # Since we're dealing with IP traffic
            timestamp = datetime.datetime.now()

            # Check if the IP -> MAC mapping exists and if it is correct
            if src_ip in self.ip_mac_mapping:
                if self.ip_mac_mapping[src_ip] != src_mac:
                    # If the IP is already mapped to a different MAC, trigger a spoofing alert
                    return {
                        "ip": src_ip,
                        "type": "Spoofing",
                        "details": f"IP {src_ip} is associated with unexpected MAC {src_mac}, expected MAC {self.ip_mac_mapping[src_ip]}",
                        "timestamp": timestamp,
                        "severity": "High",  # IP spoofing is considered a high-severity issue
                        "port": "N/A",  # Port is not applicable in this scenario
                        "protocol": protocol,
                        "possible_fixes": "Consider enabling ARP inspection, monitoring MAC-IP bindings, and using IDS/IPS to detect and prevent IP spoofing."
                    }
            else:
                # Store the correct IP -> MAC mapping
                self.ip_mac_mapping[src_ip] = src_mac

        return None  # No alert if nothing is detected
