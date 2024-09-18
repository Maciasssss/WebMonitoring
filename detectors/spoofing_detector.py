import datetime
from scapy.all import IP, Ether

from .detector_strategy import DetectorStrategy

class SpoofingDetector(DetectorStrategy):
    def __init__(self):
        self.ip_mac_mapping = {}  

    def monitor_traffic(self, packet):
        if packet.haslayer(IP) and packet.haslayer(Ether):
            src_ip = packet[IP].src
            src_mac = packet[Ether].src
            protocol = "IP" 
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
                        "severity": "High",  
                        "port": "N/A",  
                        "protocol": protocol,
                        "possible_fixes": "Consider enabling ARP inspection, monitoring MAC-IP bindings, and using IDS/IPS to detect and prevent IP spoofing."
                    }
            else:
                self.ip_mac_mapping[src_ip] = src_mac
        return None  
