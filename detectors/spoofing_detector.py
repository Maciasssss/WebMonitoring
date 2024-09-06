import datetime
from scapy.all import IP, Ether

from .detector_strategy import DetectorStrategy

class SpoofingDetector(DetectorStrategy):
    def __init__(self):
        self.ip_mac_mapping = {}  # Mapa IP do MAC

    def monitor_traffic(self, packet):
        if packet.haslayer(IP) and packet.haslayer(Ether):
            src_ip = packet[IP].src
            src_mac = packet[Ether].src

            # Check if the IP -> MAC mapping exists and if it is correct
            if src_ip in self.ip_mac_mapping:
                if self.ip_mac_mapping[src_ip] != src_mac:
                    return {
                        "ip": src_ip,
                        "type": "Spoofing",
                        "details": f"IP {src_ip} is associated with unexpected MAC {src_mac}, expected MAC {self.ip_mac_mapping[src_ip]}",
                        "timestamp": datetime.now()
                    }
            else:
                # Store the correct IP -> MAC mapping
                self.ip_mac_mapping[src_ip] = src_mac
        return None  # No alert if nothing is detected
