from scapy.all import IP, Ether

class SpoofingDetector:
    def __init__(self):
        self.ip_mac_mapping = {}  # Mapa IP do MAC

    def monitor_traffic(self, packet):
        if packet.haslayer(IP) and packet.haslayer(Ether):
            src_ip = packet[IP].src
            src_mac = packet[Ether].src

            # Sprawdzanie czy istnieje już zapis IP -> MAC
            if src_ip in self.ip_mac_mapping:
                if self.ip_mac_mapping[src_ip] != src_mac:
                    print(f"Potential spoofing attack detected: IP {src_ip} is associated with MAC {src_mac}, expected MAC {self.ip_mac_mapping[src_ip]}")
            else:
                self.ip_mac_mapping[src_ip] = src_mac
