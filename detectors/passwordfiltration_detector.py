import re
from collections import defaultdict
from scapy.all import IP, TCP, Raw

from .detector_strategy import DetectorStrategy

class PasswordExfiltrationDetector(DetectorStrategy):
    def __init__(self):
        self.sent_passwords = defaultdict(set)  # Track passwords sent by each IP to different destinations

    def monitor_traffic(self, packet):
        if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            payload = packet[Raw].load.decode(errors='ignore')

            # Check for password fields in the POST data
            if "POST" in payload:
                password_match = re.search(r'password=([^&]+)', payload)
                if password_match:
                    password = password_match.group(1)
                    if password in self.sent_passwords[src_ip]:
                        if dst_ip not in self.sent_passwords[src_ip][password]:
                            # Return alert when potential password exfiltration is detected
                            return {"ip": src_ip, "details": "Potential password exfiltration detected"}
                    else:
                        self.sent_passwords[src_ip][password].add(dst_ip)
        return None  # No alert if no exfiltration detected
