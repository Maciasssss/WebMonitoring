from datetime import datetime, timedelta
import re
from collections import defaultdict
from scapy.all import IP, TCP, Raw
from .detector_strategy import DetectorStrategy

class PasswordExfiltrationDetector(DetectorStrategy):
    def __init__(self):
        self.sent_passwords = defaultdict(lambda: defaultdict(set))  # Track passwords sent by each IP to different destinations

    def monitor_traffic(self, packet):
        if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport  
            protocol = "TCP"
            timestamp = datetime.now()

            payload = packet[Raw].load.decode(errors='ignore')

            if "POST" in payload:
                # Use regex to search for password fields in the POST data
                password_match = re.search(r'password=([^&]+)', payload)
                if password_match:
                    password = password_match.group(1)
                    # Check if the password has been sent to this destination before
                    if password in self.sent_passwords[src_ip]:
                        if dst_ip not in self.sent_passwords[src_ip][password]:
                            # If the password is sent to a new destination, raise an alert
                            return {
                                "ip": src_ip,
                                "type": "Password_Exfiltration",
                                "details": f"Potential password exfiltration detected: password sent from {src_ip} to {dst_ip}",
                                "timestamp": timestamp,
                                "severity": "High",  
                                "port": dst_port,
                                "protocol": protocol,
                                "possible_fixes": "Use encryption for sensitive data, monitor traffic for suspicious activity, and consider enabling multi-factor authentication (MFA)."
                            }
                    else:
                        self.sent_passwords[src_ip][password].add(dst_ip)
        return None  
