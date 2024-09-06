import re
from collections import defaultdict
from scapy.all import IP, TCP, Raw

class PasswordExfiltrationDetector:
    def __init__(self):
        self.sent_passwords = defaultdict(set)  # Track passwords sent by each IP to different destinations

    def monitor_traffic(self, packet):
        if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            payload = packet[Raw].load.decode(errors='ignore')

            # Detect HTTP POST requests
            if "POST" in payload:
                # Check for potential password fields in the POST data using a regex
                password_match = re.search(r'password=([^&]+)', payload)
                if password_match:
                    password = password_match.group(1)

                    # Check if the password is being sent to multiple IPs
                    if password in self.sent_passwords[src_ip]:
                        # If password was sent to a different destination, flag it
                        if dst_ip not in self.sent_passwords[src_ip][password]:
                            print(f"Potential password exfiltration detected: {src_ip} sent the same password to multiple IPs!")
                            self.sent_passwords[src_ip][password].add(dst_ip)
                    else:
                        # Record the IP where the password was first sent
                        self.sent_passwords[src_ip][password].add(dst_ip)
