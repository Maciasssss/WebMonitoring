from collections import defaultdict
from datetime import datetime, timedelta
from scapy.all import IP, TCP, Raw

class BruteForceLoginDetector:
    def __init__(self, time_window=60, attempt_threshold=5):
        self.time_window = time_window
        self.attempt_threshold = attempt_threshold
        self.failed_login_attempts = defaultdict(list)

    def monitor_traffic(self, packet):
        if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors='ignore')  # Decode the raw payload

            if "POST" in payload and "/login" in payload:  # Check for HTTP POST requests to login endpoint
                src_ip = packet[IP].src
                timestamp = datetime.now()

                # Check for login failure by identifying relevant status codes in the response
                if "401 Unauthorized" in payload or "403 Forbidden" in payload:
                    # Remove failed attempts that are older than the time window
                    self.failed_login_attempts[src_ip] = [ts for ts in self.failed_login_attempts[src_ip]
                                                          if ts > timestamp - timedelta(seconds=self.time_window)]
                    # Add the current failed login attempt
                    self.failed_login_attempts[src_ip].append(timestamp)

                    # Check if the number of failed attempts exceeds the threshold
                    if len(self.failed_login_attempts[src_ip]) > self.attempt_threshold:
                        return {
                            "ip": src_ip,
                            "type": "Brute Force Login",
                            "details": f"{len(self.failed_login_attempts[src_ip])} failed login attempts detected from {src_ip}",
                            "timestamp": timestamp
                        }
        return None  # No alert if nothing is detected