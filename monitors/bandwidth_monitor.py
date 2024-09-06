from datetime import datetime
from scapy.all import sniff

from .monitor_strategy import MonitorStrategy

class BandwidthMonitor(MonitorStrategy):
    def __init__(self, time_window=1):
        self.time_window = time_window
        self.data_transferred = 0
        self.last_check = datetime.now()

    def monitor_traffic(self, packet):
        self.data_transferred += len(packet)
        now = datetime.now()

        if (now - self.last_check).total_seconds() >= self.time_window:
            bandwidth = (self.data_transferred * 8) / self.time_window / 1024  # Przepustowość w kbps
            print(f"Current bandwidth: {bandwidth:.2f} kbps")
            self.data_transferred = 0
            self.last_check = now
