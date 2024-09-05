# udp_handler.py
import socket
from scapy.all import UDP, IP, Ether
from .packet_handler_strategy import PacketHandlerStrategy
from datetime import datetime
from colorama import Fore, Style

class UDPHandler(PacketHandlerStrategy):
    def __init__(self, sniffer):
        self.sniffer = sniffer
  
    def get_interface_ip(self):
        """Get the local IP address dynamically."""
        try:
            hostname = socket.gethostname()
            interface_ip = socket.gethostbyname(hostname)
            return interface_ip
        except Exception as e:
            print(f"Error retrieving IP for interface: {e}")
            return None
  
    def handle_packet(self, packet):
        if packet.haslayer(UDP):
            udp_packet = packet.getlayer(UDP)
            ip_header = packet.getlayer(IP)
            ether_header = packet.getlayer(Ether)
          
            if ip_header:
                src_ip = ip_header.src
                dst_ip = ip_header.dst
                ip_version = ip_header.version
                ttl = ip_header.ttl if ip_header.ttl else "N/A"
            else:
                src_ip = "N/A"
                dst_ip = "N/A"
                ip_version = "N/A"
                ttl = "N/A"
              
              # Get the interface IP dynamically
            interface_ip = self.get_interface_ip()

            # If the packet is sent from the machine, consider it "sent bytes"
            if src_ip == interface_ip:
                self.sniffer.total_bytes_sent += len(packet)
            else:
                # Otherwise, consider it "received bytes"
                self.sniffer.total_bytes_received += len(packet)
                
            if ether_header:
                src_mac = ether_header.src
                dst_mac = ether_header.dst
            else:
                src_mac = "N/A"
                dst_mac = "N/A"

            packet_size = len(packet)
            src_port = udp_packet.sport
            dst_port = udp_packet.dport
            udp_length = udp_packet.len

            protocol_str = "UDP"
            self.display_packet_info(
                "UDP", src_ip, dst_ip, src_mac, dst_mac, ip_version, ttl,
                f"UDP Length: {udp_length}", packet_size, f"UDP {src_port}->{dst_port}",
                "N/A", "N/A", packet
            )
            self.sniffer.udp_count += 1

            # Add packet info
            packet_info = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "ip_version": ip_version,
                "ttl": ttl,
                "checksum": f"UDP Length: {udp_length}",
                "packet_size": f"{packet_size} bytes",
                "passing_time": datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S'),
                "protocol": protocol_str,
                "identifier": "N/A",
                "sequence": "N/A"
            }
            self.sniffer.packets_info.append(packet_info)
            if len(self.sniffer.packets_info) > 100:
                self.sniffer.packets_info.pop(0)

    def display_packet_info(self, protocol, src_ip, dst_ip, src_mac, dst_mac, ip_version, ttl, checksum, packet_size, protocol_str, identifier, sequence, packet):
        timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')
        
        print(f"{Fore.CYAN}\t{protocol} Packet Detected:{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Source IP      :{Style.RESET_ALL} {src_ip}")
        print(f"{Fore.GREEN}Destination IP :{Style.RESET_ALL} {dst_ip}")
        print(f"{Fore.GREEN}Source MAC     :{Style.RESET_ALL} {src_mac}")
        print(f"{Fore.GREEN}Destination MAC:{Style.RESET_ALL} {dst_mac}")
        print(f"{Fore.GREEN}IP Version     :{Style.RESET_ALL} {ip_version}")
        print(f"{Fore.GREEN}TTL            :{Style.RESET_ALL} {ttl}")
        print(f"{Fore.GREEN}Checksum       :{Style.RESET_ALL} {checksum}")
        print(f"{Fore.GREEN}Packet Size    :{Style.RESET_ALL} {packet_size} bytes")
        print(f"{Fore.GREEN}Passing Time   :{Style.RESET_ALL} {timestamp}")
        print(f"{Fore.GREEN}Protocol       :{Style.RESET_ALL} {protocol_str}")
        print(f"{Fore.GREEN}Identifier     :{Style.RESET_ALL} {identifier}")
        print(f"{Fore.GREEN}Sequence       :{Style.RESET_ALL} {sequence}")
        print("-" * 40)
