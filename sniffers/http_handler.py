import re
from scapy.all import TCP, Raw, IP
from .packet_handler_strategy import PacketHandlerStrategy
from datetime import datetime
from colorama import Fore, Style

class HTTPHandler(PacketHandlerStrategy):
    def __init__(self, sniffer):
        self.sniffer = sniffer
        
    def handle_packet(self, packet):
        if packet.haslayer(TCP):
            if packet.haslayer(Raw):  
                payload = packet[Raw].load
                try:
                    decoded_payload = payload.decode('utf-8', errors='ignore')  
                except UnicodeDecodeError:
                    decoded_payload = ""

                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport

                    protocol_str = "Unknown HTTP Traffic"
                    http_info = "Unknown HTTP Traffic"
                    http_method = "N/A"

                    # Use regex to capture HTTP methods and responses
                    http_method_match = re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)", decoded_payload)
                    http_response_match = re.match(r"^HTTP\/\d\.\d\s(\d{3})", decoded_payload)

                    # Check if the packet is an HTTP request
                    if http_method_match:
                        http_method = http_method_match.group(0)  
                        protocol_str = "HTTP Request"
                        http_info = f"{http_method} {src_port}->{dst_port}"
                    
                    # Check if the packet is an HTTP response
                    elif http_response_match:
                        status_code = http_response_match.group(1)  
                        protocol_str = "HTTP Response"
                        http_info = f"HTTP/{status_code} {src_port}->{dst_port}"

                    packet_size = len(packet)
                    self.display_packet_info(
                        protocol_str, src_ip, dst_ip, "N/A", "N/A", "IPv4", "N/A",
                        protocol_str, packet_size, http_info, "N/A", "N/A", packet
                    )
                    self.sniffer.http_count += 1

                    packet_info = {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_mac": "N/A",
                        "dst_mac": "N/A",
                        "ip_version": "IPv4",
                        "ttl": "N/A",
                        "checksum": "N/A",
                        "packet_size": f"{packet_size} bytes",
                        "passing_time": datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S'),
                        "protocol": protocol_str,
                        "identifier": "N/A",
                        "sequence": "N/A",
                        "HTTP Method": http_method
                    }
                    self.sniffer.packets_info.append(packet_info)
                    if len(self.sniffer.packets_info) > 100:
                        self.sniffer.packets_info.pop(0)

            else:  
                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport

                    if dst_port == 443 or src_port == 443:
                        protocol_str = "HTTPS Traffic"
                        packet_size = len(packet)
                        self.display_packet_info(
                            protocol_str, src_ip, dst_ip, "N/A", "N/A", "IPv4", "N/A",
                            "TCP", packet_size, "Encrypted HTTPS Traffic", "N/A", "N/A", packet
                        )
                        self.sniffer.http_count += 1

                        packet_info = {
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_mac": "N/A",
                            "dst_mac": "N/A",
                            "ip_version": "IPv4",
                            "ttl": "N/A",
                            "checksum": "N/A",
                            "packet_size": f"{packet_size} bytes",
                            "passing_time": datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S'),
                            "protocol": "HTTPS",
                            "identifier": "N/A",
                            "sequence": "N/A",
                            "HTTP Method": "N/A"  
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
