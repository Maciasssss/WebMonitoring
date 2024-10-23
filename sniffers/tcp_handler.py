# tcp_http_handler.py
import re
from scapy.all import TCP, Raw, IP, Ether
from .packet_handler_strategy import PacketHandlerStrategy
from datetime import datetime
from colorama import Fore, Style

class TCPHandler(PacketHandlerStrategy):
    def __init__(self, sniffer):
        self.sniffer = sniffer

    def handle_packet(self, packet):
        if not packet.haslayer(TCP):
            return 

        tcp_layer = packet.getlayer(TCP)
        ip_layer = packet.getlayer(IP)
        ether_layer = packet.getlayer(Ether)

        # Extract IP information
        if ip_layer:
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            ip_version = ip_layer.version
            ttl = ip_layer.ttl if hasattr(ip_layer, 'ttl') else "N/A"
        else:
            src_ip = dst_ip = "N/A"
            ip_version = "N/A"
            ttl = "N/A"

        # Extract MAC information
        if ether_layer:
            src_mac = ether_layer.src
            dst_mac = ether_layer.dst
        else:
            src_mac = dst_mac = "N/A"

        # Determine packet direction using the provided interface IP
        interface_ip = self.sniffer.interface_ip  
        if src_ip == interface_ip:
            self.sniffer.total_bytes_sent += len(packet)
        else:
            self.sniffer.total_bytes_received += len(packet)

        # Extract TCP information
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport
        sequence_number = tcp_layer.seq
        acknowledgment_number = tcp_layer.ack
        tcp_flags = tcp_layer.flags
        window_size = tcp_layer.window
        mss_option = next((opt[1] for opt in tcp_layer.options if opt[0] == 'MSS'), None)

        # Determine TCP flag description
        protocol_str = "TCP"
        if tcp_flags == 0x02:
            protocol_str += " (SYN)"
        elif tcp_flags == 0x12:
            protocol_str += " (SYN-ACK)"
        elif tcp_flags == 0x10:
            protocol_str += " (ACK)"

        packet_size = len(packet)
        timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')

        # Initialize HTTP-related variables
        http_info = "N/A"
        protocol_type = "TCP"  
        http_method = "N/A"

        # Flag to determine if packet is HTTP or HTTPS
        is_http_or_https = False

        # Check for HTTPS traffic first to prioritize encryption status
        if dst_port == 443 or src_port == 443:
            protocol_type = "HTTPS Traffic"
            http_info = "Encrypted HTTPS Traffic"
            self.sniffer.http_count += 1
            is_http_or_https = True
        else:
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                try:
                    decoded_payload = payload.decode('utf-8', errors='ignore')
                except UnicodeDecodeError:
                    decoded_payload = ""

                http_method_match = re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)", decoded_payload)
                http_response_match = re.match(r"^HTTP/\d\.\d\s(\d{3})", decoded_payload)

                if http_method_match:
                    http_method = http_method_match.group(0)
                    protocol_type = "HTTP Request"
                    http_info = f"{http_method} {src_port}->{dst_port}"
                    self.sniffer.http_count += 1
                    is_http_or_https = True
                elif http_response_match:
                    status_code = http_response_match.group(1)
                    protocol_type = "HTTP Response"
                    http_info = f"HTTP/{status_code} {src_port}->{dst_port}"
                    self.sniffer.http_count += 1
                    is_http_or_https = True

        if not is_http_or_https:
            self.sniffer.tcp_count += 1

        self.display_packet_info(
            protocol_type, src_ip, dst_ip, src_mac, dst_mac, ip_version, ttl,
            f"Window Size: {window_size}, MSS: {mss_option}", packet_size, 
            protocol_str, sequence_number, acknowledgment_number, packet, http_info
        )

        packet_info = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "ip_version": ip_version,
            "ttl": ttl,
            "checksum": f"Window Size: {window_size}, MSS: {mss_option}",
            "packet_size": f"{packet_size} bytes",
            "passing_time": timestamp,
            "protocol": protocol_type,
            "identifier": sequence_number,
            "sequence": acknowledgment_number,
            "http_info": http_info
        }

        self.sniffer.packets_info.append(packet_info)
        if len(self.sniffer.packets_info) > 100:
            self.sniffer.packets_info.pop(0)

    def display_packet_info(self, protocol, src_ip, dst_ip, src_mac, dst_mac, ip_version, ttl, checksum, packet_size, protocol_str, identifier, sequence, packet, http_info):
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
        if http_info != "N/A":
            print(f"{Fore.YELLOW}HTTP Info      :{Style.RESET_ALL} {http_info}")
        print("-" * 40)
