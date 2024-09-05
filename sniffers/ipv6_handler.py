from scapy.all import IPv6
from .packet_handler_strategy import PacketHandlerStrategy
from datetime import datetime
from colorama import Fore, Style

class IPv6Handler(PacketHandlerStrategy):
    def __init__(self, sniffer):
        self.sniffer = sniffer
        
    def handle_packet(self, packet):
        if packet.haslayer(IPv6):
            ipv6_packet = packet.getlayer(IPv6)

            # IPv6 specific fields
            src_ip = ipv6_packet.src
            dst_ip = ipv6_packet.dst
            flow_label = ipv6_packet.fl  # Flow label
            traffic_class = ipv6_packet.tc  # Traffic class
            hop_limit = ipv6_packet.hlim  # Hop limit
            next_header = ipv6_packet.nh  # Next header (protocol)
            
            # Other metadata
            packet_size = len(packet)
            protocol_str = "IPv6"

            self.display_packet_info(
                "IPv6", src_ip, dst_ip, "N/A", "N/A", "IPv6", hop_limit, 
                f"Flow Label: {flow_label}, Traffic Class: {traffic_class}, Next Header: {next_header}", 
                packet_size, protocol_str, "N/A", "N/A", packet
            )
            self.sniffer.ipv6_count += 1

            # Add packet information to the sniffer's packet info list
            packet_info = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_mac": "N/A",
                "dst_mac": "N/A",
                "ip_version": "IPv6",
                "hop_limit": hop_limit,
                "traffic_class": traffic_class,
                "flow_label": flow_label,
                "next_header": next_header,
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
