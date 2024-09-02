from scapy.all import UDP, IP, Ether
from .packet_handler_strategy import PacketHandlerStrategy
from datetime import datetime
from colorama import Fore, Style

class UDPHandler(PacketHandlerStrategy):
    def handle_packet(self, packet):
        if packet.haslayer(UDP):
            udp_packet = packet.getlayer(UDP)
            ip_header = packet.getlayer(IP)
            ether_header = packet.getlayer(Ether)

            src_ip = ip_header.src
            dst_ip = ip_header.dst
            ip_version = ip_header.version
            ttl = ip_header.ttl if ip_header.ttl else "N/A"
            src_mac = ether_header.src
            dst_mac = ether_header.dst
            packet_size = len(packet)
            src_port = udp_packet.sport
            dst_port = udp_packet.dport

            protocol_str = "UDP"
            self.display_packet_info("UDP", src_ip, dst_ip, src_mac, dst_mac, ip_version, ttl, protocol_str, packet_size, f"UDP {src_port}->{dst_port}", "N/A", "N/A", packet)

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