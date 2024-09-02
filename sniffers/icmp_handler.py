from scapy.all import ICMP, Ether, IP
from .packet_handler_strategy import PacketHandlerStrategy
from datetime import datetime
from colorama import Fore, Style

class ICMPHandler(PacketHandlerStrategy):
    def __init__(self, sniffer):
        self.sniffer = sniffer

    def handle_packet(self, packet):
        if packet.haslayer(ICMP):
            icmp_packet = packet.getlayer(ICMP)
            ip_header = packet.getlayer(IP)
            ether_header = packet.getlayer(Ether)

            src_ip = ip_header.src
            dst_ip = ip_header.dst
            ip_version = ip_header.version
            ttl = ip_header.ttl if ip_header.ttl else "N/A"
            src_mac = ether_header.src
            dst_mac = ether_header.dst
            packet_size = len(packet)
            icmp_type = icmp_packet.type
            icmp_echo_identifier = icmp_packet.id
            icmp_echo_sequence = icmp_packet.seq
            icmp_checksum = icmp_packet.chksum

            if icmp_type == 8:  # ICMP Echo Request
                protocol_str = "Echo Request"
                self.echo_request_count += 1
                self.total_bytes_sent += packet_size
            elif icmp_type == 0:  # ICMP Echo Reply
                protocol_str = "Echo Reply"
                self.echo_reply_count += 1
                self.total_bytes_received += packet_size
            else:
                protocol_str = f"ICMP Type {icmp_type}"

            self.display_packet_info("ICMP", src_ip, dst_ip, src_mac, dst_mac, ip_version, ttl, protocol_str, packet_size, f"ICMP {protocol_str}", icmp_echo_identifier, icmp_echo_sequence, packet)

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
