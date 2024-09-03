from scapy.all import ARP, Ether
from .packet_handler_strategy import PacketHandlerStrategy
from datetime import datetime
from colorama import Fore, Style

class ARPHandler(PacketHandlerStrategy):
    def __init__(self, sniffer):
        self.sniffer = sniffer
        
    def handle_packet(self, packet):
        if packet.haslayer(ARP):
            arp_packet = packet.getlayer(ARP)
            src_ip = arp_packet.psrc
            dst_ip = arp_packet.pdst
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            packet_size = len(packet)
            protocol_str = "ARP"
            self.display_packet_info("ARP", src_ip, dst_ip, src_mac, dst_mac, "N/A", "N/A", "N/A", packet_size, "ARP", "N/A", "N/A", packet)
            self.sniffer.arp_count += 1

        # Add packet information to the sniffer's packet info list
            packet_info = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_mac": "N/A",
                "dst_mac": "N/A",
                "ip_version": "IPv6",
                "ttl": "N/A",
                "checksum": "N/A",
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