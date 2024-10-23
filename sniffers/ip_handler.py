from scapy.all import IP,UDP,DNS,TCP
from .packet_handler_strategy import PacketHandlerStrategy
from datetime import datetime
from colorama import Fore, Style

class IPHandler(PacketHandlerStrategy):
    def __init__(self, sniffer):
        self.sniffer = sniffer

    def handle_packet(self, packet):
        if packet.haslayer(UDP) and packet.haslayer(DNS) and packet.haslayer(TCP):
            return  

        if packet.haslayer(IP):
            ip_packet = packet.getlayer(IP)

            src_ip = ip_packet.src
            dst_ip = ip_packet.dst
            ttl = ip_packet.ttl if ip_packet.ttl else "N/A"
            total_length = ip_packet.len  
            fragment_offset = ip_packet.frag  
            flags = str(ip_packet.flags) 

            packet_size = len(packet)
            protocol_str = f"IP (TTL: {ttl})"

            self.display_packet_info(
                "IP", src_ip, dst_ip, "N/A", "N/A", "IPv4", ttl,
                f"Total Length: {total_length}, Fragment Offset: {fragment_offset}, Flags: {flags}", 
                packet_size, protocol_str, "N/A", "N/A", packet
            )
            self.sniffer.ip_count += 1

            packet_info = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_mac": "N/A",
                "dst_mac": "N/A",
                "ip_version": "IPv4",
                "ttl": ttl,
                "total_length": total_length,
                "fragment_offset": fragment_offset,
                "flags": flags,
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
        print(f"{Fore.GREEN}Packet Size    :{Style.RESET_ALL} {packet_size}")
        print(f"{Fore.GREEN}Passing Time   :{Style.RESET_ALL} {timestamp}")
        print(f"{Fore.GREEN}Protocol       :{Style.RESET_ALL} {protocol_str}")
        print(f"{Fore.GREEN}Identifier     :{Style.RESET_ALL} {identifier}")
        print(f"{Fore.GREEN}Sequence       :{Style.RESET_ALL} {sequence}")
        print("-" * 40)
