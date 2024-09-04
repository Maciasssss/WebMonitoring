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
            
            # Check if it's an Echo Request (type 8) or Echo Reply (type 0)
            if icmp_packet.type == 8:
                # Echo Request (Ping)
                self.sniffer.echo_request_count += 1
            elif icmp_packet.type == 0:
                # Echo Reply
                self.sniffer.echo_reply_count += 1
            # Check if the IP layer exists
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

            # Handle cases where the Ether layer might not be present
            if ether_header:
                src_mac = ether_header.src
                dst_mac = ether_header.dst
            else:
                src_mac = "N/A"
                dst_mac = "N/A"

            packet_size = len(packet)
            icmp_type = icmp_packet.type
            icmp_echo_identifier = icmp_packet.id
            icmp_echo_sequence = icmp_packet.seq

            if icmp_type == 8:  # ICMP Echo Request
                protocol_str = "Echo Request"
                self.sniffer.echo_request_count += 1
                self.sniffer.total_bytes_sent += packet_size
            elif icmp_type == 0:  # ICMP Echo Reply
                protocol_str = "Echo Reply"
                self.sniffer.echo_reply_count += 1
                self.sniffer.total_bytes_received += packet_size
            else:
                protocol_str = f"ICMP Type {icmp_type}"

            self.display_packet_info("ICMP", src_ip, dst_ip, src_mac, dst_mac, ip_version, ttl, "ICMP", packet_size, f"ICMP {protocol_str}", icmp_echo_identifier, icmp_echo_sequence, packet)

            # Add packet information to the sniffer's packet info list
            packet_info = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "ip_version": ip_version,
                "ttl": ttl,
                "checksum": "ICMP",
                "packet_size": f"{packet_size} bytes",
                "passing_time": datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S'),
                "protocol": protocol_str,
                "identifier": icmp_echo_identifier,
                "sequence": icmp_echo_sequence
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
