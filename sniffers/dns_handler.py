from scapy.all import UDP, DNS, IP, Ether
from .packet_handler_strategy import PacketHandlerStrategy
from datetime import datetime
from colorama import Fore, Style

class DNSHandler(PacketHandlerStrategy):
    def __init__(self, sniffer):
        self.sniffer = sniffer
        
    def handle_packet(self, packet):
        if packet.haslayer(UDP) and packet.haslayer(DNS):
            dns_packet = packet[DNS]
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

            if ether_header:
                src_mac = ether_header.src
                dst_mac = ether_header.dst
            else:
                src_mac = "N/A"
                dst_mac = "N/A"

            query_name = dns_packet.qd.qname.decode() if dns_packet.qdcount > 0 else "N/A"
            query_type = dns_packet.qd.qtype if dns_packet.qdcount > 0 else "N/A"
            response_code = dns_packet.rcode  # Response code (0 = no error)
            is_response = dns_packet.qr == 1  

            if is_response:
                protocol_str = "DNS Response"
                answer_count = dns_packet.ancount
                dns_info = f"Response: {query_name}, Answers: {answer_count}, Response Code: {response_code}"
            else:
                protocol_str = "DNS Request"
                dns_info = f"Request: {query_name}, Query Type: {query_type}"

            packet_size = len(packet)
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

            self.display_packet_info(
                protocol_str, src_ip, dst_ip, src_mac, dst_mac, ip_version, ttl, protocol_str, 
                packet_size, f"DNS {src_port}->{dst_port}", dns_packet.id, "N/A", packet
            )
            self.sniffer.dns_count += 1

            packet_info = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "ip_version": ip_version,
                "ttl": ttl,
                "checksum": dns_info,
                "packet_size": f"{packet_size} bytes",
                "passing_time": datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S'),
                "protocol": protocol_str,
                "query_name": query_name,
                "query_type": query_type,
                "response_code": response_code,
                "identifier": dns_packet.id,
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
