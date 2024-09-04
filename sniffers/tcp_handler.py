import socket
from scapy.all import TCP, IP, Ether
from .packet_handler_strategy import PacketHandlerStrategy
from datetime import datetime
from colorama import Fore, Style

class TCPHandler(PacketHandlerStrategy):
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
        if packet.haslayer(TCP):
            tcp_packet = packet.getlayer(TCP)
            ip_header = packet.getlayer(IP)
            ether_header = packet.getlayer(Ether)

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

            # Get the interface IP dynamically
            interface_ip = self.get_interface_ip()

            # If the packet is sent from the machine, consider it "sent bytes"
            if src_ip == interface_ip:
                self.sniffer.total_bytes_sent += len(packet)
            else:
                # Otherwise, consider it "received bytes"
                self.sniffer.total_bytes_received += len(packet)

            # Handle cases where the Ether layer might not be present
            if ether_header:
                src_mac = ether_header.src
                dst_mac = ether_header.dst
            else:
                src_mac = "N/A"
                dst_mac = "N/A"

            packet_size = len(packet)
            src_port = tcp_packet.sport
            dst_port = tcp_packet.dport
            sequence_number = tcp_packet.seq
            acknowledgment_number = tcp_packet.ack
            tcp_flags = tcp_packet.flags

            protocol_str = "TCP"
            if tcp_flags == 0x02:
                protocol_str += " (SYN)"
            elif tcp_flags == 0x12:
                protocol_str += " (SYN-ACK)"
            elif tcp_flags == 0x10:
                protocol_str += " (ACK)"

            self.display_packet_info(
                "TCP", src_ip, dst_ip, src_mac, dst_mac, ip_version, ttl,
                "N/A", packet_size, f"TCP {src_port}->{dst_port}", sequence_number, acknowledgment_number, packet
            )
            self.sniffer.tcp_count += 1

            # Add packet information to the sniffer's packet info list
            packet_info = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "ip_version": ip_version,
                "ttl": ttl,
                "checksum": "N/A",
                "packet_size": f"{packet_size} bytes",
                "passing_time": datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S'),
                "protocol": protocol_str,
                "identifier": sequence_number,
                "sequence": acknowledgment_number
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
        
