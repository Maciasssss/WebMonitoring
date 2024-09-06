from scapy.all import ICMP, Ether, IP
from .packet_handler_strategy import PacketHandlerStrategy
from datetime import datetime
from colorama import Fore, Style

class ICMPHandler(PacketHandlerStrategy):
    def __init__(self, sniffer):
        self.sniffer = sniffer

    def handle_packet(self, packet):
        if packet.haslayer(ICMP) and packet.haslayer(Ether):
            icmp_packet = packet.getlayer(ICMP)
            ip_header = packet.getlayer('IP')
            ether_header = packet.getlayer(Ether)
                    #ip
            src_ip               = ip_header.src
            dst_ip               = ip_header.dst
            ip_version           = ip_header.version
            ttl                  = ip_header.ttl if ip_header.ttl else "N/A"
                    #ethernet
            src_mac              = ether_header.src
            dst_mac              = ether_header.dst
            packet_size          = len(packet)
                    #icmp
            icmp_type            = icmp_packet.type
            icmp_echo_identifier = icmp_packet.id
            icmp_echo_sequence   = icmp_packet.seq
            icmp_checksum        = icmp_packet.chksum

            icmp_type_str = f"ICMP Type {icmp_type}"

            if icmp_type == 8:  # ICMP Echo Request
                icmp_type_str = "ICMP Echo Request"
                self.echo_request_count += 1
                self.total_bytes_sent += packet_size
            elif icmp_type == 0:  # ICMP Echo Reply
                icmp_type_str = "ICMP Echo Reply"
                self.echo_reply_count += 1
                self.total_bytes_received += packet_size

            timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')
            self.sniffer.icmp_count += 1

            # Add packet info
            packet_info = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "ip_version": ip_version,
                "ttl": ttl,
                "icmp_type": icmp_type,
                "checksum": icmp_checksum,
                "packet_size": f"{packet_size} bytes",
                "passing_time": datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S'),
                "protocol": icmp_type_str,
                "identifier": icmp_packet.id,
                "sequence": icmp_packet.seq
            }
            self.sniffer.packets_info.append(packet_info)
            if len(self.sniffer.packets_info) > 100:
                self.sniffer.packets_info.pop(0)
            if icmp_packet.payload:
                payload = icmp_packet.payload.load
                payload_hex = ' '.join(format(byte, '02X') for byte in payload)
                print(f"{Fore.GREEN}Payload (Hex)  :{Style.RESET_ALL} {payload_hex}")

                try:
                    payload_content = payload.decode("utf-8")
                    print(f"{Fore.GREEN}Payload (ASCII):{Style.RESET_ALL} {payload_content}")
                except UnicodeDecodeError:
                    payload_content = "Non-UTF-8 Payload"
                    print(f"{Fore.GREEN}Payload (ASCII):{Style.RESET_ALL} {payload_content}")

            else:
                payload_hex = "No Payload"
                payload_content = "No Payload"
            print("-" * 40)

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
