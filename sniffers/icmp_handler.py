from scapy.all import ICMP, Ether, IP
from .packet_handler_strategy import PacketHandlerStrategy
from datetime import datetime
from colorama import Fore, Style

class ICMPHandler(PacketHandlerStrategy):
    def __init__(self, sniffer):
        self.sniffer = sniffer

    def handle_packet(self, packet):
        if packet.haslayer(ICMP) and packet.haslayer(IP):
            icmp_packet = packet.getlayer(ICMP)
            ip_header = packet.getlayer('IP')
            ether_header = packet.getlayer(Ether)

            src_ip = ip_header.src
            dst_ip = ip_header.dst
            ip_version = ip_header.version
            ttl = ip_header.ttl if ip_header.ttl else "N/A"

            src_mac = ether_header.src
            dst_mac = ether_header.dst
            packet_size = len(packet)

            icmp_type = icmp_packet.type
            icmp_checksum = icmp_packet.chksum
            icmp_identifier = icmp_packet.id if hasattr(icmp_packet, 'id') else 'N/A'
            icmp_sequence = icmp_packet.seq if hasattr(icmp_packet, 'seq') else 'N/A'

            # Define ICMP type as a string for readability
            icmp_type_str = self.get_icmp_type_string(icmp_type)

            if icmp_type == 8:  # ICMP Echo Request
                self.sniffer.echo_request_count += 1
                self.sniffer.total_bytes_sent += packet_size
            elif icmp_type == 0:  # ICMP Echo Reply
                self.sniffer.echo_reply_count += 1
                self.sniffer.total_bytes_received += packet_size

            self.sniffer.icmp_count += 1

            packet_info = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "ip_version": ip_version,
                "ttl": ttl,
                "icmp_type": icmp_type_str,
                "checksum": icmp_checksum,
                "packet_size": f"{packet_size} bytes",
                "passing_time": datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S'),
                "protocol": icmp_type_str,
                "identifier": icmp_identifier,
                "sequence": icmp_sequence
            }
            self.sniffer.packets_info.append(packet_info)

            if len(self.sniffer.packets_info) > 100:
                self.sniffer.packets_info.pop(0)

            self.display_packet_info(icmp_type_str, src_ip, dst_ip, src_mac, dst_mac, ip_version, ttl, icmp_checksum, packet_size, icmp_type_str, icmp_identifier, icmp_sequence, packet)

            if icmp_packet.payload:
                payload = icmp_packet.payload.load if hasattr(icmp_packet.payload, 'load') else None
                if payload:
                    payload_hex = ' '.join(format(byte, '02X') for byte in payload)
                    print(f"{Fore.GREEN}Payload (Hex)  :{Style.RESET_ALL} {payload_hex}")

                    try:
                        payload_content = payload.decode("utf-8")
                        print(f"{Fore.GREEN}Payload (ASCII):{Style.RESET_ALL} {payload_content}")
                    except UnicodeDecodeError:
                        payload_content = "Non-UTF-8 Payload"
                        print(f"{Fore.GREEN}Payload (ASCII):{Style.RESET_ALL} {payload_content}")
                else:
                    print(f"{Fore.YELLOW}No Payload Found.{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}No Payload Found.{Style.RESET_ALL}")

            print("-" * 40)

    def get_icmp_type_string(self, icmp_type):
        """
        Converts the ICMP type to a human-readable string.
        """
        icmp_type_mapping = {
            0: "ICMP Echo Reply",
            3: "Destination Unreachable",
            4: "Source Quench",
            5: "Redirect Message",
            8: "ICMP Echo Request",
            11: "Time Exceeded",
            12: "Parameter Problem",
            13: "Timestamp",
            14: "Timestamp Reply",
            15: "Information Request",
            16: "Information Reply",
            17: "Address Mask Request",
            18: "Address Mask Reply",
        }
        return icmp_type_mapping.get(icmp_type, f"ICMP Type {icmp_type}")

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
