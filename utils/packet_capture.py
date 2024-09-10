import csv

class PacketCapture:
    def __init__(self, capture_file):
        self.capture_file = capture_file

    def start_capture(self, packets_info):
        if packets_info and self.capture_file:
            with open(self.capture_file, 'w', newline='', encoding='utf-8') as csvfile:
                # Expanded fieldnames for advanced details
                fieldnames = [
                    "Source IP", "Destination IP", "Source MAC", "Destination MAC", "IP Version", "TTL",
                    "Checksum", "Packet Size", "Passing Time", "Protocol", "Identifier", "Sequence",
                    "ICMP Type", "ICMP Code", "HTTP Method", "Flow Label", "Traffic Class", "Hop Limit",
                    "Next Header", "Fragment Offset", "Flags"
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                writer.writeheader()
                for packet in packets_info:
                    # Write detailed packet information, using `.get()` to avoid KeyError for non-applicable fields
                    writer.writerow({
                        "Source IP": packet.get('src_ip', 'N/A'),
                        "Destination IP": packet.get('dst_ip', 'N/A'),
                        "Source MAC": packet.get('src_mac', 'N/A'),
                        "Destination MAC": packet.get('dst_mac', 'N/A'),
                        "IP Version": packet.get('ip_version', 'N/A'),
                        "TTL": packet.get('ttl', 'N/A'),
                        "Checksum": packet.get('checksum', 'N/A'),
                        "Packet Size": packet.get('packet_size', 'N/A'),
                        "Passing Time": packet.get('passing_time', 'N/A'),
                        "Protocol": packet.get('protocol', 'N/A'),
                        "Identifier": packet.get('identifier', 'N/A'),
                        "Sequence": packet.get('sequence', 'N/A'),
                        "ICMP Type": packet.get('icmp_type', 'N/A'),
                        "ICMP Code": packet.get('icmp_code', 'N/A'),
                        "HTTP Method": packet.get('http_method', 'N/A'),
                        "Flow Label": packet.get('flow_label', 'N/A'),
                        "Traffic Class": packet.get('traffic_class', 'N/A'),
                        "Hop Limit": packet.get('hop_limit', 'N/A'),
                        "Next Header": packet.get('next_header', 'N/A'),
                        "Fragment Offset": packet.get('fragment_offset', 'N/A'),
                        "Flags": packet.get('flags', 'N/A')
                    })