import threading
import argparse
from packet_sniffer import PacketSniffer, SnifferConfig
from scapy.all import get_if_list, get_working_ifaces
from web.routes import create_app  # Importuj teraz create_app

def run_sniffer(sniffer):
    """Konfiguruje i uruchamia sniffer pakietów."""
    sniffer.start_sniffing()
    sniffer.get_statistics()

def choose_interface():
    interfaces = get_working_ifaces()
    print("Available network interfaces:")
    for idx, iface in enumerate(interfaces, 1):
        print(f"{idx}. {iface.description} ({iface.name})")

    choice = int(input("Choose an interface by number: "))
    return interfaces[choice - 1].name

def main():
    interface = choose_interface()
    """Główna funkcja konfigurująca i uruchamiająca sniffer oraz serwer Flask."""
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show verbose packet details")
    parser.add_argument("-t", "--timeout", type=int, default=300, help="Sniffing timeout in seconds")
    parser.add_argument("-f", "--filter", default="icmp or arp or tcp or udp or http or dns or ip or ipv6", help="BPF filter for packet sniffing")
    parser.add_argument("-o", "--output", help="Output file to save captured packets")
    parser.add_argument("--type", type=int, choices=[0, 8], help="ICMP packet type to filter (0: Echo Reply, 8: Echo Request)")
    parser.add_argument("--src-ip", help="Source IP address to filter")
    parser.add_argument("--dst-ip", help="Destination IP address to filter")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to capture packets")
    parser.add_argument("-db", "--database", action="store_true", help="Store captured packets in SQLite database")
    parser.add_argument("-c", "--capture", help="Capture file to save packets in pcap format")
    args = parser.parse_args()

    # Tworzenie konfiguracji na podstawie przekazanych argumentów
    config = SnifferConfig(
        interface=interface, 
        verbose=args.verbose, 
        timeout=args.timeout, 
        filter_expr=args.filter, 
        output=args.output, 
        use_db=args.database, 
        capture_file=args.capture
    )

    # Tworzenie instancji sniffera
    sniffer = PacketSniffer(config)

    # Uruchomienie sniffera w oddzielnym wątku
    sniffer_thread = threading.Thread(target=run_sniffer, args=(sniffer,))
    sniffer_thread.start()

    # Tworzenie aplikacji Flask i przekazanie sniffera
    app = create_app(sniffer)

    # Uruchomienie serwera Flask w głównym wątku
    app.run(host='0.0.0.0', port=8080, debug=True)

if __name__ == "__main__":
    main()
