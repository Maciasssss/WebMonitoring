import threading
import argparse
from packet_sniffer import PacketSniffer
from web import app, socketio

def run_flask():
    """Uruchamia serwer Flask z SocketIO w debug mode."""
    socketio.run(app, debug=True)

def run_sniffer(interface, verbose, timeout, filter_expr, output, use_db, capture_file):
    """Konfiguruje i uruchamia sniffer pakietów."""
    sniffer = PacketSniffer(interface, verbose, timeout, filter_expr, output, use_db, capture_file)
    sniffer.start_sniffing()
    sniffer.print_statistics()

def main():
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

    # Uruchomienie serwera Flask w oddzielnym wątku
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.start()

    # Uruchomienie sniffera w głównym wątku
    run_sniffer(args.interface, args.verbose, args.timeout, args.filter, args.output, args.database, args.capture)

if __name__ == "__main__":
    main()
