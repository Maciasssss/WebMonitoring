#routes.py
import logging
import os
from flask import jsonify, render_template, request, redirect, send_file, url_for
from packet_sniffer import PacketSniffer, SnifferConfig
import threading
from scapy.all import sniff, get_if_list
import socket
from scapy.arch.windows import get_windows_if_list

import packet_sniffer

def configure_routes(app):
    sniffer = None
    sniffer_thread = None
    lock = threading.Lock()

    def get_sniffable_interfaces():
        """Returns a list of sniffable interfaces with names, GUIDs, and IPs."""
        sniffable_interfaces = []

        for iface in get_windows_if_list():
            try:
                friendly_name = iface['name']
                guid = iface['guid']
                ips = iface.get('ips', [])
                ip_address = None

                # Try to get an IPv4 address
                for ip in ips:
                    if '.' in ip:  # IPv4
                        ip_address = ip
                        break
                if not ip_address and ips:  # If no IPv4, get first available IP
                    ip_address = ips[0]

                # Only include interfaces with a valid IP address
                if ip_address:
                    sniffable_interfaces.append({
                        'name': friendly_name,
                        'guid': guid,
                        'ip': ip_address
                    })

            except Exception as e:
                print(f"Error processing interface {iface}: {e}")
                continue

        return sniffable_interfaces



    def get_friendly_to_guid_mapping():
        """Returns a dictionary mapping friendly interface names to GUIDs."""
        friendly_to_guid = {}

        for iface in get_windows_if_list():
            try:
                friendly_name = iface['name']
                guid = iface['guid']

                # Add to the friendly_name to GUID mapping
                friendly_to_guid[friendly_name] = guid

            except Exception as e:
                print(f"Error processing interface {iface}: {e}")
                continue

        return friendly_to_guid

    @app.route('/')
    def index():
        interfaces = get_sniffable_interfaces()
        statistics = {}
        if sniffer:
            statistics = sniffer.get_statistics()
        return render_template('index.html', interfaces=interfaces, statistics=statistics)

    @app.route('/start_sniffer', methods=['POST'])
    def start_sniffer():
        nonlocal sniffer, sniffer_thread

        # Get the selected interface (friendly name) from the form
        selected_friendly_name = request.form['interface']

        # Get the mapping of friendly names to GUIDs
        friendly_to_guid = get_friendly_to_guid_mapping()

        # Convert the selected friendly name to its corresponding GUID
        if selected_friendly_name in friendly_to_guid:
            guid = friendly_to_guid[selected_friendly_name]
            # Format the interface for Npcap
            interface_guid = f"\\Device\\NPF_{guid}"  # Proper format for Windows
        else:
            logging.error(f"Selected interface {selected_friendly_name} not found.")
            return jsonify({"error": "Selected interface not found"}), 400

        verbose = 'verbose' in request.form
        timeout = int(request.form['timeout'])

        # Handle capture file path
        capture_file = request.form.get('capture_file')

        # Ensure the captures directory exists
        capture_directory = os.path.join(os.getcwd(), "captures")
        if not os.path.exists(capture_directory):
            os.makedirs(capture_directory)
        
        if capture_file:
            capture_file_path = os.path.join(capture_directory, capture_file)  # Save to 'captures' directory
        else:
            capture_file_path = None  # No file chosen


        # Use the GUID for sniffing without filters
        config = SnifferConfig(
            interface=interface_guid,  # Pass formatted GUID for sniffing
            verbose=verbose,
            timeout=timeout,
            use_db=False,
            capture_file=capture_file_path
        )

        try:
            sniffer = PacketSniffer(config)
            sniffer_thread = threading.Thread(target=sniffer.start_sniffing)
            sniffer_thread.start()
        except Exception as e:
            logging.error(f"Error starting sniffer: {e}")
            return jsonify({"error": str(e)}), 500

        return jsonify({"status": "sniffer started"})


    @app.route('/download_capture')
    def download_capture():
        # Ensure that the capture file exists
        if sniffer and sniffer.capture_file and os.path.exists(sniffer.capture_file):
            return send_file(sniffer.capture_file, as_attachment=True)
        return jsonify({"error": "No capture file available"}), 404
    
    @app.route('/check_capture')
    def check_capture():
        """API route to check if the capture file is available for download."""
        if sniffer and sniffer.capture_file and os.path.exists(sniffer.capture_file):
            return jsonify({'capture_available': True})
        return jsonify({'capture_available': False})

    
    @app.route('/stop_sniffer', methods=['POST'])
    def stop_sniffer():
        nonlocal sniffer, sniffer_thread

        if sniffer and sniffer_thread:
            sniffer.stop_sniffing()
            sniffer_thread.join()
            sniffer = None
            sniffer_thread = None

        return redirect(url_for('index'))

    @app.route('/statistics')
    def get_statistics():
        nonlocal sniffer
        with lock:
            if sniffer:
                return jsonify(sniffer.get_statistics())
        return jsonify({})
    
    @app.route('/packets')
    def get_recent_packets():
        nonlocal sniffer
        if sniffer:
            return jsonify(sniffer.packets_info)
        return jsonify([])

    # routes.py
    @app.route('/flow_statistics')
    def get_flow_statistics():
        nonlocal sniffer
        if sniffer:
            flow_stats = sniffer.get_flow_statistics()
            return jsonify(flow_stats)
        return jsonify({"error": "No flow statistics available"}), 404


    # Assuming 'sniffer' is your PacketSniffer instance
    from flask import jsonify

    @app.route('/detector_alerts')
    def get_detector_alerts():
        try:
            # Collect alerts from your alert manager
            alerts = {
                'dns_tunneling': sniffer.alert_manager.get_alerts_by_type('dns_tunneling'),
                'brute_force': sniffer.alert_manager.get_alerts_by_type('brute_force'),
                'ddos': sniffer.alert_manager.get_alerts_by_type('ddos'),
                'port_scan': sniffer.alert_manager.get_alerts_by_type('port_scan'),
                'spoofing': sniffer.alert_manager.get_alerts_by_type('spoofing'),
                'password_exfiltration': sniffer.alert_manager.get_alerts_by_type('password_exfiltration'),
                'synflood': sniffer.alert_manager.get_alerts_by_type('synflood')
            }
            return jsonify(alerts)

        except Exception as e:
            app.logger.error(f"Error fetching detector alerts: {e}")
            return jsonify({"error": "Failed to fetch alerts"}), 500







