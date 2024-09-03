import logging
import os
from flask import jsonify, render_template, request, redirect, url_for
from packet_sniffer import PacketSniffer, SnifferConfig
import threading
from scapy.all import sniff, get_if_list

def configure_routes(app):
    sniffer = None
    sniffer_thread = None
    lock = threading.Lock()

    @app.route('/')
    def index():
        interfaces = get_if_list()
        statistics = {}
        if sniffer:
            statistics = sniffer.get_statistics()
        return render_template('index.html', interfaces=interfaces, statistics=statistics)

    @app.route('/start_sniffer', methods=['POST'])
    def start_sniffer():
        nonlocal sniffer, sniffer_thread

        interface = request.form['interface']
        verbose = 'verbose' in request.form
        timeout = int(request.form['timeout'])
        filter_expr = request.form['filter']
        capture_file = request.form.get('capture_file')

        if capture_file and os.path.exists(capture_file):
            os.remove(capture_file)  # Remove existing capture file to avoid appending

        config = SnifferConfig(
            interface=interface,
            verbose=verbose,
            timeout=timeout,
            filter_expr=filter_expr,
            output=None,
            use_db=False,
            capture_file=capture_file
        )

        try:
            sniffer = PacketSniffer(config)
            sniffer_thread = threading.Thread(target=sniffer.start_sniffing)
            sniffer_thread.start()
        except Exception as e:
            logging.error(f"Error starting sniffer: {e}")
            return jsonify({"error": str(e)}), 500

        return redirect(url_for('index'))

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
