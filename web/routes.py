from flask import jsonify, render_template, request, send_file, redirect, url_for
from .sniffer_services import SnifferService
import logging

def configure_routes(app):
    sniffer_service = SnifferService()

    @app.route('/')
    def index():
        interfaces = SnifferService.get_sniffable_interfaces()
        statistics = {}
        return render_template('index.html', interfaces=interfaces, statistics=statistics)

    @app.route('/start_sniffer', methods=['POST'])
    def start_sniffer():
        selected_friendly_name = request.form['interface']
        friendly_to_guid = SnifferService.get_friendly_to_guid_mapping()

        if selected_friendly_name in friendly_to_guid:
            interface_guid = f"\\Device\\NPF_{friendly_to_guid[selected_friendly_name]}"
        else:
            logging.error(f"Selected interface {selected_friendly_name} not found.")
            return jsonify({"error": "Selected interface not found"}), 400

        verbose = 'verbose' in request.form
        timeout = int(request.form['timeout'])
        capture_file = request.form.get('capture_file')

        try:
            sniffer_service.start_sniffer(interface_guid, verbose, timeout, capture_file)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

        return jsonify({"status": "sniffer started"})

    @app.route('/stop_sniffer', methods=['POST'])
    def stop_sniffer():
        sniffer_service.stop_sniffer()
        return redirect(url_for('index'))

    @app.route('/statistics')
    def get_statistics():
        return jsonify(sniffer_service.get_statistics())

    @app.route('/packets')
    def get_recent_packets():
        return jsonify(sniffer_service.get_packets())

    @app.route('/flow_statistics')
    def get_flow_statistics():
        stats = sniffer_service.get_flow_statistics()
        if stats:
            return jsonify(stats)
        return jsonify({"error": "No flow statistics available"}), 404

    @app.route('/detector_alerts')
    def get_detector_alerts():
        alerts = sniffer_service.get_detector_alerts()
        if alerts is not None:
            return jsonify(alerts)
        return jsonify({"error": "Failed to fetch alerts"}), 500

    @app.route('/download_capture')
    def download_capture():
        capture_file = sniffer_service.get_capture_file()
        if capture_file:
            return send_file(capture_file, as_attachment=True)
        return jsonify({"error": "No capture file available"}), 404

    @app.route('/check_capture')
    def check_capture():
        capture_available = sniffer_service.get_capture_file() is not None
        return jsonify({'capture_available': capture_available})
