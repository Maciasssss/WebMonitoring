$(document).ready(function() {
    let captureStarted = false;  // Flag to prevent multiple starts
    const packetTable = $('#packetTable').DataTable();  // Initialize DataTable

    // Function to fetch statistics
    function fetchStatistics() {
        $.get('/statistics', function(stats) {
            if (stats) {
                $('#statistics').html(`
                    <p>Total Packets: ${stats.total_packets}</p>
                    <p>Echo Request Packets: ${stats.echo_request_count}</p>
                    <p>Echo Reply Packets: ${stats.echo_reply_count}</p>
                    <p>ARP Packets: ${stats.arp_count}</p>
                    <p>TCP Packets: ${stats.tcp_count}</p>
                    <p>UDP Packets: ${stats.udp_count}</p>
                    <p>HTTP Packets: ${stats.http_count}</p>
                    <p>ICMP Packets: ${stats.icmp_count}</p>
                    <p>DNS Packets: ${stats.dns_count}</p>
                    <p>IP Packets: ${stats.ip_count}</p>
                    <p>IPv6 Packets: ${stats.ipv6_count}</p>
                    <p>Total Bytes Sent: ${stats.total_bytes_sent} bytes</p>
                    <p>Total Bytes Received: ${stats.total_bytes_received} bytes</p>
                `);
            } else {
                $('#statistics').html(`<p>No data available.</p>`);
            }
        }).fail(function(jqXHR, textStatus, errorThrown) {
            $('#statistics').html(`<p>Error communicating with the server.</p>`);
        });
    }

    // Function to fetch packets
    function fetchPackets() {
        fetch('/packets')
            .then(response => response.json())
            .then(data => {
                packetTable.clear();  // Clear the table before adding new rows

                data.slice(-1000).forEach(packet => {
                    const rowNode = packetTable.row.add([
                        packet.src_ip || 'N/A',
                        packet.dst_ip || 'N/A',
                        packet.src_mac || 'N/A',
                        packet.dst_mac || 'N/A',
                        packet.ip_version || 'N/A',
                        packet.ttl || 'N/A',
                        packet.checksum || 'N/A',
                        packet.packet_size || 'N/A',
                        packet.passing_time || 'N/A',
                        packet.protocol || 'N/A',
                        packet.identifier || 'N/A',
                        packet.sequence || 'N/A'
                    ]).draw(false).node();

                    $(rowNode).data('packetDetails', packet);
                });

                $('#packetTable tbody').on('click', 'tr', function() {
                    const packetDetails = $(this).data('packetDetails');
                    if (packetDetails) {
                        displayPacketDetails(packetDetails);
                    }
                });
            });
    }

    // Function to display packet details in modal
    function displayPacketDetails(packet) {
        const detailsHtml = `
            <h3>Packet Details</h3>
            <p><strong>Source IP:</strong> ${packet.src_ip}</p>
            <p><strong>Destination IP:</strong> ${packet.dst_ip}</p>
            <p><strong>Source MAC:</strong> ${packet.src_mac}</p>
            <p><strong>Destination MAC:</strong> ${packet.dst_mac}</p>
            <p><strong>IP Version:</strong> ${packet.ip_version}</p>
            <p><strong>TTL:</strong> ${packet.ttl}</p>
            <p><strong>Checksum:</strong> ${packet.checksum}</p>
            <p><strong>Packet Size:</strong> ${packet.packet_size}</p>
            <p><strong>Passing Time:</strong> ${packet.passing_time}</p>
            <p><strong>Protocol:</strong> ${packet.protocol}</p>
            <p><strong>Identifier:</strong> ${packet.identifier}</p>
            <p><strong>Sequence:</strong> ${packet.sequence}</p>
        `;

        $('#packetDetails').html(detailsHtml);
        $('#packetModal').show();
    }

    // Function to check capture file availability and show the download button
    function checkCaptureStatus() {
        fetch('/check_capture')
            .then(response => response.json())
            .then(data => {
                if (data.capture_available) {
                    $('#downloadContainer').show();
                }
            });
    }

    // Form submission via AJAX
    $('#startCaptureForm').submit(function(event) {
        event.preventDefault();  // Prevent the form from submitting normally

        if (!captureStarted) {
            captureStarted = true;  // Prevent multiple submissions

            const formData = $(this).serialize();  // Get form data

            // Send the form data via AJAX to start the sniffer
            $.post('/start_sniffer', formData)
                .done(function() {
                    // Inform the user that the sniffer has started
                    alert("Packet sniffer started!");

                    // Start polling for statistics and packets after the sniffer starts
                    setInterval(fetchStatistics, 500);
                    setInterval(fetchPackets, 500);
                    setInterval(checkCaptureStatus, 5000);
                })
                .fail(function() {
                    alert('Failed to start the sniffer.');
                });
        }
    });
});
