$(document).ready(function() {
    const packetTable = $('#packetTable').DataTable();
    function fetchStatistics() {
        $.get('/statistics', function(stats) {
            console.log("Received statistics:", stats);
            if (stats) {
                $('#statistics').html(`
                    <p>Total Packets: ${stats.total_packets}</p>
                    <p>Echo Request Packets: ${stats.echo_request_count}</p>
                    <p>Echo Reply Packets: ${stats.echo_reply_count}</p>
                    <p>ARP Packets: ${stats.arp_count}</p>
                    <p>TCP Packets: ${stats.tcp_count}</p>
                    <p>UDP Packets: ${stats.udp_count}</p>
                    <p>HTTP Packets: ${stats.http_count}</p>
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
            console.error("Error communicating with the server:", textStatus, errorThrown);
            $('#statistics').html(`<p>Error communicating with the server.</p>`);
        });
    }

    function fetchPackets() {
        fetch('/packets')
            .then(response => response.json())
            .then(data => {
                packetTable.clear();  // Clear the table before adding new rows

                // Loop through packets and add them to the table
                data.slice(-100).forEach(packet => {
                    packetTable.row.add([
                        packet.src_ip,
                        packet.dst_ip,
                        packet.src_mac,
                        packet.dst_mac,
                        packet.ip_version,
                        packet.ttl,
                        packet.checksum,
                        packet.packet_size,
                        packet.passing_time,
                        packet.protocol,
                        packet.identifier,
                        packet.sequence
                    ]).draw(false);
                });
            });
    }

    // Function to display the download button if the capture file is available
    function checkCaptureStatus() {
        fetch('/check_capture')
            .then(response => response.json())
            .then(data => {
                if (data.capture_available) {
                    document.getElementById('downloadContainer').style.display = 'block';
                }
            });
    }
    // Poll for capture file availability every 5 seconds
    setInterval(checkCaptureStatus, 5000);

    // Fetch statistics every 5 seconds
    fetchStatistics();
    setInterval(fetchStatistics, 1000);  // Adjust the interval as needed

    // Fetch packets every second
    fetchPackets();
    setInterval(fetchPackets, 1000);
});

