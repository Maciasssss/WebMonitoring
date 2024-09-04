$(document).ready(function() {
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
                const tableBody = document.getElementById('packetTable').getElementsByTagName('tbody')[0];
                tableBody.innerHTML = '';  // Clear the table
                // Only keep the last 100 packets
                const displayData = data.slice(-100);
                data.forEach(packet => {
                    const row = tableBody.insertRow();
                    row.insertCell(0).innerText = packet.src_ip;
                    row.insertCell(1).innerText = packet.dst_ip;
                    row.insertCell(2).innerText = packet.src_mac;
                    row.insertCell(3).innerText = packet.dst_mac;
                    row.insertCell(4).innerText = packet.ip_version;
                    row.insertCell(5).innerText = packet.ttl;
                    row.insertCell(6).innerText = packet.checksum;
                    row.insertCell(7).innerText = packet.packet_size;
                    row.insertCell(8).innerText = packet.passing_time;
                    row.insertCell(9).innerText = packet.protocol;
                    row.insertCell(10).innerText = packet.identifier;
                    row.insertCell(11).innerText = packet.sequence;
                });
            });
    }

    function filterTable() {
        const searchInput = document.getElementById('searchInput').value.toLowerCase();
        const table = document.getElementById('packetTable');
        const rows = table.getElementsByTagName('tr');

        for (let i = 1; i < rows.length; i++) {  // Start from 1 to skip the header
            const cells = rows[i].getElementsByTagName('td');
            let rowContainsQuery = false;

            for (let j = 0; j < cells.length; j++) {
                if (cells[j]) {
                    const cellValue = cells[j].innerText.toLowerCase();
                    if (cellValue.includes(searchInput)) {
                        rowContainsQuery = true;
                        break;
                    }
                }
            }

            if (rowContainsQuery) {
                rows[i].style.display = '';  // Show the row
            } else {
                rows[i].style.display = 'none';  // Hide the row
            }
        }
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

