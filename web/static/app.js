$(document).ready(function() {
    function fetchStatistics() {
        $.get('/statistics', function(stats) {
            console.log("Received statistics:", stats);
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
        });
    }

    // Fetch statistics every 5 seconds
    fetchStatistics();
    setInterval(fetchStatistics, 5000);  // Adjust the interval as needed
});
