$(document).ready(function() {
    let captureStarted = false;  // Flag to prevent multiple starts
    const MAX_ALERTS_DISPLAYED = 5;
    let totalAlertCount = 0;

    const packetTable = $('#packetTable').DataTable({
        columns: [
            { title: "Source IP" },
            { title: "Destination IP" },
            { title: "Source MAC" },
            { title: "Destination MAC" },
            { title: "IP Version" },
            { title: "TTL" },
            { title: "Checksum" },
            { title: "Packet Size (bytes)" },
            { title: "Passing Time" },
            { title: "Protocol" },
            { title: "Identifier" },
            { title: "Sequence" }
        ],
        pageLength: 10,  // Adjust the number of rows displayed per page
        responsive: true  // Make it responsive
    });  // Initialize DataTable
    const flowStatisticsTable = $('#flowStatisticsTable').DataTable({
        pageLength: 10,  // Adjust the number of rows displayed per page
        responsive: true  // Make it responsive
    });
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
                    // Ensure all required columns have data, or use 'N/A' as a fallback
                    const rowNode = packetTable.row.add([
                        packet.src_ip || 'N/A',
                        packet.dst_ip || 'N/A',
                        packet.src_mac || 'N/A',
                        packet.dst_mac || 'N/A',
                        packet.ip_version || 'N/A',
                        packet.ttl || 'N/A',
                        packet.checksum || 'N/A',  // Ensure checksum is available
                        packet.packet_size || 'N/A',
                        packet.passing_time || 'N/A',
                        packet.protocol || 'N/A',
                        packet.identifier || 'N/A',
                        packet.sequence || 'N/A'
                    ]).draw(false).node();
    
                    // Store detailed packet info in the row for later access
                    $(rowNode).data('packetDetails', packet);
                });
    
                // Add click event to display detailed packet info
                $('#packetTable tbody').on('click', 'tr', function() {
                    const packetDetails = $(this).data('packetDetails');
                    if (packetDetails) {
                        displayPacketDetails(packetDetails);
                    }
                });
            });
    }

    function displayPacketDetails(packet) {
        // Build the modal content including the advanced details
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
    
            <!-- Add Advanced Fields -->
            <hr>
            <h4>Advanced Details</h4>
            <p><strong>ICMP Type:</strong> ${packet.icmp_type || 'N/A'}</p>
            <p><strong>ICMP Code:</strong> ${packet.icmp_code || 'N/A'}</p>
            <p><strong>HTTP Method:</strong> ${packet.http_method || 'N/A'}</p>
            <p><strong>Flow Label:</strong> ${packet.flow_label || 'N/A'}</p>
            <p><strong>Traffic Class:</strong> ${packet.traffic_class || 'N/A'}</p>
            <p><strong>Hop Limit:</strong> ${packet.hop_limit || 'N/A'}</p>
            <p><strong>Next Header:</strong> ${packet.next_header || 'N/A'}</p>
            <p><strong>Fragment Offset:</strong> ${packet.fragment_offset || 'N/A'}</p>
            <p><strong>Flags:</strong> ${packet.flags || 'N/A'}</p>
        `;
    
        $('#packetDetails').html(detailsHtml);
    
        // Display the modal
        const modal = document.getElementById("packetModal");
        modal.style.display = "block";
    
        // Close modal logic
        const span = document.getElementsByClassName("close")[0];
        span.onclick = function() {
            modal.style.display = "none";
        }
    
        window.onclick = function(event) {
            if (event.target == modal) {
                modal.style.display = "none";
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
    // Fetch flow statistics and filter based on the user's input
    function fetchFlowStatistics() {
        $.get('/flow_statistics', function(flow_stats) {
            // Clear the flow statistics table
            flowStatisticsTable.clear();

            for (let flow in flow_stats) {
                const flowData = flow_stats[flow];
                flowStatisticsTable.row.add([
                    flow,
                    flowData.throughput.toFixed(2),             // Throughput in B/s
                    flowData.packet_delay.toFixed(2),           // Packet delay in ms
                    flowData.jitter.toFixed(2),                 // Jitter in ms
                    flowData.packet_loss.toFixed(2),            // Packet loss in percentage
                    flowData.rtt.toFixed(2),                    // Round Trip Time (RTT) in ms
                    flowData.ttl,                               // Time To Live (TTL)
                    flowData.bandwidth_utilization.toFixed(2)   // Bandwidth utilization in percentage
                ]);
            }

            flowStatisticsTable.draw(false);  // Redraw the table with the updated data
        });
    }

    

    // Handle user input in the IP filter field
    $('#flowIpFilter').on('input', function() {
        fetchFlowStatistics();  // Re-fetch flow statistics when the input changes
    });
    

    function fetchDetectorAlerts() {
        $.get('/detector_alerts', function (alerts) {
            try {
                // Ensure alerts data is available
                if (!alerts) throw new Error("No alerts data received");

                // Clear previous alerts
                clearAllAlerts();

                let alertCounts = {
                    dnsTunneling: alerts.dns_tunneling ? alerts.dns_tunneling.length : 0,
                    bruteForce: alerts.brute_force ? alerts.brute_force.length : 0,
                    ddos: alerts.ddos ? alerts.ddos.length : 0,
                    portScan: alerts.port_scan ? alerts.port_scan.length : 0,
                    spoofing: alerts.spoofing ? alerts.spoofing.length : 0,
                    passwordExfiltration: alerts.password_exfiltration ? alerts.password_exfiltration.length : 0,
                    synflood: alerts.synflood ? alerts.synflood.length : 0
                };

                updateNotificationCounts(alertCounts);

                // Display the alerts (capping at MAX_ALERTS_DISPLAYED per type)
                displayAlerts('dnsTunneling', alerts.dns_tunneling);
                displayAlerts('bruteForce', alerts.brute_force);
                displayAlerts('ddos', alerts.ddos);
                displayAlerts('portScan', alerts.port_scan);
                displayAlerts('spoofing', alerts.spoofing);
                displayAlerts('passwordExfiltration', alerts.password_exfiltration);
                displayAlerts('synflood', alerts.synflood);

                // Attach modal click event to show detailed info
                $('.alert-link').on('click', function (event) {
                    event.preventDefault();
                    const alertDetails = $(this).data('alert');
                    displayAlertModal(alertDetails); // Show alert in modal
                });

            } catch (error) {
                console.error("Error processing alerts:", error.message);
            }
        }).fail(function (jqXHR, textStatus, errorThrown) {
            console.error("Error fetching alerts:", textStatus, errorThrown);
        });
    }

    // Function to clear all alert sections before repopulating
    function clearAllAlerts() {
        $('#dnsTunnelingAlerts').empty();
        $('#bruteForceAlerts').empty();
        $('#ddosAlerts').empty();
        $('#portScanAlerts').empty();
        $('#spoofingAlerts').empty();
        $('#passwordExfiltrationAlerts').empty();
        $('#synfloodAlerts').empty();
    }

    // Function to display alerts with a maximum limit and show red flag icon
    function displayAlerts(type, alerts) {
        const alertSection = $('#' + type + 'Alerts');
        const alertFlag = $('#' + type + 'Flag');
        const alertCountBadge = $('#' + type + 'Count');

        if (alerts && alerts.length > 0) {
            alertFlag.removeClass('hidden'); // Show red flag icon
            alertCountBadge.text(alerts.length); // Update alert count

            alerts.slice(0, MAX_ALERTS_DISPLAYED).forEach(alert => {
                const listItem = `<li><a href="#" class="alert-link" data-alert="${alert.details}">${alert.details} </a></li>`;
                alertSection.append(listItem);
            });
        } else {
            alertFlag.addClass('hidden'); // Hide red flag icon
            alertCountBadge.text('0'); // Reset alert count
        }
    }

    // Update total notification counts
    function updateNotificationCounts(counts) {
        // Update total alert count
        totalAlertCount = Object.values(counts).reduce((sum, count) => sum + count, 0);
        $('#totalAlertCount').text(totalAlertCount);
    }

    // Function to display the alert modal with more details
    function displayAlertModal(details) {
        const detailsHtml = `
            <h3>Alert Details</h3>
            <p>${details}</p>
        `;
        $('#alertDetails').html(detailsHtml); // Insert the details into the modal content

        // Show the modal
        const modal = document.getElementById("alertModal");
        modal.style.display = "block";

        // Close modal when clicking the "X" button
        const span = document.getElementsByClassName("close")[0];
        span.onclick = function () {
            modal.style.display = "none";
        }

        // Close the modal if the user clicks anywhere outside the modal
        window.onclick = function (event) {
            if (event.target == modal) {
                modal.style.display = "none";
            }
        }
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
                    setInterval(fetchDetectorAlerts, 1000);
                    setInterval(fetchStatistics, 1000);
                    setInterval(fetchFlowStatistics, 1000);
                    setInterval(fetchPackets, 1000);
                    setInterval(checkCaptureStatus, 5000);
                })
                .fail(function() {
                    alert('Failed to start the sniffer.');
                });
        }
    });

});




