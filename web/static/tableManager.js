class TableManager {
    constructor(tableId, columns) {
        this.table = $(tableId).DataTable({
            columns: columns,
            pageLength: 10,
            responsive: true
        });
    }

    updateTable(data, rowMapper) {
        this.table.clear();
        data.forEach(item => {
            const rowData = rowMapper(item);
            this.table.row.add(rowData).draw(false);
        });
    }
}

class PacketTableManager extends TableManager {
    constructor() {
        super('#packetTable', [
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
        ]);
       
    }

    populatePackets(packets) {
        this.updateTable(packets.slice(-100), packet => [
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
        ]);
         // Attach click event to rows after data is populated
        $('#packetTable tbody').off('click').on('click', 'tr', (event) => {
            const rowData = this.table.row(event.currentTarget).data();
            console.log("Row clicked:", rowData); // Log row data when clicked

            if (rowData) {
                ModalManager.displayPacketDetails(rowData); // Pass packet data to modal
            } else {
                console.error("No row data available for this row.");
            }
        });
    }
}
class StatisticsTableManager extends TableManager {
    constructor() {
        super('#statisticsTable', [
            { title: "Total Packets" },
            { title: "Echo Request Count" },
            { title: "Echo Reply Count" },
            { title: "ARP Count" },
            { title: "TCP Count" },
            { title: "UDP Count" },
            { title: "HTTP Count" },
            { title: "DNS Count" },
            { title: "ICMP Count" },
            { title: "IP Count" },
            { title: "IPv6 Count" },
            { title: "Total Bytes Sent" },
            { title: "Total Bytes Received" }
        ]);
    }

    populateStatistics(stats) {
        this.updateTable([stats], stat => [
            stat.total_packets || 'N/A',
            stat.echo_request_count || 'N/A',
            stat.echo_reply_count || 'N/A',
            stat.arp_count || 'N/A',
            stat.tcp_count || 'N/A',
            stat.udp_count || 'N/A',
            stat.http_count || 'N/A',
            stat.dns_count || 'N/A',
            stat.icmp_count || 'N/A',
            stat.ip_count || 'N/A',
            stat.ipv6_count || 'N/A',
            stat.total_bytes_sent || 'N/A',
            stat.total_bytes_received || 'N/A'
        ]);
    }
}

class FlowStatisticsTableManager extends TableManager {
    constructor() {
        super('#flowStatisticsTable', [
            { title: "Flow" },
            { title: "Throughput (B/s)" },
            { title: "Packet Delay (ms)" },
            { title: "Jitter (ms)" },
            { title: "Packet Loss (%)" },
            { title: "RTT (ms)" },
            { title: "TTL" },
            { title: "Bandwidth Utilization (%)" }
        ]);
    }

    populateFlowStatistics(flowStats) {
        this.updateTable(Object.keys(flowStats), flow => [
            flow,
            flowStats[flow].throughput.toFixed(2),
            flowStats[flow].packet_delay.toFixed(2),
            flowStats[flow].jitter.toFixed(2),
            flowStats[flow].packet_loss.toFixed(2),
            flowStats[flow].rtt.toFixed(2),
            flowStats[flow].ttl,
            flowStats[flow].bandwidth_utilization.toFixed(2)
        ]);
    }
}
