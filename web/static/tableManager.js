class TableManager {
    constructor(tableId, columns) {
        this.tableElement = $(tableId);
        this.columns = columns;
        this.table = this.tableElement.DataTable({
            columns: columns.map(col => ({ title: col.title })),
            pageLength: 10,
            responsive: true,
            autoWidth: false,
            language: {
                paginate: {
                    next: '&raquo;', // » symbol
                    previous: '&laquo;' // « symbol
                },
                search: "_INPUT_",
                searchPlaceholder: "Search..."
            },
            headerCallback: (thead, data, start, end, display) => {
                $(thead).find('th').each((index, th) => {
                    const tooltip = this.columns[index].tooltip;
                    if (tooltip) {
                        $(th).attr('title', tooltip);
                    }
                });
            }
        });
    }

    updateTable(data, rowMapper) {
        this.table.clear();
        data.forEach(item => {
            const rowData = rowMapper(item);
            this.table.row.add(rowData);
        });
        this.table.draw(false);

        // Add data-title attributes for responsive design
        this.addDataTitles();
    }

    addDataTitles() {
        const headers = this.columns.map(col => col.title);
        this.tableElement.find('tbody tr').each((index, row) => {
            $(row).find('td').each((i, cell) => {
                $(cell).attr('data-title', headers[i]);
            });
        });
    }

    updateTable(data, rowMapper) {
        this.table.clear();
        data.forEach(item => {
            const rowData = rowMapper(item);
            this.table.row.add(rowData);
        });
        this.table.draw(false);

        this.addDataTitles();
    }

    addDataTitles() {
        const headers = this.columns.map(col => col.title);
        this.tableElement.find('tbody tr').each((index, row) => {
            $(row).find('td').each((i, cell) => {
                $(cell).attr('data-title', headers[i]);
            });
        });
    }
}


class PacketTableManager extends TableManager {
    constructor() {
        super('#packetTable', [
            { title: "Source IP", tooltip: "The source IP address of the packet" },
            { title: "Destination IP", tooltip: "The destination IP address of the packet" },
            { title: "Source MAC", tooltip: "The source MAC address of the packet" },
            { title: "Destination MAC", tooltip: "The destination MAC address of the packet" },
            { title: "IP Version", tooltip: "The IP protocol version (IPv4 or IPv6)" },
            { title: "TTL", tooltip: "Time To Live of the packet" },
            { title: "Checksum", tooltip: "Checksum value of the packet" },
            { title: "Packet Size (bytes)", tooltip: "Size of the packet in bytes" },
            { title: "Passing Time", tooltip: "The time when the packet was captured" },
            { title: "Protocol", tooltip: "The protocol used (TCP, UDP, etc.)" },
            { title: "Identifier", tooltip: "Identifier field from the IP header" },
            { title: "Sequence", tooltip: "Sequence number of the packet" }
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

        $('#packetTable tbody').off('click').on('click', 'tr', (event) => {
            const rowData = this.table.row(event.currentTarget).data();

            if (rowData) {
                ModalManager.displayPacketDetails(rowData); 
            } else {
                console.error("No row data available for this row.");
            }
        });
    }
}

class StatisticsTableManager extends TableManager {
    constructor() {
        super('#statisticsTable', [
            { title: "Total Packets", tooltip: "Total number of packets captured" },
            { title: "Echo Request Count", tooltip: "Number of ICMP Echo Request packets" },
            { title: "Echo Reply Count", tooltip: "Number of ICMP Echo Reply packets" },
            { title: "ARP Count", tooltip: "Number of ARP packets" },
            { title: "TCP Count", tooltip: "Number of TCP packets" },
            { title: "UDP Count", tooltip: "Number of UDP packets" },
            { title: "HTTP Count", tooltip: "Number of HTTP packets" },
            { title: "DNS Count", tooltip: "Number of DNS packets" },
            { title: "ICMP Count", tooltip: "Number of ICMP packets" },
            { title: "IP Count", tooltip: "Number of IP packets" },
            { title: "IPv6 Count", tooltip: "Number of IPv6 packets" },
            { title: "Total Bytes Sent", tooltip: "Total bytes sent from the source" },
            { title: "Total Bytes Received", tooltip: "Total bytes received at the destination" }
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
            { title: "Flow", tooltip: "Source and Destination IPs and Ports" },
            { title: "Throughput (B/s)", tooltip: "Amount of data transferred per second" },
            { title: "Packet Delay (ms)", tooltip: "Average time delay of packets" },
            { title: "Jitter (ms)", tooltip: "Variation in packet delay" },
            { title: "Packet Loss (%)", tooltip: "Percentage of packets lost during transmission" },
            { title: "RTT (ms)", tooltip: "Round Trip Time of packets" },
            { title: "TTL", tooltip: "Time To Live value indicating packet lifespan" },
            { title: "Bandwidth Utilization (%)", tooltip: "Percentage of bandwidth used by the flow" }
        ]);
    }

    getStatValue(stat, defaultValue = '0.00', isFixed = true) {
        return stat !== undefined ? (isFixed ? stat.toFixed(2) : stat) : defaultValue;
    }

    populateFlowStatistics(flowStats) {
        this.updateTable(Object.keys(flowStats), flow => [
            flow,
            this.getStatValue(flowStats[flow].throughput),
            this.getStatValue(flowStats[flow].packet_delay),
            this.getStatValue(flowStats[flow].jitter),
            this.getStatValue(flowStats[flow].packet_loss),
            this.getStatValue(flowStats[flow].rtt),
            this.getStatValue(flowStats[flow].ttl, 'N/A', false),
            this.getStatValue(flowStats[flow].bandwidth_utilization)
        ]);
    }
}


