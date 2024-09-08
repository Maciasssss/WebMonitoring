class ModalManager {
    static displayPacketDetails(packet) {
        const detailsHtml = `
            <h3>Packet Details</h3>
            <p><strong>Source IP:</strong> ${packet.src_ip}</p>
            <p><strong>Destination IP:</strong> ${packet.dst_ip}</p>
            <!-- Add more fields as needed -->
        `;
        $('#packetDetails').html(detailsHtml);
        ModalManager.showModal('#packetModal');
    }

    static displayAlertDetails(details, alertType) {
        let detailedInfoHtml = '';
        // Custom message based on alert type
        if (alertType === 'ddos') {
            detailedInfoHtml = `<h3>DDoS Attack Details</h3> <p><strong>IP Address:</strong> ${details.ip}</p>`;
        }
        // More cases for other alert types...
        $('#alertDetails').html(detailedInfoHtml);
        ModalManager.showModal('#alertModal');
    }

    static showModal(modalId) {
        $(modalId).show();
        $('.close').click(() => $(modalId).hide());
        $(window).click(event => {
            if (event.target == $(modalId)[0]) {
                $(modalId).hide();
            }
        });
    }
}
