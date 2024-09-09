class ModalManager {
    static displayPacketDetails(packet) {
        console.log(packet); // This will show the row data as an array

        // Update to access array elements based on their indices
        const detailsHtml = `
            <h3>Packet Details</h3>
            <p><strong>Source IP:</strong> ${packet[0]}</p>
            <p><strong>Destination IP:</strong> ${packet[1]}</p>
            <p><strong>Source MAC:</strong> ${packet[2]}</p>
            <p><strong>Destination MAC:</strong> ${packet[3]}</p>
            <p><strong>IP Version:</strong> ${packet[4]}</p>
            <p><strong>TTL:</strong> ${packet[5]}</p>
            <p><strong>Checksum:</strong> ${packet[6]}</p>
            <p><strong>Packet Size:</strong> ${packet[7]}</p>
            <p><strong>Passing Time:</strong> ${packet[8]}</p>
            <p><strong>Protocol:</strong> ${packet[9]}</p>
            <p><strong>Identifier:</strong> ${packet[10]}</p>
            <p><strong>Sequence:</strong> ${packet[11]}</p>
        `;
        $('#packetDetails').html(detailsHtml);
        ModalManager.showModal('#packetModal');
    }
     // Method to display alert details in the modal
     static displayAlertDetails(alert) {
        const displayType = alert.type.replace(/_/g, ' ');

        const detailsHtml = `
            <p><strong>Type:</strong> ${displayType}</p>  <!-- Show transformed type -->
            <p><strong>IP Address:</strong> ${alert.ip}</p>
            <p><strong>Details:</strong> ${alert.details || 'N/A'}</p>
            <p><strong>Timestamp:</strong> ${alert.timestamp || 'N/A'}</p>
            <hr>
            <h4>Advanced Information</h4>
            <p><strong>Severity:</strong> ${alert.severity || 'N/A'}</p>
            <p><strong>Port:</strong> ${alert.port || 'N/A'}</p>
            <p><strong>Protocol:</strong> ${alert.protocol || 'N/A'}</p>
            <h4>Possible Fixes</h4>
            <p>${alert.possible_fixes || 'N/A'}</p>
        `;

        $('#alertDetails').html(detailsHtml);
        ModalManager.showModal('#alertModal');
    }
    
    static showModal(modalId, content) {
        $(modalId).find('.modal-content').html(content);
        $(modalId).show();
        $('.close').on('click', function() {
            $(modalId).hide();
        });
        $(window).on('click', function(event) {
            if (event.target === $(modalId)[0]) {
                $(modalId).hide();
            }
        });
    }
}

