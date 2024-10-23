class ModalManager {
    static displayPacketDetails(packet) {
        const detailsHtml = `
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
            <p><strong>HTTP Info:</strong> ${packet[12]}</p>
        `;
        $('#packetModal .modal-body').html(detailsHtml);
        ModalManager.showModal('#packetModal');
    }

    static displayAlertDetails(alert) {
        const displayType = alert.type.replace(/_/g, ' ');

        const detailsHtml = `
            <p><strong>Type:</strong> ${displayType}</p>
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

        $('#alertModal .modal-body').html(detailsHtml);
        ModalManager.showModal('#alertModal');
    }

    static showAlert(message, callback) {
        $('#customAlertMessage').text(message);
        ModalManager.showModal('#customAlertModal', callback, true);
    }

    static showConfirm(message, callback) {
        $('#customConfirmMessage').text(message);
        ModalManager.showModal('#customConfirmModal', callback, false, true);
    }

    static showModal(modalId, callback = null, isAlert = false, isConfirm = false) {
        $(modalId).fadeIn(200);
        $('body').css('overflow', 'hidden');

        $(modalId).find('.close').off('click.modal').on('click.modal', function() {
            ModalManager.closeModal(modalId, callback, false);
        });

        $(document).off('keydown.modal').on('keydown.modal', function(event) {
            if (event.key === "Escape") {
                ModalManager.closeModal(modalId, callback, false);
            }
        });

        $(modalId).off('click.modal').on('click.modal', function(event) {
            if ($(event.target).is(modalId)) {
                ModalManager.closeModal(modalId, callback, false);
            }
        });

        // Additional handlers for Alert and Confirm modals
        if (isAlert) {
            // OK button for Alert modal
            $('#customAlertOkButton').off('click.modal').on('click.modal', function() {
                ModalManager.closeModal(modalId, callback, true);
            });
        }

        if (isConfirm) {
            $('#customConfirmYesButton').off('click.modal').on('click.modal', function() {
                ModalManager.closeModal(modalId, callback, true, true);
            });

            $('#customConfirmNoButton').off('click.modal').on('click.modal', function() {
                ModalManager.closeModal(modalId, callback, true, false);
            });
        }
    }

    static closeModal(modalId, callback, fromButton = false, confirmResult = null) {
        $(modalId).fadeOut(200);
        $('body').css('overflow', '');
        ModalManager.removeModalEventHandlers(modalId);

        if (callback && fromButton) {
            if (confirmResult !== null) {
                callback(confirmResult); 
            } else {
                callback(); 
            }
        }
    }

    static removeModalEventHandlers(modalId) {
        // Remove event handlers to prevent duplicates
        $(modalId).find('.close').off('click.modal');
        $(document).off('keydown.modal');
        $(modalId).off('click.modal');
        $('#customAlertOkButton').off('click.modal');
        $('#customConfirmYesButton').off('click.modal');
        $('#customConfirmNoButton').off('click.modal');
    }
}
