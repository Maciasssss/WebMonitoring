class AlertManager {
    constructor() {
        this.alertsMap = {
            'dns_tunneling': { attacks: [], elementId: '#dns-tunneling' },
            'brute_force': { attacks: [], elementId: '#brute-force' },
            'ddos': { attacks: [], elementId: '#ddos' },
            'port_scan': { attacks: [], elementId: '#port-scan' },
            'spoofing': { attacks: [], elementId: '#spoofing' },
            'password_exfiltration': { attacks: [], elementId: '#password-exfiltration' },
            'synflood': { attacks: [], elementId: '#synflood' }
        };

        this.attachGlobalEventHandlers();  // Attach event listeners only once
    }

    displayAlerts(alerts) {
        // Combine all types of alerts into one array
        let combinedAlerts = [
            ...alerts.dns_tunneling || [],
            ...alerts.brute_force || [],
            ...alerts.ddos || [],
            ...alerts.port_scan || [],
            ...alerts.spoofing || [],
            ...alerts.password_exfiltration || [],
            ...alerts.synflood || []
        ];

        combinedAlerts.forEach(alert => {
            this.updateAlertBox(alert);
        });
    }

    updateAlertBox(alert) {
        const alertType = alert.type.replace(/\s+/g, '_').toLowerCase(); // Normalize type to match key (e.g., "Port Scan" -> "port_scan")
        const alertData = this.alertsMap[alertType];

        if (alertData) {
            // Check if an alert from this IP is already present
            let existingAttack = alertData.attacks.find(a => a.ip === alert.ip);

            if (existingAttack) {
                // If it exists, increment the counter
                existingAttack.counter++;
                this.updateAttackList(alertData, alertType);
            } else {
                // If it's a new alert from a new IP, add it to the attack list
                alert.counter = 1; // Initialize counter to 1
                alertData.attacks.push(alert);
                this.updateAttackList(alertData, alertType);
            }
        }
    }

    updateAttackList(alertData, alertType) {
        // Clear the current list
        const alertBox = $(alertData.elementId);
        const attackList = alertBox.find('.attack-list');
        attackList.empty();

        // Rebuild the list of attacks for this alert type
        alertData.attacks.forEach(attack => {
            const listItem = $(`
                <li>
                    <p><strong>IP:</strong> ${attack.ip} - <strong>Counter:</strong> ${attack.counter}</p>
                    <button class="details-button" data-type="${alertType}" data-ip="${attack.ip}">View Details</button>
                </li>
            `);
            attackList.append(listItem);
        });
    }

    attachGlobalEventHandlers() {
        // Attach a global event listener for all details-button clicks (event delegation)
        $(document).on('click', '.details-button', function() {
            const type = $(this).data('type');
            const ip = $(this).data('ip');
            
            // Find the correct alertData for the attack type
            const alertManager = window.alertManager;  // Use globally accessible instance of AlertManager
            const alertData = alertManager.alertsMap[type];
            if (alertData) {
                const attackDetails = alertData.attacks.find(a => a.ip === ip);
                if (attackDetails) {
                    displayAlertDetails(attackDetails);
                }
            }
        });
    }
}

function displayAlertDetails(alert) {
    const detailsHtml = `
        <p><strong>Type:</strong> ${alert.type}</p>
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
    $('#alertModal').show(); // Show the modal

    // Close modal logic
    $('.close').on('click', function() {
        $('#alertModal').hide();
    });

    $(window).on('click', function(event) {
        if (event.target === $('#alertModal')[0]) {
            $('#alertModal').hide();
        }
    });
}
