class AlertManager {
    constructor() {
        this.alertsMap = {
            'DNS_Tunneling': { attacks: [], currentIndex: 0, elementId: '#dns-tunneling' },
            'Brute_Force_Login': { attacks: [], currentIndex: 0, elementId: '#brute-force' },
            'DDoS_Attack': { attacks: [], currentIndex: 0, elementId: '#ddos' },
            'Port_Scan': { attacks: [], currentIndex: 0, elementId: '#port-scan' },
            'Spoofing': { attacks: [], currentIndex: 0, elementId: '#spoofing' },
            'Password_Exfiltration': { attacks: [], currentIndex: 0, elementId: '#password-exfiltration' },
            'SYN_Flood': { attacks: [], currentIndex: 0, elementId: '#synflood' }
        };

        this.attachGlobalEventHandlers();
    }

    displayAlerts(alerts) {
        let combinedAlerts = [
            ...alerts.DNS_Tunneling || [],
            ...alerts.Brute_Force_Login || [],
            ...alerts.DDoS_Attack || [],
            ...alerts.Port_Scan || [],
            ...alerts.Spoofing || [],
            ...alerts.Password_Exfiltration || [],
            ...alerts.SYN_Flood || []
        ];

        combinedAlerts.forEach(alert => {
            this.updateAlertBox(alert);
        });
    }

    updateAlertBox(alert) {
        const alertType = alert.type;
        const alertData = this.alertsMap[alertType];

        if (alertData) {
            let existingAttack = alertData.attacks.find(a => a.ip === alert.ip);

            // Ensure the alert contains all necessary fields
            alert.severity = alert.severity || 'N/A';
            alert.port = alert.port || 'N/A';
            alert.protocol = alert.protocol || 'N/A';
            alert.possible_fixes = alert.possible_fixes || 'N/A';

            if (existingAttack) {
                existingAttack.counter++;
                this.updateAlertCounter(existingAttack, alertType);
            } else {
                alert.counter = 1; // Initialize counter if it's a new attack
                alertData.attacks.push(alert);
                if (alertData.attacks.length === 1) {
                    this.showCurrentAlert(alertType);  // Show the alert if it's the first one
                }
            }
        }
    }

    showCurrentAlert(alertType) {
        const alertData = this.alertsMap[alertType];
        const alertBox = $(alertData.elementId);
        const attackList = alertBox.find('.attack-list');
        const currentIndex = alertData.currentIndex;

        if (alertData.attacks.length > 0) {
            // Get the current alert to display
            const currentAttack = alertData.attacks[currentIndex];
            attackList.empty(); // Ensure only one alert is shown

            const listItem = $(`
                <li>
                    <p><strong>IP:</strong> ${currentAttack.ip} - <strong class="alert-counter">Counter:</strong> ${currentAttack.counter}</p>
                    <p><strong>Severity:</strong> ${currentAttack.severity}</p>
                    <button class="details-button" data-type="${alertType}" data-ip="${currentAttack.ip}">View Details</button>
                    <button class="previous-alert-button" data-type="${alertType}"><- Previous</button>
                    <button class="next-alert-button" data-type="${alertType}">Next -></button>
                </li>
            `);
            attackList.append(listItem);
        } else {
            attackList.empty();
        }
    }

    updateAlertCounter(attack, alertType) {
        const alertData = this.alertsMap[alertType];
        const alertBox = $(alertData.elementId);
        const currentAttackIndex = alertData.currentIndex;

        // Only update the counter for the currently displayed alert
        if (alertData.attacks[currentAttackIndex].ip === attack.ip) {
            const attackList = alertBox.find('.attack-list');
            const counterElement = attackList.find('.alert-counter');
            counterElement.text(`Counter: ${attack.counter}`);
        }
    }

    attachGlobalEventHandlers() {
        // View details handler
        $(document).on('click', '.details-button', function() {
            const type = $(this).data('type');
            const ip = $(this).data('ip');

            const alertManager = window.alertManager;
            const alertData = alertManager.alertsMap[type];
            if (alertData) {
                const attackDetails = alertData.attacks.find(a => a.ip === ip);
                if (attackDetails) {
                    ModalManager.displayAlertDetails(attackDetails);
                }
            }
        });

        // Next alert handler
        $(document).on('click', '.next-alert-button', function() {
            const type = $(this).data('type');
            const alertManager = window.alertManager;
            const alertData = alertManager.alertsMap[type];

            if (alertData) {
                // Increment the index and wrap around if needed
                alertData.currentIndex = (alertData.currentIndex + 1) % alertData.attacks.length;
                alertManager.showCurrentAlert(type);
            }
        });

        // Previous alert handler
        $(document).on('click', '.previous-alert-button', function() {
            const type = $(this).data('type');
            const alertManager = window.alertManager;
            const alertData = alertManager.alertsMap[type];

            if (alertData) {
                // Decrement the index and wrap around if needed
                alertData.currentIndex = (alertData.currentIndex - 1 + alertData.attacks.length) % alertData.attacks.length;
                alertManager.showCurrentAlert(type);
            }
        });
    }
}
