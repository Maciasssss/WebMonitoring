class AlertManager {
    constructor() {
        this.alertsMap = {
            'DNS_Tunneling': { attacks: [], elementId: '#dns-tunneling' },
            'Brute_Force_Login': { attacks: [], elementId: '#brute-force' },
            'DDoS_Attack': { attacks: [], elementId: '#ddos' },
            'Port_Scan': { attacks: [], elementId: '#port-scan' },
            'Spoofing': { attacks: [], elementId: '#spoofing' },
            'Password_Exfiltration': { attacks: [], elementId: '#password-exfiltration' },
            'SYN_Flood': { attacks: [], elementId: '#synflood' }
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
        const alertType = alert.type
        const alertData = this.alertsMap[alertType];
    
        if (alertData) {
            let existingAttack = alertData.attacks.find(a => a.ip === alert.ip);
    
            // Make sure the alert contains all necessary fields
            alert.severity = alert.severity || 'N/A';
            alert.port = alert.port || 'N/A';
            alert.protocol = alert.protocol || 'N/A';
            alert.possible_fixes = alert.possible_fixes || 'N/A';
    
            if (existingAttack) {
                existingAttack.counter++;
                this.updateAttackList(alertData, alertType);
            } else {
                alert.counter = 1; // Initialize counter if it's a new attack
                alertData.attacks.push(alert);
                this.updateAttackList(alertData, alertType);
            }
        }
    }
    

    updateAttackList(alertData, alertType) {
        const alertBox = $(alertData.elementId);
        const attackList = alertBox.find('.attack-list');
        attackList.empty();

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
    }
}
