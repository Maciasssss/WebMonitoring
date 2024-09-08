class AlertManager {
    constructor(maxAlertsDisplayed) {
        this.maxAlertsDisplayed = maxAlertsDisplayed || 5;
        this.alertSections = {
            dnsTunneling: $('#dnsTunnelingAlerts'),
            bruteForce: $('#bruteForceAlerts'),
            ddos: $('#ddosAlerts'),
            portScan: $('#portScanAlerts'),
            spoofing: $('#spoofingAlerts'),
            passwordExfiltration: $('#passwordExfiltrationAlerts'),
            synflood: $('#synfloodAlerts')
        };
    }

    displayAlerts(type, alerts) {
        const alertSection = this.alertSections[type];
        if (alerts && alerts.length > 0) {
            alertSection.empty();
            alerts.slice(0, this.maxAlertsDisplayed).forEach(alert => {
                const listItem = `<li><a href="#" class="alert-link" data-alert='${JSON.stringify(alert)}'>${alert.details} detected from ${alert.ip}</a></li>`;
                alertSection.append(listItem);
            });
        }
    }

    clearAlerts() {
        Object.values(this.alertSections).forEach(section => section.empty());
    }
}
