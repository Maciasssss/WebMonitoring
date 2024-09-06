# alert_manager.py

import datetime


class AlertManager:
    def __init__(self):
        self.alerts = []

    def add_alert(self, ip, details, alert_type):
        self.alerts.append({"ip": ip, "details": details, "type": alert_type})

    def get_alerts_by_type(self, alert_type):
        return [alert for alert in self.alerts if alert["type"] == alert_type]

    def clear_alerts(self):
        self.alerts.clear()


    