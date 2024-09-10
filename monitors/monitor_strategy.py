class MonitorStrategy:
    def monitor_traffic(self, packet):
        raise NotImplementedError
        pass
    def get_metric(self, flow_key):
        raise NotImplementedError
