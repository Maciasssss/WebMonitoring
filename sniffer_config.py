class SnifferConfig:
    def __init__(self, interface, timeout, use_db, capture_file, filter_options=None):
        self.interface = interface
        self.timeout = timeout
        self.use_db = use_db
        self.capture_file = capture_file
        self.filter_options = filter_options 
