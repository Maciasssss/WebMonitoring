class SnifferConfig:
    def __init__(self, interface, verbose, timeout, use_db, capture_file):
        self.interface = interface
        self.verbose = verbose
        self.timeout = timeout
        self.use_db = use_db
        self.capture_file = capture_file
