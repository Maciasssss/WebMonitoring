import sqlite3

class Database:

    def __init__(self, dbname="packets.db"):
        self.conn = sqlite3.connect(dbname)
        self.cursor = self.conn.cursor()
        self.create_table()

    def create_table(self):
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS packets
            (timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_mac TEXT,
            dst_mac TEXT,
            ip_version TEXT,
            ttl TEXT,
            checksum TEXT,
            packet_size TEXT,
            protocol_str TEXT,
            identifier TEXT,
            sequence TEXT,
            payload_hex TEXT,
            payload_content TEXT
        )''')
        self.conn.commit()

    def insert_packet(self, packet_data):
        query = '''INSERT INTO packets (timestamp, src_ip, dst_ip, src_mac, dst_mac, ip_version, ttl, checksum, 
                   packet_size, protocol_str, identifier, sequence, payload_hex, payload_content)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'''
        self.cursor.execute(query, packet_data)
        self.conn.commit()
    
    def fetch_all_packets(self):
        self.cursor.execute("SELECT * FROM packets")
        return self.cursor.fetchall()

    def close(self):
        self.conn.close()
