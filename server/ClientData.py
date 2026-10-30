import uuid
from datetime import datetime


class ClientData:
    def __init__(self, name,  id=None, last_seen=None):
        self.name = name
        self.crypto_manager = None
        self.last_seen = last_seen or datetime.now()
        if id is None:  # register
            self.id = uuid.uuid4().hex  # generate id string
        else:  # login
            self.id = id
        self.wating_packets = []
        self.decrypted_file = None  # decrypted file that waiting for crc check
        self.client_files = []  # list of ClientFile that client has
        self.wating_file_data = None  # Packets_data that client is waiting for

    def update_last_seen(self):
        self.last_seen = datetime.now()

# reset file state after
    def reset_file_state(self):
        self.wating_packets.clear()
        self.decrypted_file = None
        self.wating_file_data = None

    def check_packet(self, file_name, packet_number, content_size,
                     orig_file_size, total_packets):
        if self.wating_file_data is None:
            return False
        if self.wating_file_data.file_name != file_name:
            return False
        if self.wating_file_data.content_size != content_size:
            return False
        if self.wating_file_data.orig_file_size != orig_file_size:
            return False
        if self.wating_file_data.total_packets != total_packets:
            return False
        if self.wating_file_data.next_packet_number != packet_number:
            return False
        return True

    def insert_file(self, file):
        found = False
        for f in self.client_files:
            if f == file:
                f.verify = file.verify
                f.path = file.path
                found = True
                break
        if not found:
            self.client_files.append(file)


class Packets_data:
    def __init__(self, file_name, content_size,
                 orig_file_size, total_packets):
        self.file_name = file_name
        self.content_size = content_size
        self.orig_file_size = orig_file_size
        self.total_packets = total_packets

        self.next_packet_number = 1
        self.crc = False


class ClientFile:
    def __init__(self, file_name, path, verified=False):
        self.file_name = file_name
        self.path = path
        self.verify = verified

    def __eq__(self, other):
        return self.file_name == other.file_name
