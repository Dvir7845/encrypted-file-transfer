import sqlite3
from ClientData import ClientData, ClientFile
from CryptoManager import CryptoManager
import threading

COL_ID = 0
COL_NAME = 1
COL_PUBKEY = 2
COL_LASTSEEN = 3
COL_AESKEY = 4


COL_FILE_NAME = 1
COL_PATH_NAME = 2
COL_VERIFIED = 3


class DataBase:
    def __init__(self):
        self.db_name = "defensive.db"
        self.conn = sqlite3.connect(self.db_name, check_same_thread=False)
        self.lock = threading.Lock()  # for thread safety
        # create tables of clients and files if they don't exist
        with self.lock:
            self.conn.execute("""CREATE TABLE IF NOT EXISTS clients (
                             ID BLOB PRIMARY KEY NOT NULL
                             CHECK (length(ID) = 16),
                             Name TEXT NOT NULL ,
                             PublicKey BLOB ,
                             LastSeen DATETIME NOT NULL,
                             AESKey BLOB)""")

            self.conn.execute("""CREATE TABLE IF NOT EXISTS files(
                             ID BLOB  NOT NULL CHECK (length(ID) = 16),
                             FileName TEXT NOT NULL
                             CHECK (length(FileName)<=255),
                             PathName TEXT NOT NULL
                             CHECK (length(PathName)<=255),
                             verified BOOLEAN NOT NULL
                             CHECK(verified IN(0, 1)),
                             PRIMARY KEY (ID, FileName))""")

            self.conn.commit()

# this function inserts a client to the database
    def insert_client(self, ID_hex, Name, LastSeen):
        query = """INSERT INTO clients (ID, Name, LastSeen)
                 VALUES (?,?,?)"""
        try:
            ID = bytes.fromhex(ID_hex)
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute(query, (ID, Name, LastSeen))

                self.conn.commit()
            return True
        except sqlite3.IntegrityError as e:
            print(f"Error inserting client: {e}")
            return False  # client already exists

    # this function updates the last seen of a client
    def update_client_last_seen(self, ID_hex, LastSeen):
        try:
            ID = bytes.fromhex(ID_hex)
            query = """UPDATE clients SET LastSeen = ? WHERE ID = ?"""
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute(query, (LastSeen, ID))
                self.conn.commit()
        except sqlite3.IntegrityError as e:
            print(f"Error updating client last seen: {e}")

# this function updates the keys of a client
    def set_client_keys(self, ID_hex, PublicKey, AESKey):
        try:
            ID = bytes.fromhex(ID_hex)
            query = """UPDATE clients SET PublicKey = ?, AESKey = ?
                       WHERE ID = ?"""
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute(query, (PublicKey, AESKey, ID))
                self.conn.commit()
                return True
        except sqlite3.IntegrityError as e:
            print(f"Error updating client keys: {e}")
            return False

# this function inserts a file
# if the file already exists it will be updated
    def insert_file(self, ID_hex, FileName, PathName, verified=False):
        query = """INSERT OR REPLACE INTO files (ID, FileName,
                                                 PathName, verified)
                 VALUES (?,?,?,?)"""
        try:
            ID = bytes.fromhex(ID_hex)
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute(query, (ID, FileName, PathName,
                                       1 if verified else 0))
                self.conn.commit()
            return True
        except sqlite3.IntegrityError as e:
            print(f"Error inserting file: {e}")
            return False

# this function sets a file as verified after crc check
    def set_verified(self, ID_hex, FileName):
        try:
            ID = bytes.fromhex(ID_hex)
            query = """UPDATE files SET verified = 1 WHERE ID = ? AND
                                                           FileName = ?"""
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute(query, (ID, FileName))
                self.conn.commit()
                return cursor.rowcount == 1
        except sqlite3.IntegrityError as e:
            print(f"Error updating file: {e}")
            return False

# this function returns a dictionary of all clients
    def get_all_client(self):
        query = """SELECT * FROM clients """
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute(query)
            rows = cursor.fetchall()
        clients = {}
        for row in rows:
            hex_id = row[COL_ID].hex()
            name = row[COL_NAME]
            public_key = row[COL_PUBKEY]
            last_seen = row[COL_LASTSEEN]
            AES_Key = row[COL_AESKEY]
            client = ClientData(name, hex_id, last_seen)
            # set crypto manager of client
            if public_key:
                client.crypto_manager = CryptoManager(public_key)
                if AES_Key:
                    client.crypto_manager.set_AES_key(AES_Key)
            clients[hex_id] = client
        return clients

    def get_saved_files(self, ID_hex):
        query = """SELECT * FROM files WHERE ID = ?"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute(query, (bytes.fromhex(ID_hex),))
            rows = cursor.fetchall()
        files = []
        for row in rows:
            file_name = row[COL_FILE_NAME]
            path_name = row[COL_PATH_NAME]
            verified = row[COL_VERIFIED]
            files.append(ClientFile(file_name, path_name, verified))
        return files
