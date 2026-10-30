from DataBase import DataBase
import socket
import threading
from Protocol import Request, Response, Code
from ClientData import ClientData, Packets_data, ClientFile
from CryptoManager import CryptoManager
import cksum
import os
import hashlib
from pathlib import Path


DEFAULT_PORT = 1369
MIN_PORT = 1024
MAX_PORT = 65535
MAX_LISTEN = 5
VERSION = 3
MAX_BYTE_TO_RECIVE = 4096
ID_LEN = 16
REC_FILE_LEN = 279
EMPTY_PAYLOAD = 0

TIMEOUT = 300


class Server:
    def __init__(self):
        self.port = self.extract_port()
        self.database = DataBase()
        # get clients from database
        self.clients = self.database.get_all_client()
        for client in self.clients.values():
            client.client_files = self.database.get_saved_files(client.id)
        self.registration_lock = threading.Lock()  # for thread safety
        print(f"Server running on port {self.port}...")
        os.makedirs("files_received", exist_ok=True)

    # this function extract port from file port.info
    def extract_port(self):
        path = os.path.join(os.path.dirname(
            os.path.abspath(__file__)), "port.info")
        try:
            with open(path, "r") as f:
                port = int(f.read().strip())
                if not (MIN_PORT <= port <= MAX_PORT):
                    raise ValueError(f"port {port} out of range")
                return port
        except (OSError, ValueError):
            print(f"Failed to read port from {path} \
                   using default port {DEFAULT_PORT}")
            return DEFAULT_PORT

    def handle_client(self, conn, addr):
        try:
            conn.settimeout(TIMEOUT)
            while True:
                request = Request.from_socket(conn)
                if not request:
                    break
                match request.code:  # noqa: E999
                    case Code.REGISTER:
                        self.handle_register(request, conn)
                    case Code.SEND_RSA_KEY:
                        self.handle_send_rsa_key(request, conn)
                    case Code.LOGIN:
                        self.handle_login(request, conn)
                    case Code.SEND_FILE:
                        self.handle_send_file(request, conn)
                    case Code.CORRECT_CRC:
                        self.handle_correct_crc(request, conn)
                    case Code.INCORRECT_CRC:
                        pass  # wait for another try
                    case Code.INCORRECT_CRC_4:
                        self.handle_incorrect_crc_4(request, conn)
        except socket.timeout:
            print(f"Client {addr} timed out")
        except ConnectionResetError:
            print("Client disconnected")
        except Exception as e:
            print(f"Error handling client: {e}")
            try:
                self.send_general_error(conn)
            except OSError:
                pass  # client disconnected

        finally:
            conn.close()

    def start_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # listen right now on all available network interfaces need to change
        server.bind(("0.0.0.0", self.port))
        server.listen(MAX_LISTEN)
        try:
            while True:
                conn, addr = server.accept()
                t = threading.Thread(target=self.handle_client,
                                     args=(conn, addr), daemon=True)
                t.start()
                print(f"Client {addr} connected")
        except KeyboardInterrupt:
            print("Server stopped")
        finally:
            server.close()

    def handle_register(self, request, conn):
        client = ClientData(request.name, None)
        with self.registration_lock:
            name_exists = any(c.name == client.name
                              for c in self.clients.values())
            if name_exists:
                response = Response(VERSION, Code.FAIL_REGISTER,
                                    EMPTY_PAYLOAD)
            else:
                saved = self.database.insert_client(client.id,
                                                    client.name,
                                                    client.last_seen)
                if not saved:
                    response = Response(VERSION, Code.GENERAL_ERROR,
                                        EMPTY_PAYLOAD)
                else:
                    self.clients[client.id] = client
                    response = Response(VERSION, Code.SUCCESS_REGISTER,
                                        ID_LEN, client.id)
        conn.sendall(response.bytes)

    def handle_send_rsa_key(self, request, conn):
        client = self.get_client_by_id(request.id, conn)
        if not client:
            return
        client.crypto_manager = CryptoManager(request.public_key)
        encrypted_AES_key = client.crypto_manager.get_AES_key_encrypted()
        # update client keys in database with new keys
        saved = self.database.set_client_keys(client.id, request.public_key,
                                              client.crypto_manager.AES_key)
        if not saved:
            self.send_general_error(conn)
            return
        response = Response(VERSION, Code.SEND_AES_KEY,
                            ID_LEN + len(encrypted_AES_key),
                            request.id, AES_key=encrypted_AES_key)
        conn.sendall(response.bytes)
        client.update_last_seen()  # update last seen to now
        self.database.update_client_last_seen(client.id, client.last_seen)

    def handle_login(self, request, conn):
        # check if client exists
        if request.id not in self.clients:
            print("client not found " + request.id)
            conn.sendall(Response(VERSION, Code.LOGIN_FAIL,
                                  ID_LEN, request.id).bytes)
            return
        client = self.clients[request.id]
        if client.name != request.name:
            print("client not found " + request.id)
            conn.sendall(Response(VERSION, Code.LOGIN_FAIL,
                                  ID_LEN, request.id).bytes)
            return
        # check if client has key
        if client.crypto_manager is None:
            print("client not has key " + request.id)
            conn.sendall(Response(VERSION, Code.LOGIN_FAIL,
                                  ID_LEN, request.id).bytes)
            return
        # create new AES key
        encrypted_AES_key = client.crypto_manager.get_new_AES_key_encrypted()
        saved = self.database.set_client_keys(request.id,
                                              client.crypto_manager.public_key,
                                              client.crypto_manager.AES_key)
        if not saved:
            self.send_general_error(conn)
            return
        response = Response(VERSION, Code.LOGIN_SUCCESS,
                            ID_LEN + len(encrypted_AES_key),
                            request.id, AES_key=encrypted_AES_key)
        client.update_last_seen()  # update last seen to now
        self.database.update_client_last_seen(request.id, client.last_seen)
        conn.sendall(response.bytes)

    def handle_send_file(self, request, conn):
        client = self.get_client_by_id(request.id, conn)
        if not client:
            return
        # check if packet number is correct
        if not 1 <= request.packet_number <= request.total_packets:
            self.send_general_error(conn)
            client.reset_file_state()
            return
        # check if its the first packet
        if request.packet_number == 1:
            client.reset_file_state()  # to clean old data if exists
            packet_data = Packets_data(request.file_name,
                                       request.content_size,
                                       request.orig_file_size,
                                       request.total_packets)
            client.wating_file_data = packet_data
        else:  # check if packet number and file name are correct
            if not client.check_packet(request.file_name,
                                       request.packet_number,
                                       request.content_size,
                                       request.orig_file_size,
                                       request.total_packets):
                self.send_general_error(conn)
                client.reset_file_state()
                return
        client.wating_packets.append(request.packet)
        # hundle file after all packets received
        if request.total_packets == request.packet_number:
            full_data = b"".join(client.wating_packets)

            if request.content_size != len(full_data):
                self.send_general_error(conn)
                return

            # decrypt file
            try:
                original_file = client.crypto_manager.decrypt_file(full_data)
            except (ValueError, KeyError, Exception):
                self.send_general_error(conn)
                return
            if request.orig_file_size != len(original_file):
                self.send_general_error(conn)
                return
            crc = cksum.memcrc(original_file)  # culculate crc

            client_dir = (Path("files_received") / client.id).resolve()
            storage_name = hashlib.sha256(
                request.file_name.encode("ascii")).hexdigest()
            file_path = (client_dir / storage_name).resolve()
            # check if its not path injection
            if not file_path.is_relative_to(client_dir) or \
               file_path == client_dir:
                self.send_general_error(conn)
                return

            # save file data in DB
            ralative_path = os.path.relpath(file_path)
            saved = self.database.insert_file(client.id,
                                              request.file_name, ralative_path)
            if not saved:
                self.send_general_error(conn)
                return
            # send response
            conn.sendall(Response(VERSION, Code.RECEIVE_FILE, REC_FILE_LEN,
                                  request.id, request.content_size,
                                  request.file_name, crc).bytes)
            client.wating_packets.clear()
            client.decrypted_file = original_file
        else:  # wait for next packet
            client.wating_file_data.next_packet_number += 1
        # update last seen to now
        client.update_last_seen()
        self.database.update_client_last_seen(client.id, client.last_seen)

    def handle_correct_crc(self, request, conn):
        client = self.get_client_by_id(request.id, conn)
        if not client:
            return
        if client.decrypted_file is None or \
           client.wating_file_data.file_name != request.file_name:
            self.send_general_error(conn)
            return
        # save file in files_received in folder of client
        # and set file as verified in DB
        file_path = self.save_verified_file(client.id, request.file_name,
                                            client.decrypted_file)
        if not file_path:
            self.send_general_error(conn)
            return
        # save file in DB and client files
        saved = self.database.set_verified(client.id, request.file_name)
        if not saved:
            self.send_general_error(conn)
            return
        relative_path = os.path.relpath(file_path)
        client.insert_file(ClientFile(request.file_name, relative_path, True))
        client.reset_file_state()
        # send response
        response = Response(VERSION, Code.MESSAGE_RECEIVED,
                            ID_LEN, request.id)
        conn.sendall(response.bytes)
        client.update_last_seen()  # update last seen to now
        self.database.update_client_last_seen(client.id, client.last_seen)

    def handle_incorrect_crc_4(self, request, conn):
        client = self.get_client_by_id(request.id, conn)
        if not client:
            return
        client.reset_file_state()
        response = Response(VERSION, Code.MESSAGE_RECEIVED,
                            ID_LEN, request.id)
        conn.sendall(response.bytes)
        client.update_last_seen()  # update last seen to now
        self.database.update_client_last_seen(client.id, client.last_seen)

    def get_client_by_id(self, ID_hex, conn):
        if ID_hex not in self.clients:
            self.send_general_error(conn)
            return False
        return self.clients.get(ID_hex)

    def send_general_error(self, conn):
        response = Response(VERSION, Code.GENERAL_ERROR, EMPTY_PAYLOAD)
        conn.sendall(response.bytes)

    def save_verified_file(self, client_id, file_name, data):
        try:
            client_dir = (Path("files_received") / client_id).resolve()
            storage_name = hashlib.sha256(
                file_name.encode("ascii")).hexdigest()
            file_path = (client_dir / storage_name).resolve()
            # check if its not path injection
            if not file_path.is_relative_to(client_dir) or \
               file_path == client_dir:
                return None
            file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, "wb") as f:
                f.write(data)
            return file_path
        except (OSError, IOError) as e:
            print(f"Failed to write file to disk: {e}")
            return None
