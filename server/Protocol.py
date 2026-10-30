import struct
import io


class Code:
    # Protocol codes from client to server
    REGISTER = 825
    SEND_RSA_KEY = 826
    LOGIN = 827
    SEND_FILE = 828
    CORRECT_CRC = 900
    INCORRECT_CRC = 901
    INCORRECT_CRC_4 = 902

    # Protocol codes from server to client
    SUCCESS_REGISTER = 1600
    FAIL_REGISTER = 1601
    SEND_AES_KEY = 1602
    RECEIVE_FILE = 1603
    MESSAGE_RECEIVED = 1604
    LOGIN_SUCCESS = 1605
    LOGIN_FAIL = 1606
    GENERAL_ERROR = 1607


# length of data
ID_LEN = 16
VERSION_LEN = 1
CODE_LEN = 2
SIZE_LEN = 4
NAME_LEN = 255
KEY_LEN = 160
HEADER_SIZE = 23
FILE_META_HEADER_LEN = 12


# Receive exactly n bytes from a socket
def recv_exact(conn, n):
    data = bytearray()
    while len(data) < n:
        read = conn.recv(n - len(data))
        if not read:
            return None
        data.extend(read)
    return bytes(data)


# parse request
# header :
# id : 16 bytes
# version : 1 byte
# code : 2 bytes
# size : 4 bytes
#
# payload :
# name/filename : 255 bytes
# key : 160 bytes
# content_size : 4 bytes
# orig_file_size : 4 bytes
# packet_number : 2 bytes
# total_packets : 2 bytes
class Request:
    def __init__(self, data: bytes):
        # read header
        if len(data) < HEADER_SIZE:
            raise ValueError(f"data too short for header, len :{len(data)}")
        stream = io.BytesIO(data)
        self.id = stream.read(ID_LEN).hex()
        self.version = int.from_bytes(stream.read(1),
                                      byteorder='little')
        self.code = int.from_bytes(stream.read(2),
                                   byteorder='little')
        self.size = int.from_bytes(stream.read(4),
                                   byteorder='little')
        # read payload
        if not self.check_length(len(data)-HEADER_SIZE):
            raise ValueError(f"data too short for payload ,len :{len(data)}")
        match self.code:  # noqa: E999
            case Code.REGISTER:
                self.name = stream.read(
                    NAME_LEN).split(b'\x00')[0].decode('ascii')
            case Code.SEND_RSA_KEY:
                self.name = stream.read(
                    NAME_LEN).split(b'\x00')[0].decode('ascii')
                self.public_key = stream.read(KEY_LEN)
            case Code.LOGIN:
                self.name = stream.read(
                    NAME_LEN).split(b'\x00')[0].decode('ascii')
            case Code.SEND_FILE:
                self.content_size = int.from_bytes(stream.read(4),
                                                   byteorder='little')
                self.orig_file_size = int.from_bytes(stream.read(4),
                                                     byteorder='little')
                self.packet_number = int.from_bytes(stream.read(2),
                                                    byteorder='little')
                self.total_packets = int.from_bytes(stream.read(2),
                                                    byteorder='little')
                self.file_name = stream.read(
                    NAME_LEN).split(b'\x00')[0].decode('ascii')
                self.packet = stream.read(self.size - FILE_META_HEADER_LEN
                                          - NAME_LEN)
            case Code.CORRECT_CRC:
                self.file_name = stream.read(
                    NAME_LEN).split(b'\x00')[0].decode('ascii')
            case Code.INCORRECT_CRC:
                self.file_name = stream.read(
                    NAME_LEN).split(b'\x00')[0].decode('ascii')
            case Code.INCORRECT_CRC_4:
                self.file_name = stream.read(
                    NAME_LEN).split(b'\x00')[0].decode('ascii')

    def check_length(self, len_payload):
        if len_payload != self.size:
            return False
        if self.code == Code.SEND_RSA_KEY:
            return NAME_LEN + KEY_LEN == len_payload
        if self.code == Code.SEND_FILE:
            return FILE_META_HEADER_LEN + NAME_LEN < len_payload
        if self.code in (Code.REGISTER, Code.LOGIN, Code.CORRECT_CRC,
                         Code.INCORRECT_CRC, Code.INCORRECT_CRC_4):
            return NAME_LEN == len_payload
        return False  # unknown code

    @classmethod
    def from_socket(cls, conn):
        header = recv_exact(conn, HEADER_SIZE)
        if not header:
            return None  # Connection closed

        offset_payload = ID_LEN + VERSION_LEN + CODE_LEN
        payload_size = int.from_bytes(header[offset_payload:
                                             offset_payload+SIZE_LEN],
                                      byteorder='little')
        payload = b""
        if payload_size > 0:
            payload = recv_exact(conn, payload_size)
            if payload is None:
                return None
        return cls(header + payload)


class Response:
    def __init__(
            self,
            version: int,
            code: int,
            size: int,
            id: str = None,
            content_size: int = None,
            file_name: str = None,
            Cksum: int = None,
            AES_key: bytes = None):
        # create header
        self.bytes = struct.pack('<BHI', version, code, size)
        # create payload
        match code:
            case Code.SUCCESS_REGISTER:
                self.bytes += bytes.fromhex(id)
            case Code.FAIL_REGISTER:
                # no payload
                pass
            case Code.SEND_AES_KEY:
                self.bytes += bytes.fromhex(id)
                self.bytes += AES_key
            case Code.RECEIVE_FILE:
                self.bytes += bytes.fromhex(id)
                self.bytes += struct.pack('<I', content_size)
                self.bytes += file_name.encode(
                              'ascii')[:NAME_LEN].ljust(NAME_LEN, b'\x00')
                self.bytes += struct.pack('<I', Cksum)
            case Code.MESSAGE_RECEIVED:
                self.bytes += bytes.fromhex(id)
            case Code.LOGIN_SUCCESS:
                self.bytes += bytes.fromhex(id)
                self.bytes += AES_key
            case Code.LOGIN_FAIL:
                self.bytes += bytes.fromhex(id)
            case Code.GENERAL_ERROR:
                # no payload
                pass
