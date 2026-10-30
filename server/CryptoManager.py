from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad

AES_KEY_SIZE = 32


# this class get public key of client and encrypt AES key
# the AES key sent back to the client to provide him to send encrypted files
class CryptoManager:
    IV = b'\x00' * 16

    def __init__(self, public_key: bytes):
        self.public_key = public_key
        self.RSA = RSA.import_key(public_key)
        self.AES_key = get_random_bytes(AES_KEY_SIZE)

    def get_AES_key_encrypted(self):
        return PKCS1_OAEP.new(self.RSA).encrypt(self.AES_key)

    # generate new AES key for login
    def get_new_AES_key_encrypted(self):
        self.AES_key = get_random_bytes(AES_KEY_SIZE)
        return PKCS1_OAEP.new(self.RSA).encrypt(self.AES_key)

    def set_AES_key(self, encrypted_AES_key: bytes):
        self.AES_key = encrypted_AES_key

# decrypte file from client with AES key
    def decrypt_file(self, encrypted_file: bytes):
        chipher = AES.new(self.AES_key, AES.MODE_CBC, self.IV)
        decrypted_file = chipher.decrypt(encrypted_file)
        return unpad(decrypted_file, AES.block_size)
