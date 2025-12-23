import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, DES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class RSAManager:
    @staticmethod
    def generate_keys(bits=2048):
        key = RSA.generate(bits)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key

    def __init__(self, private_key_data=None, public_key_data=None):
        self.private_key = RSA.import_key(private_key_data) if private_key_data else None
        self.public_key = RSA.import_key(public_key_data) if public_key_data else None
        self.cipher_encrypt = PKCS1_OAEP.new(self.public_key) if self.public_key else None
        self.cipher_decrypt = PKCS1_OAEP.new(self.private_key) if self.private_key else None

    def encrypt(self, data: bytes) -> bytes:
        if not self.cipher_encrypt:
            raise ValueError("Public key not loaded for encryption")
        return self.cipher_encrypt.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        if not self.cipher_decrypt:
            raise ValueError("Private key not loaded for decryption")
        return self.cipher_decrypt.decrypt(data)

    def sign(self, data: bytes) -> bytes:
        if not self.private_key:
            raise ValueError("Private key not loaded for signing")
        h = SHA256.new(data)
        return pkcs1_15.new(self.private_key).sign(h)

    def verify(self, data: bytes, signature: bytes) -> bool:
        if not self.public_key:
            raise ValueError("Public key not loaded for verification")
        h = SHA256.new(data)
        try:
            pkcs1_15.new(self.public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

class DESManager:
    def __init__(self, key: bytes):
        if len(key) != 8:
            # PRD: DES uses 56 bits usually represented as 8 bytes (64 bits with parity)
            # PyCryptodome DES requires 8 bytes key
            raise ValueError("DES key must be 8 bytes long")
        self.key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        # PRD requires DES. CBC is a safe default mode.
        cipher = DES.new(self.key, DES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(plaintext, DES.block_size))
        return cipher.iv + ct_bytes

    def decrypt(self, ciphertext: bytes) -> bytes:
        iv = ciphertext[:8]
        ct = ciphertext[8:]
        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), DES.block_size)
        return pt

    @staticmethod
    def generate_key():
        return get_random_bytes(8)
