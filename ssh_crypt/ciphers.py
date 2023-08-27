import sys
import random
import base64
from abc import ABC
from hashlib import sha3_256
from secrets import token_bytes
from collections import deque

from paramiko import AgentKey
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend

from .constants import VALID_SSH_NAME
from .constants import NONCE_LENGTH


class ProcessorsAbc(ABC):
    pass


class EncryptingCipher:
    def __init__(self, key: bytes):
        self.buf = deque()
        self.algorithm = algorithms.AES

        self.block_size = int(self.algorithm.block_size / 8)
        iv = token_bytes(self.block_size)
        self.cipher = self._get_cipher(key, iv).encryptor()
        self.padder = PKCS7(self.block_size * 8).padder()
        self.buf.extend(self.padder.update(iv))

    def _get_cipher(self, key: bytes, iv: bytes) -> Cipher:
        return Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    def encode(self, data: bytes) -> bytes:
        if not data:
            self.buf.extend(
                self.cipher.update(self.padder.finalize()) + self.cipher.finalize()
            )
        else:
            padded = self.padder.update(data)
            self.buf.extend(self.cipher.update(padded))

        data = bytes(self.buf)
        self.buf.clear()
        return data


class DecryptingCipher:
    def __init__(self, key: bytes):
        self.buf = deque()
        self.key = key
        self.algorithm = algorithms.AES
        self.block_size = int(self.algorithm.block_size / 8)
        self.unpadder = PKCS7(self.block_size * 8).unpadder()
        self.cipher = None

    def configure_cipher(self, iv: bytes) -> None:
        self.cipher = self._get_cipher(self.key, iv).decryptor()

    def _get_cipher(self, key: bytes, iv: bytes) -> Cipher:
        return Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    def decode(self, data: bytes) -> bytes:
        self.buf.extend(data)
        if self.cipher is None and len(self.buf) >= self.block_size:
            self.configure_cipher(
                bytes([self.buf.popleft() for _i in range(self.block_size)])
            )

        if not data:
            decrypted = self.cipher.update(bytes(self.buf)) + self.cipher.finalize()

            unpadded = b""

            if decrypted:
                unpadded = self.unpadder.update(unpadded)

            unpadded = unpadded + self.unpadder.finalize()
            return unpadded

        decrypted = self.cipher.update(bytes(self.buf))
        self.buf.clear()
        unpadded = self.unpadder.update(decrypted)
        return unpadded


class Encryptor(ProcessorsAbc):
    def __init__(self, ssh_key: AgentKey, binary):
        if ssh_key.name not in VALID_SSH_NAME:
            raise ValueError(
                "Incompatible Key Material (Only RSA or ED25519 is Supported"
            )
        self.nonce = self.generate_nonce()
        self.buf = deque()
        self.binary = binary
        self.buf.extend(self.nonce + b":")
        self.encoder = EncryptingCipher(self.get_encryption_key(ssh_key))

    def get_encryption_key(self, ssh_key: AgentKey) -> bytes:
        return sha3_256(ssh_key.sign_ssh_data(self.nonce)).digest()

    def generate_nonce(self) -> bytes:
        return base64.b85encode(
            random.getrandbits(NONCE_LENGTH).to_bytes(int(NONCE_LENGTH / 8), "big")
        )

    def send(self, data: bytes) -> bytes:
        data = self.encoder.encode(data)

        if not self.binary:
            data = base64.b85encode(data)

        self.buf.extend(data)
        data = bytes(self.buf)
        self.buf.clear()
        return data


class Decryptor(ProcessorsAbc):
    def __init__(self, ssh_key: AgentKey, binary):
        if ssh_key.name not in VALID_SSH_NAME:
            raise ValueError(
                "Incompatible Key Material (Only RSA or ED25519 is Supported"
            )
        self.ssh_key = ssh_key
        self.decoder = None
        self.buf = deque()
        self.binary = binary

    def get_encryption_key(self, nonce: bytes) -> bytes:
        return sha3_256(self.ssh_key.sign_ssh_data(nonce)).digest()

    def init_decoder(self, nonce: bytes) -> None:
        self.decoder = DecryptingCipher(self.get_encryption_key(nonce))

    def send(self, data: bytes) -> bytes:
        self.buf.extend(data)

        if self.decoder is None:
            if int.from_bytes(b":", "big") in self.buf:
                nonce = bytes(self.buf).split(b":")[0]
                [self.buf.popleft() for _i in range(len(nonce) + 1)]
                self.init_decoder(nonce)
            if not self.buf:
                return b""

        if not self.decoder:
            sys.stderr.write("Unable to decrypt data")
            exit(2)

        if not self.binary:
            b85block_size = len(self.buf) - (len(self.buf) % 5)
            data = base64.b85decode(
                bytes([self.buf.popleft() for _i in range(b85block_size)])
            )
        else:
            data = bytes(self.buf)
            self.buf.clear()

        data = self.decoder.decode(data)
        return data
