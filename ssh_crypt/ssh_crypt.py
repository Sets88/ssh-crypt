import sys
import random
import base64
import argparse
import binascii

from io import BytesIO
from typing import Union
from typing import Optional
from hashlib import sha3_256
from secrets import token_bytes
from collections import deque

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from paramiko import Agent
from paramiko import AgentKey
from paramiko.ssh_exception import SSHException
from paramiko.agent import cSSH2_AGENTC_REQUEST_IDENTITIES, SSH2_AGENT_IDENTITIES_ANSWER

NONCE_LENGTH = 64
VALID_SSH_NAME = ["ssh-rsa", "ssh-ed25519"]


def get_keys():
    agent = Agent()
    ptype, result = agent._send_message(cSSH2_AGENTC_REQUEST_IDENTITIES)
    if ptype != SSH2_AGENT_IDENTITIES_ANSWER:
        raise SSHException("could not get keys from ssh-agent")
    keys = []
    for i in range(result.get_int()):
        key_blob = result.get_binary()
        key_comment = result.get_string()
        keys.append((AgentKey(agent, key_blob), key_comment))
    return keys


def get_first_key():
    # Only RSA and ED25519 keys have capability to get the same sign data from same nonce
    keys = get_keys()
    keys = [key for key in keys if key[0].name in VALID_SSH_NAME]
    if keys:
        return keys[0][0]


def find_filter_key(ssh_filter):
    ssh_filter = ssh_filter.encode()
    filter_keys = []
    for key in [key for key in get_keys() if key[0].name in VALID_SSH_NAME]:
        if ssh_filter in key[1]:
            filter_keys.append(key)
        elif ssh_filter in binascii.hexlify(key[0].get_fingerprint(), sep=":"):
            filter_keys.append(key)
    if filter_keys:
        return filter_keys[0][0]


class EncryptingCipher():
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
            self.buf.extend(self.cipher.update(self.padder.finalize()) + self.cipher.finalize())
        else:
            padded = self.padder.update(data)
            self.buf.extend(self.cipher.update(padded))

        data = bytes(self.buf)
        self.buf.clear()
        return data


class DecryptingCipher():
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
            self.configure_cipher(bytes([self.buf.popleft() for _i in range(self.block_size)]))

        if not data:
            decrypted = self.cipher.update(bytes(self.buf)) + self.cipher.finalize()

            unpadded = b''

            if decrypted:
                unpadded = self.unpadder.update(unpadded)

            unpadded = unpadded + self.unpadder.finalize()
            return unpadded

        decrypted = self.cipher.update(bytes(self.buf))
        self.buf.clear()
        unpadded = self.unpadder.update(decrypted)
        return unpadded


class Encryptor():
    def __init__(self, ssh_key: AgentKey, binary):
        if ssh_key.name not in VALID_SSH_NAME:
            raise ValueError("Incompatible Key Material (Only RSA or ED25519 is Supported")
        self.nonce = self.generate_nonce()
        self.buf = deque()
        self.binary = binary
        self.buf.extend(self.nonce + b':')
        self.encoder = EncryptingCipher(self.get_encryption_key(ssh_key))

    def get_encryption_key(self, ssh_key: AgentKey) -> bytes:
        return sha3_256(ssh_key.sign_ssh_data(self.nonce)).digest()

    def generate_nonce(self) -> bytes:
        return base64.b85encode(random.getrandbits(NONCE_LENGTH).to_bytes(int(NONCE_LENGTH / 8), 'big'))

    def send(self, data: bytes) -> bytes:
        data = self.encoder.encode(data)

        if not self.binary:
            data = base64.b85encode(data)

        self.buf.extend(data)
        data = bytes(self.buf)
        self.buf.clear()
        return data


class Decryptor():
    def __init__(self, ssh_key: AgentKey, binary):
        if ssh_key.name not in VALID_SSH_NAME:
            raise ValueError("Incompatible Key Material (Only RSA or ED25519 is Supported")
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
            if int.from_bytes(b':', 'big') in self.buf:
                nonce = bytes(self.buf).split(b':')[0]
                [self.buf.popleft() for _i in range(len(nonce) + 1)]
                self.init_decoder(nonce)
            if not self.buf:
                return ''

        if not self.decoder:
            sys.stderr.write('Unable to decrypt data')
            exit(2)

        if not self.binary:
            b85block_size = len(self.buf) - (len(self.buf) % 5)
            data = base64.b85decode(bytes([self.buf.popleft() for _i in range(b85block_size)]))
        else:
            data = bytes(self.buf)
            self.buf.clear()

        data = self.decoder.decode(data)
        return data


class Processor():
    def __init__(
            self,
            ssh_key: AgentKey,
            processor: Union[Encryptor, Decryptor],
            input_file: Optional[str],
            output_file: Optional[str],
            string_data: Optional[str],
            binary: Optional[bool] = False
    ):
        try:
            self.processor = processor(ssh_key, binary)
        except ValueError as err:
            sys.stderr.write('%s\n' % err)
            exit(1)
        self.input = sys.stdin.buffer
        if string_data:
            self.input = BytesIO(string_data.encode('utf-8'))
        if input_file:
            self.input = open(input_file, 'rb')
        self.output = sys.stdout.buffer
        if output_file:
            self.output = open(output_file, 'wb')

    def run(self) -> None:
        while True:
            data = self.input.read(4096)

            if not data:
                break

            chunk = self.processor.send(data)
            if chunk:
                self.output.write(chunk)
            if len(data) < 4096:
                break

        self.output.write(self.processor.send(b''))
        self.output.flush()


class E():
    def __init__(self, data: Union[str, bytes], binary=False):
        if isinstance(data, str):
            data = data.encode('utf-8')
        self.data = data

    def __bytes__(self) -> bytes:
        ssh_key = get_first_key()

        decryptor = Decryptor(ssh_key, binary=False)
        return decryptor.send(self.data) + decryptor.send(b'')

    def __str__(self) -> str:
        return self.__bytes__().decode('utf-8')


def main() -> None:
    ssh_key = get_first_key()
    if not ssh_key:
        sys.stderr.write('SSH key not found\n')
        exit(1)

    parser = argparse.ArgumentParser(description='Encrypting/Decrypting data using key from ssh-agent')
    parser.add_argument('--encrypt', '-e', dest='processor', action='store_const',
                        const=Encryptor, default=Encryptor,
                        help='Encrypt incomming data(default)')

    parser.add_argument('--decrypt', '-d', dest='processor', action='store_const',
                        const=Decryptor, default=None,
                        help='Decrypt incomming data')

    parser.add_argument('--input', '-i', nargs='?', help='input file')

    parser.add_argument('--output', '-o', nargs='?', help='output file')

    parser.add_argument('--string', '-s', nargs='?', help='input string')

    # List all keys fingerprints in md5
    # # ssh-add -l -E md5
    # 2048 MD5:12:34:56:78:90:ab:cd:ef:01:23:34:56:78:90:12:34 Public key for PIV Authentication (RSA)
    # --key '12:34:56:78:90:ab:cd:ef:01:23:34:56:78:90:12:34'
    parser.add_argument('--key', '-k', nargs='?', help='Key Filter')

    parser.add_argument('--binary', '-b', action='store_true', default=False, help='encrypt into binary data')

    args = parser.parse_args()
    if args.key:
        ssh_key = find_filter_key(args.key)
        if not ssh_key:
            sys.stderr.write('SSH key not found\n')
            exit(1)
    Processor(
        ssh_key,
        args.processor,
        args.input,
        args.output,
        args.string,
        args.binary
    ).run()


if __name__ == '__main__':
    main()
