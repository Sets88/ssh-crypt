import pytest

import types
import tempfile
import random
import string
import binascii

from paramiko import AgentKey, Message
from paramiko.rsakey import RSAKey
from paramiko.dsskey import DSSKey
from paramiko.ecdsakey import ECDSAKey

from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import Encoding

from ssh_crypt.ssh_crypt import Processor
from ssh_crypt.ciphers import Decryptor, Encryptor
from ssh_crypt.utils import get_keys, get_first_key, find_filter_key, E, encrypt

SSH2_AGENTC_ADD_IDENTITY = 17
SSH_AGENT_SUCCESS = 6


def rsa_to_agent(self, ssh_agent, comment="TEST_RSA_KEY"):
    msg = Message()
    numbers = self.key.private_numbers()
    msg.add_byte(bytes([SSH2_AGENTC_ADD_IDENTITY]))
    msg.add_string(self.get_name())
    msg.add_mpint(numbers.public_numbers.n)
    msg.add_mpint(numbers.public_numbers.e)
    msg.add_mpint(numbers.d)
    msg.add_mpint(0)
    msg.add_mpint(numbers.p)
    msg.add_mpint(numbers.q)
    msg.add_string(comment)
    response = ssh_agent._send_message(msg)[0]
    ssh_agent._connect(ssh_agent._conn)
    return response


def dss_to_agent(self, ssh_agent, comment="TEST_DSS_KEY"):
    msg = Message()
    msg.add_byte(bytes([SSH2_AGENTC_ADD_IDENTITY]))
    msg.add_string(self.get_name())
    msg.add_mpint(self.p)
    msg.add_mpint(self.q)
    msg.add_mpint(self.g)
    msg.add_mpint(self.y)
    msg.add_mpint(self.x)
    msg.add_string(comment)
    response = ssh_agent._send_message(msg)[0]
    ssh_agent._connect(ssh_agent._conn)
    return response


def ecdsa_to_agent(self, ssh_agent, comment="TEST_ECDSA_KEY"):
    msg = Message()
    msg.add_byte(bytes([SSH2_AGENTC_ADD_IDENTITY]))
    msg.add_string(self.get_name())
    msg.add_string(self.ecdsa_curve.nist_name)
    msg.add_string(
        self.signing_key.public_key().public_bytes(
            encoding=Encoding.X962, format=PublicFormat.UncompressedPoint
        )
    )
    msg.add_mpint(self.signing_key.private_numbers().private_value)
    msg.add_string(comment)
    response = ssh_agent._send_message(msg)[0]
    ssh_agent._connect(ssh_agent._conn)
    return response


@pytest.fixture
def rsa_key():
    key = RSAKey.generate(bits=1024)
    key.add_to_agent = types.MethodType(rsa_to_agent, key)
    yield key


@pytest.fixture
def dss_key():
    key = DSSKey.generate(bits=1024)
    key.add_to_agent = types.MethodType(dss_to_agent, key)
    yield key


@pytest.fixture
def ecdsa_key():
    key = ECDSAKey.generate(bits=256)
    key.add_to_agent = types.MethodType(ecdsa_to_agent, key)
    yield key


@pytest.fixture
def rsa_in_agent(ssh_agent, rsa_key):
    assert rsa_key.add_to_agent(ssh_agent) == SSH_AGENT_SUCCESS
    yield AgentKey(ssh_agent, rsa_key.asbytes())


@pytest.fixture
def dss_in_agent(ssh_agent, dss_key):
    assert dss_key.add_to_agent(ssh_agent) == SSH_AGENT_SUCCESS
    yield AgentKey(ssh_agent, dss_key.asbytes())


@pytest.fixture
def ecdsa_in_agent(ssh_agent, ecdsa_key):
    assert ecdsa_key.add_to_agent(ssh_agent) == SSH_AGENT_SUCCESS
    yield AgentKey(ssh_agent, ecdsa_key.asbytes())


def test_start_agent(ssh_agent):
    assert len(ssh_agent.get_keys()) == 0


def test_rsa_in_agent(ssh_agent, rsa_key):
    assert len(ssh_agent.get_keys()) == 0
    assert rsa_key.add_to_agent(ssh_agent) == SSH_AGENT_SUCCESS
    assert rsa_key.get_fingerprint() == ssh_agent.get_keys()[0].get_fingerprint()


def test_dss_in_agent(ssh_agent, dss_key):
    assert len(ssh_agent.get_keys()) == 0
    assert dss_key.add_to_agent(ssh_agent) == SSH_AGENT_SUCCESS
    assert dss_key.get_fingerprint() == ssh_agent.get_keys()[0].get_fingerprint()


def test_ecdsa_in_agent(ssh_agent, ecdsa_key):
    assert len(ssh_agent.get_keys()) == 0
    assert ecdsa_key.add_to_agent(ssh_agent) == SSH_AGENT_SUCCESS
    assert ecdsa_key.get_fingerprint() == ssh_agent.get_keys()[0].get_fingerprint()


def test_encrypt_rsa(rsa_in_agent):
    processor = Encryptor(rsa_in_agent, False)
    data = processor.send(b"test_string")
    assert len(data) > 0


def test_encrypt_dss(dss_in_agent):
    with pytest.raises(ValueError):
        processor = Encryptor(dss_in_agent, False)
        data = processor.send(b"test_string")
        assert len(data) > 0


def test_encrypt_ecdsa(ecdsa_in_agent):
    with pytest.raises(ValueError):
        processor = Encryptor(ecdsa_in_agent, False)
        data = processor.send(b"test_string")
        assert len(data) > 0


def test_decrypt_ecdsa(ecdsa_in_agent):
    with pytest.raises(ValueError):
        encryptor = Encryptor(ecdsa_in_agent, False)
        data = encryptor.send(b"test_string")
        decryptor = Decryptor(ecdsa_in_agent, False)
        data_out = decryptor.send(data)
        assert len(data_out) > 0


def test_decrypt_rsa(rsa_in_agent):
    encryptor = Encryptor(rsa_in_agent, False)
    decryptor = Decryptor(rsa_in_agent, False)
    random_data = "".join(
        random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits)
        for _ in range(64)
    )
    with tempfile.NamedTemporaryFile() as file_obj_encryptor:
        with tempfile.NamedTemporaryFile("r") as file_obj_decryptor:
            encryptor = Processor(
                data_processor=encryptor,
                string_data=random_data,
                output_file=file_obj_encryptor.name,
                input_file=None,
            )
            encryptor.run()
            decryptor = Processor(
                data_processor=decryptor,
                string_data=None,
                output_file=file_obj_decryptor.name,
                input_file=file_obj_encryptor.name,
            )
            decryptor.run()
            file_obj_decryptor.read() == random_data


def test_decrypt_dss(dss_in_agent):
    with pytest.raises(ValueError):
        Encryptor(dss_in_agent, False)
        random_data = "".join(
            random.choice(
                string.ascii_lowercase + string.ascii_uppercase + string.digits
            )
            for _ in range(64)
        )
        with tempfile.NamedTemporaryFile() as file_obj_encryptor:
            with tempfile.NamedTemporaryFile("r") as file_obj_decryptor:
                encryptor = Processor(
                    data_processor=Encryptor,
                    string_data=random_data,
                    output_file=file_obj_encryptor.name,
                    input_file=None,
                )
                encryptor.run()
                decryptor = Processor(
                    data_processor=Decryptor,
                    string_data=None,
                    output_file=file_obj_decryptor.name,
                    input_file=file_obj_encryptor.name,
                )
                decryptor.run()
                file_obj_decryptor.read() == random_data


def test_first_key(ssh_agent, key_count=13):
    choose_fingerprint = None
    for i in range(0, key_count):
        key = RSAKey.generate(bits=1024)
        key.add_to_agent = types.MethodType(rsa_to_agent, key)
        key.add_to_agent(ssh_agent, f"RSA_KEY_{i}")
        if i == 0:
            choose_fingerprint = key.get_fingerprint()
    assert len(get_keys()) == key_count
    assert get_first_key().get_fingerprint() == choose_fingerprint


def test_filter_key_comment(ssh_agent, key_count=13):
    indx = random.randint(0, key_count - 1)
    choose_fingerprint = None
    for i in range(0, key_count):
        key = RSAKey.generate(bits=1024)
        key.add_to_agent = types.MethodType(rsa_to_agent, key)
        key.add_to_agent(ssh_agent, f"RSA_KEY_{i}")
        if i == indx:
            choose_fingerprint = key.get_fingerprint()
    assert len(get_keys()) == key_count
    assert find_filter_key(f"KEY_{indx}").get_fingerprint() == choose_fingerprint


def test_filter_key_fingerprint(ssh_agent, key_count=13):
    indx = random.randint(0, key_count - 1)
    choose_fingerprint = None
    for i in range(0, key_count):
        key = RSAKey.generate(bits=1024)
        key.add_to_agent = types.MethodType(rsa_to_agent, key)
        key.add_to_agent(ssh_agent, f"RSA_KEY_{i}")
        if i == indx:
            choose_fingerprint = key.get_fingerprint()
    assert len(get_keys()) == key_count
    sample = binascii.hexlify(choose_fingerprint, sep=":")[9:20].decode()
    assert find_filter_key(sample).get_fingerprint() == choose_fingerprint


def test_E_and_encrypt(rsa_in_agent):
    random_data = ''.join(
        random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in range(64)
    )
    assert str(E(encrypt(random_data, ssh_key=rsa_in_agent))) == random_data
