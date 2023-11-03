import os
import binascii
from typing import Union, Optional

from paramiko import Agent
from paramiko import AgentKey
from paramiko.agent import cSSH2_AGENTC_REQUEST_IDENTITIES, SSH2_AGENT_IDENTITIES_ANSWER

from .ciphers import Decryptor
from .ciphers import Encryptor
from .constants import VALID_SSH_NAME
from .exceptions import SSHCrypAgentNotConnected, SSHCryptCannotRetrieveKeysError


def get_keys():
    agent = Agent()

    # this is the only reliable way to check if there's a connection
    # (see paramiko.agent.Agent.__init__)
    if not agent._conn:
        raise SSHCrypAgentNotConnected(
            "no connection to an ssh agent",
            "is ssh-agent running? is SSH_AUTH_SOCK set?",
        )
    ptype, result = agent._send_message(cSSH2_AGENTC_REQUEST_IDENTITIES)
    if ptype != SSH2_AGENT_IDENTITIES_ANSWER:
        raise SSHCryptCannotRetrieveKeysError(
            "could not get keys from ssh-agent",
            f"check SSH_AUTH_SOCK={os.getenv('SSH_AUTH_SOCK')} "
            f"or SSH_AGENT_PID={os.getenv('SSH_AGENT_PID')} are"
            f" pointing to the right agent and it is running",
        )
    keys = []
    for i in range(result.get_int()):
        key_blob = result.get_binary()
        key_comment = result.get_string()
        keys.append((AgentKey(agent, key_blob), key_comment))
    return keys


def get_first_key():
    # Only RSA and ED25519 keys have capability to get
    # the same sign data from same nonce
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


def choose_ssh_key(
    key: Optional[str] = None,
    ssh_key: Optional[AgentKey] = None
) -> AgentKey:
    if ssh_key:
        return ssh_key

    if key:
        ssh_key = find_filter_key(key)

    if not ssh_key:
        ssh_key = get_first_key()

    return ssh_key


def encrypt(
    data: Union[str, bytes],
    binary: bool = False,
    key: Optional[str] = None,
    ssh_key: Optional[AgentKey] = None
) -> bytes:
    ssh_key = choose_ssh_key(key, ssh_key)

    if isinstance(data, str):
        data = data.encode("utf-8")

    encryptor = Encryptor(ssh_key, binary=binary)
    return encryptor.send(data) + encryptor.send(b"")


class E:
    def __init__(
        self,
        data: Union[str, bytes],
        binary=False,
        key: Optional[str] = None,
        ssh_key: Optional[AgentKey] = None,
    ):
        self.binary = binary

        self.ssh_key = choose_ssh_key(key, ssh_key)

        if isinstance(data, str):
            data = data.encode("utf-8")
        self.data = data

    def __bytes__(self) -> bytes:
        decryptor = Decryptor(self.ssh_key, binary=self.binary)
        return decryptor.send(self.data) + decryptor.send(b"")

    def __str__(self) -> str:
        return self.__bytes__().decode("utf-8")
