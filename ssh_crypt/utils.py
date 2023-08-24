import binascii
from typing import Union, Optional

from paramiko import Agent
from paramiko import AgentKey
from paramiko.ssh_exception import SSHException
from paramiko.agent import cSSH2_AGENTC_REQUEST_IDENTITIES, SSH2_AGENT_IDENTITIES_ANSWER

from .ciphers import Decryptor
from .constants import VALID_SSH_NAME


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


class E():
    def __init__(
            self,
            data: Union[str, bytes],
            binary=False,
            key: Optional[str] = None,
            ssh_key: Optional[AgentKey] = None
        ):
        if ssh_key:
            self.ssh_key = ssh_key
        if key:
            self.ssh_key = find_filter_key(key)
        if not key:
            self.ssh_key = get_first_key()

        if isinstance(data, str):
            data = data.encode('utf-8')
        self.data = data

    def __bytes__(self) -> bytes:
        ssh_key = get_first_key()

        decryptor = Decryptor(ssh_key, binary=False)
        return decryptor.send(self.data) + decryptor.send(b'')

    def __str__(self) -> str:
        return self.__bytes__().decode('utf-8')
