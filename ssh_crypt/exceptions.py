class SSHCryptError(Exception):
    pass


class SSHCrypAgentNotConnected(SSHCryptError):
    pass


class SSHCryptCannotRetrieveKeysError(SSHCryptError):
    pass
