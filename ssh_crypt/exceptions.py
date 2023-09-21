class SSHCryptError(Exception):
    def __init__(self, message: str, hint: str = "", **kwargs):
        # in a cli driver app, on a failure we
        # would like to display the error message
        # and a hint (if possible) on how to solve the issue
        self.message = message
        self.hint = hint
        super().__init__(**kwargs)


class SSHCrypAgentNotConnected(SSHCryptError):
    pass


class SSHCryptCannotRetrieveKeysError(SSHCryptError):
    pass
