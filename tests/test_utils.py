
import pytest

import ssh_crypt
from ssh_crypt import exceptions, utils


def test_get_keys_missing_agent(monkeypatch):
    """test failure to connect to an agent"""

    # make sure we don't connect to any ssh agent
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    monkeypatch.delenv("SSH_AGENT_PID", raising=False)
    pytest.raises(exceptions.SSHCrypAgentNotConnected, ssh_crypt.E, "Hello world")
    pytest.raises(exceptions.SSHCrypAgentNotConnected, utils.get_keys)


def test_get_keys_empty_agent(ssh_agent):
    assert len(utils.get_keys()) == 0
