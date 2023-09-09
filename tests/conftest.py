import os
import subprocess
import shlex
import signal

import pytest


@pytest.fixture
def ssh_agent(monkeypatch):
    from paramiko.agent import Agent


    ssh_agent_exec = subprocess.run(
        ["ssh-agent"], capture_output=True, encoding="utf-8"
    )
    pid = next(
        iter(
            [
                s.split("=")[1].strip(";")
                for s in shlex.split(ssh_agent_exec.stdout)
                if "SSH_AGENT_PID=" in s
            ]
        ),
        None,
    )
    auth_sock = next(
        iter(
            [
                s.split("=")[1].strip(";")
                for s in shlex.split(ssh_agent_exec.stdout)
                if "SSH_AUTH_SOCK=" in s
            ]
        ),
        None,
    )
    os.environ["SSH_AUTH_SOCK"] = auth_sock
    os.environ["SSH_AGENT_PID"] = pid

    # make sure we connect to this agent
    monkeypatch.setenv("SSH_AUTH_SOCK", auth_sock)
    monkeypatch.setenv("SSH_AGENT_PID", pid)
    agent = Agent()
    yield agent
    os.kill(int(pid), signal.SIGSTOP)

