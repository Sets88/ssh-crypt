import os
import subprocess
import shlex
import signal

import pytest


@pytest.fixture(scope="function")
def ssh_agent(monkeypatch, tmp_path):
    from paramiko.agent import Agent

    # this will make sure all ssh* operations will occour
    # under a temporary directory (eg. non user ~/.ssh)
    monkeypatch.setenv("SSH_HOME", str(tmp_path / ".ssh"))

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

    # make sure we connect to this agent, but after the test
    # is terminated we restore the current state
    monkeypatch.setenv("SSH_AUTH_SOCK", auth_sock)
    monkeypatch.setenv("SSH_AGENT_PID", pid)

    agent = Agent()
    yield agent
    os.kill(int(pid), signal.SIGSTOP)

