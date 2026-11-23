"""SSH transport tests.

These need a real SSH server, so they are skipped unless REMORA_TEST_SSH is set
to a target you can already log in to with a key, for example:

    REMORA_TEST_SSH=admin@192.168.122.50 uv run pytest tests/test_transport_ssh.py

The host must already be in ~/.ssh/known_hosts. CI skips them.
"""

import os
from pathlib import Path

import pytest

from remora.transport import CommandNotAllowed, SSHTransport, TransportError

TARGET = os.environ.get("REMORA_TEST_SSH", "")

pytestmark = pytest.mark.skipif(not TARGET, reason="set REMORA_TEST_SSH=user@host to run")


def _split(target: str) -> tuple[str | None, str, int]:
    user, _, rest = target.rpartition("@")
    host, _, port = rest.partition(":")
    return (user or None), host, int(port or 22)


@pytest.fixture
def ssh() -> SSHTransport:
    user, host, port = _split(TARGET)
    return SSHTransport(host, user=user, port=port)


def test_run_returns_output(ssh: SSHTransport) -> None:
    with ssh:
        result = ssh.run(["uname", "-s"])
    assert result.ok
    assert result.stdout.strip() == "Linux"


def test_nonzero_exit_is_a_result(ssh: SSHTransport) -> None:
    with ssh:
        result = ssh.run(["cat", "--", "/nonexistent/remora-test"])
    assert not result.ok
    assert result.stderr


def test_hostile_file_name_stays_one_argument(ssh: SSHTransport) -> None:
    with ssh:
        result = ssh.run(["cat", "--", "/nonexistent; echo INJECTED"])
    assert "INJECTED" not in result.stdout


def test_read_file(ssh: SSHTransport) -> None:
    with ssh:
        data = ssh.read_file("/etc/os-release")
    assert data is not None
    assert b"ID=" in data


def test_read_missing_file_returns_none(ssh: SSHTransport) -> None:
    with ssh:
        assert ssh.read_file("/nonexistent/remora-test") is None


def test_oversized_file_is_refused(ssh: SSHTransport) -> None:
    with ssh, pytest.raises(TransportError):
        ssh.read_file("/etc/os-release", max_bytes=10)


def test_disallowed_program_never_runs(ssh: SSHTransport) -> None:
    with ssh, pytest.raises(CommandNotAllowed):
        ssh.run(["touch", "/tmp/remora-should-not-exist"])


def test_unknown_host_is_refused(tmp_path: Path) -> None:
    user, host, port = _split(TARGET)
    empty = tmp_path / "known_hosts"
    empty.write_text("")
    with pytest.raises(TransportError):
        SSHTransport(host, user=user, port=port, known_hosts=str(empty))


def test_trusted_unknown_host_connects_without_saving_key(tmp_path: Path) -> None:
    user, host, port = _split(TARGET)
    empty = tmp_path / "known_hosts"
    empty.write_text("")
    with SSHTransport(
        host, user=user, port=port, known_hosts=str(empty), trust_unknown_host=True
    ) as ssh:
        assert ssh.run(["id", "-u"]).ok
    assert empty.read_text() == ""
