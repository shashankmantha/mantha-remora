from pathlib import Path

import pytest

from remora.transport import CommandNotAllowed, LocalTransport, TransportError


@pytest.fixture
def local() -> LocalTransport:
    return LocalTransport()


def test_target_label(local: LocalTransport) -> None:
    assert local.target == "local"


def test_run_returns_output(local: LocalTransport) -> None:
    result = local.run(["uname", "-s"])
    assert result.ok
    assert result.stdout.strip() == "Linux"
    assert result.argv == ("uname", "-s")


def test_nonzero_exit_is_a_result_not_an_error(local: LocalTransport, tmp_path: Path) -> None:
    result = local.run(["cat", "--", str(tmp_path / "missing")])
    assert not result.ok
    assert result.stderr


def test_disallowed_program_never_runs(local: LocalTransport) -> None:
    with pytest.raises(CommandNotAllowed):
        local.run(["touch", "/tmp/remora-should-not-exist"])


def test_read_file(local: LocalTransport, tmp_path: Path) -> None:
    path = tmp_path / "os-release"
    path.write_bytes(b'ID=ubuntu\nVERSION_ID="26.04"\n')
    assert local.read_file(str(path)) == b'ID=ubuntu\nVERSION_ID="26.04"\n'


def test_read_missing_file_returns_none(local: LocalTransport, tmp_path: Path) -> None:
    assert local.read_file(str(tmp_path / "missing")) is None


def test_read_directory_returns_none(local: LocalTransport, tmp_path: Path) -> None:
    assert local.read_file(str(tmp_path)) is None


def test_oversized_file_is_refused(local: LocalTransport, tmp_path: Path) -> None:
    path = tmp_path / "big"
    path.write_bytes(b"x" * 11)
    with pytest.raises(TransportError):
        local.read_file(str(path), max_bytes=10)


def test_context_manager(tmp_path: Path) -> None:
    with LocalTransport() as transport:
        assert transport.run(["id", "-u"]).ok
