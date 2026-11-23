import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from fakes import FakeTransport, os_release
from remora import __version__, cli
from remora.cli import app
from remora.snapshot import loads
from remora.transport import TransportError

runner = CliRunner()


def test_version_flag_prints_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == f"remora {__version__}"


def test_short_version_flag() -> None:
    result = runner.invoke(app, ["-V"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_no_arguments_shows_help() -> None:
    result = runner.invoke(app, [])
    assert "Usage" in result.output


def test_scan_without_subcommand_shows_help() -> None:
    result = runner.invoke(app, ["scan"])
    assert "local" in result.output
    assert "ssh" in result.output


def test_scan_local_names_the_distro(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeTransport({"/etc/os-release": os_release("ubuntu-26.04")}, target="local")
    monkeypatch.setattr(cli, "LocalTransport", lambda: fake)
    result = runner.invoke(app, ["scan", "local"])
    assert result.exit_code == 0
    assert "Ubuntu 26.04 LTS" in result.stdout
    assert "debian" in result.stdout
    assert fake.closed


def test_scan_local_on_this_machine() -> None:
    # The real thing, against whatever Linux runs the tests.
    result = runner.invoke(app, ["scan", "local"])
    assert result.exit_code == 0
    assert "Family" in result.stdout


def test_scan_local_without_os_release_is_not_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "LocalTransport", lambda: FakeTransport({}, target="local"))
    result = runner.invoke(app, ["scan", "local"])
    assert result.exit_code == 0
    assert "not checked" in result.stdout


def test_scan_ssh_splits_user_and_host(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_ssh(host: str, **kwargs: object) -> FakeTransport:
        seen.update(kwargs, host=host)
        return FakeTransport(
            {"/etc/os-release": os_release("rocky-10")}, target=f"ssh://admin@{host}"
        )

    monkeypatch.setattr(cli, "SSHTransport", fake_ssh)
    result = runner.invoke(app, ["scan", "ssh", "admin@vm1", "-p", "2222"])
    assert result.exit_code == 0
    assert seen["host"] == "vm1"
    assert seen["user"] == "admin"
    assert seen["port"] == 2222
    assert seen["trust_unknown_host"] is False
    assert "Rocky Linux 10.0" in result.stdout
    assert "rhel" in result.stdout


def test_scan_ssh_without_user_passes_none(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_ssh(host: str, **kwargs: object) -> FakeTransport:
        seen.update(kwargs, host=host)
        return FakeTransport({"/etc/os-release": os_release("debian-13")})

    monkeypatch.setattr(cli, "SSHTransport", fake_ssh)
    result = runner.invoke(app, ["scan", "ssh", "vm1"])
    assert result.exit_code == 0
    assert seen["user"] is None


def test_scan_ssh_connection_failure_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(host: str, **kwargs: object) -> FakeTransport:
        raise TransportError(f"cannot connect to {host}")

    monkeypatch.setattr(cli, "SSHTransport", refuse)
    result = runner.invoke(app, ["scan", "ssh", "admin@vm1"])
    assert result.exit_code == 2
    assert "cannot connect" in result.stderr


def test_read_failure_mid_scan_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeTransport({"/etc/os-release": TransportError("connection lost")})
    monkeypatch.setattr(cli, "LocalTransport", lambda: fake)
    result = runner.invoke(app, ["scan", "local"])
    assert result.exit_code == 2
    assert "connection lost" in result.stderr
    assert fake.closed


def test_scan_local_out_writes_a_valid_snapshot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = FakeTransport({"/etc/os-release": os_release("ubuntu-26.04")}, target="local")
    monkeypatch.setattr(cli, "LocalTransport", lambda: fake)
    out = tmp_path / "vm1.json"
    result = runner.invoke(app, ["scan", "local", "--out", str(out)])
    assert result.exit_code == 0
    assert "Ubuntu 26.04 LTS" in result.stdout  # still prints the table
    assert "Snapshot saved" in result.stderr  # stdout stays the report
    snapshot = loads(out.read_bytes())
    assert snapshot.target == "local"
    assert snapshot.os is not None
    assert snapshot.os.family.value == "debian"
    assert snapshot.started_at <= snapshot.os.id.collected_at <= snapshot.finished_at
    assert [p.name for p in tmp_path.iterdir()] == ["vm1.json"]  # no temp file left


def test_scan_ssh_out_short_flag(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fake_ssh(host: str, **kwargs: object) -> FakeTransport:
        return FakeTransport(
            {"/etc/os-release": os_release("rocky-10")}, target=f"ssh://admin@{host}:22"
        )

    monkeypatch.setattr(cli, "SSHTransport", fake_ssh)
    out = tmp_path / "vm1.json"
    result = runner.invoke(app, ["scan", "ssh", "admin@vm1", "-o", str(out)])
    assert result.exit_code == 0
    assert loads(out.read_text()).target == "ssh://admin@vm1:22"


def test_out_records_not_checked(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "LocalTransport", lambda: FakeTransport({}, target="local"))
    out = tmp_path / "empty.json"
    result = runner.invoke(app, ["scan", "local", "--out", str(out)])
    assert result.exit_code == 0
    data = json.loads(out.read_text())
    assert data["os"] is None
    assert data["probes"]["os"]["status"] == "not_checked"


def test_out_overwrites(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake = FakeTransport({"/etc/os-release": os_release("debian-13")}, target="local")
    monkeypatch.setattr(cli, "LocalTransport", lambda: fake)
    out = tmp_path / "vm1.json"
    out.write_text("old")
    result = runner.invoke(app, ["scan", "local", "--out", str(out)])
    assert result.exit_code == 0
    assert loads(out.read_text()).os is not None


def test_out_to_missing_directory_fails_before_scanning(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def must_not_connect(host: str, **kwargs: object) -> FakeTransport:
        raise AssertionError("connected before checking --out")

    monkeypatch.setattr(cli, "SSHTransport", must_not_connect)
    out = tmp_path / "missing" / "vm1.json"
    result = runner.invoke(app, ["scan", "ssh", "vm1", "--out", str(out)])
    assert result.exit_code == 3
    assert "not a directory" in result.stderr


def test_out_write_failure_exits_3(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake = FakeTransport({"/etc/os-release": os_release("debian-13")}, target="local")
    monkeypatch.setattr(cli, "LocalTransport", lambda: fake)

    def refuse(*args: object, **kwargs: object) -> None:
        raise PermissionError("read-only file system")

    monkeypatch.setattr(os, "replace", refuse)
    out = tmp_path / "vm1.json"
    result = runner.invoke(app, ["scan", "local", "--out", str(out)])
    assert result.exit_code == 3
    assert "cannot write" in result.stderr
    assert list(tmp_path.iterdir()) == []  # the temp file was cleaned up


def test_no_snapshot_when_the_target_fails(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake = FakeTransport({"/etc/os-release": TransportError("connection lost")})
    monkeypatch.setattr(cli, "LocalTransport", lambda: fake)
    out = tmp_path / "vm1.json"
    result = runner.invoke(app, ["scan", "local", "--out", str(out)])
    assert result.exit_code == 2
    assert not out.exists()


def test_scan_local_out_on_this_machine(tmp_path: Path) -> None:
    out = tmp_path / "self.json"
    result = runner.invoke(app, ["scan", "local", "--out", str(out)])
    assert result.exit_code == 0
    assert loads(out.read_text()).target == "local"
