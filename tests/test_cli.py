import pytest
from typer.testing import CliRunner

from fakes import FakeTransport, os_release
from remora import __version__, cli
from remora.cli import app
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
