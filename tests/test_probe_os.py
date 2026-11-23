import pytest

from fakes import FakeTransport, os_release
from remora.probes.os import family_of, parse_os_release, probe_os
from remora.transport import TransportError


@pytest.mark.parametrize(
    ("fixture", "distro_id", "version_id", "family"),
    [
        ("ubuntu-26.04", "ubuntu", "26.04", "debian"),
        ("debian-13", "debian", "13", "debian"),
        ("rocky-10", "rocky", "10.0", "rhel"),
        ("alpine-3.22", "alpine", "3.22.2", "alpine"),
    ],
)
def test_fixtures_parse_to_the_right_family(
    fixture: str, distro_id: str, version_id: str, family: str
) -> None:
    info = probe_os(FakeTransport({"/etc/os-release": os_release(fixture)}))
    assert info is not None
    assert info.id == distro_id
    assert info.version_id == version_id
    assert info.family == family
    assert info.source == "/etc/os-release"


def test_ubuntu_details() -> None:
    info = probe_os(FakeTransport({"/etc/os-release": os_release("ubuntu-26.04")}))
    assert info is not None
    assert info.pretty_name == "Ubuntu 26.04 LTS"
    assert info.version_codename == "resolute"
    assert info.id_like == ("debian",)


def test_rocky_id_like_is_split_and_unquoted() -> None:
    info = probe_os(FakeTransport({"/etc/os-release": os_release("rocky-10")}))
    assert info is not None
    assert info.id_like == ("rhel", "centos", "fedora")
    assert info.fields["PLATFORM_ID"] == "platform:el10"


def test_falls_back_to_usr_lib() -> None:
    info = probe_os(FakeTransport({"/usr/lib/os-release": os_release("debian-13")}))
    assert info is not None
    assert info.id == "debian"
    assert info.source == "/usr/lib/os-release"


def test_etc_wins_over_usr_lib() -> None:
    files = {
        "/etc/os-release": os_release("ubuntu-26.04"),
        "/usr/lib/os-release": os_release("debian-13"),
    }
    info = probe_os(FakeTransport(files))
    assert info is not None
    assert info.id == "ubuntu"


def test_no_os_release_is_not_checked() -> None:
    assert probe_os(FakeTransport({})) is None


def test_transport_error_propagates() -> None:
    transport = FakeTransport({"/etc/os-release": TransportError("too large")})
    with pytest.raises(TransportError):
        probe_os(transport)


def test_empty_file_uses_spec_defaults() -> None:
    info = probe_os(FakeTransport({"/etc/os-release": b""}))
    assert info is not None
    assert info.id == "linux"
    assert info.pretty_name == "Linux"
    assert info.family == "unknown"


def test_unknown_derivative_lands_in_parent_family() -> None:
    assert family_of("someos", ("ubuntu", "debian")) == "debian"
    assert family_of("someos", ()) == "unknown"


def test_parser_quoting_comments_and_junk() -> None:
    text = "\n".join(
        [
            "# a comment",
            "",
            'NAME="Quoted \\"Name\\" \\$HOME"',
            "SINGLE='single quoted'",
            "BARE=bare",
            "no equals sign here",
            "1BAD=starts with a digit",
            "EMPTY=",
        ]
    )
    fields = parse_os_release(text)
    assert fields == {
        "NAME": 'Quoted "Name" $HOME',
        "SINGLE": "single quoted",
        "BARE": "bare",
        "EMPTY": "",
    }


def test_invalid_utf8_does_not_crash() -> None:
    info = probe_os(FakeTransport({"/etc/os-release": b'ID=ubuntu\nNAME="Ub\xffuntu"\n'}))
    assert info is not None
    assert info.id == "ubuntu"
