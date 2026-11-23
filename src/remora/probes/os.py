"""OS fingerprint: which Linux distribution the target runs, read from os-release.

Every systemd-era distribution, and Alpine, ships `/etc/os-release` (or only
`/usr/lib/os-release`, which `/etc/os-release` normally links to). The format is
defined in os-release(5): `KEY=value` lines, values optionally quoted.

The probe also sorts the distribution into a *family*. Later probes and rules use
the family, not the exact distribution, to pick the right package manager, firewall
and file paths: Ubuntu and Debian are both `debian`; Rocky, RHEL, Alma, CentOS and
Fedora are all `rhel`.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from remora.transport import Transport

# Checked in this order, as os-release(5) says: /etc first, then the vendor copy.
OS_RELEASE_PATHS: tuple[str, ...] = ("/etc/os-release", "/usr/lib/os-release")

# Distribution IDs that belong to each family. A distribution is matched on its own
# ID first, then on each entry of ID_LIKE in order, so a derivative we have never
# heard of still lands in its parent's family.
FAMILIES: Mapping[str, frozenset[str]] = {
    "debian": frozenset({"debian", "ubuntu", "raspbian", "linuxmint", "pop", "kali"}),
    "rhel": frozenset({"rhel", "centos", "fedora", "rocky", "almalinux", "ol", "amzn"}),
    "alpine": frozenset({"alpine"}),
    "suse": frozenset({"suse", "sles", "opensuse", "opensuse-leap", "opensuse-tumbleweed"}),
    "arch": frozenset({"arch", "manjaro", "endeavouros"}),
}
UNKNOWN_FAMILY = "unknown"

_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# Inside double quotes, a backslash escapes only these characters (os-release(5)).
_ESCAPED = re.compile(r'\\([\\"$`])')


@dataclass(frozen=True, slots=True)
class OSInfo:
    """The target's distribution, as its os-release file describes it."""

    id: str
    id_like: tuple[str, ...]
    name: str
    pretty_name: str
    version_id: str | None
    version_codename: str | None
    family: str
    source: str
    fields: dict[str, str]


def parse_os_release(text: str) -> dict[str, str]:
    """Parse os-release text into a dict. Malformed lines are skipped, not fatal.

    A missing or odd line should cost one field, not the whole fingerprint.
    """
    fields: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not _KEY.match(key):
            continue
        fields[key] = _unquote(value.strip())
    return fields


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return _ESCAPED.sub(r"\1", value[1:-1])
    if len(value) >= 2 and value[0] == value[-1] == "'":
        return value[1:-1]
    return value


def family_of(distro_id: str, id_like: tuple[str, ...]) -> str:
    """Return the family for a distribution ID, falling back on ID_LIKE."""
    for candidate in (distro_id, *id_like):
        for family, members in FAMILIES.items():
            if candidate in members:
                return family
    return UNKNOWN_FAMILY


def os_info_from_fields(fields: dict[str, str], source: str) -> OSInfo:
    """Build an OSInfo from parsed fields, using os-release(5)'s defaults when absent."""
    distro_id = fields.get("ID", "linux").lower()
    id_like = tuple(part.lower() for part in fields.get("ID_LIKE", "").split())
    name = fields.get("NAME", "Linux")
    version = fields.get("VERSION")
    pretty_name = fields.get("PRETTY_NAME") or (f"{name} {version}" if version else name)
    return OSInfo(
        id=distro_id,
        id_like=id_like,
        name=name,
        pretty_name=pretty_name,
        version_id=fields.get("VERSION_ID"),
        version_codename=fields.get("VERSION_CODENAME"),
        family=family_of(distro_id, id_like),
        source=source,
        fields=fields,
    )


def probe_os(transport: Transport) -> OSInfo | None:
    """Fingerprint the target's distribution. Returns None if no os-release file exists.

    None means "not checked", never a guess: later commits report it that way.
    TransportError from the transport (connection lost, file too large) propagates.
    """
    for path in OS_RELEASE_PATHS:
        data = transport.read_file(path)
        if data is None:
            continue
        fields = parse_os_release(data.decode("utf-8", errors="replace"))
        return os_info_from_fields(fields, source=path)
    return None
