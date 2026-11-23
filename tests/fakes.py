"""Test doubles shared by several test files."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

from remora.transport import CommandResult, Transport, TransportError
from remora.transport.base import (
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_TIMEOUT_S,
    check_command,
)

FIXTURES = Path(__file__).parent / "fixtures"


class FakeTransport(Transport):
    """A machine made of in-memory files. Runs no commands; reads only what it was given.

    `files` maps a target path to its bytes, or to an exception to raise when read.
    """

    def __init__(
        self, files: Mapping[str, bytes | TransportError], *, target: str = "fake"
    ) -> None:
        self._files = dict(files)
        self._target = target
        self.closed = False

    @property
    def target(self) -> str:
        return self._target

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
        max_output: int = DEFAULT_MAX_OUTPUT_BYTES,
    ) -> CommandResult:
        command = check_command(argv)
        return CommandResult(command, 127, "", f"{command[0]}: not faked", 0.0)

    def read_file(self, path: str, *, max_bytes: int = DEFAULT_MAX_FILE_BYTES) -> bytes | None:
        value = self._files.get(path)
        if isinstance(value, TransportError):
            raise value
        return value

    def close(self) -> None:
        self.closed = True


def os_release(name: str) -> bytes:
    """Bytes of a saved os-release file from tests/fixtures/os-release/."""
    return (FIXTURES / "os-release" / name).read_bytes()
