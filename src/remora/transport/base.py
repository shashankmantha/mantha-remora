"""The interface every way of reaching a machine implements.

Probes never talk to subprocess or SSH directly. They get a `Transport` and call
`run()` or `read_file()`, so the same probe works on the local machine, over SSH,
and later against a disk image.

Read-only is enforced here, not just promised: `run()` refuses any program that is
not on `READ_ONLY_COMMANDS`. Adding a program to that set is a deliberate, reviewed
change.
"""

from __future__ import annotations

import shlex
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from types import TracebackType
from typing import Self

# Programs remora may run on a target. Every entry must be unable to change the
# system when called the way probes call it. Probes added later extend this set.
READ_ONLY_COMMANDS: frozenset[str] = frozenset(
    {
        "cat",
        "head",
        "id",
        "uname",
    }
)

# A fixed, minimal PATH so a target user's own PATH cannot swap in a different
# program with an allowed name.
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# The C locale keeps command output in English with predictable formats.
SAFE_ENV: dict[str, str] = {"PATH": SAFE_PATH, "LC_ALL": "C", "LANG": "C"}

DEFAULT_TIMEOUT_S = 30.0
DEFAULT_MAX_OUTPUT_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_FILE_BYTES = 1024 * 1024


class TransportError(Exception):
    """The command or file read could not be carried out at all."""


class CommandTimeout(TransportError):
    """The command ran longer than its timeout and was abandoned."""


class CommandNotAllowed(TransportError):
    """A probe asked to run a program that is not on the read-only list."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    """What a command returned. A non-zero exit code is a result, not an error."""

    argv: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str
    duration_s: float

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


def check_command(argv: Sequence[str]) -> tuple[str, ...]:
    """Validate a command before it runs, and return it as a tuple.

    The program must be a bare name on the read-only list. Paths are refused so
    that `/tmp/cat` can never pass as `cat`.
    """
    if not argv:
        raise CommandNotAllowed("empty command")
    program = argv[0]
    if "/" in program:
        raise CommandNotAllowed(f"programs must be bare names, not paths: {program!r}")
    if program not in READ_ONLY_COMMANDS:
        raise CommandNotAllowed(f"{program!r} is not on the read-only command list")
    return tuple(argv)


def render_command(argv: Sequence[str]) -> str:
    """Turn an argument list into one safely quoted POSIX shell command line.

    SSH can only send a single string, which the target's shell then splits.
    Quoting every argument means a file name such as `x; rm -rf /` stays one
    harmless argument.
    """
    env = " ".join(f"{key}={shlex.quote(value)}" for key, value in SAFE_ENV.items())
    return f"{env} {shlex.join(argv)}"


class Transport(ABC):
    """A connection to one machine that can run allowed commands and read files."""

    @property
    @abstractmethod
    def target(self) -> str:
        """A short label for the machine, used in reports, such as `local` or `ssh://admin@vm1`."""

    @abstractmethod
    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
        max_output: int = DEFAULT_MAX_OUTPUT_BYTES,
    ) -> CommandResult:
        """Run an allowed program with arguments. Never goes through a shell locally."""

    @abstractmethod
    def read_file(self, path: str, *, max_bytes: int = DEFAULT_MAX_FILE_BYTES) -> bytes | None:
        """Return a file's contents, or None if it is missing or unreadable.

        Raises TransportError if the file is larger than `max_bytes`.
        """

    def close(self) -> None:  # noqa: B027  (optional hook; most transports need nothing)
        """Release the connection. Safe to call more than once."""

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
