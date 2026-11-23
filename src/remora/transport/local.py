"""Run probes on the machine remora itself is running on."""

from __future__ import annotations

import subprocess
import time
from collections.abc import Sequence

from remora.transport.base import (
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_TIMEOUT_S,
    SAFE_ENV,
    CommandResult,
    CommandTimeout,
    Transport,
    TransportError,
    check_command,
)

# Exit code a POSIX shell uses for "command not found"; reused so a missing
# program looks the same locally and over SSH.
EXIT_NOT_FOUND = 127


class LocalTransport(Transport):
    @property
    def target(self) -> str:
        return "local"

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
        max_output: int = DEFAULT_MAX_OUTPUT_BYTES,
    ) -> CommandResult:
        command = check_command(argv)
        start = time.monotonic()
        try:
            # No shell, a fixed environment, and a program already checked
            # against the read-only list.
            proc = subprocess.run(  # noqa: S603
                command,
                capture_output=True,
                env=SAFE_ENV,
                timeout=timeout,
                check=False,
                stdin=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            return CommandResult(
                argv=command,
                exit_code=EXIT_NOT_FOUND,
                stdout="",
                stderr=f"{command[0]}: command not found",
                duration_s=time.monotonic() - start,
            )
        except subprocess.TimeoutExpired as exc:
            raise CommandTimeout(f"{command[0]} timed out after {timeout:g}s") from exc

        if len(proc.stdout) > max_output or len(proc.stderr) > max_output:
            raise TransportError(f"{command[0]} produced more than {max_output} bytes of output")
        return CommandResult(
            argv=command,
            exit_code=proc.returncode,
            stdout=proc.stdout.decode("utf-8", errors="replace"),
            stderr=proc.stderr.decode("utf-8", errors="replace"),
            duration_s=time.monotonic() - start,
        )

    def read_file(self, path: str, *, max_bytes: int = DEFAULT_MAX_FILE_BYTES) -> bytes | None:
        try:
            with open(path, "rb") as handle:
                data = handle.read(max_bytes + 1)
        except (FileNotFoundError, PermissionError, IsADirectoryError, NotADirectoryError):
            return None
        if len(data) > max_bytes:
            raise TransportError(f"{path} is larger than {max_bytes} bytes")
        return data
