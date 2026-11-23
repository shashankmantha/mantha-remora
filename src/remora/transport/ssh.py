"""Run probes on another machine over SSH, without installing anything on it."""

from __future__ import annotations

import getpass
import time
from collections.abc import Sequence

import paramiko

from remora.transport.base import (
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_TIMEOUT_S,
    CommandResult,
    CommandTimeout,
    Transport,
    TransportError,
    check_command,
    render_command,
)

_CHUNK = 65536
_POLL_S = 0.01


class _TrustInMemory(paramiko.MissingHostKeyPolicy):
    """Accept an unknown host key for this run only, without saving it anywhere."""

    def missing_host_key(
        self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey
    ) -> None:
        client.get_host_keys().add(hostname, key.get_name(), key)


class SSHTransport(Transport):
    """One SSH connection, reused for every command in a scan.

    Host keys are checked against `~/.ssh/known_hosts`, or the file given as
    `known_hosts`. An unknown host is refused unless `trust_unknown_host` is
    set, because a security tool that silently trusts any server would be easy
    to point at an impostor. A trusted key is kept for this connection only and
    never written to disk.
    Authentication uses the SSH agent or the user's keys; passwords are not
    supported in v0.1.
    """

    def __init__(
        self,
        host: str,
        *,
        user: str | None = None,
        port: int = 22,
        key_filename: str | None = None,
        trust_unknown_host: bool = False,
        known_hosts: str | None = None,
        connect_timeout: float = 10.0,
    ) -> None:
        self._host = host
        self._user = user or getpass.getuser()
        self._port = port
        self._client = paramiko.SSHClient()
        # Read-only use of known_hosts: never written to, even when trusting a new host.
        self._client.load_system_host_keys(known_hosts)
        policy: paramiko.MissingHostKeyPolicy = (
            _TrustInMemory() if trust_unknown_host else paramiko.RejectPolicy()
        )
        self._client.set_missing_host_key_policy(policy)
        try:
            self._client.connect(
                hostname=host,
                port=port,
                username=self._user,
                key_filename=key_filename,
                timeout=connect_timeout,
                banner_timeout=connect_timeout,
                auth_timeout=connect_timeout,
                allow_agent=True,
                look_for_keys=True,
            )
        except paramiko.BadHostKeyException as exc:
            self._client.close()
            raise TransportError(
                f"host key for {host} does not match known_hosts; refusing to connect"
            ) from exc
        except (paramiko.SSHException, OSError) as exc:
            self._client.close()
            raise TransportError(f"cannot connect to {self.target}: {exc}") from exc

    @property
    def target(self) -> str:
        port = "" if self._port == 22 else f":{self._port}"
        return f"ssh://{self._user}@{self._host}{port}"

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
        max_output: int = DEFAULT_MAX_OUTPUT_BYTES,
    ) -> CommandResult:
        command = check_command(argv)
        exit_code, out, err, duration = self._exec(render_command(command), timeout, max_output)
        return CommandResult(
            argv=command,
            exit_code=exit_code,
            stdout=out.decode("utf-8", errors="replace"),
            stderr=err.decode("utf-8", errors="replace"),
            duration_s=duration,
        )

    def read_file(self, path: str, *, max_bytes: int = DEFAULT_MAX_FILE_BYTES) -> bytes | None:
        # One byte more than allowed, so an oversized file is detected, not truncated.
        argv = check_command(["head", "-c", str(max_bytes + 1), "--", path])
        exit_code, out, _, _ = self._exec(render_command(argv), DEFAULT_TIMEOUT_S, max_bytes + 1)
        if exit_code != 0:
            return None
        if len(out) > max_bytes:
            raise TransportError(f"{path} is larger than {max_bytes} bytes")
        return out

    def close(self) -> None:
        self._client.close()

    def _exec(
        self, command: str, timeout: float, max_output: int
    ) -> tuple[int, bytes, bytes, float]:
        """Run one command line and collect both output streams until it exits.

        Both streams are read as data arrives, so a command that writes a lot
        to stderr cannot stall while stdout is being read.
        """
        transport = self._client.get_transport()
        if transport is None or not transport.is_active():
            raise TransportError(f"connection to {self.target} is closed")
        start = time.monotonic()
        deadline = start + timeout
        channel = transport.open_session()
        try:
            channel.exec_command(command)
            out, err = bytearray(), bytearray()
            while True:
                if channel.recv_ready():
                    out += channel.recv(_CHUNK)
                elif channel.recv_stderr_ready():
                    err += channel.recv_stderr(_CHUNK)
                elif channel.exit_status_ready() and channel.eof_received:
                    break
                elif time.monotonic() > deadline:
                    raise CommandTimeout(f"command timed out after {timeout:g}s on {self.target}")
                else:
                    time.sleep(_POLL_S)
                if len(out) > max_output or len(err) > max_output:
                    raise TransportError(f"command produced more than {max_output} bytes of output")
            exit_code = channel.recv_exit_status()
        finally:
            channel.close()
        return exit_code, bytes(out), bytes(err), time.monotonic() - start
