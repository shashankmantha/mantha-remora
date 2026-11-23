"""Command-line entry point for remora.

`remora scan local` checks the machine remora runs on; `remora scan ssh HOST` checks
another machine over SSH. For now a scan only fingerprints the OS; later commits add
the other probes, the rules and the report. `--out FILE` also saves the scan as a
snapshot (see `remora.snapshot`), the JSON that rules, reports and Atoll read.
Commands such as `explain` and `rules` are added in later commits, each as its own
function here.

Exit codes: 0 the scan ran; 2 the target could not be reached or read (Typer also
uses 2 for bad command-line usage); 3 the snapshot could not be written. Exit code 1
is kept for "findings at or above --fail-on", which a later commit adds.
"""

import os
import tempfile
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from remora import __version__
from remora.probes.os import OS_RELEASE_PATHS, OSInfo, os_facts, probe_os
from remora.snapshot import ProbeOutcome, ProbeStatus, Snapshot, dumps, new_snapshot, now
from remora.transport import LocalTransport, SSHTransport, Transport, TransportError

EXIT_TARGET_ERROR = 2
EXIT_OUTPUT_ERROR = 3

app = typer.Typer(
    name="remora",
    help="Read-only security checker for Linux virtual machines.",
    no_args_is_help=True,
    add_completion=False,
)
scan_app = typer.Typer(
    help="Scan a machine. Reads only; never changes the target.",
    no_args_is_help=True,
)
app.add_typer(scan_app, name="scan")

OutOption = Annotated[
    Path | None,
    typer.Option(
        "--out",
        "-o",
        help="Also save the scan as a JSON snapshot to this file (overwrites it).",
        dir_okay=False,
    ),
]

console = Console()
err_console = Console(stderr=True)


def _print_version(value: bool) -> None:
    if value:
        typer.echo(f"remora {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            help="Show the version and exit.",
            callback=_print_version,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """Find the misconfigurations that make a Linux VM unsafe. Never changes the VM."""


@scan_app.command("local")
def scan_local(out: OutOption = None) -> None:
    """Scan the machine remora is running on."""
    _check_out(out)
    _scan(LocalTransport(), out)


@scan_app.command("ssh")
def scan_ssh(
    host: Annotated[str, typer.Argument(help="Target as HOST or USER@HOST.")],
    port: Annotated[int, typer.Option("--port", "-p", help="SSH port.")] = 22,
    identity: Annotated[
        str | None,
        typer.Option("--identity", "-i", help="Private key file. Default: agent and ~/.ssh keys."),
    ] = None,
    known_hosts: Annotated[
        str | None,
        typer.Option("--known-hosts", help="known_hosts file. Default: ~/.ssh/known_hosts."),
    ] = None,
    trust_unknown_host: Annotated[
        bool,
        typer.Option(
            "--trust-unknown-host",
            help="Connect even if the host key is not in known_hosts. The key is not saved.",
        ),
    ] = False,
    out: OutOption = None,
) -> None:
    """Scan another machine over SSH, without installing anything on it."""
    _check_out(out)
    user, _, hostname = host.rpartition("@")
    try:
        transport = SSHTransport(
            hostname,
            user=user or None,
            port=port,
            key_filename=identity,
            known_hosts=known_hosts,
            trust_unknown_host=trust_unknown_host,
        )
    except TransportError as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(EXIT_TARGET_ERROR) from exc
    _scan(transport, out)


def _check_out(out: Path | None) -> None:
    """Fail before scanning, not after, if the snapshot has nowhere to go."""
    if out is not None and not out.parent.is_dir():
        err_console.print(f"[red]error:[/red] {out.parent} is not a directory")
        raise typer.Exit(EXIT_OUTPUT_ERROR)


def _scan(transport: Transport, out: Path | None = None) -> None:
    """Run the probes against one target, print what they found, optionally save it."""
    started_at = now()
    with transport:
        try:
            info = probe_os(transport)
        except TransportError as exc:
            err_console.print(f"[red]error:[/red] {transport.target}: {exc}")
            raise typer.Exit(EXIT_TARGET_ERROR) from exc
        collected_at = now()
    _print_os(transport.target, info)
    if out is None:
        return

    if info is None:
        paths = " or ".join(OS_RELEASE_PATHS)
        outcome = ProbeOutcome(status=ProbeStatus.NOT_CHECKED, reason=f"no readable {paths}")
        os_section = None
    else:
        outcome = ProbeOutcome(status=ProbeStatus.OK)
        os_section = os_facts(info, collected_at)
    snapshot = new_snapshot(
        transport.target,
        started_at=started_at,
        finished_at=now(),
        probes={"os": outcome},
        os=os_section,
    )
    _write_snapshot(snapshot, out)


def _write_snapshot(snapshot: Snapshot, out: Path) -> None:
    """Write atomically: a crash mid-write never leaves a half-written snapshot behind."""
    try:
        fd, tmp = tempfile.mkstemp(prefix=f".{out.name}.", dir=out.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(dumps(snapshot))
            os.replace(tmp, out)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
    except OSError as exc:
        err_console.print(f"[red]error:[/red] cannot write {out}: {exc}")
        raise typer.Exit(EXIT_OUTPUT_ERROR) from exc
    err_console.print(f"Snapshot saved to {out}")


def _print_os(target: str, info: OSInfo | None) -> None:
    console.print(f"[bold]Target[/bold]  {target}")
    if info is None:
        paths = " or ".join(OS_RELEASE_PATHS)
        console.print(f"[yellow]OS: not checked[/yellow] (no readable {paths})")
        return
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style="bold")
    table.add_column()
    table.add_row("OS", info.pretty_name)
    table.add_row("ID", info.id)
    table.add_row("Version", info.version_id or "-")
    if info.version_codename:
        table.add_row("Codename", info.version_codename)
    table.add_row("Family", info.family)
    table.add_row("Source", info.source)
    console.print(table)
