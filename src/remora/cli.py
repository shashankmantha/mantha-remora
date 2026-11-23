"""Command-line entry point for remora.

`remora scan local` checks the machine remora runs on; `remora scan ssh HOST` checks
another machine over SSH. For now a scan only fingerprints the OS; later commits add
the other probes, the rules and the report. Commands such as `explain` and `rules`
are added in later commits, each as its own function here.

Exit codes: 0 the scan ran; 2 the target could not be reached or read (Typer also
uses 2 for bad command-line usage).
"""

from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from remora import __version__
from remora.probes.os import OS_RELEASE_PATHS, OSInfo, probe_os
from remora.transport import LocalTransport, SSHTransport, Transport, TransportError

EXIT_TARGET_ERROR = 2

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
def scan_local() -> None:
    """Scan the machine remora is running on."""
    _scan(LocalTransport())


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
) -> None:
    """Scan another machine over SSH, without installing anything on it."""
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
    _scan(transport)


def _scan(transport: Transport) -> None:
    """Run the probes against one target and print what they found."""
    with transport:
        try:
            info = probe_os(transport)
        except TransportError as exc:
            err_console.print(f"[red]error:[/red] {transport.target}: {exc}")
            raise typer.Exit(EXIT_TARGET_ERROR) from exc
    _print_os(transport.target, info)


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
