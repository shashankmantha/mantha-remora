"""Command-line entry point for remora.

Only the top-level app and `--version` exist so far. Commands such as `scan`,
`explain` and `rules` are added in later commits, each as its own function here.
"""

from typing import Annotated

import typer

from remora import __version__

app = typer.Typer(
    name="remora",
    help="Read-only security checker for Linux virtual machines.",
    no_args_is_help=True,
    add_completion=False,
)


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
