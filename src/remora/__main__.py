"""Allow `python -m remora`, which works even where the `remora` script is not on PATH."""

from remora.cli import app

app(prog_name="remora")
