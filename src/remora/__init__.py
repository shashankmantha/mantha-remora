"""mantha-remora: a read-only security checker for Linux virtual machines."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("mantha-remora")
except PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
