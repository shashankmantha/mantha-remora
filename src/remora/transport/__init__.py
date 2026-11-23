"""Ways of reaching the machine being checked: locally, or over SSH."""

from remora.transport.base import (
    READ_ONLY_COMMANDS,
    CommandNotAllowed,
    CommandResult,
    CommandTimeout,
    Transport,
    TransportError,
)
from remora.transport.local import LocalTransport
from remora.transport.ssh import SSHTransport

__all__ = [
    "READ_ONLY_COMMANDS",
    "CommandNotAllowed",
    "CommandResult",
    "CommandTimeout",
    "LocalTransport",
    "SSHTransport",
    "Transport",
    "TransportError",
]