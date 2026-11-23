import shlex

import pytest

from remora.transport.base import (
    READ_ONLY_COMMANDS,
    CommandNotAllowed,
    CommandResult,
    check_command,
    render_command,
)


def test_allowed_command_passes() -> None:
    assert check_command(["uname", "-a"]) == ("uname", "-a")


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["rm", "-rf", "/"],
        ["/tmp/cat", "/etc/passwd"],
        ["./uname"],
        ["sh", "-c", "uname"],
    ],
)
def test_disallowed_commands_are_refused(argv: list[str]) -> None:
    with pytest.raises(CommandNotAllowed):
        check_command(argv)


def test_allowlist_has_no_shells_or_writers() -> None:
    dangerous = {"sh", "bash", "rm", "mv", "cp", "tee", "dd", "chmod", "chown", "sudo", "env"}
    assert READ_ONLY_COMMANDS.isdisjoint(dangerous)


def test_render_command_keeps_hostile_argument_as_one_word() -> None:
    hostile = "x; rm -rf / #"
    line = render_command(["cat", "--", hostile])
    words = shlex.split(line)
    assert words[-1] == hostile
    assert words[-3:-1] == ["cat", "--"]


def test_render_command_sets_fixed_path_and_locale() -> None:
    words = shlex.split(render_command(["uname"]))
    assert "LC_ALL=C" in words
    assert any(word.startswith("PATH=/usr/local/sbin:") for word in words)


def test_result_ok_reflects_exit_code() -> None:
    passed = CommandResult(("id",), 0, "", "", 0.0)
    failed = CommandResult(("id",), 1, "", "", 0.0)
    assert passed.ok
    assert not failed.ok
