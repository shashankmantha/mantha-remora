# mantha-remora

Read-only security checker for Linux virtual machines. Point it at a VM and it reports the
configuration choices that make that VM unsafe, with the evidence and the fix for each one.
It attaches, inspects, and leaves nothing behind, the way a remora rides its host.

Part of the Mantha security tools, alongside
[Mantha Ray](https://github.com/shashankmantha/mantha-ray) and
[Mantha Hermit](https://github.com/shashankmantha/mantha-hermit).

> **Status: pre-alpha.** Only the project skeleton exists. Scanning arrives in v0.1.

## What it will check

- **VM and template hygiene:** SSH host keys or machine IDs shared between clones, secrets
  left in cloud-init data, default image accounts, trusted insecure Vagrant keys.
- **Remote access, accounts, network exposure, kernel settings, file permissions, updates,
  and access control.**
- **Across VMs:** scan several machines in one run to find what they should not have in common.

## Install (development)

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```sh
git clone https://github.com/shashankmantha/mantha-remora
cd mantha-remora
uv sync
uv run remora --version
```

## Develop

```sh
uv run pytest            # tests
uv run ruff check        # lint
uv run ruff format       # format
uv run mypy              # type check
```

## Design rules

- **Read-only.** Remora never writes to the machine it inspects.
- **Rules are data.** Checks are YAML; a rule can compare facts but can never run a command.
- **Honest about gaps.** Anything that could not be checked is reported as "not checked",
  never as passed.

## License

MIT. See [LICENSE](LICENSE).
