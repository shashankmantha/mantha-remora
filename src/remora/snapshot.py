"""The snapshot: everything one scan learned about one target, as versioned JSON.

The snapshot is remora's contract with everything downstream. Rules read it,
reports render it, and Mantha Atoll pins it. So it is versioned (`schema_version`),
and every fact in it says where it came from, when it was read and how sure remora
is of it. A change to these models is a schema change and a remora release, never a
quiet edit: `tests/test_snapshot.py` compares the models against the checked-in
`schema/snapshot-v1.json` to catch that.

Regenerate the checked-in schema after a deliberate change with:

    uv run python -m remora.snapshot > schema/snapshot-v1.json
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from remora import __version__

SCHEMA_VERSION: Literal[1] = 1
SCHEMA_ID = "https://github.com/shashankmantha/mantha-remora/schema/snapshot-v1.json"


class _Model(BaseModel):
    """Base for every snapshot model: immutable, and unknown keys are an error.

    Refusing unknown keys means a snapshot from a newer remora fails loudly here
    instead of being half-read.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")


class Confidence(StrEnum):
    """How a fact's value was arrived at."""

    OBSERVED = "observed"
    """Read directly from the target. An absent optional key read from a file that
    exists is also observed: its value is None."""

    DERIVED = "derived"
    """Computed from observed facts by a fixed rule, such as the OS family from ID."""

    ASSUMED = "assumed"
    """The source was silent and a documented default was used, such as os-release(5)
    defaulting ID to `linux`. Rules should treat these as weaker than observed."""


class Source(_Model):
    """Where on the target a fact came from."""

    kind: Literal["file", "command"]
    location: str = Field(description="A file path, or the command line that was run.")


class Fact[T](_Model):
    """One value plus its provenance: source, collection time and confidence.

    Sections use the named subclasses below, never `Fact[...]` directly: a named
    class gets a stable name in the JSON Schema, where a parametrized generic gets
    one that changes with the Python version.
    """

    value: T
    source: Source
    collected_at: AwareDatetime
    confidence: Confidence


class StrFact(Fact[str]):
    pass


class OptionalStrFact(Fact[str | None]):
    pass


class StrListFact(Fact[tuple[str, ...]]):
    pass


class StrMapFact(Fact[dict[str, str]]):
    pass


class ProbeStatus(StrEnum):
    OK = "ok"
    NOT_CHECKED = "not_checked"


class ProbeOutcome(_Model):
    """Whether a probe produced its section. "Not checked" is never a pass."""

    status: ProbeStatus
    reason: str | None = Field(default=None, description="Why the probe could not check.")


class OSFacts(_Model):
    """The `os` section: the distribution, from os-release."""

    id: StrFact
    id_like: StrListFact
    name: StrFact
    pretty_name: StrFact
    version_id: OptionalStrFact
    version_codename: OptionalStrFact
    family: StrFact
    fields: StrMapFact = Field(description="Every key in the file, as parsed.")


class Snapshot(_Model):
    """Everything one scan learned about one target."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        title="mantha-remora snapshot",
        json_schema_extra={"$id": SCHEMA_ID},
    )

    schema_version: Literal[1] = SCHEMA_VERSION
    remora_version: str
    target: str = Field(description="`local` or `ssh://user@host:port`.")
    started_at: AwareDatetime
    finished_at: AwareDatetime
    probes: dict[str, ProbeOutcome] = Field(
        description="Every probe that ran, keyed by section name, and whether it checked."
    )
    os: OSFacts | None = None


def now() -> datetime:
    """The current time in UTC. Every timestamp in a snapshot comes from here."""
    return datetime.now(UTC)


def new_snapshot(
    target: str,
    *,
    started_at: datetime,
    finished_at: datetime,
    probes: dict[str, ProbeOutcome],
    os: OSFacts | None,
) -> Snapshot:
    """Build a snapshot stamped with this remora's version."""
    return Snapshot(
        remora_version=__version__,
        target=target,
        started_at=started_at,
        finished_at=finished_at,
        probes=probes,
        os=os,
    )


def dumps(snapshot: Snapshot) -> str:
    """Serialize a snapshot to JSON text, ending in a newline."""
    return snapshot.model_dump_json(indent=2) + "\n"


def loads(text: str | bytes) -> Snapshot:
    """Parse and validate snapshot JSON. Raises pydantic.ValidationError if invalid."""
    return Snapshot.model_validate_json(text)


def json_schema() -> dict[str, Any]:
    """The JSON Schema (draft 2020-12) that every snapshot this version writes obeys."""
    schema = Snapshot.model_json_schema(mode="serialization")
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", **schema}


if __name__ == "__main__":
    print(json.dumps(json_schema(), indent=2))
