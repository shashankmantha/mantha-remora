import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from pydantic import ValidationError

from fakes import FakeTransport, os_release
from remora import __version__
from remora.probes.os import os_facts, probe_os
from remora.snapshot import (
    SCHEMA_VERSION,
    Confidence,
    ProbeOutcome,
    ProbeStatus,
    Snapshot,
    dumps,
    json_schema,
    loads,
    new_snapshot,
)

CHECKED_IN_SCHEMA = Path(__file__).parent.parent / "schema" / "snapshot-v1.json"
T0 = datetime(2026, 12, 7, 18, 0, 0, tzinfo=UTC)


def snapshot_for(fixture: str | None) -> Snapshot:
    """A snapshot as `scan --out` would build it, from a saved os-release or none."""
    files = {} if fixture is None else {"/etc/os-release": os_release(fixture)}
    info = probe_os(FakeTransport(files))
    if info is None:
        outcome = ProbeOutcome(status=ProbeStatus.NOT_CHECKED, reason="no os-release")
        section = None
    else:
        outcome = ProbeOutcome(status=ProbeStatus.OK)
        section = os_facts(info, T0 + timedelta(seconds=1))
    return new_snapshot(
        "ssh://admin@vm1:22",
        started_at=T0,
        finished_at=T0 + timedelta(seconds=2),
        probes={"os": outcome},
        os=section,
    )


def as_json(snapshot: Snapshot) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(dumps(snapshot))
    return data


@pytest.mark.parametrize("fixture", ["ubuntu-26.04", "debian-13", "rocky-10", "alpine-3.22", None])
def test_round_trips_through_json(fixture: str | None) -> None:
    snapshot = snapshot_for(fixture)
    assert loads(dumps(snapshot)) == snapshot


@pytest.mark.parametrize("fixture", ["ubuntu-26.04", "debian-13", "rocky-10", "alpine-3.22", None])
def test_output_validates_against_json_schema(fixture: str | None) -> None:
    # Checked with an independent validator, not pydantic: this is what Atoll and any
    # non-Python reader will rely on.
    jsonschema.Draft202012Validator(json_schema()).validate(as_json(snapshot_for(fixture)))


def test_json_schema_is_itself_valid() -> None:
    jsonschema.Draft202012Validator.check_schema(json_schema())


def test_checked_in_schema_matches_models() -> None:
    # Fails on any change to the snapshot models. That is the point: a schema change
    # is a release. Regenerate deliberately with:
    #   uv run python -m remora.snapshot > schema/snapshot-v1.json
    assert json.loads(CHECKED_IN_SCHEMA.read_text()) == json_schema()


def test_header_fields() -> None:
    data = as_json(snapshot_for("ubuntu-26.04"))
    assert data["schema_version"] == SCHEMA_VERSION == 1
    assert data["remora_version"] == __version__
    assert data["target"] == "ssh://admin@vm1:22"
    assert data["started_at"] == "2026-12-07T18:00:00Z"
    assert data["probes"] == {"os": {"status": "ok", "reason": None}}


def test_every_fact_carries_provenance() -> None:
    os_section = as_json(snapshot_for("rocky-10"))["os"]
    for name, fact in os_section.items():
        assert set(fact) == {"value", "source", "collected_at", "confidence"}, name
        assert fact["source"] == {"kind": "file", "location": "/etc/os-release"}
        assert fact["collected_at"] == "2026-12-07T18:00:01Z"


def test_confidence_of_os_facts() -> None:
    os_section = snapshot_for("ubuntu-26.04").os
    assert os_section is not None
    assert os_section.id.value == "ubuntu"
    assert os_section.id.confidence is Confidence.OBSERVED
    assert os_section.family.value == "debian"
    assert os_section.family.confidence is Confidence.DERIVED


def test_spec_defaults_are_marked_assumed() -> None:
    info = probe_os(FakeTransport({"/etc/os-release": b""}))
    assert info is not None
    facts = os_facts(info, T0)
    assert facts.id.value == "linux"
    assert facts.id.confidence is Confidence.ASSUMED
    assert facts.pretty_name.confidence is Confidence.ASSUMED
    assert facts.version_id.value is None
    assert facts.version_id.confidence is Confidence.OBSERVED


def test_pretty_name_built_from_name_is_derived() -> None:
    info = probe_os(FakeTransport({"/etc/os-release": b'NAME="Foo"\nVERSION="1"\n'}))
    assert info is not None
    facts = os_facts(info, T0)
    assert facts.pretty_name.value == "Foo 1"
    assert facts.pretty_name.confidence is Confidence.DERIVED


def test_not_checked_has_no_section_and_a_reason() -> None:
    data = as_json(snapshot_for(None))
    assert data["os"] is None
    assert data["probes"]["os"] == {"status": "not_checked", "reason": "no os-release"}


def test_tuple_survives_round_trip() -> None:
    restored = loads(dumps(snapshot_for("rocky-10")))
    assert restored.os is not None
    assert restored.os.id_like.value == ("rhel", "centos", "fedora")


def test_unknown_key_is_rejected() -> None:
    data = as_json(snapshot_for("debian-13"))
    data["surprise"] = True
    with pytest.raises(ValidationError, match="surprise"):
        loads(json.dumps(data))


def test_other_schema_version_is_rejected() -> None:
    data = as_json(snapshot_for("debian-13"))
    data["schema_version"] = 2
    with pytest.raises(ValidationError, match="schema_version"):
        loads(json.dumps(data))


def test_naive_timestamp_is_rejected() -> None:
    data = as_json(snapshot_for("debian-13"))
    data["started_at"] = "2026-12-07T18:00:00"
    with pytest.raises(ValidationError, match="started_at"):
        loads(json.dumps(data))


def test_unknown_confidence_is_rejected() -> None:
    data = as_json(snapshot_for("debian-13"))
    data["os"]["id"]["confidence"] = "guessed"
    with pytest.raises(ValidationError):
        loads(json.dumps(data))


def test_non_utc_timestamp_keeps_its_instant() -> None:
    pacific = timezone(timedelta(hours=-8))
    snapshot = new_snapshot(
        "local",
        started_at=T0.astimezone(pacific),
        finished_at=T0,
        probes={},
        os=None,
    )
    assert loads(dumps(snapshot)).started_at == T0


def test_snapshot_is_immutable() -> None:
    snapshot = snapshot_for("debian-13")
    with pytest.raises(ValidationError):
        snapshot.target = "elsewhere"  # type: ignore[misc]
