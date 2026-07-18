"""Dedup-key semantics (``docs/DETECTION_RULES.md`` §5)."""

import pytest
from pydantic import TypeAdapter

from app.alerts.dedup import dedup_key_for, major_version
from app.models.json_types import DedupKeyStr
from tests.factories import make_candidate

# sha1("portscan:v1:synthetic:10.0.0.50:10.0.0.10") — locks the exact key format:
# a change to the identity string is a change to every stored alert's identity
# and must be a conscious, versioned decision, not a drive-by refactor.
KNOWN_VECTOR = "f2d0651ad973f63ad1bfc59723882ec7a560ddc1"


def test_known_vector_locks_key_format() -> None:
    candidate = make_candidate(
        detector_id="portscan",
        detector_version="1.0",
        source_type="synthetic",
        src_ip="10.0.0.50",
        dst_ip="10.0.0.10",
    )
    assert dedup_key_for(candidate) == KNOWN_VECTOR


def test_key_shape_satisfies_the_model_validator() -> None:
    key = dedup_key_for(make_candidate())
    assert len(key) == 40
    assert key == key.lower()
    assert TypeAdapter(DedupKeyStr).validate_python(key) == key


def test_destination_keyed_detector_uses_placeholder_source() -> None:
    """synflood has no src_ip; the '-' placeholder takes its slot."""
    a = dedup_key_for(make_candidate(detector_id="synflood", src_ip=None))
    b = dedup_key_for(make_candidate(detector_id="synflood", src_ip="10.0.0.50"))
    assert a != b


def test_identity_components_change_the_key() -> None:
    """Changing any identity component (and only those) yields a distinct key."""
    base_key = dedup_key_for(make_candidate())
    variant_keys = [
        dedup_key_for(make_candidate(source_type="live")),
        dedup_key_for(make_candidate(detector_id="synflood", category="dos")),
        dedup_key_for(make_candidate(src_ip="10.0.0.51")),
        dedup_key_for(make_candidate(dst_ip="10.0.0.11")),
    ]
    assert base_key not in variant_keys
    assert len(set(variant_keys)) == len(variant_keys)


def test_minor_version_bump_preserves_identity() -> None:
    assert dedup_key_for(make_candidate(detector_version="1.0")) == dedup_key_for(
        make_candidate(detector_version="1.1")
    )


def test_major_version_bump_forks_identity() -> None:
    assert dedup_key_for(make_candidate(detector_version="1.9")) != dedup_key_for(
        make_candidate(detector_version="2.0")
    )


def test_major_version_extraction() -> None:
    assert major_version("1.0") == "1"
    assert major_version("2.13.4") == "2"
    assert major_version("3") == "3"
    with pytest.raises(ValueError, match="major"):
        major_version(".1")
    with pytest.raises(ValueError, match="major"):
        major_version("  ")
