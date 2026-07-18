"""Deterministic object factories shared by the Phase 3 test modules.

Everything here is plain construction — no randomness beyond explicit UUID
defaults, no clock reads — so tests stay reproducible.
"""

import itertools
import uuid
from collections.abc import Callable, Sequence

from pydantic import JsonValue

from app.models.alert import Alert
from app.models.candidate_alert import CandidateAlert
from app.models.enums import Category, Severity, SourceType
from app.models.packet_event import PacketEvent

# A syntactically valid placeholder dedup key (40 lowercase hex chars).
PLACEHOLDER_DEDUP_KEY = "0" * 40

# Shared sensor token for API tests (>= 16 chars per config validation).
TEST_SENSOR_TOKEN = "unit-test-sensor-token"


def auth_headers() -> dict[str, str]:
    """The ingest authentication header for the test sensor token."""
    return {"X-Sensor-Token": TEST_SENSOR_TOKEN}


def ingest_payload(events: Sequence[PacketEvent]) -> dict[str, object]:
    """A JSON-ready ingest request body for ``events``."""
    return {"events": [event.model_dump(mode="json") for event in events]}


def sequential_id_factory(start: int = 0) -> Callable[[], str]:
    """Return an ``id_factory`` producing deterministic, distinct UUIDv4 strings."""
    counter = itertools.count(start)

    def next_id() -> str:
        return str(uuid.UUID(int=next(counter), version=4))

    return next_id


def make_candidate(
    *,
    detector_id: str = "portscan",
    detector_version: str = "1.0",
    category: Category | None = None,
    severity: Severity = "medium",
    confidence: float = 0.6,
    src_ip: str | None = "10.0.0.50",
    dst_ip: str = "10.0.0.10",
    source_type: SourceType = "synthetic",
    evidence: dict[str, JsonValue] | None = None,
    threshold_snapshot: dict[str, JsonValue] | None = None,
    window_start: float = 1000.0,
    window_end: float = 1002.0,
) -> CandidateAlert:
    """Build a valid :class:`CandidateAlert` with overridable fields."""
    if category is None:
        category = "reconnaissance" if detector_id == "portscan" else "dos"
    return CandidateAlert(
        detector_id=detector_id,
        detector_version=detector_version,
        category=category,
        severity=severity,
        confidence=confidence,
        src_ip=src_ip,
        dst_ip=dst_ip,
        source_type=source_type,
        evidence=evidence if evidence is not None else {"distinct_port_count": 15},
        threshold_snapshot=(
            threshold_snapshot if threshold_snapshot is not None else {"PORTSCAN_MIN_PORTS": 15}
        ),
        window_start=window_start,
        window_end=window_end,
    )


def make_alert(
    *,
    alert_id: str | None = None,
    created_at: float = 1000.0,
    detector_id: str = "portscan",
    detector_version: str = "1.0",
    category: Category = "reconnaissance",
    severity: Severity = "medium",
    confidence: float = 0.6,
    src_ip: str | None = "10.0.0.50",
    dst_ip: str = "10.0.0.10",
    window_start: float = 1000.0,
    window_end: float = 1002.0,
    evidence: dict[str, JsonValue] | None = None,
    threshold_snapshot: dict[str, JsonValue] | None = None,
    dedup_key: str = PLACEHOLDER_DEDUP_KEY,
    source_type: SourceType = "synthetic",
    occurrence_count: int = 1,
    last_seen: float | None = None,
) -> Alert:
    """Build a valid persisted-shape :class:`Alert` with overridable fields."""
    return Alert(
        alert_id=alert_id if alert_id is not None else str(uuid.uuid4()),
        created_at=created_at,
        detector_id=detector_id,
        detector_version=detector_version,
        category=category,
        severity=severity,
        confidence=confidence,
        src_ip=src_ip,
        dst_ip=dst_ip,
        window_start=window_start,
        window_end=window_end,
        evidence=evidence if evidence is not None else {"distinct_port_count": 15},
        threshold_snapshot=(
            threshold_snapshot if threshold_snapshot is not None else {"PORTSCAN_MIN_PORTS": 15}
        ),
        dedup_key=dedup_key,
        source_type=source_type,
        occurrence_count=occurrence_count,
        last_seen=last_seen if last_seen is not None else created_at,
    )
