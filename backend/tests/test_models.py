"""Schema-validation tests for the Phase 2 domain models."""

import hashlib
import uuid
from collections.abc import Callable

import pytest
from pydantic import ValidationError

from app.models import Alert, CandidateAlert, PacketEvent
from app.models.candidate_alert import PortScanEvidence, SynFloodEvidence
from app.models.json_types import JsonValue


def _uuid4() -> str:
    return str(uuid.uuid4())


def _dedup_key() -> str:
    return hashlib.sha1(b"portscan:v1:synthetic:10.0.0.9:10.0.0.1").hexdigest()


# --------------------------------------------------------------------------- #
# PacketEvent — valid, including the approved nullable cases
# --------------------------------------------------------------------------- #
def test_packet_event_accepts_full_tcp_event() -> None:
    event = PacketEvent(
        event_id=_uuid4(),
        ts=1000.0,
        source_type="synthetic",
        src_ip="10.0.0.9",
        src_port=40000,
        dst_ip="10.0.0.1",
        dst_port=80,
        protocol="TCP",
        tcp_flags="S",
        packet_length=64,
    )
    assert event.tcp_flags == "S"
    assert event.protocol == "TCP"


def test_packet_event_allows_tcp_without_flags_or_ports() -> None:
    """Incomplete parsing: TCP may carry null flags and null ports."""
    event = PacketEvent(
        event_id=_uuid4(),
        ts=1.0,
        source_type="live",
        src_ip="10.0.0.9",
        dst_ip="10.0.0.1",
        protocol="TCP",
        packet_length=0,
    )
    assert event.tcp_flags is None
    assert event.src_port is None and event.dst_port is None


def test_packet_event_allows_udp_without_ports() -> None:
    event = PacketEvent(
        event_id=_uuid4(),
        ts=1.0,
        source_type="replay",
        src_ip="10.0.0.9",
        dst_ip="10.0.0.1",
        protocol="UDP",
        packet_length=10,
    )
    assert event.protocol == "UDP"


def test_packet_event_normalises_flags_uppercase() -> None:
    event = PacketEvent(
        event_id=_uuid4(),
        ts=1.0,
        source_type="synthetic",
        src_ip="10.0.0.9",
        src_port=1,
        dst_ip="10.0.0.1",
        dst_port=2,
        protocol="TCP",
        tcp_flags="sa",
        packet_length=1,
    )
    assert event.tcp_flags == "SA"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"protocol": "NOTAPROTOCOL"},
        {"source_type": "bogus"},
        {"dst_port": 70000},
        {"src_port": -1},
        {"ts": float("nan")},
        {"ts": float("inf")},
        {"ts": 0.0},
        {"ts": -5.0},
        {"event_id": "not-a-uuid"},
        {"src_ip": "not-an-ip"},
        {"tcp_flags": "SZ"},  # invalid flag letter
    ],
)
def test_packet_event_rejects_invalid_fields(kwargs: dict) -> None:
    base = {
        "event_id": _uuid4(),
        "ts": 1.0,
        "source_type": "synthetic",
        "src_ip": "10.0.0.9",
        "src_port": 1,
        "dst_ip": "10.0.0.1",
        "dst_port": 2,
        "protocol": "TCP",
        "tcp_flags": "S",
        "packet_length": 1,
    }
    base.update(kwargs)
    with pytest.raises(ValidationError):
        PacketEvent(**base)


def test_packet_event_rejects_uuid_that_is_not_v4() -> None:
    v1 = str(uuid.uuid1())
    with pytest.raises(ValidationError):
        PacketEvent(
            event_id=v1,
            ts=1.0,
            source_type="synthetic",
            src_ip="10.0.0.9",
            dst_ip="10.0.0.1",
            protocol="ICMP",
            packet_length=1,
        )


def test_packet_event_rejects_non_tcp_with_flags() -> None:
    with pytest.raises(ValidationError):
        PacketEvent(
            event_id=_uuid4(),
            ts=1.0,
            source_type="synthetic",
            src_ip="10.0.0.9",
            dst_ip="10.0.0.1",
            protocol="UDP",
            tcp_flags="S",
            packet_length=1,
        )


@pytest.mark.parametrize("protocol", ["ICMP", "OTHER"])
def test_packet_event_rejects_icmp_other_with_port(protocol: str) -> None:
    with pytest.raises(ValidationError):
        PacketEvent(
            event_id=_uuid4(),
            ts=1.0,
            source_type="synthetic",
            src_ip="10.0.0.9",
            dst_ip="10.0.0.1",
            dst_port=80,
            protocol=protocol,
            packet_length=1,
        )


def test_packet_event_is_frozen() -> None:
    event = PacketEvent(
        event_id=_uuid4(),
        ts=1.0,
        source_type="synthetic",
        src_ip="10.0.0.9",
        dst_ip="10.0.0.1",
        protocol="ICMP",
        packet_length=1,
    )
    with pytest.raises(ValidationError):
        event.ts = 2.0  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# Evidence models
# --------------------------------------------------------------------------- #
def test_portscan_evidence_rejects_too_many_sampled_ports() -> None:
    with pytest.raises(ValidationError):
        PortScanEvidence(
            distinct_port_count=25,
            sampled_ports=list(range(21)),
            syn_count=25,
            window_start=1.0,
            window_end=2.0,
            duration_s=1.0,
        )


def test_portscan_evidence_rejects_duplicate_sampled_ports() -> None:
    with pytest.raises(ValidationError):
        PortScanEvidence(
            distinct_port_count=2,
            sampled_ports=[80, 80],
            syn_count=2,
            window_start=1.0,
            window_end=2.0,
            duration_s=1.0,
        )


def test_portscan_evidence_rejects_unordered_window() -> None:
    with pytest.raises(ValidationError):
        PortScanEvidence(
            distinct_port_count=1,
            sampled_ports=[80],
            syn_count=1,
            window_start=5.0,
            window_end=2.0,
            duration_s=0.0,
        )


def test_synflood_evidence_rejects_completed_exceeding_syn_count() -> None:
    with pytest.raises(ValidationError):
        SynFloodEvidence(
            syn_count=10,
            synack_count=10,
            completed_handshakes=11,
            completion_ratio=1.0,
            distinct_src_count=1,
            syn_rate_per_s=2.0,
            window_start=1.0,
            window_end=2.0,
        )


def test_synflood_evidence_rejects_ratio_above_one() -> None:
    with pytest.raises(ValidationError):
        SynFloodEvidence(
            syn_count=10,
            synack_count=10,
            completed_handshakes=10,
            completion_ratio=1.5,
            distinct_src_count=1,
            syn_rate_per_s=2.0,
            window_start=1.0,
            window_end=2.0,
        )


# --------------------------------------------------------------------------- #
# CandidateAlert
# --------------------------------------------------------------------------- #
def _candidate(**overrides: object) -> CandidateAlert:
    kwargs: dict = {
        "detector_id": "portscan",
        "detector_version": "1.0",
        "category": "reconnaissance",
        "severity": "medium",
        "confidence": 0.6,
        "src_ip": "10.0.0.9",
        "dst_ip": "10.0.0.1",
        "source_type": "synthetic",
        "evidence": {"distinct_port_count": 15},
        "threshold_snapshot": {"PORTSCAN_MIN_PORTS": 15},
        "window_start": 1000.0,
        "window_end": 1004.0,
    }
    kwargs.update(overrides)
    return CandidateAlert(**kwargs)


def test_candidate_alert_valid() -> None:
    candidate = _candidate()
    assert candidate.severity == "medium"


def test_candidate_alert_rejects_confidence_above_cap() -> None:
    with pytest.raises(ValidationError):
        _candidate(confidence=0.96)


def test_candidate_alert_rejects_unordered_window() -> None:
    with pytest.raises(ValidationError):
        _candidate(window_start=1004.0, window_end=1000.0)


def test_candidate_alert_strips_and_requires_detector_id() -> None:
    assert _candidate(detector_id="  portscan  ").detector_id == "portscan"
    with pytest.raises(ValidationError):
        _candidate(detector_id="   ")


def test_candidate_alert_has_no_identity_or_lifecycle_fields() -> None:
    candidate = _candidate()
    for forbidden in (
        "alert_id",
        "created_at",
        "dedup_key",
        "occurrence_count",
        "last_seen",
        "ai_explanation",
        "ai_status",
    ):
        assert not hasattr(candidate, forbidden)


def test_candidate_alert_rejects_extra_lifecycle_fields() -> None:
    with pytest.raises(ValidationError):
        _candidate(alert_id=_uuid4())


# --------------------------------------------------------------------------- #
# Non-finite JSON rejection (evidence / threshold_snapshot, at any depth)
#
# Pydantic's JsonValue accepts NaN/Infinity and serialises them to null, which
# would silently destroy evidence rather than refuse it. Both alert models must
# reject them wherever they appear.
# --------------------------------------------------------------------------- #
_NON_FINITE = [float("nan"), float("inf"), float("-inf")]

_NESTINGS = [
    pytest.param(lambda bad: bad, id="top-level"),
    pytest.param(lambda bad: {"inner": bad}, id="nested-dict"),
    pytest.param(lambda bad: [1.0, bad], id="nested-list"),
    pytest.param(lambda bad: {"a": [{"b": [bad]}]}, id="deeply-nested"),
]


@pytest.mark.parametrize("bad", _NON_FINITE)
@pytest.mark.parametrize("nest", _NESTINGS)
@pytest.mark.parametrize("field", ["evidence", "threshold_snapshot"])
def test_candidate_alert_rejects_non_finite_json(
    bad: float, nest: Callable[[float], JsonValue], field: str
) -> None:
    with pytest.raises(ValidationError, match="non-finite"):
        _candidate(**{field: {"value": nest(bad)}})


@pytest.mark.parametrize("bad", _NON_FINITE)
@pytest.mark.parametrize("nest", _NESTINGS)
@pytest.mark.parametrize("field", ["evidence", "threshold_snapshot"])
def test_alert_rejects_non_finite_json(
    bad: float, nest: Callable[[float], JsonValue], field: str
) -> None:
    with pytest.raises(ValidationError, match="non-finite"):
        _alert(**{field: {"value": nest(bad)}})


@pytest.mark.parametrize("model", ["candidate", "alert"])
def test_finite_nested_json_is_accepted(model: str) -> None:
    """The recursive check must not reject ordinary nested evidence."""
    evidence: dict[str, JsonValue] = {
        "distinct_port_count": 15,
        "sampled_ports": [80, 443],
        "nested": {"rate": 1.5, "flags": [True, None, "S"]},
    }
    built = _candidate(evidence=evidence) if model == "candidate" else _alert(evidence=evidence)
    assert built.evidence == evidence


# --------------------------------------------------------------------------- #
# Alert
# --------------------------------------------------------------------------- #
def _alert(**overrides: object) -> Alert:
    kwargs: dict = {
        "alert_id": _uuid4(),
        "created_at": 1000.0,
        "detector_id": "portscan",
        "detector_version": "1.0",
        "category": "reconnaissance",
        "severity": "medium",
        "confidence": 0.6,
        "src_ip": "10.0.0.9",
        "dst_ip": "10.0.0.1",
        "window_start": 1000.0,
        "window_end": 1004.0,
        "evidence": {"distinct_port_count": 15},
        "threshold_snapshot": {"PORTSCAN_MIN_PORTS": 15},
        "dedup_key": _dedup_key(),
        "source_type": "synthetic",
        "last_seen": 1004.0,
    }
    kwargs.update(overrides)
    return Alert(**kwargs)


def test_alert_valid_defaults() -> None:
    alert = _alert()
    assert alert.occurrence_count == 1
    assert alert.ai_status == "none"


def test_alert_rejects_non_uuidv4_id() -> None:
    with pytest.raises(ValidationError):
        _alert(alert_id="not-a-uuid")


def test_alert_rejects_created_after_last_seen() -> None:
    with pytest.raises(ValidationError):
        _alert(created_at=2000.0, last_seen=1000.0)


def test_alert_rejects_unordered_window() -> None:
    with pytest.raises(ValidationError):
        _alert(window_start=1004.0, window_end=1000.0)


def test_alert_rejects_non_finite_created_at() -> None:
    with pytest.raises(ValidationError):
        _alert(created_at=float("inf"))


@pytest.mark.parametrize("bad_key", ["short", "z" * 40, "0" * 39])
def test_alert_rejects_bad_dedup_key(bad_key: str) -> None:
    with pytest.raises(ValidationError):
        _alert(dedup_key=bad_key)


def test_alert_rejects_zero_occurrence_count() -> None:
    with pytest.raises(ValidationError):
        _alert(occurrence_count=0)
