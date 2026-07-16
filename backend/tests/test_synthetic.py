"""Tests for the deterministic synthetic event generator."""

import uuid

from app.detection import DetectionEngine, PortScanDetector, SynFloodDetector
from app.ingest import synthetic
from app.models.candidate_alert import CandidateAlert
from app.models.packet_event import PacketEvent


def _run(events: list[PacketEvent], engine: DetectionEngine) -> list[CandidateAlert]:
    out: list[CandidateAlert] = []
    for event in events:
        out.extend(engine.process(event))
    return out


# --------------------------------------------------------------------------- #
# Labelling and determinism
# --------------------------------------------------------------------------- #
def test_all_default_events_are_labelled_synthetic() -> None:
    assert all(event.source_type == "synthetic" for event in synthetic.default_scenarios())


def test_scenarios_are_deterministic() -> None:
    assert synthetic.port_scan() == synthetic.port_scan()
    assert synthetic.syn_burst() == synthetic.syn_burst()
    assert synthetic.normal_traffic() == synthetic.normal_traffic()


def test_event_ids_are_deterministic() -> None:
    first = [event.event_id for event in synthetic.default_scenarios()]
    second = [event.event_id for event in synthetic.default_scenarios()]
    assert first == second


def test_event_ids_unique_across_default_scenarios() -> None:
    ids = [event.event_id for event in synthetic.default_scenarios()]
    assert len(ids) == len(set(ids))


def test_event_ids_unique_across_separately_invoked_scenarios() -> None:
    ids = [
        event.event_id
        for scenario in (synthetic.normal_traffic(), synthetic.port_scan(), synthetic.syn_burst())
        for event in scenario
    ]
    assert len(ids) == len(set(ids))


def test_deterministic_uuid4_is_valid_v4_and_injective() -> None:
    a = synthetic.deterministic_uuid4(2, 0)
    b = synthetic.deterministic_uuid4(2, 1)
    c = synthetic.deterministic_uuid4(3, 0)
    assert a.version == 4 and b.version == 4 and c.version == 4
    assert len({a, b, c}) == 3
    assert isinstance(uuid.UUID(str(a)), uuid.UUID)


# --------------------------------------------------------------------------- #
# Scenario outcomes through the engine
# --------------------------------------------------------------------------- #
def test_normal_traffic_raises_no_alerts() -> None:
    engine = _fresh_engine()
    assert _run(synthetic.normal_traffic(), engine) == []


def test_port_scan_raises_one_portscan_alert() -> None:
    engine = _fresh_engine()
    out = _run(synthetic.port_scan(), engine)
    assert len(out) == 1
    candidate = out[0]
    assert candidate.detector_id == "portscan"
    assert candidate.severity == "medium"
    # Edge-triggered: the single candidate captures state at the threshold crossing.
    assert candidate.evidence["distinct_port_count"] == 15


def test_syn_burst_raises_synflood_alert() -> None:
    engine = _fresh_engine()
    out = _run(synthetic.syn_burst(), engine)
    detectors = {candidate.detector_id for candidate in out}
    assert detectors == {"synflood"}
    synflood = next(c for c in out if c.detector_id == "synflood")
    assert synflood.evidence["syn_count"] == 100  # trigger crossing
    assert synflood.evidence["completion_ratio"] == 0.0
    assert synflood.evidence["distinct_src_count"] == 100


def test_scenarios_do_not_cross_fire() -> None:
    scan_out = _run(synthetic.port_scan(), _fresh_engine())
    burst_out = _run(synthetic.syn_burst(), _fresh_engine())
    assert {c.detector_id for c in scan_out} == {"portscan"}
    assert {c.detector_id for c in burst_out} == {"synflood"}


def _fresh_engine() -> DetectionEngine:
    from app.detection.config import DetectionSettings

    settings = DetectionSettings(_env_file=None)
    return DetectionEngine(
        [
            PortScanDetector(settings.to_portscan_config()),
            SynFloodDetector(settings.to_synflood_config()),
        ]
    )
