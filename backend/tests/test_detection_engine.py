"""Tests for the detection engine's logical clock and event-time policy."""

import pytest

from app.detection import DetectionEngine, PortScanConfig, PortScanDetector, SynFloodDetector
from app.ingest.synthetic import icmp, syn
from app.models.candidate_alert import CandidateAlert
from app.models.enums import SourceType
from app.models.packet_event import PacketEvent

SERVER = "10.0.0.10"
CLIENT = "10.0.0.50"


def _feed_ports(
    engine: DetectionEngine,
    count: int,
    *,
    start_ts: float,
    source_type: SourceType = "synthetic",
) -> list[CandidateAlert]:
    candidates: list[CandidateAlert] = []
    ts = start_ts
    for i in range(count):
        event = syn(CLIENT, SERVER, 1000 + i, ts, sport=40000 + i, source_type=source_type)
        candidates.extend(engine.process(event))
        ts += 0.1
    return candidates


# --------------------------------------------------------------------------- #
# High-water mark and reordering
# --------------------------------------------------------------------------- #
def test_hwm_advances_monotonically(engine: DetectionEngine) -> None:
    engine.process(icmp(CLIENT, SERVER, 1000.0))
    assert engine.high_water_mark("synthetic") == 1000.0
    engine.process(icmp(CLIENT, SERVER, 1005.0))
    assert engine.high_water_mark("synthetic") == 1005.0


def test_mild_reorder_does_not_rewind_hwm(engine: DetectionEngine) -> None:
    engine.process(icmp(CLIENT, SERVER, 1005.0))
    engine.process(icmp(CLIENT, SERVER, 1002.0))  # older, but within window
    assert engine.high_water_mark("synthetic") == 1005.0


def test_too_late_event_is_dropped_and_counted(engine: DetectionEngine) -> None:
    engine.process(icmp(CLIENT, SERVER, 1000.0))  # hwm = 1000, max_window = 10
    # Exactly at the lower bound is still accepted.
    assert engine.process(icmp(CLIENT, SERVER, 990.0)) == []
    assert engine.dropped_late == 0
    # Just beyond the lower bound is dropped.
    engine.process(icmp(CLIENT, SERVER, 989.999))
    assert engine.dropped_late == 1


def test_non_finite_ts_never_reaches_detectors(engine: DetectionEngine) -> None:
    # Bypass schema validation to exercise the engine's defensive guard.
    bad = PacketEvent.model_construct(
        event_id="x",
        ts=float("nan"),
        source_type="synthetic",
        src_ip=CLIENT,
        src_port=1,
        dst_ip=SERVER,
        dst_port=2,
        protocol="TCP",
        tcp_flags="S",
        packet_length=1,
        ingest_batch_id=None,
    )
    assert engine.process(bad) == []
    assert engine.dropped_invalid == 1
    assert engine.high_water_mark("synthetic") is None


# --------------------------------------------------------------------------- #
# Acceptance horizon derivation (never trust a caller value blindly)
# --------------------------------------------------------------------------- #
def test_max_window_derived_from_detectors() -> None:
    portscan = PortScanDetector(
        PortScanConfig(window_s=30.0, min_ports=15, critical_ports=100, state_ttl_s=60.0)
    )
    engine = DetectionEngine([portscan])
    assert engine.max_window_s == 30.0  # not hardcoded to any single detector


def test_supplied_max_window_below_derived_raises(
    portscan: PortScanDetector, synflood: SynFloodDetector
) -> None:
    with pytest.raises(ValueError, match="max_window_s"):
        DetectionEngine([portscan, synflood], max_window_s=5.0)  # derived is 10


def test_supplied_max_window_at_or_above_derived_accepted(
    portscan: PortScanDetector, synflood: SynFloodDetector
) -> None:
    engine = DetectionEngine([portscan, synflood], max_window_s=20.0)
    assert engine.max_window_s == 20.0


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_supplied_max_window_rejected(
    portscan: PortScanDetector, synflood: SynFloodDetector, bad: float
) -> None:
    # A non-finite horizon makes the too-late comparison meaningless: +inf accepts
    # every event, NaN drops every event, and neither is a usable policy.
    with pytest.raises(ValueError, match="finite"):
        DetectionEngine([portscan, synflood], max_window_s=bad)


class _NonFiniteHorizonDetector:
    """A detector reporting an unusable acceptance horizon (protocol conformance)."""

    detector_id = "broken"
    detector_version = "1.0"

    def __init__(self, max_event_age_s: float) -> None:
        self._age = max_event_age_s

    @property
    def max_event_age_s(self) -> float:
        return self._age

    def update(self, event: PacketEvent, now: float) -> list[CandidateAlert]:
        return []

    def expire(self, source_type: SourceType, now: float) -> None:
        return None


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_detector_derived_horizon_rejected(bad: float) -> None:
    with pytest.raises(ValueError, match="non-finite max_event_age_s"):
        DetectionEngine([_NonFiniteHorizonDetector(bad)])


# --------------------------------------------------------------------------- #
# Irrelevant traffic still advances time and expires stale state
# --------------------------------------------------------------------------- #
def test_irrelevant_traffic_advances_time_and_rearms_latch(
    portscan: PortScanDetector,
) -> None:
    engine = DetectionEngine([portscan])
    _feed_ports(engine, 15, start_ts=1000.0)
    key = ("10.0.0.50", "10.0.0.10")
    assert portscan._partitions["synthetic"].keys[key].latch.active is True

    # Only ICMP now, advancing logical time past the 10 s window.
    engine.process(icmp(CLIENT, SERVER, 1013.0))
    assert portscan._partitions["synthetic"].keys[key].latch.active is False


def test_irrelevant_traffic_expires_idle_key(portscan: PortScanDetector) -> None:
    engine = DetectionEngine([portscan])
    _feed_ports(engine, 15, start_ts=1000.0)
    assert portscan._partitions["synthetic"].keys  # key present

    engine.process(icmp(CLIENT, SERVER, 1000.0 + 60.0 + 5.0))  # past STATE_TTL (60 s)
    assert not portscan._partitions["synthetic"].keys  # idle key pruned


# --------------------------------------------------------------------------- #
# Cross-source isolation, including widely divergent timelines
# --------------------------------------------------------------------------- #
def test_live_events_do_not_expire_synthetic_state(
    portscan: PortScanDetector,
) -> None:
    engine = DetectionEngine([portscan])
    # 14 synthetic ports (no trigger yet) around ts ~1000.
    assert _feed_ports(engine, 14, start_ts=1000.0) == []
    # A live event on a far-future timeline must not expire the synthetic key.
    engine.process(syn("10.9.9.9", SERVER, 22, 1_600_000_000.0, source_type="live"))
    # The 15th synthetic port still completes the scan → exactly one candidate.
    candidates = engine.process(syn(CLIENT, SERVER, 2000, 1001.5, sport=41000))
    assert [c.detector_id for c in candidates] == ["portscan"]


def test_engine_expires_only_the_events_own_source_type(portscan: PortScanDetector) -> None:
    engine = DetectionEngine([portscan])
    _feed_ports(engine, 1, start_ts=1000.0)
    _feed_ports(engine, 1, start_ts=1000.0, source_type="live")
    # Processing a far-future live event drives expire("live", now) only, so the
    # synthetic partition's clock must not be dragged forward with it.
    engine.process(syn("10.9.9.9", SERVER, 22, 1_600_000_000.0, source_type="live"))
    assert portscan._partitions["synthetic"].hwm == 1000.0
    assert portscan._partitions["synthetic"].keys


# --------------------------------------------------------------------------- #
# Replay parity: detection depends only on ts, not on call spacing
# --------------------------------------------------------------------------- #
def test_identical_timestamps_yield_identical_alerts(
    portscan_config: PortScanConfig,
) -> None:
    def run() -> list[dict]:
        engine = DetectionEngine([PortScanDetector(portscan_config)])
        out = _feed_ports(engine, 15, start_ts=5000.0)
        return [c.evidence for c in out]

    assert run() == run()
