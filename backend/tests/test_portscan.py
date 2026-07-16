"""Tests for the ``portscan`` detector (v1.0)."""

import pytest

from app.detection import PortScanDetector
from app.ingest.synthetic import ack, icmp, make_event, syn, synack
from app.models.candidate_alert import CandidateAlert
from app.models.enums import SourceType

CLIENT = "10.0.0.50"
SERVER = "10.0.0.10"
SYNTH: SourceType = "synthetic"


def _scan(
    detector: PortScanDetector,
    n: int,
    *,
    ts: float = 1000.0,
    now: float | None = None,
    first_port: int = 1000,
    client: str = CLIENT,
    server: str = SERVER,
) -> list[CandidateAlert]:
    """Feed ``n`` distinct ports at the same timestamp; return emitted candidates."""
    at = ts if now is None else now
    out: list[CandidateAlert] = []
    for i in range(n):
        event = syn(client, server, first_port + i, ts, sport=40000 + i)
        out.extend(detector.update(event, at))
    return out


def _keys(detector: PortScanDetector) -> dict:
    partition = detector._partitions.get(SYNTH)
    return {} if partition is None else partition.keys


# --------------------------------------------------------------------------- #
# Threshold boundary
# --------------------------------------------------------------------------- #
def test_below_threshold_does_not_alert(portscan: PortScanDetector) -> None:
    assert _scan(portscan, 14) == []


def test_at_threshold_alerts_once(portscan: PortScanDetector) -> None:
    out = _scan(portscan, 15)
    assert len(out) == 1
    assert out[0].detector_id == "portscan"
    assert out[0].severity == "medium"
    assert out[0].evidence["distinct_port_count"] == 15
    assert out[0].confidence == pytest.approx(0.60)


def test_exactly_one_candidate_for_steady_scan(portscan: PortScanDetector) -> None:
    assert len(_scan(portscan, 20)) == 1  # stays medium (15-29) -> one candidate


# --------------------------------------------------------------------------- #
# Inclusive lower window bound
# --------------------------------------------------------------------------- #
def test_syn_at_lower_bound_is_counted(portscan: PortScanDetector) -> None:
    now = 1010.0  # window 10 -> lower bound 1000.0
    for i in range(14):
        portscan.update(syn(CLIENT, SERVER, 1000 + i, 1010.0, sport=40000 + i), now)
    out = portscan.update(syn(CLIENT, SERVER, 2000, 1000.0, sport=41000), now)
    assert len(out) == 1  # 15th port at exactly the lower bound counts


def test_syn_just_below_lower_bound_is_excluded(portscan: PortScanDetector) -> None:
    now = 1010.0
    for i in range(14):
        portscan.update(syn(CLIENT, SERVER, 1000 + i, 1010.0, sport=40000 + i), now)
    out = portscan.update(syn(CLIENT, SERVER, 2000, 999.999, sport=41000), now)
    assert out == []  # excluded -> only 14 distinct ports


# --------------------------------------------------------------------------- #
# Severity bands, confidence, escalation
# --------------------------------------------------------------------------- #
def test_severity_escalates_and_emits_each_higher_band(portscan: PortScanDetector) -> None:
    out = _scan(portscan, 100)
    assert [c.severity for c in out] == ["medium", "high", "critical"]
    assert [c.evidence["distinct_port_count"] for c in out] == [15, 30, 100]
    assert out[-1].confidence == pytest.approx(0.95)


def test_high_band_boundary(portscan: PortScanDetector) -> None:
    out = _scan(portscan, 30)
    assert [c.severity for c in out] == ["medium", "high"]


# --------------------------------------------------------------------------- #
# Out-of-order insertion and window expiry
# --------------------------------------------------------------------------- #
def test_out_of_order_in_window_syn_counts(portscan: PortScanDetector) -> None:
    for i in range(10):
        portscan.update(syn(CLIENT, SERVER, 1000 + i, 1000.0, sport=40000 + i), 1000.0)
    for i in range(4):
        portscan.update(syn(CLIENT, SERVER, 1100 + i, 1005.0, sport=41000 + i), 1005.0)
    # An out-of-order but still in-window SYN (ts=1001, now=1005) is the 15th port.
    out = portscan.update(syn(CLIENT, SERVER, 2000, 1001.0, sport=42000), 1005.0)
    assert len(out) == 1


def test_window_slide_evicts_old_ports(portscan: PortScanDetector) -> None:
    _scan(portscan, 15, ts=1000.0)  # triggers
    key = (CLIENT, SERVER)
    # Advance well past the window using irrelevant traffic; old ports age out.
    portscan.update(icmp(CLIENT, SERVER, 1013.0), 1013.0)
    assert _keys(portscan)[key].distinct_ports == 0
    assert _keys(portscan)[key].latch.active is False


# --------------------------------------------------------------------------- #
# State TTL boundary and re-arm / re-fire
# --------------------------------------------------------------------------- #
def test_state_ttl_boundary_exact(portscan: PortScanDetector) -> None:
    portscan.update(syn(CLIENT, SERVER, 80, 1000.0), 1000.0)
    key = (CLIENT, SERVER)
    portscan.update(icmp(CLIENT, SERVER, 1060.0), 1060.0)  # exactly TTL (60 s)
    assert key in _keys(portscan)
    portscan.update(icmp(CLIENT, SERVER, 1060.001), 1060.001)  # just beyond
    assert key not in _keys(portscan)


def test_rearm_allows_refire(portscan: PortScanDetector) -> None:
    first = _scan(portscan, 15, ts=1000.0)
    portscan.update(icmp(CLIENT, SERVER, 1015.0), 1015.0)  # ports age out, latch re-arms
    second = _scan(portscan, 15, ts=1016.0, first_port=5000)
    assert len(first) == 1
    assert len(second) == 1


# --------------------------------------------------------------------------- #
# Source-aware expiry: expire(source_type, now) honours the supplied logical
# time, but only for the named partition (DETECTION_RULES §2).
# --------------------------------------------------------------------------- #
def test_expire_retains_state_at_exact_ttl_boundary(portscan: PortScanDetector) -> None:
    portscan.update(syn(CLIENT, SERVER, 80, 1000.0), 1000.0)
    portscan.expire(SYNTH, 1060.0)  # exactly PORTSCAN_STATE_TTL_S
    assert (CLIENT, SERVER) in _keys(portscan)


def test_expire_removes_state_just_beyond_ttl(portscan: PortScanDetector) -> None:
    portscan.update(syn(CLIENT, SERVER, 80, 1000.0), 1000.0)
    portscan.expire(SYNTH, 1060.001)
    assert (CLIENT, SERVER) not in _keys(portscan)


def test_expiring_live_leaves_synthetic_state_untouched(portscan: PortScanDetector) -> None:
    portscan.update(syn(CLIENT, SERVER, 80, 1000.0), 1000.0)
    portscan.update(syn(CLIENT, SERVER, 80, 1000.0, source_type="live"), 1000.0)
    portscan.expire("live", 1_600_000_000.0)
    assert not portscan._partitions["live"].keys  # the named partition is swept
    assert (CLIENT, SERVER) in _keys(portscan)  # the other provenance survives
    assert portscan._partitions[SYNTH].hwm == 1000.0  # and its clock never moved


def test_expiring_synthetic_leaves_live_state_untouched(portscan: PortScanDetector) -> None:
    portscan.update(syn(CLIENT, SERVER, 80, 1000.0), 1000.0)
    portscan.update(syn(CLIENT, SERVER, 80, 1000.0, source_type="live"), 1000.0)
    portscan.expire(SYNTH, 1_600_000_000.0)
    assert not _keys(portscan)
    assert portscan._partitions["live"].keys
    assert portscan._partitions["live"].hwm == 1000.0


def test_expire_on_unknown_source_type_is_a_no_op(portscan: PortScanDetector) -> None:
    portscan.update(syn(CLIENT, SERVER, 80, 1000.0), 1000.0)
    portscan.expire("replay", 1_600_000_000.0)  # no replay state has ever been seen
    assert (CLIENT, SERVER) in _keys(portscan)
    assert "replay" not in portscan._partitions


# --------------------------------------------------------------------------- #
# Evidence window times
# --------------------------------------------------------------------------- #
def test_evidence_window_times_use_span(portscan: PortScanDetector) -> None:
    out: list[CandidateAlert] = []
    ts = 1000.0
    for i in range(15):
        out.extend(portscan.update(syn(CLIENT, SERVER, 1000 + i, ts, sport=40000 + i), ts))
        ts += 0.1
    candidate = out[-1]
    assert candidate.window_end == pytest.approx(1000.0 + 14 * 0.1)
    assert candidate.window_start == pytest.approx(1000.0)
    assert candidate.evidence["duration_s"] == pytest.approx(
        candidate.window_end - candidate.window_start
    )


def test_window_end_is_hwm_not_triggering_event_ts(portscan: PortScanDetector) -> None:
    for i in range(14):
        portscan.update(syn(CLIENT, SERVER, 1000 + i, 1000.0, sport=40000 + i), 1000.0)
    # Triggering event is out-of-order (ts=1002) but HWM is ahead (now=1008).
    out = portscan.update(syn(CLIENT, SERVER, 2000, 1002.0, sport=41000), 1008.0)
    assert len(out) == 1
    assert out[0].window_end == pytest.approx(1008.0)  # HWM, not 1002
    assert out[0].window_start == pytest.approx(1000.0)


# --------------------------------------------------------------------------- #
# Duplicate/retransmit, ignored packets, isolation, monotonic timestamps
# --------------------------------------------------------------------------- #
def test_duplicate_port_not_double_counted(portscan: PortScanDetector) -> None:
    for i in range(14):
        portscan.update(syn(CLIENT, SERVER, 1000 + i, 1000.0, sport=40000 + i), 1000.0)
    # Re-probe an already-seen port: distinct stays 14, no alert.
    assert portscan.update(syn(CLIENT, SERVER, 1000, 1000.0, sport=50000), 1000.0) == []
    out = portscan.update(syn(CLIENT, SERVER, 2000, 1000.0, sport=50001), 1000.0)
    assert len(out) == 1
    assert out[0].evidence["distinct_port_count"] == 15
    assert out[0].evidence["syn_count"] == 16  # includes the retransmit


def test_ignores_missing_required_fields(portscan: PortScanDetector) -> None:
    no_port = make_event(
        ts=1000.0, src_ip=CLIENT, src_port=1, dst_ip=SERVER, protocol="TCP", tcp_flags="S"
    )
    no_flags = make_event(
        ts=1000.0, src_ip=CLIENT, src_port=1, dst_ip=SERVER, dst_port=80, protocol="TCP"
    )
    assert portscan.update(no_port, 1000.0) == []
    assert portscan.update(no_flags, 1000.0) == []
    assert not _keys(portscan)


def test_syn_ack_and_final_ack_are_not_counted(portscan: PortScanDetector) -> None:
    for i in range(15):
        portscan.update(synack(CLIENT, SERVER, 1000 + i, 1000.0, sport=40000 + i), 1000.0)
        portscan.update(ack(CLIENT, SERVER, 1000 + i, 1000.0, sport=40000 + i), 1000.0)
    assert not _keys(portscan)


def test_multiple_attackers_are_isolated(portscan: PortScanDetector) -> None:
    attacker2 = "10.0.0.51"
    triggered = _scan(portscan, 15, client=CLIENT, first_port=1000)
    quiet = _scan(portscan, 14, client=attacker2, first_port=3000)
    assert len(triggered) == 1
    assert quiet == []
    assert (CLIENT, SERVER) in _keys(portscan)
    assert (attacker2, SERVER) in _keys(portscan)


def test_last_syn_ts_is_monotonic(portscan: PortScanDetector) -> None:
    portscan.update(syn(CLIENT, SERVER, 80, 1005.0), 1005.0)
    portscan.update(syn(CLIENT, SERVER, 81, 1002.0), 1005.0)  # out of order
    assert _keys(portscan)[(CLIENT, SERVER)].last_syn_ts == 1005.0
