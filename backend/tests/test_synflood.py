"""Tests for the ``synflood`` detector (v1.0)."""

from collections.abc import Callable

import pytest

from app.detection import SynFloodConfig, SynFloodDetector
from app.detection.synflood import _KeyState
from app.ingest.synthetic import ack, icmp, rst, syn, synack
from app.models.candidate_alert import CandidateAlert
from app.models.enums import SourceType
from app.models.packet_event import PacketEvent

CLIENT = "10.0.0.50"
SERVER = "10.0.0.10"
SYNTH: SourceType = "synthetic"


def _small(min_count: int = 10) -> SynFloodDetector:
    return SynFloodDetector(
        SynFloodConfig(
            window_s=5.0,
            min_count=min_count,
            max_completion_ratio=0.2,
            handshake_ttl_s=10.0,
            state_ttl_s=30.0,
        )
    )


def _state(
    detector: SynFloodDetector, target: str = SERVER, source_type: SourceType = SYNTH
) -> _KeyState:
    return detector._partitions[source_type].keys[target]


def _has_key(
    detector: SynFloodDetector, target: str = SERVER, source_type: SourceType = SYNTH
) -> bool:
    partition = detector._partitions.get(source_type)
    return partition is not None and target in partition.keys


def _flood(
    detector: SynFloodDetector,
    n: int,
    *,
    server: str = SERVER,
    dport: int = 80,
    start_ts: float = 1000.0,
    step: float = 0.01,
    source_type: SourceType = SYNTH,
) -> tuple[list[CandidateAlert], float]:
    out: list[CandidateAlert] = []
    ts = start_ts
    for i in range(n):
        client = f"10.3.{i // 250}.{i % 250 + 1}"
        out.extend(
            detector.update(
                syn(client, server, dport, ts, sport=40000 + i % 60000, source_type=source_type),
                ts,
            )
        )
        ts += step
    return out, ts


# --------------------------------------------------------------------------- #
# Threshold boundary and headline trigger
# --------------------------------------------------------------------------- #
def test_below_min_count_does_not_alert(synflood: SynFloodDetector) -> None:
    out, _ = _flood(synflood, 99)
    assert out == []


def test_at_min_count_alerts(synflood: SynFloodDetector) -> None:
    out, _ = _flood(synflood, 100)
    assert len(out) == 1
    candidate = out[0]
    assert candidate.detector_id == "synflood"
    assert candidate.src_ip is None
    assert candidate.dst_ip == SERVER
    assert candidate.evidence["syn_count"] == 100
    assert candidate.evidence["completion_ratio"] == 0.0
    assert candidate.evidence["distinct_src_count"] == 100
    assert candidate.severity == "high"  # ratio 0 < max/2


def test_syn_ts_lower_bound_inclusive() -> None:
    detector = _small(min_count=10)  # window 5
    now = 1010.0  # lower bound = 1005
    for i in range(9):
        detector.update(syn(f"10.4.0.{i + 1}", SERVER, 80, 1010.0, sport=40000 + i), now)
    out = detector.update(syn("10.4.9.9", SERVER, 80, 1005.0, sport=45000), now)
    assert len(out) == 1  # 10th SYN at exactly the lower bound counts


def test_syn_ts_just_below_lower_bound_excluded() -> None:
    detector = _small(min_count=10)
    now = 1010.0
    for i in range(9):
        detector.update(syn(f"10.4.0.{i + 1}", SERVER, 80, 1010.0, sport=40000 + i), now)
    out = detector.update(syn("10.4.9.9", SERVER, 80, 1004.999, sport=45000), now)
    assert out == []


# --------------------------------------------------------------------------- #
# Severity and confidence formulas
# --------------------------------------------------------------------------- #
def test_severity_bands(synflood: SynFloodDetector) -> None:
    assert synflood._severity(100, 0.15) == "medium"
    assert synflood._severity(100, 0.05) == "high"  # ratio < max/2
    assert synflood._severity(200, 0.15) == "high"  # count >= 2*min
    assert synflood._severity(500, 0.04) == "critical"
    assert synflood._severity(500, 0.06) == "high"  # ratio not < max/4


def test_confidence_formula(synflood: SynFloodDetector) -> None:
    assert synflood._confidence(0.0) == pytest.approx(0.95)
    assert synflood._confidence(0.15) == pytest.approx(0.6875)
    assert synflood._confidence(0.2) == pytest.approx(0.60)


def test_medium_severity_via_completed_handshakes() -> None:
    detector = _small(min_count=10)  # max ratio 0.2
    # One completed handshake, then nine bare SYNs -> syn_count 10, ratio 0.1 -> medium.
    handshake = [
        syn(CLIENT, SERVER, 80, 1000.00, sport=5000),
        synack(CLIENT, SERVER, 80, 1000.01, sport=5000),
        ack(CLIENT, SERVER, 80, 1000.02, sport=5000),
    ]
    for event in handshake:
        detector.update(event, event.ts)
    out: list[CandidateAlert] = []
    ts = 1000.03
    for i in range(9):
        out.extend(detector.update(syn(f"10.5.0.{i + 1}", SERVER, 80, ts, sport=6000 + i), ts))
        ts += 0.01
    assert len(out) == 1
    assert out[0].severity == "medium"
    assert out[0].evidence["completion_ratio"] == pytest.approx(0.1)


# --------------------------------------------------------------------------- #
# Handshake state machine
# --------------------------------------------------------------------------- #
def test_retransmitted_syn_not_double_counted(synflood: SynFloodDetector) -> None:
    synflood.update(syn(CLIENT, SERVER, 80, 1000.0, sport=5000), 1000.0)
    synflood.update(syn(CLIENT, SERVER, 80, 1000.1, sport=5000), 1000.1)
    syn_count, _ = synflood._counts(_state(synflood))
    assert syn_count == 1


def test_orphan_syn_ack_does_not_count_syn(synflood: SynFloodDetector) -> None:
    synflood.update(synack(CLIENT, SERVER, 80, 1000.0, sport=5000), 1000.0)
    state = _state(synflood)
    syn_count, _ = synflood._counts(state)
    assert syn_count == 0
    assert len(state.synack_ts) == 1
    pending = next(iter(state.pending.values()))
    assert pending.syn_observed is False
    assert pending.state == "SYN_ACK_SEEN"


def test_orphan_syn_ack_then_ack_adds_no_completion(synflood: SynFloodDetector) -> None:
    synflood.update(synack(CLIENT, SERVER, 80, 1000.0, sport=5000), 1000.0)
    synflood.update(ack(CLIENT, SERVER, 80, 1000.2, sport=5000), 1000.2)
    syn_count, completed = synflood._counts(_state(synflood))
    assert (syn_count, completed) == (0, 0)


def test_observed_syn_missing_synack_then_ack_counts_completion(
    synflood: SynFloodDetector,
) -> None:
    synflood.update(syn(CLIENT, SERVER, 80, 1000.0, sport=5000), 1000.0)
    synflood.update(ack(CLIENT, SERVER, 80, 1000.2, sport=5000), 1000.2)
    syn_count, completed = synflood._counts(_state(synflood))
    assert (syn_count, completed) == (1, 1)


def test_late_syn_after_orphan_keeps_syn_ack_progress(synflood: SynFloodDetector) -> None:
    synflood.update(synack(CLIENT, SERVER, 80, 1000.0, sport=5000), 1000.0)
    synflood.update(syn(CLIENT, SERVER, 80, 1000.1, sport=5000), 1000.1)
    state = _state(synflood)
    pending = next(iter(state.pending.values()))
    assert pending.syn_observed is True
    assert pending.state == "SYN_ACK_SEEN"  # progress not lost
    assert synflood._counts(state)[0] == 1  # now cohort-eligible
    synflood.update(ack(CLIENT, SERVER, 80, 1000.2, sport=5000), 1000.2)
    assert synflood._counts(state) == (1, 1)


def test_four_tuple_reuse_creates_new_attempt(synflood: SynFloodDetector) -> None:
    synflood.update(syn(CLIENT, SERVER, 80, 1000.0, sport=5000), 1000.0)
    synflood.update(ack(CLIENT, SERVER, 80, 1000.2, sport=5000), 1000.2)  # completes attempt 1
    synflood.update(syn(CLIENT, SERVER, 80, 1000.4, sport=5000), 1000.4)  # reuse -> new attempt
    syn_count, completed = synflood._counts(_state(synflood))
    assert (syn_count, completed) == (2, 1)  # only the first attempt is completed


def test_rst_removes_pending_without_completion(synflood: SynFloodDetector) -> None:
    synflood.update(syn(CLIENT, SERVER, 80, 1000.0, sport=5000), 1000.0)
    synflood.update(rst(CLIENT, SERVER, 80, 1000.2, sport=5000), 1000.2)
    state = _state(synflood)
    assert state.pending == {}
    assert synflood._counts(state) == (1, 0)


def test_late_ack_is_age_gated(synflood: SynFloodDetector) -> None:
    synflood.update(syn(CLIENT, SERVER, 80, 1000.0, sport=5000), 1000.0)
    # ACK older than now - HANDSHAKE_TTL_S (10) must not complete anything.
    synflood.update(ack(CLIENT, SERVER, 80, 985.0, sport=5000), 1000.0)
    state = _state(synflood)
    assert synflood._counts(state) == (1, 0)
    assert state.pending  # pending untouched


# --------------------------------------------------------------------------- #
# State-creation gates: a packet that cannot affect the detector must leave no
# trace. Creating a key (or refreshing its TTL) for traffic the detector then
# ignores would leak memory and keep dead keys alive indefinitely.
# --------------------------------------------------------------------------- #
def test_out_of_window_syn_creates_no_state(synflood: SynFloodDetector) -> None:
    # SYN_WINDOW_S = 5, so a SYN at 994.999 cannot join the cohort at now = 1000.
    assert synflood.update(syn(CLIENT, SERVER, 80, 994.999, sport=5000), 1000.0) == []
    assert not _has_key(synflood)


@pytest.mark.parametrize("builder", [synack, ack, rst])
def test_age_gated_handshake_packet_creates_no_state(
    synflood: SynFloodDetector, builder: Callable[..., PacketEvent]
) -> None:
    # HANDSHAKE_TTL_S = 10, so a packet at 989.999 is beyond the gate at now = 1000.
    assert synflood.update(builder(CLIENT, SERVER, 80, 989.999, sport=5000), 1000.0) == []
    assert not _has_key(synflood)


def test_bare_ack_creates_no_target_key(synflood: SynFloodDetector) -> None:
    assert synflood.update(ack(CLIENT, SERVER, 80, 1000.0, sport=5000), 1000.0) == []
    assert not _has_key(synflood)


def test_unmatched_rst_creates_no_target_key(synflood: SynFloodDetector) -> None:
    assert synflood.update(rst(CLIENT, SERVER, 80, 1000.0, sport=5000), 1000.0) == []
    assert not _has_key(synflood)


def test_out_of_window_syn_does_not_refresh_state_ttl(synflood: SynFloodDetector) -> None:
    synflood.update(syn(CLIENT, SERVER, 80, 1000.0, sport=5000), 1000.0)
    synflood.update(icmp(CLIENT, SERVER, 1006.0), 1006.0)  # advance the HWM only
    # 1000.5 is newer than the key's last activity, but outside SYN_WINDOW_S (1001+).
    synflood.update(syn(CLIENT, SERVER, 80, 1000.5, sport=7000), 1006.0)
    state = _state(synflood)
    assert state.last_activity_ts == 1000.0  # TTL not refreshed by an ignored SYN
    assert synflood._counts(state)[0] == 0  # no cohort attempt registered
    assert list(state.pending) == [(CLIENT, 5000, SERVER, 80)]  # no new pending entry


@pytest.mark.parametrize("builder", [ack, rst])
def test_unmatched_handshake_packet_does_not_refresh_state_ttl(
    synflood: SynFloodDetector, builder: Callable[..., PacketEvent]
) -> None:
    synflood.update(syn(CLIENT, SERVER, 80, 1000.0, sport=5000), 1000.0)
    assert _state(synflood).last_activity_ts == 1000.0
    # Established-flow traffic on a 4-tuple the detector never tracked must not
    # keep the key alive past its idle TTL.
    synflood.update(builder(CLIENT, SERVER, 80, 1005.0, sport=6000), 1005.0)
    assert _state(synflood).last_activity_ts == 1000.0


# --------------------------------------------------------------------------- #
# SYN-ACK progression is separate from evidence-window accounting (§4.2)
# --------------------------------------------------------------------------- #
def test_old_syn_ack_progresses_pending_without_becoming_evidence(
    synflood: SynFloodDetector,
) -> None:
    synflood.update(syn(CLIENT, SERVER, 80, 1000.0, sport=5000), 1000.0)
    synflood.update(icmp(CLIENT, SERVER, 1008.0), 1008.0)  # advance the HWM only
    # ts 1001 is within HANDSHAKE_TTL_S (>= 998) but outside SYN_WINDOW_S (>= 1003).
    synflood.update(synack(CLIENT, SERVER, 80, 1001.0, sport=5000), 1008.0)
    state = _state(synflood)
    pending = next(iter(state.pending.values()))
    assert pending.state == "SYN_ACK_SEEN"  # progression is still allowed
    assert state.synack_ts == []  # but it never enters the evidence window


def test_out_of_window_syn_ack_absent_from_candidate_evidence() -> None:
    detector = _small(min_count=10)  # window 5, handshake TTL 10
    out, ts = _flood(detector, 9, start_ts=1006.0, step=0.01)
    assert out == []
    # A late-arriving SYN-ACK timestamped before the evidence window opened: it may
    # still match a handshake, but must not inflate synack_count.
    detector.update(synack(CLIENT, SERVER, 80, 1000.5, sport=5000), ts)
    assert _state(detector).synack_ts == []
    # The tenth SYN triggers; the old SYN-ACK is absent from the evidence.
    out = detector.update(syn("10.6.0.9", SERVER, 80, ts, sport=45000), ts)
    assert len(out) == 1
    assert out[0].evidence["synack_count"] == 0


def test_in_window_syn_ack_is_counted_as_evidence(synflood: SynFloodDetector) -> None:
    synflood.update(syn(CLIENT, SERVER, 80, 1000.0, sport=5000), 1000.0)
    synflood.update(synack(CLIENT, SERVER, 80, 1000.1, sport=5000), 1000.1)
    assert _state(synflood).synack_ts == [1000.1]


# --------------------------------------------------------------------------- #
# Source-aware expiry: expire(source_type, now) honours the supplied logical
# time, but only for the named partition (DETECTION_RULES §2).
# --------------------------------------------------------------------------- #
def test_expire_retains_state_at_exact_ttl_boundary(synflood: SynFloodDetector) -> None:
    synflood.update(syn(CLIENT, SERVER, 80, 1000.0, sport=5000), 1000.0)
    synflood.expire(SYNTH, 1030.0)  # exactly SYN_STATE_TTL_S
    assert _has_key(synflood)


def test_expire_removes_state_just_beyond_ttl(synflood: SynFloodDetector) -> None:
    synflood.update(syn(CLIENT, SERVER, 80, 1000.0, sport=5000), 1000.0)
    synflood.expire(SYNTH, 1030.001)
    assert not _has_key(synflood)


def test_expiring_live_leaves_synthetic_state_untouched(synflood: SynFloodDetector) -> None:
    synflood.update(syn(CLIENT, SERVER, 80, 1000.0, sport=5000), 1000.0)
    synflood.update(syn(CLIENT, SERVER, 80, 1000.0, sport=5000, source_type="live"), 1000.0)
    synflood.expire("live", 1_600_000_000.0)
    assert not _has_key(synflood, SERVER, "live")  # the named partition is swept
    assert _has_key(synflood, SERVER, SYNTH)  # the other provenance survives
    assert synflood._partitions[SYNTH].hwm == 1000.0  # and its clock never moved


def test_expiring_synthetic_leaves_live_state_untouched(synflood: SynFloodDetector) -> None:
    synflood.update(syn(CLIENT, SERVER, 80, 1000.0, sport=5000), 1000.0)
    synflood.update(syn(CLIENT, SERVER, 80, 1000.0, sport=5000, source_type="live"), 1000.0)
    synflood.expire(SYNTH, 1_600_000_000.0)
    assert not _has_key(synflood, SERVER, SYNTH)
    assert _has_key(synflood, SERVER, "live")
    assert synflood._partitions["live"].hwm == 1000.0


# --------------------------------------------------------------------------- #
# Reversed SYN-ACK / RST operate on the same destination-centric state
# --------------------------------------------------------------------------- #
def test_reversed_syn_ack_matches_inbound_syn_state(synflood: SynFloodDetector) -> None:
    synflood.update(syn(CLIENT, SERVER, 80, 1000.0, sport=5000), 1000.0)  # target = SERVER
    synflood.update(synack(CLIENT, SERVER, 80, 1000.1, sport=5000), 1000.1)  # target = src = SERVER
    state = _state(synflood, SERVER)
    pending = next(iter(state.pending.values()))
    assert pending.state == "SYN_ACK_SEEN"
    synflood.update(ack(CLIENT, SERVER, 80, 1000.2, sport=5000), 1000.2)
    assert synflood._counts(state) == (1, 1)  # completion recorded on the SERVER key


def test_reversed_rst_matches_inbound_syn_state(synflood: SynFloodDetector) -> None:
    synflood.update(syn(CLIENT, SERVER, 80, 1000.0, sport=5000), 1000.0)
    synflood.update(rst(CLIENT, SERVER, 80, 1000.1, sport=5000), 1000.1)  # target = src = SERVER
    state = _state(synflood, SERVER)
    assert state.pending == {}
    assert synflood._counts(state) == (1, 0)


# --------------------------------------------------------------------------- #
# Ratio bounds across mixed sequences
# --------------------------------------------------------------------------- #
def test_completion_ratio_bounds_hold(synflood: SynFloodDetector) -> None:
    ts = 1000.0
    for i in range(20):
        sport = 5000 + i
        synflood.update(syn(CLIENT, SERVER, 80, ts, sport=sport), ts)
        ts += 0.01
        if i % 3 == 0:  # some retransmits
            synflood.update(syn(CLIENT, SERVER, 80, ts, sport=sport), ts)
            ts += 0.01
        if i % 2 == 0:  # some completions
            synflood.update(ack(CLIENT, SERVER, 80, ts, sport=sport), ts)
            ts += 0.01
    # Some orphan SYN-ACKs
    for i in range(5):
        synflood.update(synack("10.7.0.9", SERVER, 90, ts, sport=7000 + i), ts)
        ts += 0.01
    syn_count, completed = synflood._counts(_state(synflood))
    assert completed <= syn_count
    assert 0.0 <= (completed / syn_count if syn_count else 0.0) <= 1.0


# --------------------------------------------------------------------------- #
# Cohort / pending expiry
# --------------------------------------------------------------------------- #
def test_syn_ages_out_of_cohort(synflood: SynFloodDetector) -> None:
    synflood.update(syn(CLIENT, SERVER, 80, 1000.0, sport=5000), 1000.0)
    assert synflood._counts(_state(synflood))[0] == 1
    synflood.update(icmp(CLIENT, SERVER, 1006.0), 1006.0)  # window 5 -> syn_ts 1000 < 1001
    assert synflood._counts(_state(synflood))[0] == 0


def test_pending_expiry_boundary_exact(synflood: SynFloodDetector) -> None:
    synflood.update(syn(CLIENT, SERVER, 80, 1000.0, sport=5000), 1000.0)
    synflood.update(icmp(CLIENT, SERVER, 1010.0), 1010.0)  # exactly HANDSHAKE_TTL (10)
    assert _state(synflood).pending  # retained at == TTL
    synflood.update(icmp(CLIENT, SERVER, 1010.001), 1010.001)  # just beyond
    assert _state(synflood).pending == {}
    assert synflood._counts(_state(synflood))[1] == 0  # expiry never adds a completion


def test_out_of_order_syn_then_window_expiry(synflood: SynFloodDetector) -> None:
    synflood.update(syn(CLIENT, SERVER, 80, 1003.0, sport=5000), 1005.0)  # in window
    assert synflood._counts(_state(synflood))[0] == 1
    synflood.update(icmp(CLIENT, SERVER, 1011.0), 1011.0)  # lower bound 1006 > 1003
    assert synflood._counts(_state(synflood))[0] == 0


# --------------------------------------------------------------------------- #
# Isolation and evidence window times
# --------------------------------------------------------------------------- #
def test_cross_source_type_counts_do_not_merge(synflood: SynFloodDetector) -> None:
    for i in range(5):
        synflood.update(syn(f"10.8.0.{i + 1}", SERVER, 80, 1000.0, sport=5000 + i), 1000.0)
    for i in range(3):
        synflood.update(
            syn(f"10.9.0.{i + 1}", SERVER, 80, 1000.0, sport=6000 + i, source_type="live"), 1000.0
        )
    assert synflood._counts(_state(synflood, SERVER, "synthetic"))[0] == 5
    assert synflood._counts(_state(synflood, SERVER, "live"))[0] == 3


def test_multiple_targets_are_isolated(synflood: SynFloodDetector) -> None:
    other = "10.0.0.20"
    synflood.update(syn(CLIENT, SERVER, 80, 1000.0, sport=5000), 1000.0)
    synflood.update(syn(CLIENT, other, 80, 1000.0, sport=5001), 1000.0)
    assert _has_key(synflood, SERVER)
    assert _has_key(synflood, other)
    assert synflood._counts(_state(synflood, SERVER))[0] == 1
    assert synflood._counts(_state(synflood, other))[0] == 1


def test_evidence_window_times(synflood: SynFloodDetector) -> None:
    out, _ = _flood(synflood, 100, start_ts=1000.0, step=0.01)
    candidate = out[0]
    # window_end is the HWM (the last SYN's ts); window_start is the earliest SYN.
    assert candidate.window_end == pytest.approx(1000.0 + 99 * 0.01)
    assert candidate.window_start == pytest.approx(1000.0)
