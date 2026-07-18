"""Cooldown/deduplication gate tests (``docs/TESTING_STRATEGY.md`` §4).

All timing uses explicit logical ``now`` values — the same clock-injection
discipline as the Phase 2 detector tests. Cooldown default in these tests is 60s.
"""

from collections.abc import Iterator

import pytest

from app.alerts.engine import AlertDelta, AlertEngine
from app.storage import AlertRepository, Database
from tests.factories import make_candidate, sequential_id_factory

COOLDOWN_S = 60.0


@pytest.fixture
def alert_engine(alert_repository: AlertRepository) -> AlertEngine:
    return AlertEngine(
        alert_repository,
        {"portscan": COOLDOWN_S, "synflood": COOLDOWN_S},
        id_factory=sequential_id_factory(),
    )


@pytest.fixture
def run(database: Database, alert_engine: AlertEngine) -> Iterator[AlertEngine]:
    """The engine, with every test call wrapped in one open transaction."""
    with database.transaction():
        yield alert_engine


def test_first_trigger_creates(run: AlertEngine, alert_repository: AlertRepository) -> None:
    delta = run.process(make_candidate(), now=1000.0)
    assert delta.type == "alert.created"
    assert delta.alert.occurrence_count == 1
    assert delta.alert.created_at == 1000.0
    assert delta.alert.last_seen == 1000.0
    stored = alert_repository.get(delta.alert.alert_id)
    assert stored == delta.alert


def test_duplicate_within_cooldown_updates_one_row(
    run: AlertEngine, alert_repository: AlertRepository
) -> None:
    first = run.process(make_candidate(window_end=1002.0), now=1000.0)
    second = run.process(make_candidate(window_end=1032.0), now=1030.0)
    assert (first.type, second.type) == ("alert.created", "alert.updated")
    assert second.alert.alert_id == first.alert.alert_id
    assert second.alert.occurrence_count == 2
    assert second.alert.last_seen == 1030.0
    assert second.alert.window_end == 1032.0
    assert alert_repository.count() == 1


def test_trigger_after_cooldown_creates_second_row(
    run: AlertEngine, alert_repository: AlertRepository
) -> None:
    """The dedup key never permanently suppresses future alerts."""
    first = run.process(make_candidate(), now=1000.0)
    second = run.process(make_candidate(), now=1000.0 + COOLDOWN_S + 1.0)
    assert second.type == "alert.created"
    assert second.alert.alert_id != first.alert.alert_id
    assert second.alert.occurrence_count == 1
    assert alert_repository.count() == 2


def test_exact_cooldown_boundary_creates(run: AlertEngine) -> None:
    """elapsed == cooldown -> create; elapsed just below -> update."""
    run.process(make_candidate(), now=1000.0)
    at_boundary = run.process(make_candidate(), now=1000.0 + COOLDOWN_S)
    assert at_boundary.type == "alert.created"

    run.process(make_candidate(dst_ip="10.0.0.99"), now=2000.0)
    just_below = run.process(make_candidate(dst_ip="10.0.0.99"), now=2000.0 + COOLDOWN_S - 1e-6)
    assert just_below.type == "alert.updated"


def test_last_fired_at_is_fixed_from_creation_not_sliding(run: AlertEngine) -> None:
    """An update must NOT refresh the cooldown clock.

    Were the window sliding, a sustained attack would never let the cooldown
    elapse and alert.created would never fire again.
    """
    run.process(make_candidate(), now=1000.0)
    updated = run.process(make_candidate(), now=1030.0)  # update at +30
    assert updated.type == "alert.updated"
    after = run.process(make_candidate(), now=1000.0 + COOLDOWN_S + 1.0)  # +61 from CREATE
    assert after.type == "alert.created"


def test_severity_escalates_but_never_lowers(run: AlertEngine) -> None:
    run.process(make_candidate(severity="medium"), now=1000.0)
    escalated = run.process(make_candidate(severity="high"), now=1010.0)
    assert escalated.alert.severity == "high"
    not_lowered = run.process(make_candidate(severity="medium"), now=1020.0)
    assert not_lowered.alert.severity == "high"
    assert not_lowered.alert.occurrence_count == 3


def test_update_preserves_window_start_and_refreshes_evidence(run: AlertEngine) -> None:
    run.process(
        make_candidate(window_start=1000.0, window_end=1002.0, evidence={"n": 15}, confidence=0.6),
        now=1002.0,
    )
    updated = run.process(
        make_candidate(window_start=1010.0, window_end=1012.0, evidence={"n": 30}, confidence=0.7),
        now=1012.0,
    )
    alert = updated.alert
    assert alert.window_start == 1000.0  # row spans the whole episode
    assert alert.window_end == 1012.0  # extended
    assert alert.evidence == {"n": 30}  # refreshed to latest
    assert alert.confidence == 0.7  # refreshed to latest (D2)
    assert alert.created_at == 1002.0  # unchanged
    assert alert.created_at <= alert.last_seen


def test_out_of_order_now_cannot_rewind_last_seen_or_window_end(run: AlertEngine) -> None:
    run.process(make_candidate(window_end=1040.0), now=1040.0)
    stale = run.process(make_candidate(window_end=1005.0), now=1041.0)
    assert stale.alert.window_end == 1040.0
    assert stale.alert.last_seen == 1041.0


def test_gate_expiry_is_partitioned_by_source_type(run: AlertEngine) -> None:
    """One provenance's clock must never evict another's entries — both ways."""
    run.process(make_candidate(source_type="synthetic"), now=1000.0)
    run.process(make_candidate(source_type="live"), now=5_000_000.0)
    assert run.gate_size() == 2

    # Live time far beyond the synthetic cooldown sweeps ONLY live.
    run.expire("live", now=5_000_000.0 + COOLDOWN_S)
    assert run.gate_size() == 1

    # Synthetic time far beyond the live cooldown sweeps ONLY synthetic.
    run.expire("synthetic", now=1000.0 + COOLDOWN_S)
    assert run.gate_size() == 0


def test_gate_expiry_uses_each_partitions_own_cooldown(
    database: Database, alert_repository: AlertRepository
) -> None:
    engine = AlertEngine(
        alert_repository,
        {"portscan": 60.0, "synflood": 10.0},
        id_factory=sequential_id_factory(),
    )
    with database.transaction():
        engine.process(make_candidate(detector_id="portscan"), now=1000.0)
        engine.process(make_candidate(detector_id="synflood", src_ip=None), now=1000.0)
    engine.expire("synthetic", now=1020.0)  # +20: synflood (10s) out, portscan (60s) alive
    assert engine.gate_size() == 1
    engine.expire("synthetic", now=1060.0)
    assert engine.gate_size() == 0


def test_dangling_gate_reference_creates_instead_of_crashing(
    run: AlertEngine, alert_repository: AlertRepository, database: Database
) -> None:
    """A gate entry whose row is gone (pruned/rolled back) must yield a create."""
    first = run.process(make_candidate(), now=1000.0)
    with database.cursor() as cur:  # simulate pruning of the referenced row
        cur.execute("DELETE FROM alerts WHERE alert_id = ?", (first.alert.alert_id,))
    recovered = run.process(make_candidate(), now=1010.0)  # within cooldown
    assert recovered.type == "alert.created"
    assert recovered.alert.alert_id != first.alert.alert_id
    assert alert_repository.get(recovered.alert.alert_id) is not None


def test_unknown_detector_raises(run: AlertEngine) -> None:
    with pytest.raises(ValueError, match="no cooldown configured"):
        run.process(make_candidate(detector_id="mystery", category="dos"), now=1000.0)


def test_non_positive_or_non_finite_cooldowns_rejected(
    alert_repository: AlertRepository,
) -> None:
    for bad in (0.0, -5.0, float("inf"), float("nan")):
        with pytest.raises(ValueError, match="finite and positive"):
            AlertEngine(alert_repository, {"portscan": bad})


def test_same_hosts_different_source_types_never_merge(
    run: AlertEngine, alert_repository: AlertRepository
) -> None:
    synthetic = run.process(make_candidate(source_type="synthetic"), now=1000.0)
    live = run.process(make_candidate(source_type="live"), now=1000.0)
    assert synthetic.type == live.type == "alert.created"
    assert synthetic.alert.dedup_key != live.alert.dedup_key
    assert alert_repository.count() == 2


def test_delta_types_are_the_documented_envelope_values(run: AlertEngine) -> None:
    created = run.process(make_candidate(), now=1000.0)
    updated = run.process(make_candidate(), now=1001.0)
    assert isinstance(created, AlertDelta)
    assert created.type == "alert.created"
    assert updated.type == "alert.updated"
