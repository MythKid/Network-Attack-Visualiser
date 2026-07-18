"""Event-pipeline tests: serialisation, rollback, pruning-vs-deltas, recovery."""

import sqlite3
import threading
from collections.abc import Iterator

import pytest

from app.alerts.engine import AlertEngine
from app.alerts.pipeline import EventPipeline
from app.detection import (
    DetectionEngine,
    DetectionSettings,
    PortScanDetector,
    SynFloodDetector,
)
from app.ingest.synthetic import port_scan, syn_burst
from app.storage import AlertRepository, Database, EventStatsRepository, aggregate_event_stats
from tests.factories import sequential_id_factory

JOIN_TIMEOUT_S = 10.0

COOLDOWNS = {"portscan": 60.0, "synflood": 60.0}


def build_pipeline(
    database: Database, *, max_rows: int | None = None
) -> tuple[EventPipeline, AlertRepository, EventStatsRepository, AlertEngine]:
    """A full pipeline over ``database`` with default detection thresholds."""
    settings = DetectionSettings(_env_file=None)
    detection = DetectionEngine(
        [
            PortScanDetector(settings.to_portscan_config()),
            SynFloodDetector(settings.to_synflood_config()),
        ]
    )
    repository = AlertRepository(database, max_rows=max_rows)
    stats = EventStatsRepository(database)
    engine = AlertEngine(repository, COOLDOWNS, id_factory=sequential_id_factory())
    pipeline = EventPipeline(
        detection=detection,
        alerts=engine,
        alert_repository=repository,
        stats=stats,
        database=database,
    )
    return pipeline, repository, stats, engine


@pytest.fixture
def parts(
    database: Database,
) -> Iterator[tuple[EventPipeline, AlertRepository, EventStatsRepository, AlertEngine]]:
    yield build_pipeline(database)


# --------------------------------------------------------------------------- #
# aggregate_event_stats (pure)
# --------------------------------------------------------------------------- #


def test_aggregate_event_stats_is_pure_bucketing() -> None:
    events = port_scan(start_ts=1000.25, num_ports=3, step_s=0.25)
    buckets = aggregate_event_stats(events)
    # ts values 1000.25, 1000.5, 1000.75 all fall into the 1000.0 second.
    assert buckets == {(1000.0, "TCP", "synthetic"): (3, 3 * 64)}
    assert aggregate_event_stats([]) == {}


# --------------------------------------------------------------------------- #
# End-to-end batch behaviour
# --------------------------------------------------------------------------- #


def test_port_scan_batch_produces_one_created_delta(
    parts: tuple[EventPipeline, AlertRepository, EventStatsRepository, AlertEngine],
) -> None:
    pipeline, repository, stats, _ = parts
    deltas = pipeline.process_batch(port_scan(num_ports=20))
    assert [d.type for d in deltas] == ["alert.created"]
    assert deltas[0].alert.detector_id == "portscan"
    assert repository.count() == 1
    packets, _ = stats.totals()
    assert packets == 20  # every accepted event is counted, alert or not


def test_normal_traffic_produces_no_deltas(
    parts: tuple[EventPipeline, AlertRepository, EventStatsRepository, AlertEngine],
) -> None:
    from app.ingest.synthetic import normal_traffic

    pipeline, repository, _, _ = parts
    assert pipeline.process_batch(normal_traffic()) == []
    assert repository.count() == 0


def test_cooldown_update_across_batches_via_latch_rearm(
    parts: tuple[EventPipeline, AlertRepository, EventStatsRepository, AlertEngine],
) -> None:
    """The documented §7 timeline: scan, quiet past the window, scan again.

    The second burst re-arms the detector latch and lands inside the 60s
    cooldown, so it must reinforce the existing row, not insert a second one.
    """
    pipeline, repository, _, _ = parts
    first = pipeline.process_batch(port_scan(start_ts=1000.0, num_ports=20))
    # Quiet gap: the second scan starts at 1014, beyond window_s=10 after the
    # first burst's evidence, so the SeverityLatch has re-armed.
    second = pipeline.process_batch(port_scan(start_ts=1014.0, num_ports=20))
    assert [d.type for d in first] == ["alert.created"]
    assert [d.type for d in second] == ["alert.updated"]
    assert second[0].alert.alert_id == first[0].alert.alert_id
    assert second[0].alert.occurrence_count == 2
    assert repository.count() == 1


def test_new_row_after_cooldown_elapses(
    parts: tuple[EventPipeline, AlertRepository, EventStatsRepository, AlertEngine],
) -> None:
    pipeline, repository, _, _ = parts
    pipeline.process_batch(port_scan(start_ts=1000.0, num_ports=20))
    late = pipeline.process_batch(port_scan(start_ts=1100.0, num_ports=20))  # > 60s later
    assert [d.type for d in late] == ["alert.created"]
    assert repository.count() == 2


# --------------------------------------------------------------------------- #
# Prune-vs-delta regression (ALERT_MAX_ROWS=1, two alerts in one batch)
# --------------------------------------------------------------------------- #


def test_same_batch_pruned_delta_is_discarded_not_broadcast(database: Database) -> None:
    """One batch creating more alerts than the cap must not emit phantom deltas.

    A syn_burst across many ports triggers BOTH detectors (two dedup keys, two
    inserts). With ALERT_MAX_ROWS=1 the earlier insert is pruned inside the same
    transaction; its delta must vanish from the return value — broadcasting a
    row absent from REST would desynchronise every client.
    """
    pipeline, repository, _, engine = build_pipeline(database, max_rows=1)
    # 120 SYNs from one source across 120 distinct ports: portscan fires (>=15
    # distinct ports) and synflood fires (>=100 SYNs, zero completions).
    events = [
        event.model_copy(update={"src_ip": "10.9.9.9", "dst_port": 1000 + i})
        for i, event in enumerate(syn_burst(num_syns=120))
    ]
    deltas = pipeline.process_batch(events)

    assert repository.count() == 1  # the cap held at commit
    # portscan fired first (15th distinct port) and was pruned by synflood's
    # later insert: every portscan delta (create + escalation updates) must be
    # discarded, leaving only the synflood survivor.
    assert len(deltas) == 1
    survivor = deltas[0]
    assert survivor.type == "alert.created"
    assert survivor.alert.detector_id == "synflood"
    assert repository.get(survivor.alert.alert_id) is not None  # fetchable via REST

    # The gate still remembers both keys; the pruned one now dangles.
    assert engine.gate_size() == 2


def test_pruned_key_recovers_with_a_fresh_create_within_cooldown(database: Database) -> None:
    """A dangling gate entry (same-batch prune) must yield alert.created next time."""
    pipeline, repository, _, _ = build_pipeline(database, max_rows=1)
    events = [
        event.model_copy(update={"src_ip": "10.9.9.9", "dst_port": 1000 + i})
        for i, event in enumerate(syn_burst(num_syns=120))
    ]
    first = pipeline.process_batch(events)
    assert first[0].alert.detector_id == "synflood"  # portscan's row was pruned

    # The same burst again, re-armed past both windows (first evidence ends
    # ~2001.2; restart at 2014) and inside the 60s cooldown of both gate keys.
    second = pipeline.process_batch(
        [
            event.model_copy(update={"src_ip": "10.9.9.9", "dst_port": 3000 + i})
            for i, event in enumerate(syn_burst(start_ts=2014.0, num_syns=120))
        ]
    )
    assert repository.count() == 1  # cap=1 held again
    # portscan's dangling key recovered by CREATING a fresh row (never an error);
    # that new row is this batch's final insert chain, so its deltas survive
    # while synflood's update (whose row the prune evicted) is discarded.
    surviving_ids = {delta.alert.alert_id for delta in second}
    assert len(surviving_ids) == 1
    assert all(delta.alert.detector_id == "portscan" for delta in second)
    assert second[0].type == "alert.created"


# --------------------------------------------------------------------------- #
# Rollback semantics
# --------------------------------------------------------------------------- #


def test_storage_failure_rolls_back_everything_and_propagates(
    database: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    pipeline, repository, stats, _ = build_pipeline(database)

    def boom() -> int:
        raise sqlite3.OperationalError("simulated storage failure")

    monkeypatch.setattr(repository, "prune_to_max_rows", boom)
    with pytest.raises(sqlite3.OperationalError, match="simulated storage failure"):
        pipeline.process_batch(port_scan(num_ports=20))

    assert repository.count() == 0  # alert rows rolled back
    assert stats.totals() == (0, 0)  # stats rolled back with them


def test_gate_sweep_still_runs_when_persistence_fails(
    database: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Repeated storage failures must not accumulate stale gate entries forever."""
    pipeline, repository, _, engine = build_pipeline(database)
    # Key A's entry, fired at logical time ~1002.8.
    pipeline.process_batch(port_scan(client="10.7.0.1", start_ts=1000.0, num_ports=20))
    assert engine.gate_size() == 1

    def boom() -> int:
        raise sqlite3.OperationalError("simulated storage failure")

    monkeypatch.setattr(repository, "prune_to_max_rows", boom)
    # A failing batch for a DIFFERENT key, far past A's cooldown: without the
    # failure-path sweep the gate would now hold both A (stale) and B.
    with pytest.raises(sqlite3.OperationalError):
        pipeline.process_batch(port_scan(client="10.7.0.2", start_ts=2000.0, num_ports=20))
    assert engine.gate_size() == 1  # A swept despite the failure; only B remains


def test_gate_recovery_after_rolled_back_transaction(
    database: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A gate entry referencing a rolled-back row must recover with a create."""
    pipeline, repository, _, engine = build_pipeline(database)

    call_count = 0
    original = repository.prune_to_max_rows

    def fail_once() -> int:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise sqlite3.OperationalError("simulated storage failure")
        return original()

    monkeypatch.setattr(repository, "prune_to_max_rows", fail_once)
    with pytest.raises(sqlite3.OperationalError):
        pipeline.process_batch(port_scan(start_ts=1000.0, num_ports=20))
    assert repository.count() == 0
    assert engine.gate_size() == 1  # dangling: references a rolled-back row

    # Re-armed second scan within the cooldown: the update path finds no row
    # and must create a fresh one without raising.
    deltas = pipeline.process_batch(port_scan(start_ts=1014.0, num_ports=20))
    assert [d.type for d in deltas] == ["alert.created"]
    assert repository.count() == 1


# --------------------------------------------------------------------------- #
# Serialisation under concurrency
# --------------------------------------------------------------------------- #


def test_concurrent_batches_serialise_without_corruption(database: Database) -> None:
    """N threads with independent keys each yield exactly one clean alert."""
    pipeline, repository, _, _ = build_pipeline(database)
    thread_count = 4
    barrier = threading.Barrier(thread_count)
    errors: list[BaseException] = []

    def worker(index: int) -> None:
        try:
            events = port_scan(client=f"10.7.{index}.1", num_ports=20)
            barrier.wait(timeout=JOIN_TIMEOUT_S)
            pipeline.process_batch(events)
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(thread_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=JOIN_TIMEOUT_S)
        assert not thread.is_alive()

    assert errors == []
    items, total = repository.list()
    assert total == thread_count
    assert all(alert.occurrence_count == 1 for alert in items)
    assert len({alert.dedup_key for alert in items}) == thread_count
