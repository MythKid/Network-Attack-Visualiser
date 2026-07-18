"""Storage-layer tests: schema, repositories, transactions, ownership, sessions.

The transaction/ownership/read-session tests use real threads with events and
generous join timeouts; correctness never depends on sleep durations — a sleep
only widens a window in which a guaranteed-blocked thread is observed blocked.
"""

import logging
import sqlite3
import threading
import time
from typing import Any, cast

import pytest

from app.storage import (
    AlertRepository,
    Database,
    EventStatsRepository,
    connect,
    dumps_finite,
    initialise_schema,
    loads_finite,
)
from tests.factories import make_alert

JOIN_TIMEOUT_S = 10.0


# --------------------------------------------------------------------------- #
# connect() / schema
# --------------------------------------------------------------------------- #


def test_connect_enables_wal_for_file_databases(tmp_path: object) -> None:
    """A file database genuinely runs in WAL mode (asserted, not assumed)."""
    path = f"{tmp_path}/wal.sqlite3"
    connection = connect(path)
    try:
        mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode == "wal"
    finally:
        connection.close()


def test_connect_restricts_file_permissions(tmp_path: object) -> None:
    """The database file is private to the owning user (0600)."""
    from pathlib import Path

    path = Path(f"{tmp_path}/perm.sqlite3")
    connection = connect(str(path))
    try:
        assert path.stat().st_mode & 0o777 == 0o600
    finally:
        connection.close()


def test_connect_memory_database_has_no_wal(tmp_path: object) -> None:
    """SQLite silently ignores WAL for ':memory:'; we never claim otherwise."""
    connection = connect(":memory:")
    try:
        mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode == "memory"
    finally:
        connection.close()


def test_initialise_schema_is_idempotent(database: Database) -> None:
    """Applying the schema twice is harmless (IF NOT EXISTS throughout)."""
    connection = connect(":memory:")
    try:
        initialise_schema(connection)
        initialise_schema(connection)
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert {"alerts", "event_stats"} <= tables
    finally:
        connection.close()


# --------------------------------------------------------------------------- #
# Finite-JSON boundary
# --------------------------------------------------------------------------- #


def test_dumps_finite_rejects_nan() -> None:
    with pytest.raises(ValueError):
        dumps_finite({"ratio": float("nan")})


def test_loads_finite_rejects_stored_non_finite_constants() -> None:
    for text in ('{"x": NaN}', '{"x": Infinity}', '{"x": [-Infinity]}'):
        with pytest.raises(ValueError, match="non-finite"):
            loads_finite(text)


def test_get_rejects_externally_corrupted_evidence(
    database: Database, alert_repository: AlertRepository
) -> None:
    """A row whose JSON was edited to contain NaN fails loudly on read."""
    alert = make_alert()
    with database.transaction():
        alert_repository.insert(alert)
    with database.cursor() as cur:
        cur.execute(
            "UPDATE alerts SET evidence = ? WHERE alert_id = ?",
            ('{"count": NaN}', alert.alert_id),
        )
    with pytest.raises(ValueError, match="non-finite"):
        alert_repository.get(alert.alert_id)


# --------------------------------------------------------------------------- #
# Repository round-trips, listing, ordering, pruning
# --------------------------------------------------------------------------- #


def test_insert_get_round_trip(database: Database, alert_repository: AlertRepository) -> None:
    """Every field survives storage exactly, including nested JSON and floats."""
    alert = make_alert(
        created_at=1000.123456,
        evidence={"nested": {"ports": [1, 2, 3], "ratio": 0.25}, "n": 15},
        threshold_snapshot={"PORTSCAN_WINDOW_S": 10.0},
        last_seen=1010.654321,
    )
    with database.transaction():
        alert_repository.insert(alert)
    loaded = alert_repository.get(alert.alert_id)
    assert loaded == alert


def test_update_round_trip(database: Database, alert_repository: AlertRepository) -> None:
    alert = make_alert()
    with database.transaction():
        alert_repository.insert(alert)
    reinforced = alert.model_copy(
        update={"occurrence_count": 2, "last_seen": 1010.0, "window_end": 1010.0}
    )
    with database.transaction():
        alert_repository.update(reinforced)
    loaded = alert_repository.get(alert.alert_id)
    assert loaded is not None
    assert loaded.occurrence_count == 2
    assert loaded.last_seen == 1010.0
    assert loaded.window_end == 1010.0


def test_update_missing_row_raises(database: Database, alert_repository: AlertRepository) -> None:
    with database.transaction(), pytest.raises(LookupError):
        alert_repository.update(make_alert())


def test_list_orders_by_recording_not_event_time(
    database: Database, alert_repository: AlertRepository
) -> None:
    """Regression: 'newest first' means insertion order, not created_at.

    created_at is logical event time; a live alert (~1.7e9) must not outrank a
    synthetic alert (~1000) that was recorded after it.
    """
    a = make_alert(alert_id=None, created_at=1000.0, source_type="synthetic")
    b = make_alert(alert_id=None, created_at=1.7e9, source_type="live")
    c = make_alert(alert_id=None, created_at=1001.0, source_type="synthetic")
    with database.transaction():
        for alert in (a, b, c):
            alert_repository.insert(alert)
    items, total = alert_repository.list()
    assert total == 3
    assert [item.alert_id for item in items] == [c.alert_id, b.alert_id, a.alert_id]


def test_list_filters_and_pagination(database: Database, alert_repository: AlertRepository) -> None:
    with database.transaction():
        for i in range(5):
            alert_repository.insert(
                make_alert(created_at=1000.0 + i, severity="medium" if i % 2 == 0 else "high")
            )
    items, total = alert_repository.list(severity="high")
    assert total == 2
    assert all(item.severity == "high" for item in items)

    page, total = alert_repository.list(limit=2, offset=2)
    assert total == 5
    assert len(page) == 2

    beyond, total = alert_repository.list(limit=2, offset=10)
    assert total == 5
    assert beyond == []


def test_prune_keeps_newest_inserted_regardless_of_created_at(database: Database) -> None:
    """Regression: pruning is by insertion order, never by event-time created_at."""
    repository = AlertRepository(database, max_rows=2)
    old_live = make_alert(created_at=1.7e9, source_type="live")
    new_synth_1 = make_alert(created_at=1000.0, source_type="synthetic")
    new_synth_2 = make_alert(created_at=1001.0, source_type="synthetic")
    with database.transaction():
        for alert in (old_live, new_synth_1, new_synth_2):
            repository.insert(alert)
        deleted = repository.prune_to_max_rows()
    assert deleted == 1
    assert repository.get(old_live.alert_id) is None  # oldest INSERTED, despite max created_at
    assert repository.get(new_synth_1.alert_id) is not None
    assert repository.get(new_synth_2.alert_id) is not None


def test_existing_ids_returns_surviving_subset(
    database: Database, alert_repository: AlertRepository
) -> None:
    kept = make_alert()
    gone = make_alert()
    with database.transaction():
        alert_repository.insert(kept)
    assert alert_repository.existing_ids([kept.alert_id, gone.alert_id]) == {kept.alert_id}
    assert alert_repository.existing_ids([]) == set()


def test_latest_for_dedup_key_returns_newest(
    database: Database, alert_repository: AlertRepository
) -> None:
    key = "ab" * 20
    first = make_alert(created_at=1000.0, dedup_key=key)
    second = make_alert(created_at=1100.0, last_seen=1100.0, dedup_key=key)
    with database.transaction():
        alert_repository.insert(first)
        alert_repository.insert(second)
    latest = alert_repository.latest_for_dedup_key(key)
    assert latest is not None
    assert latest.alert_id == second.alert_id
    assert alert_repository.latest_for_dedup_key("cd" * 20) is None


# --------------------------------------------------------------------------- #
# Transaction contract
# --------------------------------------------------------------------------- #


def test_exception_rolls_back_and_reraises(
    database: Database, alert_repository: AlertRepository
) -> None:
    with pytest.raises(RuntimeError, match="boom"), database.transaction():
        alert_repository.insert(make_alert())
        raise RuntimeError("boom")
    assert alert_repository.count() == 0


def test_nested_transaction_raises(database: Database) -> None:
    with (
        database.transaction(),
        pytest.raises(RuntimeError, match="nested"),
        database.transaction(),
    ):
        pass  # pragma: no cover - the inner transaction refuses to open


def test_write_outside_transaction_raises(alert_repository: AlertRepository) -> None:
    with pytest.raises(RuntimeError, match="active transaction"):
        alert_repository.insert(make_alert())


def test_reads_need_no_transaction(database: Database, alert_repository: AlertRepository) -> None:
    with database.transaction():
        alert_repository.insert(make_alert())
    items, total = alert_repository.list()
    assert total == 1 and len(items) == 1


# --------------------------------------------------------------------------- #
# BEGIN / COMMIT failure paths (via a delegating flaky connection)
# --------------------------------------------------------------------------- #


class _FlakyConnection:
    """Delegates to a real connection; can fail BEGIN, COMMIT or ROLLBACK once."""

    def __init__(self, real: sqlite3.Connection) -> None:
        self._real = real
        self.fail_begin = False
        self.fail_commit = False
        self.fail_rollback = False

    def execute(self, sql: str, *args: Any) -> sqlite3.Cursor:
        if self.fail_begin and sql.startswith("BEGIN"):
            self.fail_begin = False
            raise sqlite3.OperationalError("database is locked")
        return self._real.execute(sql, *args)

    def commit(self) -> None:
        if self.fail_commit:
            self.fail_commit = False
            raise sqlite3.OperationalError("simulated commit failure")
        self._real.commit()

    def rollback(self) -> None:
        if self.fail_rollback:
            self.fail_rollback = False
            raise sqlite3.OperationalError("simulated rollback failure")
        self._real.rollback()

    def cursor(self) -> sqlite3.Cursor:
        return self._real.cursor()

    @property
    def in_transaction(self) -> bool:
        return self._real.in_transaction

    def close(self) -> None:
        self._real.close()


@pytest.fixture
def flaky() -> _FlakyConnection:
    real = connect(":memory:")
    initialise_schema(real)
    return _FlakyConnection(real)


def _insert_stats_row(db: Database) -> None:
    with db.cursor() as cur:
        cur.execute("INSERT INTO event_stats VALUES (1.0, 'TCP', 'synthetic', 1, 64)")


def _stats_rows(db: Database) -> int:
    with db.cursor() as cur:
        return int(cur.execute("SELECT COUNT(*) FROM event_stats").fetchone()[0])


def test_begin_failure_leaves_database_reusable(flaky: _FlakyConnection) -> None:
    """A failed BEGIN must not leak transaction ownership.

    Were ownership taken before BEGIN, one transient 'database is locked' would
    poison every later transaction with a spurious nested-transaction error.
    """
    db = Database(cast(sqlite3.Connection, flaky))
    flaky.fail_begin = True
    with pytest.raises(sqlite3.OperationalError, match="locked"), db.transaction():
        pass  # pragma: no cover - never entered
    # Ownership was never taken; the very next transaction succeeds.
    with db.transaction():
        _insert_stats_row(db)
    assert _stats_rows(db) == 1


def test_commit_failure_rolls_back_and_preserves_original(flaky: _FlakyConnection) -> None:
    db = Database(cast(sqlite3.Connection, flaky))
    flaky.fail_commit = True
    with (
        pytest.raises(sqlite3.OperationalError, match="simulated commit failure"),
        db.transaction(),
    ):
        _insert_stats_row(db)
    assert not flaky.in_transaction  # rollback ran
    assert _stats_rows(db) == 0  # nothing persisted
    with db.transaction():  # ownership cleared; reusable
        _insert_stats_row(db)
    assert _stats_rows(db) == 1


def test_rollback_failure_is_logged_and_never_masks_original(
    flaky: _FlakyConnection, caplog: pytest.LogCaptureFixture
) -> None:
    db = Database(cast(sqlite3.Connection, flaky))
    flaky.fail_commit = True
    flaky.fail_rollback = True
    with (
        caplog.at_level(logging.ERROR, logger="app.storage.database"),
        pytest.raises(sqlite3.OperationalError, match="simulated commit failure"),
        db.transaction(),
    ):
        _insert_stats_row(db)
    assert "rollback failed" in caplog.text
    # The failed rollback left a real open transaction; clean it up, then the
    # Database must be usable again.
    if flaky.in_transaction:
        flaky.rollback()
    with db.transaction():
        _insert_stats_row(db)


# --------------------------------------------------------------------------- #
# Thread ownership
# --------------------------------------------------------------------------- #


def test_non_owner_thread_write_blocks_then_fails(
    database: Database, alert_repository: AlertRepository
) -> None:
    """A foreign thread can neither join nor escape another thread's transaction.

    The intruder blocks on the database lock while the owner works, and once the
    owner commits it raises RuntimeError — it never executes SQL, so its write
    can never become a silent autocommit.
    """
    owner_alert = make_alert()
    intruder_alert = make_alert()
    in_transaction = threading.Event()
    release_owner = threading.Event()
    intruder_done = threading.Event()
    intruder_errors: list[BaseException] = []

    def owner() -> None:
        with database.transaction():
            alert_repository.insert(owner_alert)
            in_transaction.set()
            release_owner.wait(timeout=JOIN_TIMEOUT_S)

    def intruder() -> None:
        try:
            alert_repository.insert(intruder_alert)
        except BaseException as exc:
            intruder_errors.append(exc)
        finally:
            intruder_done.set()

    owner_thread = threading.Thread(target=owner)
    owner_thread.start()
    assert in_transaction.wait(timeout=JOIN_TIMEOUT_S)
    intruder_thread = threading.Thread(target=intruder)
    intruder_thread.start()
    # While the owner holds the lock the intruder cannot complete; the sleep only
    # widens the observation window, it does not carry the correctness.
    time.sleep(0.2)
    assert not intruder_done.is_set()
    release_owner.set()
    owner_thread.join(timeout=JOIN_TIMEOUT_S)
    intruder_thread.join(timeout=JOIN_TIMEOUT_S)
    assert not owner_thread.is_alive() and not intruder_thread.is_alive()

    assert len(intruder_errors) == 1
    assert isinstance(intruder_errors[0], RuntimeError)
    assert alert_repository.get(owner_alert.alert_id) is not None
    assert alert_repository.get(intruder_alert.alert_id) is None  # never written


def test_ownership_cleared_after_rollback(
    database: Database, alert_repository: AlertRepository
) -> None:
    with pytest.raises(RuntimeError), database.transaction():
        raise RuntimeError("force rollback")
    with database.transaction():
        alert_repository.insert(make_alert())
    assert alert_repository.count() == 1


# --------------------------------------------------------------------------- #
# read_session
# --------------------------------------------------------------------------- #


def test_read_session_blocks_writers_until_it_ends(
    database: Database, alert_repository: AlertRepository
) -> None:
    session_open = threading.Event()
    release_reader = threading.Event()
    writer_done = threading.Event()

    def reader() -> None:
        with database.read_session():
            session_open.set()
            release_reader.wait(timeout=JOIN_TIMEOUT_S)

    def writer() -> None:
        with database.transaction():
            alert_repository.insert(make_alert())
        writer_done.set()

    reader_thread = threading.Thread(target=reader)
    reader_thread.start()
    assert session_open.wait(timeout=JOIN_TIMEOUT_S)
    writer_thread = threading.Thread(target=writer)
    writer_thread.start()
    time.sleep(0.2)
    assert not writer_done.is_set()  # writer waits while the read session is open
    release_reader.set()
    reader_thread.join(timeout=JOIN_TIMEOUT_S)
    writer_thread.join(timeout=JOIN_TIMEOUT_S)
    assert writer_done.is_set()
    assert alert_repository.count() == 1


def test_repository_reads_reenter_read_session_without_deadlock(
    database: Database, alert_repository: AlertRepository
) -> None:
    with database.transaction():
        alert_repository.insert(make_alert())
    with database.read_session():
        items, total = alert_repository.list()
        assert total == 1
        assert alert_repository.count() == 1
        assert len(items) == 1


def test_write_inside_bare_read_session_still_raises(
    database: Database, alert_repository: AlertRepository
) -> None:
    """A read session is not a transaction; writes inside it must fail."""
    with database.read_session(), pytest.raises(RuntimeError, match="active transaction"):
        alert_repository.insert(make_alert())


# --------------------------------------------------------------------------- #
# Event-stats repository
# --------------------------------------------------------------------------- #


def test_stats_upsert_accumulates(
    database: Database, stats_repository: EventStatsRepository
) -> None:
    with database.transaction():
        stats_repository.upsert({(1000.0, "TCP", "synthetic"): (5, 320)})
        stats_repository.upsert({(1000.0, "TCP", "synthetic"): (3, 192)})
    assert stats_repository.totals() == (8, 512)
    distribution = stats_repository.protocol_distribution()
    assert len(distribution) == 1
    assert distribution[0].protocol == "TCP"
    assert distribution[0].packet_count == 8


def test_stats_timeline_selects_buckets_per_source_type(
    database: Database, stats_repository: EventStatsRepository
) -> None:
    """Regression: live timestamps must not crowd synthetic buckets out."""
    with database.transaction():
        stats_repository.upsert(
            {
                (1000.0, "TCP", "synthetic"): (5, 320),
                (1001.0, "TCP", "synthetic"): (7, 448),
                (1002.0, "TCP", "synthetic"): (9, 576),
                (1.7e9, "TCP", "live"): (3, 192),
                (1.7e9 + 1, "TCP", "live"): (4, 256),
            }
        )
    rows = stats_repository.timeline(buckets=2)
    by_source: dict[str, list[float]] = {"synthetic": [], "live": []}
    for row in rows:
        by_source[row.source_type].append(row.bucket_ts)
    assert by_source["synthetic"] == [1001.0, 1002.0]  # latest 2 synthetic seconds
    assert by_source["live"] == [1.7e9, 1.7e9 + 1]  # latest 2 live seconds

    filtered = stats_repository.timeline(buckets=2, source_type="synthetic")
    assert {row.source_type for row in filtered} == {"synthetic"}


def test_stats_timeline_counts_distinct_seconds_not_rows(
    database: Database, stats_repository: EventStatsRepository
) -> None:
    """One second carrying TCP and UDP rows consumes ONE bucket, not two."""
    with database.transaction():
        stats_repository.upsert(
            {
                (1000.0, "TCP", "synthetic"): (5, 320),
                (1000.0, "UDP", "synthetic"): (1, 64),
                (999.0, "TCP", "synthetic"): (2, 128),
            }
        )
    rows = stats_repository.timeline(buckets=1)
    assert {row.bucket_ts for row in rows} == {1000.0}
    assert {row.protocol for row in rows} == {"TCP", "UDP"}
