"""SQLite connection ownership, schema and transaction management.

One :class:`Database` object owns the single ``sqlite3`` connection **and** the
lock that guards it. Repositories are handed the ``Database`` and never touch
``sqlite3`` directly; two repositories creating independent locks over one
connection would serialise nothing.

Concurrency model (see ``docs/API.md``): all database access — reads and writes —
is serialised through this one connection and lock. Reads are **not** concurrent
with writes: a ``GET`` issued while a batch transaction is open waits for it.
WAL is enabled for file databases because the documented schema specifies it and
it improves commit behaviour, but its concurrent-reader benefit requires separate
reader connections and is therefore dormant in Phase 3.
"""

import json
import logging
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Final

from pydantic import JsonValue

logger = logging.getLogger(__name__)

# Table and index definitions from docs/ALERT_SCHEMA.md §4. The WAL pragma from
# that section is connection-level and is applied in connect() — only for file
# databases, because SQLite silently ignores WAL for ':memory:' (it reports
# journal_mode 'memory'); asserting WAL there would assert a falsehood.
SCHEMA_SQL: Final[str] = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id            TEXT    PRIMARY KEY,
    created_at          REAL    NOT NULL,
    detector_id         TEXT    NOT NULL,
    detector_version    TEXT    NOT NULL,
    category            TEXT    NOT NULL,
    severity            TEXT    NOT NULL,
    confidence          REAL    NOT NULL,
    src_ip              TEXT,
    dst_ip              TEXT    NOT NULL,
    window_start        REAL    NOT NULL,
    window_end          REAL    NOT NULL,
    evidence            TEXT    NOT NULL,   -- JSON
    threshold_snapshot  TEXT    NOT NULL,   -- JSON
    dedup_key           TEXT    NOT NULL,
    source_type         TEXT    NOT NULL,
    occurrence_count    INTEGER NOT NULL DEFAULT 1,
    last_seen           REAL    NOT NULL,
    ai_explanation      TEXT,
    ai_status           TEXT    NOT NULL DEFAULT 'none'
);

-- Non-unique: dedup_key must NEVER permanently block future alerts for the same hosts.
CREATE INDEX IF NOT EXISTS idx_alerts_dedup      ON alerts (dedup_key, created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_detector   ON alerts (detector_id, severity);

CREATE TABLE IF NOT EXISTS event_stats (
    bucket_ts     REAL    NOT NULL,
    protocol      TEXT    NOT NULL,
    source_type   TEXT    NOT NULL,
    packet_count  INTEGER NOT NULL,
    byte_count    INTEGER NOT NULL,
    PRIMARY KEY (bucket_ts, protocol, source_type)
);
"""


def _reject_json_constant(value: str) -> None:
    """Refuse ``NaN``/``Infinity`` literals when reading stored JSON.

    Python's JSON decoder accepts these non-standard tokens by default; letting
    them through would break the finite-JSON invariant the models enforce, e.g.
    after an externally edited database file.
    """
    raise ValueError(f"stored JSON contains the non-finite constant {value!r}")


def dumps_finite(value: JsonValue) -> str:
    """Serialise JSON for storage, refusing non-finite numbers outright.

    ``allow_nan=False`` makes ``json.dumps`` raise instead of emitting the
    non-standard ``NaN``/``Infinity`` tokens that would silently corrupt evidence.
    """
    return json.dumps(value, allow_nan=False, separators=(",", ":"))


def loads_finite(text: str) -> JsonValue:
    """Parse stored JSON, rejecting non-finite constants at any depth."""
    result: JsonValue = json.loads(text, parse_constant=_reject_json_constant)
    return result


def connect(database_path: str) -> sqlite3.Connection:
    """Open the application's SQLite connection.

    ``isolation_level=None`` disables the driver's implicit transaction
    management so BEGIN/COMMIT are explicit and auditable (see
    :meth:`Database.transaction`). ``check_same_thread=False`` is required
    because threadpool workers hand the connection around — safe only because
    every access goes through the :class:`Database` lock.
    """
    is_memory = database_path == ":memory:"
    if not is_memory:
        parent = Path(database_path).parent
        if str(parent) not in ("", "."):
            parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(
        database_path,
        check_same_thread=False,
        isolation_level=None,
    )
    connection.row_factory = sqlite3.Row
    if not is_memory:
        mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        if mode != "wal":
            connection.close()
            raise RuntimeError(
                f"failed to enable WAL journal mode for {database_path!r} (got {mode!r})"
            )
        # The database holds lab telemetry; keep it private to the owning user.
        Path(database_path).chmod(0o600)
    return connection


def initialise_schema(connection: sqlite3.Connection) -> None:
    """Create the documented tables and indexes (idempotent)."""
    connection.executescript(SCHEMA_SQL)


class Database:
    """Sole owner of the sqlite3 connection and the lock that guards it.

    The lock is an :class:`threading.RLock` because repository calls legitimately
    re-acquire it from inside an open :meth:`transaction` or :meth:`read_session`
    (via :meth:`cursor`); a plain ``Lock`` would self-deadlock on the first
    nested acquisition. Re-entrancy applies to the *lock* only — nested
    transactions are explicitly forbidden.
    """

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._conn = connection
        self._lock = threading.RLock()
        # threading.get_ident() of the thread owning the open transaction, if any.
        self._txn_owner: int | None = None

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """One exclusive write transaction, owned by the calling thread.

        Not nestable: Phase 3 has exactly one transaction owner (the event
        pipeline) and one boundary (the ingest batch), so a nested call is a
        programming error and fails loudly rather than being emulated.

        Exception safety: ``BEGIN IMMEDIATE`` runs inside the cleanup structure
        and ownership is taken only after it succeeds, so a failed BEGIN leaves
        no trace and the connection stays usable. A failed commit attempts
        rollback while preserving the original exception; a rollback failure is
        logged, never allowed to replace it.
        """
        with self._lock:
            if self._txn_owner is not None:
                # The lock is held and ownership is cleared (in `finally`) before
                # the lock is released, so a non-None owner here is necessarily
                # this thread's own ident: a nested call.
                raise RuntimeError(
                    "nested transactions are not supported; repositories must "
                    "participate in the pipeline-owned transaction"
                )
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                self._txn_owner = threading.get_ident()
                yield
                self._conn.commit()
            except BaseException:
                if self._conn.in_transaction:
                    try:
                        self._conn.rollback()
                    except Exception:
                        # Logged, never raised: the original exception is the
                        # truth about what went wrong and must propagate.
                        logger.exception("rollback failed after transaction failure")
                raise
            finally:
                self._txn_owner = None

    @contextmanager
    def cursor(self) -> Iterator[sqlite3.Cursor]:
        """A short-lived cursor under the database lock."""
        with self._lock:
            cur = self._conn.cursor()
            try:
                yield cur
            finally:
                cur.close()

    @contextmanager
    def read_session(self) -> Iterator[None]:
        """Hold the database lock across one multi-query logical read.

        This guarantees a single response is internally consistent against
        **in-process writers** sharing this lock (a writer cannot commit between
        the queries of one read). It is *not* a database-level snapshot against
        unrelated external SQLite connections: no SQL read transaction is opened,
        so a hypothetical second process writing the same file could interleave.
        In Phase 3 this process holds the sole connection, so lock-level
        consistency is exactly sufficient.
        """
        with self._lock:
            yield

    def require_transaction(self) -> None:
        """Guard for repository writes: the current thread must own the transaction.

        Checked under the lock, verifying both ownership and that the connection
        is genuinely inside a transaction. A non-owner thread may block here
        until the owner releases the lock and *then* fail — it can never pass:
        the owner holds the lock for the whole transaction, so a foreign write
        can neither join it nor run as a silent autocommit afterwards.
        """
        with self._lock:
            if self._txn_owner != threading.get_ident() or not self._conn.in_transaction:
                raise RuntimeError("write requires an active transaction owned by this thread")

    def close(self) -> None:
        """Close the underlying connection."""
        with self._lock:
            self._conn.close()
