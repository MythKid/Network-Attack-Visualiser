"""The alert repository: persisted :class:`~app.models.alert.Alert` rows.

All SQL lives here, uses placeholders exclusively, and runs through the shared
:class:`~app.storage.database.Database` lock. Ordering and row-cap pruning use
SQLite's implicit ``rowid`` (insertion order) rather than ``created_at``:
``created_at`` is *logical event time*, so synthetic (epoch ~1000) and live
(epoch ~1.7e9) values are different timelines, not different instants — ordering
or pruning across provenances by ``created_at`` would bury or delete fresh
synthetic alerts behind stale live ones. ``rowid`` is never exposed in the API.
"""

import sqlite3
from collections.abc import Sequence
from typing import cast

from pydantic import JsonValue

from app.models.alert import Alert
from app.models.enums import Category, Severity, SourceType
from app.storage.database import Database, dumps_finite, loads_finite

# Filterable columns for list(); names are fixed here, never caller-supplied.
_FILTER_COLUMNS = ("severity", "detector_id", "source_type", "category")

_INSERT_SQL = """
INSERT INTO alerts (
    alert_id, created_at, detector_id, detector_version, category, severity,
    confidence, src_ip, dst_ip, window_start, window_end, evidence,
    threshold_snapshot, dedup_key, source_type, occurrence_count, last_seen,
    ai_explanation, ai_status
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

_UPDATE_SQL = """
UPDATE alerts SET
    detector_version = ?, severity = ?, confidence = ?, window_end = ?,
    evidence = ?, threshold_snapshot = ?, occurrence_count = ?, last_seen = ?
WHERE alert_id = ?
"""


class AlertRepository:
    """CRUD, listing, statistics and row-cap pruning for alert rows."""

    def __init__(self, database: Database, *, max_rows: int | None = None) -> None:
        self._db = database
        self._max_rows = max_rows

    # ------------------------------------------------------------------ #
    # Writes (require the pipeline-owned transaction)
    # ------------------------------------------------------------------ #

    def insert(self, alert: Alert) -> None:
        """Insert a new alert row."""
        self._db.require_transaction()
        with self._db.cursor() as cur:
            cur.execute(
                _INSERT_SQL,
                (
                    alert.alert_id,
                    alert.created_at,
                    alert.detector_id,
                    alert.detector_version,
                    alert.category,
                    alert.severity,
                    alert.confidence,
                    alert.src_ip,
                    alert.dst_ip,
                    alert.window_start,
                    alert.window_end,
                    dumps_finite(alert.evidence),
                    dumps_finite(alert.threshold_snapshot),
                    alert.dedup_key,
                    alert.source_type,
                    alert.occurrence_count,
                    alert.last_seen,
                    alert.ai_explanation,
                    alert.ai_status,
                ),
            )

    def update(self, alert: Alert) -> None:
        """Persist the mutable fields of a reinforced alert."""
        self._db.require_transaction()
        with self._db.cursor() as cur:
            cur.execute(
                _UPDATE_SQL,
                (
                    alert.detector_version,
                    alert.severity,
                    alert.confidence,
                    alert.window_end,
                    dumps_finite(alert.evidence),
                    dumps_finite(alert.threshold_snapshot),
                    alert.occurrence_count,
                    alert.last_seen,
                    alert.alert_id,
                ),
            )
            if cur.rowcount != 1:
                raise LookupError(f"alert {alert.alert_id} not found for update")

    def prune_to_max_rows(self) -> int:
        """Keep the newest ``max_rows`` rows by insertion order; return rows deleted.

        Runs once per batch, inside the batch transaction. The just-inserted rows
        hold the highest rowids, so with ``max_rows >= 1`` the final insert of a
        batch always survives; earlier same-batch rows may not — the pipeline
        filters its deltas against :meth:`existing_ids` afterwards.
        """
        if self._max_rows is None:
            return 0
        self._db.require_transaction()
        with self._db.cursor() as cur:
            cur.execute(
                "DELETE FROM alerts WHERE rowid NOT IN "
                "(SELECT rowid FROM alerts ORDER BY rowid DESC LIMIT ?)",
                (self._max_rows,),
            )
            return int(cur.rowcount)

    # ------------------------------------------------------------------ #
    # Reads
    # ------------------------------------------------------------------ #

    def get(self, alert_id: str) -> Alert | None:
        """Fetch one alert by id."""
        with self._db.cursor() as cur:
            row = cur.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        return None if row is None else _row_to_alert(row)

    def latest_for_dedup_key(self, dedup_key: str) -> Alert | None:
        """Most recent alert for a dedup key (uses ``idx_alerts_dedup``)."""
        with self._db.cursor() as cur:
            row = cur.execute(
                "SELECT * FROM alerts WHERE dedup_key = ? "
                "ORDER BY created_at DESC, rowid DESC LIMIT 1",
                (dedup_key,),
            ).fetchone()
        return None if row is None else _row_to_alert(row)

    def existing_ids(self, alert_ids: Sequence[str]) -> set[str]:
        """Return the subset of ``alert_ids`` that still exist as rows."""
        if not alert_ids:
            return set()
        placeholders = ",".join("?" for _ in alert_ids)
        with self._db.cursor() as cur:
            rows = cur.execute(
                f"SELECT alert_id FROM alerts WHERE alert_id IN ({placeholders})",
                tuple(alert_ids),
            ).fetchall()
        return {row["alert_id"] for row in rows}

    def list(
        self,
        *,
        severity: Severity | None = None,
        detector_id: str | None = None,
        source_type: SourceType | None = None,
        category: Category | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Alert], int]:
        """One page of alerts (newest-recorded first) plus the matching total.

        The page and count queries run inside one read session, so a single
        response is internally consistent; separate requests are not snapshot-
        stable against concurrent ingest (ordinary offset-pagination behaviour).
        """
        clauses: list[str] = []
        params: list[str] = []
        for column, value in zip(
            _FILTER_COLUMNS, (severity, detector_id, source_type, category), strict=True
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                params.append(value)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._db.read_session(), self._db.cursor() as cur:
            rows = cur.execute(
                f"SELECT * FROM alerts{where} ORDER BY rowid DESC LIMIT ? OFFSET ?",
                (*params, limit, offset),
            ).fetchall()
            total = cur.execute(
                f"SELECT COUNT(*) FROM alerts{where}",
                tuple(params),
            ).fetchone()[0]
        return [_row_to_alert(row) for row in rows], int(total)

    # ------------------------------------------------------------------ #
    # Statistics support (single queries; /stats wraps them in a read session)
    # ------------------------------------------------------------------ #

    def count(self, *, source_type: SourceType | None = None) -> int:
        """Number of alert rows (distinct alerts, not reinforcements)."""
        with self._db.cursor() as cur:
            value = cur.execute(
                "SELECT COUNT(*) FROM alerts WHERE (:st IS NULL OR source_type = :st)",
                {"st": source_type},
            ).fetchone()[0]
        return int(value)

    def occurrence_total(self, *, source_type: SourceType | None = None) -> int:
        """Total triggers including reinforcements (``SUM(occurrence_count)``)."""
        with self._db.cursor() as cur:
            value = cur.execute(
                "SELECT COALESCE(SUM(occurrence_count), 0) FROM alerts "
                "WHERE (:st IS NULL OR source_type = :st)",
                {"st": source_type},
            ).fetchone()[0]
        return int(value)

    def counts_by(self, column: str, *, source_type: SourceType | None = None) -> dict[str, int]:
        """Row counts grouped by one of the filterable columns."""
        if column not in _FILTER_COLUMNS:
            raise ValueError(f"cannot group alerts by {column!r}")
        with self._db.cursor() as cur:
            rows = cur.execute(
                f"SELECT {column} AS grp, COUNT(*) AS n FROM alerts "
                "WHERE (:st IS NULL OR source_type = :st) GROUP BY grp",
                {"st": source_type},
            ).fetchall()
        return {row["grp"]: int(row["n"]) for row in rows}


def _row_to_alert(row: sqlite3.Row) -> Alert:
    """Rebuild a validated :class:`Alert` from a database row."""
    return Alert(
        alert_id=row["alert_id"],
        created_at=row["created_at"],
        detector_id=row["detector_id"],
        detector_version=row["detector_version"],
        category=cast(Category, row["category"]),
        severity=cast(Severity, row["severity"]),
        confidence=row["confidence"],
        src_ip=row["src_ip"],
        dst_ip=row["dst_ip"],
        window_start=row["window_start"],
        window_end=row["window_end"],
        evidence=cast(dict[str, JsonValue], loads_finite(row["evidence"])),
        threshold_snapshot=cast(dict[str, JsonValue], loads_finite(row["threshold_snapshot"])),
        dedup_key=row["dedup_key"],
        source_type=cast(SourceType, row["source_type"]),
        occurrence_count=row["occurrence_count"],
        last_seen=row["last_seen"],
        ai_explanation=row["ai_explanation"],
        ai_status=row["ai_status"],
    )
