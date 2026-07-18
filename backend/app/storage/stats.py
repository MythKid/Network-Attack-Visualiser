"""Pre-aggregated ``event_stats`` storage (one-second buckets).

Raw events are never persisted (``docs/ALERT_SCHEMA.md`` §3): ingestion
aggregates each batch in memory (:func:`aggregate_event_stats`, a pure function)
and upserts one row per ``(bucket_ts, protocol, source_type)`` — not one per
event. Timeline selection is provenance-aware: ``bucket_ts`` is *logical event
time*, so the "latest" buckets are ranked independently per ``source_type`` and
merged — a global ranking would let live timestamps crowd every synthetic and
replay bucket out of the timeline entirely.
"""

import math
from collections.abc import Sequence
from typing import NamedTuple, cast

from app.models.enums import Protocol, SourceType
from app.models.packet_event import PacketEvent
from app.storage.database import Database

# (bucket_ts, protocol, source_type) -> (packet_count, byte_count)
StatsBuckets = dict[tuple[float, str, str], tuple[int, int]]

_UPSERT_SQL = """
INSERT INTO event_stats (bucket_ts, protocol, source_type, packet_count, byte_count)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT (bucket_ts, protocol, source_type) DO UPDATE SET
    packet_count = packet_count + excluded.packet_count,
    byte_count   = byte_count + excluded.byte_count
"""

# Latest N distinct bucket timestamps per source_type, then merged. DENSE_RANK
# (not ROW_NUMBER) so all protocol rows sharing one second rank together and
# `buckets` counts distinct timestamps, not rows.
_TIMELINE_SQL = """
WITH ranked AS (
    SELECT bucket_ts, protocol, source_type, packet_count, byte_count,
           DENSE_RANK() OVER (
               PARTITION BY source_type ORDER BY bucket_ts DESC
           ) AS rnk
      FROM event_stats
     WHERE (:st IS NULL OR source_type = :st)
)
SELECT bucket_ts, protocol, source_type, packet_count, byte_count
  FROM ranked
 WHERE rnk <= :buckets
 ORDER BY source_type, bucket_ts, protocol
"""


class ProtocolCount(NamedTuple):
    """Aggregated traffic for one protocol."""

    protocol: Protocol
    packet_count: int
    byte_count: int


class TimelineBucket(NamedTuple):
    """One ``event_stats`` row of the traffic timeline."""

    bucket_ts: float
    protocol: Protocol
    source_type: SourceType
    packet_count: int
    byte_count: int


def aggregate_event_stats(events: Sequence[PacketEvent]) -> StatsBuckets:
    """Aggregate a batch into one-second buckets (pure; no database access)."""
    buckets: StatsBuckets = {}
    for event in events:
        key = (float(math.floor(event.ts)), event.protocol, event.source_type)
        packets, bytes_ = buckets.get(key, (0, 0))
        buckets[key] = (packets + 1, bytes_ + event.packet_length)
    return buckets


class EventStatsRepository:
    """Upserts and reads for the ``event_stats`` table."""

    def __init__(self, database: Database) -> None:
        self._db = database

    def upsert(self, buckets: StatsBuckets) -> None:
        """Add a batch's aggregated counts (one upsert per bucket)."""
        if not buckets:
            return
        self._db.require_transaction()
        rows = [
            (bucket_ts, protocol, source_type, packets, bytes_)
            for (bucket_ts, protocol, source_type), (packets, bytes_) in buckets.items()
        ]
        with self._db.cursor() as cur:
            cur.executemany(_UPSERT_SQL, rows)

    def totals(self, *, source_type: SourceType | None = None) -> tuple[int, int]:
        """``(packet_count, byte_count)`` summed over all retained rows."""
        with self._db.cursor() as cur:
            row = cur.execute(
                "SELECT COALESCE(SUM(packet_count), 0), COALESCE(SUM(byte_count), 0) "
                "FROM event_stats WHERE (:st IS NULL OR source_type = :st)",
                {"st": source_type},
            ).fetchone()
        return int(row[0]), int(row[1])

    def protocol_distribution(
        self, *, source_type: SourceType | None = None
    ) -> list[ProtocolCount]:
        """Traffic per protocol over all retained rows."""
        with self._db.cursor() as cur:
            rows = cur.execute(
                "SELECT protocol, SUM(packet_count) AS packets, SUM(byte_count) AS bytes_ "
                "FROM event_stats WHERE (:st IS NULL OR source_type = :st) "
                "GROUP BY protocol ORDER BY protocol",
                {"st": source_type},
            ).fetchall()
        return [
            ProtocolCount(
                protocol=cast(Protocol, row["protocol"]),
                packet_count=int(row["packets"]),
                byte_count=int(row["bytes_"]),
            )
            for row in rows
        ]

    def timeline(
        self, *, buckets: int, source_type: SourceType | None = None
    ) -> list[TimelineBucket]:
        """The most recent ``buckets`` distinct event-time seconds, per provenance."""
        with self._db.cursor() as cur:
            rows = cur.execute(_TIMELINE_SQL, {"st": source_type, "buckets": buckets}).fetchall()
        return [
            TimelineBucket(
                bucket_ts=float(row["bucket_ts"]),
                protocol=cast(Protocol, row["protocol"]),
                source_type=cast(SourceType, row["source_type"]),
                packet_count=int(row["packet_count"]),
                byte_count=int(row["byte_count"]),
            )
            for row in rows
        ]
