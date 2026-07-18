"""The event pipeline: one serialised path from events to committed deltas.

``process_batch`` is the single writer. Phase 2's detectors, the detection
engine and the alert gate are all mutable and none is thread-safe, so the whole
read-modify-write path runs under one pipeline lock; lock ordering is strictly
``pipeline → database`` and read endpoints take only the database lock, so the
two can never deadlock.

The batch runs in three phases:

- **A — compute** (no database): aggregate event stats and run detection.
- **B — persist** (one transaction): stats upserts, alert create/update, then a
  single row-cap prune, after which the delta list is filtered to the rows that
  actually survive. *A delta is returned, counted and broadcast iff its row
  exists at commit* — without the filter, a batch creating more alerts than
  ``ALERT_MAX_ROWS`` would broadcast rows already deleted inside its own
  transaction.
- **C — gate sweep** (no database): best-effort on **both** paths. After the
  commit the ingest has succeeded, so a cleanup failure is logged and must
  never turn the committed batch into an error response (which would invite a
  retry of committed data); on the failure path it still runs — so repeated
  storage failures cannot accumulate stale gate entries — but the original
  storage exception is what propagates.

Failure semantics (``docs/API.md``): ingest is **non-idempotent and
retry-unsafe**. Detector state mutates in phase A and cannot be rolled back: a
storage failure in phase B rolls the rows *and statistics* back, but the
detectors have already consumed the events, so those candidates are lost
permanently and re-feeding the batch distorts detector windows. Statistics
double-counting is the *other* hazard — a commit that succeeded whose response
was lost, where a retry re-adds already-committed counts.
"""

import logging
import threading
from collections.abc import Sequence

from app.alerts.engine import AlertDelta, AlertEngine
from app.detection.engine import DetectionEngine
from app.models.candidate_alert import CandidateAlert
from app.models.enums import SourceType
from app.models.packet_event import PacketEvent
from app.storage.alerts import AlertRepository
from app.storage.database import Database
from app.storage.stats import EventStatsRepository, aggregate_event_stats

logger = logging.getLogger(__name__)


class EventPipeline:
    """Serialises detection, alert gating, persistence and pruning per batch."""

    def __init__(
        self,
        *,
        detection: DetectionEngine,
        alerts: AlertEngine,
        alert_repository: AlertRepository,
        stats: EventStatsRepository,
        database: Database,
    ) -> None:
        self._detection = detection
        self._alerts = alerts
        self._alert_repo = alert_repository
        self._stats = stats
        self._database = database
        self._lock = threading.Lock()

    def process_batch(self, events: Sequence[PacketEvent]) -> list[AlertDelta]:
        """Run one validated batch end to end; return the surviving deltas."""
        with self._lock:
            # Phase A — compute. No database access.
            buckets = aggregate_event_stats(events)
            pending: list[tuple[CandidateAlert, float]] = []
            marks: dict[SourceType, float] = {}
            for event in events:
                candidates = self._detection.process(event)
                high_water_mark = self._detection.high_water_mark(event.source_type)
                if high_water_mark is None:
                    continue  # nothing established a logical clock for this source yet
                marks[event.source_type] = high_water_mark
                for candidate in candidates:
                    pending.append((candidate, high_water_mark))

            # Phase B — persist. One transaction; the DB lock is held only here.
            try:
                with self._database.transaction():
                    self._stats.upsert(buckets)
                    deltas = [self._alerts.process(c, now) for c, now in pending]
                    if self._alert_repo.prune_to_max_rows():
                        deltas = self._filter_to_survivors(deltas)
            except BaseException:
                # The gate sweep must still run so repeated storage failures do
                # not accumulate stale entries; best-effort here because the
                # original storage exception is what must propagate.
                try:
                    self._sweep_gate(marks)
                except Exception:
                    logger.exception("gate sweep failed while handling a storage failure")
                raise

            # Phase C — gate sweep, also best-effort: the transaction has
            # COMMITTED, so the ingest succeeded and a cleanup failure must be
            # logged, never allowed to turn the committed batch into an error
            # response that would invite an unsafe retry. Elapsed entries the
            # failed sweep leaves behind are re-swept by later batches.
            try:
                self._sweep_gate(marks)
            except Exception:
                logger.exception("gate sweep failed after a committed batch")
            return deltas

    def _filter_to_survivors(self, deltas: list[AlertDelta]) -> list[AlertDelta]:
        """Drop deltas whose rows were pruned inside this same transaction."""
        surviving = self._alert_repo.existing_ids([d.alert.alert_id for d in deltas])
        kept: list[AlertDelta] = []
        for delta in deltas:
            if delta.alert.alert_id in surviving:
                kept.append(delta)
            else:
                logger.info(
                    "alert %s (%s) was pruned within its own batch; delta discarded",
                    delta.alert.alert_id,
                    delta.type,
                )
        return kept

    def _sweep_gate(self, marks: dict[SourceType, float]) -> None:
        for source_type, now in marks.items():
            self._alerts.expire(source_type, now)
