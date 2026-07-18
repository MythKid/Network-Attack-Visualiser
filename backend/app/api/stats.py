"""The statistics endpoint: ``GET /api/v1/stats``.

The whole response is assembled by :func:`stats_snapshot` inside **one**
database read session, so its sections are mutually consistent — an ingest
batch cannot commit between the alert counts and the timeline of a single
response. The handler is a synchronous ``def`` route, so the entire snapshot
(read session included) runs on one worker thread, never on the event loop.

Timeline selection is provenance-aware (``docs/API.md``): ``buckets`` counts
the most recent *distinct logical event-time seconds* independently per
``source_type`` — a global ranking would let live timestamps crowd synthetic
and replay buckets out entirely.
"""

from typing import Annotated, get_args

from fastapi import APIRouter, Depends, Query

from app.api.deps import get_alert_repository, get_database, get_detector_ids, get_stats_repository
from app.api.schemas import (
    ProtocolCountSchema,
    StatsResponse,
    StatsTotals,
    TimelineBucketSchema,
)
from app.models.enums import Severity, SourceType
from app.storage.alerts import AlertRepository
from app.storage.database import Database
from app.storage.stats import EventStatsRepository

router = APIRouter(prefix="/api/v1", tags=["stats"])


def stats_snapshot(
    database: Database,
    alerts: AlertRepository,
    stats: EventStatsRepository,
    *,
    detector_ids: tuple[str, ...],
    buckets: int,
    source_type: SourceType | None,
) -> StatsResponse:
    """Assemble one internally consistent statistics response.

    Every query runs inside a single read session: in-process writers wait for
    the whole snapshot, so ``sum(alerts_by_severity) == totals.alert_count``
    always holds within one response. Counts with no rows are zero-filled for
    every known enum key so the frontend never needs defaulting.
    """
    with database.read_session():
        alert_count = alerts.count(source_type=source_type)
        occurrence_total = alerts.occurrence_total(source_type=source_type)
        severity_counts = alerts.counts_by("severity", source_type=source_type)
        detector_counts = alerts.counts_by("detector_id", source_type=source_type)
        source_counts = alerts.counts_by("source_type", source_type=source_type)
        packet_total, byte_total = stats.totals(source_type=source_type)
        distribution = stats.protocol_distribution(source_type=source_type)
        timeline = stats.timeline(buckets=buckets, source_type=source_type)

    return StatsResponse(
        totals=StatsTotals(
            alert_count=alert_count,
            alert_occurrence_total=occurrence_total,
            event_count=packet_total,
            byte_count=byte_total,
        ),
        alerts_by_severity={
            severity: severity_counts.get(severity, 0) for severity in get_args(Severity)
        },
        alerts_by_detector={
            detector: detector_counts.get(detector, 0) for detector in detector_ids
        },
        alerts_by_source_type={
            source: source_counts.get(source, 0) for source in get_args(SourceType)
        },
        protocol_distribution=[
            ProtocolCountSchema(
                protocol=row.protocol,
                packet_count=row.packet_count,
                byte_count=row.byte_count,
            )
            for row in distribution
        ],
        traffic_timeline=[
            TimelineBucketSchema(
                bucket_ts=row.bucket_ts,
                protocol=row.protocol,
                source_type=row.source_type,
                packet_count=row.packet_count,
                byte_count=row.byte_count,
            )
            for row in timeline
        ],
    )


@router.get(
    "/stats",
    response_model=StatsResponse,
    summary="Overview statistics, protocol distribution and traffic timeline",
)
def get_stats(
    database: Annotated[Database, Depends(get_database)],
    alerts: Annotated[AlertRepository, Depends(get_alert_repository)],
    stats: Annotated[EventStatsRepository, Depends(get_stats_repository)],
    detector_ids: Annotated[tuple[str, ...], Depends(get_detector_ids)],
    buckets: Annotated[int, Query(ge=1, le=3600)] = 300,
    source_type: Annotated[SourceType | None, Query()] = None,
) -> StatsResponse:
    """One consistent snapshot; ``source_type`` scopes every section."""
    return stats_snapshot(
        database,
        alerts,
        stats,
        detector_ids=detector_ids,
        buckets=buckets,
        source_type=source_type,
    )
