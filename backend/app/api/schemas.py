"""Typed request/response models for the API layer."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.models.alert import Alert
from app.models.enums import Protocol, Severity, SourceType
from app.models.packet_event import PacketEvent


class HealthResponse(BaseModel):
    """Response body for ``GET /health``.

    ``status`` is a fixed literal so a healthy response is unambiguous, and
    ``version`` echoes the configured application version.
    """

    status: Literal["ok"]
    version: str


class AlertListResponse(BaseModel):
    """Response body for ``GET /api/v1/alerts``.

    ``items`` and ``total`` are mutually consistent within one response (they
    are read under a single database session); separate requests are not
    snapshot-stable against concurrent ingest (see ``docs/API.md``).
    """

    items: list[Alert]
    total: int = Field(ge=0, description="Rows matching the filters, ignoring pagination.")
    limit: int = Field(ge=1, description="The page size applied.")
    offset: int = Field(ge=0, description="The offset applied.")


class StatsTotals(BaseModel):
    """Whole-retained-history totals for ``GET /api/v1/stats``."""

    alert_count: int = Field(ge=0, description="Alert rows (distinct alerts).")
    alert_occurrence_total: int = Field(
        ge=0, description="Total triggers including reinforcements; always >= alert_count."
    )
    event_count: int = Field(ge=0, description="Packets over all retained stats buckets.")
    byte_count: int = Field(ge=0, description="Bytes over all retained stats buckets.")


class ProtocolCountSchema(BaseModel):
    """Aggregated traffic for one protocol."""

    protocol: Protocol
    packet_count: int = Field(ge=0)
    byte_count: int = Field(ge=0)


class TimelineBucketSchema(BaseModel):
    """One one-second ``event_stats`` bucket row of the traffic timeline."""

    bucket_ts: float = Field(description="Bucket start in logical event-time epoch seconds.")
    protocol: Protocol
    source_type: SourceType
    packet_count: int = Field(ge=0)
    byte_count: int = Field(ge=0)


class StatsResponse(BaseModel):
    """Response body for ``GET /api/v1/stats`` (contract in ``docs/API.md``)."""

    totals: StatsTotals
    alerts_by_severity: dict[Severity, int]
    alerts_by_detector: dict[str, int]
    alerts_by_source_type: dict[SourceType, int]
    protocol_distribution: list[ProtocolCountSchema]
    traffic_timeline: list[TimelineBucketSchema]


class IngestRequest(BaseModel):
    """Request body for ``POST /api/v1/ingest/events``.

    The whole batch is validated before anything is processed; a partially
    invalid batch is rejected outright and nothing is ingested.
    """

    model_config = ConfigDict(extra="forbid")

    events: list[PacketEvent] = Field(min_length=1)


class IngestResponse(BaseModel):
    """Response body for a successfully committed ingest batch.

    ``alerts_created``/``alerts_updated`` count only deltas whose rows survive
    same-batch row-cap pruning — an alert created and pruned within one batch
    has no external existence (see ``docs/API.md``).
    """

    accepted: int = Field(ge=0, description="Events accepted into the pipeline (whole batch).")
    alerts_created: int = Field(ge=0)
    alerts_updated: int = Field(ge=0)


class AlertEnvelope(BaseModel):
    """One WebSocket message on ``WS /api/v1/ws/alerts`` (``ALERT_SCHEMA`` §5)."""

    type: Literal["alert.created", "alert.updated"]
    alert: Alert
