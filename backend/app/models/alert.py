"""The persisted :class:`Alert` model (shape only).

An ``Alert`` is produced from a detector's
:class:`~app.models.candidate_alert.CandidateAlert` and finalised by the Alert
Engine's cooldown/deduplication gate (see ``docs/ALERT_SCHEMA.md`` §2 and
``docs/DETECTION_RULES.md`` §5). Phase 2 defines the schema only; the create/update
lifecycle that populates ``dedup_key``/``occurrence_count``/``last_seen`` and the
AI fields is introduced in Phase 3.
"""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.enums import AIStatus, Category, Severity, SourceType
from app.models.json_types import (
    Confidence,
    DedupKeyStr,
    FiniteFloat,
    FiniteJsonValue,
    IPStr,
    NonEmptyStr,
    PositiveFiniteFloat,
    UUIDv4Str,
)


class Alert(BaseModel):
    """A persisted alert row (see ``docs/ALERT_SCHEMA.md`` §2)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    alert_id: UUIDv4Str
    created_at: PositiveFiniteFloat
    detector_id: NonEmptyStr
    detector_version: NonEmptyStr
    category: Category
    severity: Severity
    confidence: Confidence
    src_ip: IPStr | None = None
    dst_ip: IPStr
    window_start: FiniteFloat
    window_end: FiniteFloat
    evidence: dict[str, FiniteJsonValue]
    threshold_snapshot: dict[str, FiniteJsonValue]
    dedup_key: DedupKeyStr
    source_type: SourceType
    occurrence_count: Annotated[int, Field(ge=1)] = 1
    last_seen: PositiveFiniteFloat
    ai_explanation: str | None = None
    ai_status: AIStatus = "none"

    @model_validator(mode="after")
    def _check_time_relationships(self) -> "Alert":
        if self.window_start > self.window_end:
            raise ValueError("window_start must not be after window_end")
        if self.created_at > self.last_seen:
            raise ValueError("created_at must not be after last_seen")
        return self
