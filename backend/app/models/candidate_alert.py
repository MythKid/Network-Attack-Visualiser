"""The :class:`CandidateAlert` detector-output DTO and its typed evidence models.

Detectors return ``CandidateAlert`` objects (see ``docs/ALERT_SCHEMA.md`` §2.0),
never the persisted :class:`~app.models.alert.Alert`. A ``CandidateAlert`` carries
only what a detector can know; it deliberately has **no** identity, timing,
deduplication or AI fields — those are added later by the Alert Engine (Phase 3).
"""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.enums import Category, Severity, SourceType
from app.models.json_types import (
    Confidence,
    FiniteFloat,
    FiniteJsonValue,
    IPStr,
    NonEmptyStr,
    Port,
)

# Maximum number of ports sampled onto portscan evidence (see DETECTION_RULES §3).
MAX_SAMPLED_PORTS = 20


class PortScanEvidence(BaseModel):
    """Evidence recorded for a ``portscan`` candidate (DETECTION_RULES §3)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    distinct_port_count: Annotated[int, Field(ge=0)]
    sampled_ports: list[Port]
    syn_count: Annotated[int, Field(ge=0)]
    window_start: FiniteFloat
    window_end: FiniteFloat
    duration_s: Annotated[float, Field(ge=0)]

    @field_validator("sampled_ports")
    @classmethod
    def _check_sampled_ports(cls, ports: list[int]) -> list[int]:
        if len(ports) > MAX_SAMPLED_PORTS:
            raise ValueError(f"sampled_ports must contain at most {MAX_SAMPLED_PORTS} entries")
        if len(set(ports)) != len(ports):
            raise ValueError("sampled_ports must be unique")
        return ports

    @model_validator(mode="after")
    def _check_window(self) -> "PortScanEvidence":
        if self.window_start > self.window_end:
            raise ValueError("window_start must not be after window_end")
        return self


class SynFloodEvidence(BaseModel):
    """Evidence recorded for a ``synflood`` candidate (DETECTION_RULES §4)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    syn_count: Annotated[int, Field(ge=0)]
    synack_count: Annotated[int, Field(ge=0)]
    completed_handshakes: Annotated[int, Field(ge=0)]
    completion_ratio: Annotated[float, Field(ge=0.0, le=1.0)]
    distinct_src_count: Annotated[int, Field(ge=0)]
    syn_rate_per_s: Annotated[float, Field(ge=0.0)]
    window_start: FiniteFloat
    window_end: FiniteFloat

    @model_validator(mode="after")
    def _check_invariants(self) -> "SynFloodEvidence":
        if self.completed_handshakes > self.syn_count:
            raise ValueError("completed_handshakes must not exceed syn_count")
        if self.window_start > self.window_end:
            raise ValueError("window_start must not be after window_end")
        return self


class CandidateAlert(BaseModel):
    """A detector's proposed alert, prior to Alert-Engine finalisation.

    It carries **no** ``alert_id``, ``created_at``, ``dedup_key``,
    ``occurrence_count``, ``last_seen`` or AI fields — those belong to
    :class:`~app.models.alert.Alert`.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    detector_id: NonEmptyStr
    detector_version: NonEmptyStr
    category: Category
    severity: Severity
    confidence: Confidence
    src_ip: IPStr | None = None
    dst_ip: IPStr
    source_type: SourceType
    evidence: dict[str, FiniteJsonValue]
    threshold_snapshot: dict[str, FiniteJsonValue]
    window_start: FiniteFloat
    window_end: FiniteFloat

    @model_validator(mode="after")
    def _check_window(self) -> "CandidateAlert":
        if self.window_start > self.window_end:
            raise ValueError("window_start must not be after window_end")
        return self
