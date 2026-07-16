"""Typed domain schemas for the Network Attack Visualiser backend.

This package defines the Phase 2 data model (see ``docs/ALERT_SCHEMA.md``):

- :class:`~app.models.packet_event.PacketEvent` — the source-agnostic transport DTO
  consumed by the detection engine.
- :class:`~app.models.candidate_alert.CandidateAlert` — a detector's proposed alert,
  with typed :class:`~app.models.candidate_alert.PortScanEvidence` /
  :class:`~app.models.candidate_alert.SynFloodEvidence` evidence.
- :class:`~app.models.alert.Alert` — the persisted alert shape (finalised by the
  Phase 3 Alert Engine).
"""

from app.models.alert import Alert
from app.models.candidate_alert import CandidateAlert, PortScanEvidence, SynFloodEvidence
from app.models.enums import (
    SEVERITY_ORDER,
    AIStatus,
    Category,
    Protocol,
    Severity,
    SourceType,
)
from app.models.packet_event import PacketEvent

__all__ = [
    "SEVERITY_ORDER",
    "AIStatus",
    "Alert",
    "CandidateAlert",
    "Category",
    "PacketEvent",
    "PortScanEvidence",
    "Protocol",
    "Severity",
    "SourceType",
    "SynFloodEvidence",
]
