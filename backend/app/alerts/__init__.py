"""Alert lifecycle: cooldown/deduplication gate, event pipeline, broadcasting.

Phase 3 provides :class:`~app.alerts.engine.AlertEngine` (the gate that turns
detector :class:`~app.models.candidate_alert.CandidateAlert` objects into
persisted :class:`~app.models.alert.Alert` rows), the
:class:`~app.alerts.pipeline.EventPipeline` that serialises the whole
ingest→detect→persist path, and the
:class:`~app.alerts.broadcaster.AlertBroadcaster` that fans live deltas out to
WebSocket subscribers.
"""

from app.alerts.broadcaster import AlertBroadcaster, AlertSubscription
from app.alerts.dedup import dedup_key_for, major_version
from app.alerts.engine import AlertDelta, AlertEngine, AlertEventType
from app.alerts.pipeline import EventPipeline

__all__ = [
    "AlertBroadcaster",
    "AlertDelta",
    "AlertEngine",
    "AlertEventType",
    "AlertSubscription",
    "EventPipeline",
    "dedup_key_for",
    "major_version",
]
