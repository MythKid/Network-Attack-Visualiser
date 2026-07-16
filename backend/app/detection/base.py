"""The detector interface and small shared helpers.

Every detector implements the :class:`Detector` protocol (see
``docs/DETECTION_RULES.md`` §2). Detectors are pure and clock-injected: they
receive the canonical logical event time ``now`` as a parameter and never read a
real clock. The additive ``max_event_age_s`` attribute lets the engine derive the
oldest event age any detector can still use, so no valid event is silently dropped.
"""

from dataclasses import dataclass
from typing import Protocol

from app.models.candidate_alert import CandidateAlert
from app.models.enums import SEVERITY_ORDER, Severity, SourceType
from app.models.packet_event import PacketEvent


class Detector(Protocol):
    """Consumes ``PacketEvent`` objects at logical time ``now`` and proposes alerts."""

    detector_id: str
    detector_version: str

    @property
    def max_event_age_s(self) -> float:
        """Oldest event age (relative to ``now``) this detector can still make use of."""
        ...

    def update(self, event: PacketEvent, now: float) -> list[CandidateAlert]:
        """Consume one event at logical time ``now``; return zero or more candidates."""
        ...

    def expire(self, source_type: SourceType, now: float) -> None:
        """Prune ``source_type`` state whose window/TTL has elapsed as of ``now``.

        Expiry is per-provenance because detector state is partitioned by
        ``source_type`` and each partition runs on its own logical clock. Advancing
        one provenance's time must never age out another's state, so the caller
        names the partition the supplied ``now`` belongs to.
        """
        ...


@dataclass
class SeverityLatch:
    """Per-key emission gate implementing severity-aware, re-armable triggering.

    A candidate is emitted on the first crossing of the trigger predicate and again
    only when the severity *increases*; equal or lower severities are suppressed.
    The latch is fully re-armed once the predicate drops below threshold, so a
    genuinely new burst re-triggers.
    """

    active: bool = False
    last_severity: Severity | None = None

    def should_emit(self, severity: Severity) -> bool:
        """Return whether an alert should be emitted at ``severity``."""
        if not self.active or self.last_severity is None:
            return True
        return SEVERITY_ORDER[severity] > SEVERITY_ORDER[self.last_severity]

    def mark(self, severity: Severity) -> None:
        """Record that an alert was emitted at ``severity``."""
        self.active = True
        self.last_severity = severity

    def reset(self) -> None:
        """Re-arm the latch (predicate has fallen below threshold)."""
        self.active = False
        self.last_severity = None


def is_syn_only(flags: str) -> bool:
    """True for a connection-initiating SYN (``SYN=1, ACK=0``)."""
    return "S" in flags and "A" not in flags


def is_syn_ack(flags: str) -> bool:
    """True for a SYN-ACK (``SYN=1, ACK=1``)."""
    return "S" in flags and "A" in flags


def is_final_ack(flags: str) -> bool:
    """True for a bare final ACK (``ACK=1, SYN=0, RST=0, FIN=0``)."""
    return "A" in flags and "S" not in flags and "R" not in flags and "F" not in flags


def is_rst(flags: str) -> bool:
    """True for any segment carrying RST."""
    return "R" in flags
