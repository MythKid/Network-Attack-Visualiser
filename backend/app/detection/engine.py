"""The detection engine.

The engine owns the canonical logical clock: for each ``PacketEvent`` it advances a
per-``source_type`` monotonic high-water mark (HWM) derived from ``PacketEvent.ts``
and passes that ``now`` to every detector. It performs the event-time,
out-of-order and too-late policy from ``docs/DETECTION_RULES.md`` §2.1, then routes
the event to the detectors and drives their periodic expiry.

No real clock is read anywhere: an accelerated replay and a real-time replay of the
same timestamps therefore produce identical alerts.
"""

import math
from collections.abc import Sequence

from app.detection.base import Detector
from app.models.candidate_alert import CandidateAlert
from app.models.enums import SourceType
from app.models.packet_event import PacketEvent


class DetectionEngine:
    """Routes events to detectors under a per-``source_type`` logical clock."""

    def __init__(self, detectors: Sequence[Detector], *, max_window_s: float | None = None) -> None:
        """Build the engine.

        Args:
            detectors: The detectors to run, in order.
            max_window_s: Optional override for the maximum accepted event age. When
                ``None`` the engine derives it from the detectors. A supplied value
                must be finite and at least the largest detector ``max_event_age_s``
                so no valid event is ever silently dropped; a smaller value raises.
        """
        self._detectors: list[Detector] = list(detectors)
        for detector in self._detectors:
            # A non-finite horizon would make the too-late comparison meaningless
            # (every event in-window for +inf, none for NaN), so reject it up front.
            if not math.isfinite(detector.max_event_age_s):
                raise ValueError(
                    f"detector {detector.detector_id!r} reports a non-finite "
                    f"max_event_age_s ({detector.max_event_age_s})"
                )
        derived = max((d.max_event_age_s for d in self._detectors), default=0.0)
        if max_window_s is None:
            resolved = derived
        elif not math.isfinite(max_window_s):
            # Checked before any comparison: NaN compares false against everything
            # and would otherwise slip through the bound check below.
            raise ValueError(f"max_window_s must be finite (got {max_window_s})")
        elif max_window_s < derived:
            raise ValueError(
                f"max_window_s ({max_window_s}) must be >= the largest detector "
                f"max_event_age_s ({derived})"
            )
        else:
            resolved = max_window_s
        if resolved <= 0:
            raise ValueError("max_window_s must be positive (are there any detectors?)")
        self._max_window_s: float = resolved
        self._hwm: dict[SourceType, float] = {}
        self.dropped_late: int = 0
        self.dropped_invalid: int = 0

    @property
    def max_window_s(self) -> float:
        """The resolved maximum accepted event age."""
        return self._max_window_s

    def high_water_mark(self, source_type: SourceType) -> float | None:
        """Return the current logical high-water mark for ``source_type`` (if any)."""
        return self._hwm.get(source_type)

    def process(self, event: PacketEvent) -> list[CandidateAlert]:
        """Advance logical time, apply the event-time policy, and route the event."""
        if not math.isfinite(event.ts):  # defensive; the schema already rejects this
            self.dropped_invalid += 1
            return []

        source_type = event.source_type
        previous = self._hwm.get(source_type)
        now = event.ts if previous is None else max(previous, event.ts)

        # Too-late: older than any detector's window. Dropped, never routed.
        if event.ts < now - self._max_window_s:
            self.dropped_late += 1
            return []

        self._hwm[source_type] = now

        candidates: list[CandidateAlert] = []
        for detector in self._detectors:
            candidates.extend(detector.update(event, now))
        for detector in self._detectors:
            detector.expire(source_type, now)
        return candidates
