"""The Alert Engine: cooldown/deduplication gate over persisted alerts.

Turns each detector :class:`~app.models.candidate_alert.CandidateAlert` into a
persisted :class:`~app.models.alert.Alert` (``docs/DETECTION_RULES.md`` §5):
within the cooldown the existing row is reinforced (``alert.updated``); at or
after it a new row is created (``alert.created``). The cooldown is a **fixed
window from row creation** — ``last_fired_at`` is set on create only, never
refreshed by updates, so a sustained attack still yields a fresh row every
cooldown period instead of one row absorbing it forever.

The in-memory gate is partitioned by ``(source_type, detector_id)``. Each entry
holds exactly the documented ``{latest_alert_id, last_fired_at}``; the cooldown
is a property of the partition (every key in it shares one detector), which is
what lets :meth:`AlertEngine.expire` resolve expiry for opaque hashed keys and
keeps provenances structurally isolated, mirroring ``Detector.expire``.

The engine is synchronous and returns an :class:`AlertDelta` instead of
broadcasting: it has no broadcaster, so broadcasting uncommitted state is
structurally impossible. All ``now`` values are canonical logical event time
supplied by the caller — never a wall clock.
"""

import math
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Literal

from app.alerts.dedup import dedup_key_for
from app.models.alert import Alert
from app.models.candidate_alert import CandidateAlert
from app.models.enums import SEVERITY_ORDER, SourceType
from app.storage.alerts import AlertRepository

AlertEventType = Literal["alert.created", "alert.updated"]


@dataclass(frozen=True)
class AlertDelta:
    """One change to the alert table, for the response and the WebSocket feed."""

    type: AlertEventType
    alert: Alert


@dataclass
class _GateEntry:
    """Per-dedup-key gate state — exactly the shape DETECTION_RULES §5 specifies."""

    latest_alert_id: str
    last_fired_at: float  # logical event time; set on CREATE only


def _default_id_factory() -> str:
    return str(uuid.uuid4())


class AlertEngine:
    """Applies the cooldown/deduplication gate and persists the outcome."""

    def __init__(
        self,
        repository: AlertRepository,
        cooldowns: Mapping[str, float],
        *,
        id_factory: Callable[[], str] = _default_id_factory,
    ) -> None:
        """Build the engine.

        Args:
            repository: Alert storage; every call happens inside the caller's
                transaction.
            cooldowns: ``detector_id`` → cooldown seconds. A candidate from a
                detector absent here is a wiring bug and fails loudly.
            id_factory: Produces ``alert_id`` values; injected so tests can make
                identities deterministic, mirroring Phase 2's clock injection.
        """
        for detector_id, cooldown in cooldowns.items():
            if not math.isfinite(cooldown) or cooldown <= 0:
                raise ValueError(
                    f"cooldown for detector {detector_id!r} must be finite and positive "
                    f"(got {cooldown})"
                )
        self._repo = repository
        self._cooldowns = dict(cooldowns)
        self._id_factory = id_factory
        self._gate: dict[tuple[SourceType, str], dict[str, _GateEntry]] = {}

    def process(self, candidate: CandidateAlert, now: float) -> AlertDelta:
        """Gate one candidate at logical time ``now``; persist and describe the outcome."""
        cooldown = self._cooldowns.get(candidate.detector_id)
        if cooldown is None:
            raise ValueError(f"no cooldown configured for detector {candidate.detector_id!r}")
        dedup_key = dedup_key_for(candidate)
        partition = self._gate.setdefault((candidate.source_type, candidate.detector_id), {})
        entry = partition.get(dedup_key)

        if entry is not None and now - entry.last_fired_at < cooldown:
            existing = self._repo.get(entry.latest_alert_id)
            if existing is not None:
                updated = _merge(existing, candidate, now)
                self._repo.update(updated)
                return AlertDelta(type="alert.updated", alert=updated)
            # The referenced row is gone (pruned, or its transaction rolled
            # back). The honest outcome is a fresh alert: fall through to create.

        alert = self._create(candidate, dedup_key, now)
        self._repo.insert(alert)
        # Gate state mutates only after the row write succeeded, so the gate can
        # never point at an id that was never written. (If the enclosing
        # transaction later rolls back, the dangling reference is handled by the
        # recovery branch above.)
        partition[dedup_key] = _GateEntry(latest_alert_id=alert.alert_id, last_fired_at=now)
        return AlertDelta(type="alert.created", alert=alert)

    def expire(self, source_type: SourceType, now: float) -> None:
        """Drop gate entries in ``source_type`` partitions whose cooldown elapsed.

        An elapsed entry is useless — the next trigger creates a new row
        regardless — so removing it changes no behaviour and bounds the gate at
        O(live dedup keys within cooldown). Only the named provenance is swept:
        one source's logical clock must never evict another's entries.
        """
        for (partition_source, detector_id), bucket in self._gate.items():
            if partition_source != source_type:
                continue
            cooldown = self._cooldowns[detector_id]
            expired = [key for key, e in bucket.items() if now - e.last_fired_at >= cooldown]
            for key in expired:
                del bucket[key]

    def gate_size(self) -> int:
        """Total live gate entries across all partitions (tests/observability)."""
        return sum(len(bucket) for bucket in self._gate.values())

    def _create(self, candidate: CandidateAlert, dedup_key: str, now: float) -> Alert:
        return Alert(
            alert_id=self._id_factory(),
            created_at=now,
            detector_id=candidate.detector_id,
            detector_version=candidate.detector_version,
            category=candidate.category,
            severity=candidate.severity,
            confidence=candidate.confidence,
            src_ip=candidate.src_ip,
            dst_ip=candidate.dst_ip,
            window_start=candidate.window_start,
            window_end=candidate.window_end,
            evidence=candidate.evidence,
            threshold_snapshot=candidate.threshold_snapshot,
            dedup_key=dedup_key,
            source_type=candidate.source_type,
            occurrence_count=1,
            last_seen=now,
            ai_explanation=None,
            ai_status="none",
        )


def _merge(existing: Alert, candidate: CandidateAlert, now: float) -> Alert:
    """Reinforce ``existing`` with ``candidate`` per DETECTION_RULES §5.

    Severity only escalates (never auto-lowers, to avoid flapping); evidence,
    threshold snapshot and confidence refresh to the latest values so the row
    stays self-consistent; ``window_start`` is preserved (the row spans the whole
    episode) while ``window_end`` extends; ``created_at`` and the AI fields are
    untouched. Rebuilt via the model constructor so every validator re-runs.
    """
    severity = (
        candidate.severity
        if SEVERITY_ORDER[candidate.severity] > SEVERITY_ORDER[existing.severity]
        else existing.severity
    )
    merged = existing.model_dump()
    merged.update(
        detector_version=candidate.detector_version,
        severity=severity,
        confidence=candidate.confidence,
        window_end=max(existing.window_end, candidate.window_end),
        evidence=candidate.evidence,
        threshold_snapshot=candidate.threshold_snapshot,
        occurrence_count=existing.occurrence_count + 1,
        last_seen=max(existing.last_seen, now),
    )
    return Alert(**merged)
