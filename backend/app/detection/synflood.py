"""The ``synflood`` detector (v1.0).

Detects SYN floods / half-open abuse against a victim: a high rate of connection
initiations with a low proportion of completed handshakes (see
``docs/DETECTION_RULES.md`` §4).

State is keyed ``(source_type, target_ip)`` — destination-centric. The target of a
packet is ``dst_ip`` for an inbound SYN or final ACK and ``src_ip`` for an outbound
SYN-ACK or RST, so a reversed SYN-ACK/RST operates on the same state created by the
original inbound SYN. Completion accounting is gated on whether *this* detector
actually observed the initiating SYN, and each observed SYN attempt has a stable
identity so 4-tuple reuse can never complete the wrong attempt.
"""

import bisect
from dataclasses import dataclass, field

from app.detection.base import (
    SeverityLatch,
    is_final_ack,
    is_rst,
    is_syn_ack,
    is_syn_only,
)
from app.detection.config import SynFloodConfig
from app.models.candidate_alert import CandidateAlert, SynFloodEvidence
from app.models.enums import Severity, SourceType
from app.models.packet_event import PacketEvent

_FourTuple = tuple[str, int, str, int]  # (src_ip, src_port, dst_ip, dst_port)

_SYN = "SYN"
_SYNACK = "SYNACK"
_ACK = "ACK"
_RST = "RST"

_STATE_SYN_SEEN = "SYN_SEEN"
_STATE_SYN_ACK_SEEN = "SYN_ACK_SEEN"


@dataclass
class _Attempt:
    """One observed-SYN connection attempt in the window cohort."""

    syn_ts: float
    src_ip: str
    completed: bool = False


@dataclass
class _Pending:
    """A half-open handshake tracked for matching, keyed by 4-tuple.

    ``attempt_id`` is set if and only if ``syn_observed`` is true: an entry born
    from an orphan SYN-ACK has neither until a real SYN is observed for it.
    """

    attempt_id: int | None  # cohort identity, set only once a SYN is observed
    syn_observed: bool
    state: str
    last_progress_ts: float


@dataclass
class _KeyState:
    """Per-target sliding-window state within one source_type."""

    pending: dict[_FourTuple, _Pending] = field(default_factory=dict)
    attempts: dict[int, _Attempt] = field(default_factory=dict)
    synack_ts: list[float] = field(default_factory=list)
    last_activity_ts: float = 0.0
    latch: SeverityLatch = field(default_factory=SeverityLatch)
    _next_attempt_id: int = 0

    def new_attempt(self, syn_ts: float, src_ip: str) -> int:
        """Register a new cohort attempt and return its stable id."""
        self._next_attempt_id += 1
        attempt_id = self._next_attempt_id
        self.attempts[attempt_id] = _Attempt(syn_ts=syn_ts, src_ip=src_ip)
        return attempt_id


@dataclass
class _Partition:
    hwm: float = 0.0
    keys: dict[str, _KeyState] = field(default_factory=dict)


class SynFloodDetector:
    """Destination-centric SYN-flood / half-open detector."""

    detector_id = "synflood"
    detector_version = "1.0"

    def __init__(self, config: SynFloodConfig) -> None:
        self._cfg = config
        self._partitions: dict[SourceType, _Partition] = {}

    @property
    def max_event_age_s(self) -> float:
        return self._cfg.max_event_age_s

    def _partition(self, source_type: SourceType) -> _Partition:
        partition = self._partitions.get(source_type)
        if partition is None:
            partition = _Partition()
            self._partitions[source_type] = partition
        return partition

    def _sweep(self, partition: _Partition) -> None:
        """Evict aged cohort/pending state and re-arm keys below threshold."""
        syn_lower = partition.hwm - self._cfg.window_s
        dead_keys: list[str] = []
        for target, state in partition.keys.items():
            dead_attempts = [aid for aid, att in state.attempts.items() if att.syn_ts < syn_lower]
            for aid in dead_attempts:
                del state.attempts[aid]
            cut = bisect.bisect_left(state.synack_ts, syn_lower)
            if cut:
                del state.synack_ts[:cut]
            dead_pending = [
                ft
                for ft, pend in state.pending.items()
                if partition.hwm - pend.last_progress_ts > self._cfg.handshake_ttl_s
            ]
            for ft in dead_pending:
                del state.pending[ft]
            if partition.hwm - state.last_activity_ts > self._cfg.state_ttl_s:
                dead_keys.append(target)
                continue
            if not self._triggered(state):
                state.latch.reset()
        for target in dead_keys:
            del partition.keys[target]

    def update(self, event: PacketEvent, now: float) -> list[CandidateAlert]:
        partition = self._partition(event.source_type)
        if now > partition.hwm:
            partition.hwm = now
        self._sweep(partition)

        classified = self._classify(event)
        if classified is None:
            return []
        packet_type, target_ip, four_tuple = classified

        # Age-gate before touching state: a packet that cannot affect this detector
        # must create no key, pending entry or cohort attempt (§2). Last-activity —
        # and so the key's idle TTL — advances only once admission has succeeded,
        # meaning the packet genuinely creates, progresses, completes or removes state.
        state = self._admit(packet_type, partition, target_ip, four_tuple, event)
        if state is None:
            return []
        if event.ts > state.last_activity_ts:
            state.last_activity_ts = event.ts

        self._apply(packet_type, state, four_tuple, event, partition.hwm)

        if not self._triggered(state):
            return []
        syn_count, completed = self._counts(state)
        ratio = completed / syn_count
        severity = self._severity(syn_count, ratio)
        if not state.latch.should_emit(severity):
            return []
        state.latch.mark(severity)
        return [
            self._candidate(
                target_ip,
                event.source_type,
                state,
                partition.hwm,
                syn_count,
                completed,
                ratio,
                severity,
            )
        ]

    def expire(self, source_type: SourceType, now: float) -> None:
        """Advance the ``source_type`` partition to ``now`` and sweep only it.

        Only the named partition's logical clock moves: applying a foreign
        ``source_type``'s time to another provenance would break the cross-source
        isolation the partitioned state exists to guarantee.
        """
        partition = self._partitions.get(source_type)
        if partition is None:
            return
        if now > partition.hwm:
            partition.hwm = now
        self._sweep(partition)

    def _key_state(self, partition: _Partition, target_ip: str) -> _KeyState:
        """Return the target's key state, creating it if absent."""
        state = partition.keys.get(target_ip)
        if state is None:
            state = _KeyState()
            partition.keys[target_ip] = state
        return state

    def _admit(
        self,
        packet_type: str,
        partition: _Partition,
        target_ip: str,
        four_tuple: _FourTuple,
        event: PacketEvent,
    ) -> _KeyState | None:
        """Apply the packet-specific age gate and resolve the key state to mutate.

        Returns ``None`` when the packet can no longer affect detector state, in
        which case the caller must not create or touch anything at all.
        """
        if packet_type == _SYN:
            # A SYN older than the evidence window can never join a cohort.
            if event.ts < partition.hwm - self._cfg.window_s:
                return None
            return self._key_state(partition, target_ip)
        # SYN-ACK / final ACK / RST only matter for the handshake lifetime.
        if event.ts < partition.hwm - self._cfg.handshake_ttl_s:
            return None
        if packet_type == _SYNACK:
            # A SYN-ACK may legitimately open state for a SYN this detector missed.
            return self._key_state(partition, target_ip)
        # A bare ACK or an unmatched RST is established-flow traffic (§4.1): with no
        # matching pending entry it is ignored, and must not materialise a key.
        state = partition.keys.get(target_ip)
        if state is None or four_tuple not in state.pending:
            return None
        return state

    def _classify(self, event: PacketEvent) -> tuple[str, str, _FourTuple] | None:
        """Return (packet_type, target_ip, four_tuple) or ``None`` if irrelevant."""
        flags = event.tcp_flags
        if flags is None or event.src_port is None or event.dst_port is None:
            return None
        forward: _FourTuple = (event.src_ip, event.src_port, event.dst_ip, event.dst_port)
        reverse: _FourTuple = (event.dst_ip, event.dst_port, event.src_ip, event.src_port)
        if is_syn_only(flags):
            return (_SYN, event.dst_ip, forward)
        if is_syn_ack(flags):
            return (_SYNACK, event.src_ip, reverse)
        if is_final_ack(flags):
            return (_ACK, event.dst_ip, forward)
        if is_rst(flags):
            return (_RST, event.src_ip, reverse)
        return None

    def _apply(
        self,
        packet_type: str,
        state: _KeyState,
        four_tuple: _FourTuple,
        event: PacketEvent,
        hwm: float,
    ) -> None:
        if packet_type == _SYN:
            self._apply_syn(state, four_tuple, event)
        elif packet_type == _SYNACK:
            self._apply_synack(state, four_tuple, event, hwm)
        elif packet_type == _ACK:
            self._apply_final_ack(state, four_tuple)
        elif packet_type == _RST:
            self._apply_rst(state, four_tuple)

    def _apply_syn(self, state: _KeyState, four_tuple: _FourTuple, event: PacketEvent) -> None:
        # In-window by construction: ``_admit`` has already applied the SYN age gate.
        pending = state.pending.get(four_tuple)
        if pending is None:
            state.pending[four_tuple] = _Pending(
                attempt_id=state.new_attempt(event.ts, event.src_ip),
                syn_observed=True,
                state=_STATE_SYN_SEEN,
                last_progress_ts=event.ts,
            )
            return
        if event.ts > pending.last_progress_ts:
            pending.last_progress_ts = event.ts
        if pending.syn_observed:
            return  # retransmitted SYN: refresh only, never double-count
        # Late SYN after an orphan SYN-ACK: becomes cohort-eligible now, without
        # losing any SYN_ACK_SEEN progress already recorded.
        pending.syn_observed = True
        pending.attempt_id = state.new_attempt(event.ts, event.src_ip)

    def _apply_synack(
        self, state: _KeyState, four_tuple: _FourTuple, event: PacketEvent, hwm: float
    ) -> None:
        # Progression and evidence accounting are deliberately separate (§4.2): a
        # SYN-ACK within HANDSHAKE_TTL_S may progress a pending entry, but it enters
        # the evidence window only if it is also inside SYN_WINDOW_S, so synack_count
        # and the SYN cohort always describe the same window.
        if event.ts >= hwm - self._cfg.window_s:
            bisect.insort(state.synack_ts, event.ts)
        pending = state.pending.get(four_tuple)
        if pending is None:
            state.pending[four_tuple] = _Pending(
                attempt_id=None,
                syn_observed=False,
                state=_STATE_SYN_ACK_SEEN,
                last_progress_ts=event.ts,
            )
            return
        pending.state = _STATE_SYN_ACK_SEEN
        if event.ts > pending.last_progress_ts:
            pending.last_progress_ts = event.ts

    def _apply_final_ack(self, state: _KeyState, four_tuple: _FourTuple) -> None:
        # A matching pending entry is guaranteed by ``_admit``.
        pending = state.pending.pop(four_tuple)
        if pending.syn_observed and pending.attempt_id is not None:
            attempt = state.attempts.get(pending.attempt_id)
            if attempt is not None:
                attempt.completed = True

    def _apply_rst(self, state: _KeyState, four_tuple: _FourTuple) -> None:
        del state.pending[four_tuple]  # remove without counting a completion

    def _counts(self, state: _KeyState) -> tuple[int, int]:
        syn_count = len(state.attempts)
        completed = sum(1 for att in state.attempts.values() if att.completed)
        return syn_count, completed

    def _triggered(self, state: _KeyState) -> bool:
        syn_count, completed = self._counts(state)
        if syn_count < self._cfg.min_count:
            return False
        ratio = completed / syn_count
        return ratio < self._cfg.max_completion_ratio

    def _severity(self, syn_count: int, ratio: float) -> Severity:
        mx = self._cfg.max_completion_ratio
        if syn_count >= 5 * self._cfg.min_count and ratio < mx / 4:
            return "critical"
        if syn_count >= 2 * self._cfg.min_count or ratio < mx / 2:
            return "high"
        return "medium"

    def _confidence(self, ratio: float) -> float:
        raw = 0.60 + 0.35 * (1 - ratio / self._cfg.max_completion_ratio)
        return min(0.95, max(0.0, raw))

    def _candidate(
        self,
        target_ip: str,
        source_type: SourceType,
        state: _KeyState,
        window_end: float,
        syn_count: int,
        completed: int,
        ratio: float,
        severity: Severity,
    ) -> CandidateAlert:
        window_start = min((att.syn_ts for att in state.attempts.values()), default=window_end)
        distinct_src = len({att.src_ip for att in state.attempts.values()})
        evidence = SynFloodEvidence(
            syn_count=syn_count,
            synack_count=len(state.synack_ts),
            completed_handshakes=completed,
            completion_ratio=ratio,
            distinct_src_count=distinct_src,
            syn_rate_per_s=syn_count / self._cfg.window_s,
            window_start=window_start,
            window_end=window_end,
        )
        snapshot: dict[str, float | int] = {
            "SYN_WINDOW_S": self._cfg.window_s,
            "SYN_MIN_COUNT": self._cfg.min_count,
            "SYN_MAX_COMPLETION_RATIO": self._cfg.max_completion_ratio,
        }
        return CandidateAlert(
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            category="dos",
            severity=severity,
            confidence=self._confidence(ratio),
            src_ip=None,
            dst_ip=target_ip,
            source_type=source_type,
            evidence=evidence.model_dump(),
            threshold_snapshot=snapshot,
            window_start=window_start,
            window_end=window_end,
        )
