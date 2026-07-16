"""The ``portscan`` detector (v1.0).

Detects TCP port enumeration: a single source probing many distinct ports on a
single destination within a sliding window (see ``docs/DETECTION_RULES.md`` §3).

State is keyed ``(source_type, src_ip, dst_ip)`` — nested here as
``partition[source_type] -> keys[(src_ip, dst_ip)]`` so provenances never share an
evidence window and each partition's expiry is driven by its own logical clock.
All window structures are safe against mildly out-of-order insertion.
"""

import bisect
from dataclasses import dataclass, field

from app.detection.base import SeverityLatch, is_syn_only
from app.detection.config import PortScanConfig
from app.models.candidate_alert import MAX_SAMPLED_PORTS, CandidateAlert, PortScanEvidence
from app.models.enums import Severity, SourceType
from app.models.packet_event import PacketEvent

_PortScanInnerKey = tuple[str, str]  # (src_ip, dst_ip)


@dataclass
class _KeyState:
    """Per-``(src_ip, dst_ip)`` sliding-window state within one source_type."""

    # Most recent SYN-only timestamp per distinct destination port (order-safe).
    port_last_ts: dict[int, float] = field(default_factory=dict)
    # Sorted timestamps of every in-window SYN-only packet (for syn_count).
    syn_ts: list[float] = field(default_factory=list)
    # Greatest SYN timestamp seen on this key (monotonic; drives key TTL).
    last_syn_ts: float = 0.0
    latch: SeverityLatch = field(default_factory=SeverityLatch)

    def record(self, port: int, ts: float) -> None:
        """Record a SYN-only packet to ``port`` at time ``ts``."""
        previous = self.port_last_ts.get(port)
        if previous is None or ts > previous:
            self.port_last_ts[port] = ts
        bisect.insort(self.syn_ts, ts)
        if ts > self.last_syn_ts:
            self.last_syn_ts = ts

    def evict(self, lower: float) -> None:
        """Drop evidence older than ``lower`` (inclusive lower window bound)."""
        dead_ports = [port for port, ts in self.port_last_ts.items() if ts < lower]
        for port in dead_ports:
            del self.port_last_ts[port]
        cut = bisect.bisect_left(self.syn_ts, lower)
        if cut:
            del self.syn_ts[:cut]

    @property
    def distinct_ports(self) -> int:
        return len(self.port_last_ts)


@dataclass
class _Partition:
    hwm: float = 0.0
    keys: dict[_PortScanInnerKey, _KeyState] = field(default_factory=dict)


class PortScanDetector:
    """Sliding-window distinct-destination-port detector."""

    detector_id = "portscan"
    detector_version = "1.0"

    def __init__(self, config: PortScanConfig) -> None:
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
        """Prune window evidence and idle keys, and re-arm keys below threshold."""
        lower = partition.hwm - self._cfg.window_s
        dead_keys: list[_PortScanInnerKey] = []
        for key, state in partition.keys.items():
            state.evict(lower)
            if partition.hwm - state.last_syn_ts > self._cfg.state_ttl_s:
                dead_keys.append(key)
                continue
            if state.distinct_ports < self._cfg.min_ports:
                state.latch.reset()
        for key in dead_keys:
            del partition.keys[key]

    def update(self, event: PacketEvent, now: float) -> list[CandidateAlert]:
        partition = self._partition(event.source_type)
        if now > partition.hwm:
            partition.hwm = now
        self._sweep(partition)

        # Relevance + required-field gate: only SYN-only TCP with a destination port.
        flags = event.tcp_flags or ""
        if not is_syn_only(flags) or event.dst_port is None:
            return []
        # Event-age gate (inclusive lower bound): ignore before mutating state.
        if event.ts < partition.hwm - self._cfg.window_s:
            return []

        key: _PortScanInnerKey = (event.src_ip, event.dst_ip)
        state = partition.keys.get(key)
        if state is None:
            state = _KeyState()
            partition.keys[key] = state
        state.record(event.dst_port, event.ts)

        distinct = state.distinct_ports
        if distinct < self._cfg.min_ports:
            return []
        severity = self._severity(distinct)
        if not state.latch.should_emit(severity):
            return []
        state.latch.mark(severity)
        return [self._candidate(event, state, partition.hwm, distinct, severity)]

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

    def _severity(self, distinct: int) -> Severity:
        if distinct >= self._cfg.critical_ports:
            return "critical"
        if distinct >= 2 * self._cfg.min_ports:
            return "high"
        return "medium"

    def _confidence(self, distinct: int) -> float:
        span = self._cfg.critical_ports - self._cfg.min_ports
        raw = 0.60 + 0.35 * (distinct - self._cfg.min_ports) / span
        return min(0.95, raw)

    def _candidate(
        self,
        event: PacketEvent,
        state: _KeyState,
        window_end: float,
        distinct: int,
        severity: Severity,
    ) -> CandidateAlert:
        window_start = state.syn_ts[0] if state.syn_ts else window_end
        sampled = sorted(state.port_last_ts.keys())[:MAX_SAMPLED_PORTS]
        evidence = PortScanEvidence(
            distinct_port_count=distinct,
            sampled_ports=sampled,
            syn_count=len(state.syn_ts),
            window_start=window_start,
            window_end=window_end,
            duration_s=window_end - window_start,
        )
        snapshot: dict[str, float | int] = {
            "PORTSCAN_WINDOW_S": self._cfg.window_s,
            "PORTSCAN_MIN_PORTS": self._cfg.min_ports,
            "PORTSCAN_CRITICAL_PORTS": self._cfg.critical_ports,
        }
        return CandidateAlert(
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            category="reconnaissance",
            severity=severity,
            confidence=self._confidence(distinct),
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            source_type=event.source_type,
            evidence=evidence.model_dump(),
            threshold_snapshot=snapshot,
            window_start=window_start,
            window_end=window_end,
        )
