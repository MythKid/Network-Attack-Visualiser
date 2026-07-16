"""Deterministic synthetic event generation (Phase 2).

Produces clearly-labelled ``source_type="synthetic"`` :class:`PacketEvent` streams
for tests and demonstrations. Sequences are fully deterministic — including event
ids, which come from an injective scenario-and-counter UUIDv4 factory rather than a
PRNG, so ids are unique **by construction** both within and across scenarios.

The three canonical scenarios mirror ``docs/DETECTION_RULES.md`` §7:

- :func:`normal_traffic` — completed handshakes and some UDP/ICMP; no alerts.
- :func:`port_scan` — one source, many distinct ports; a ``portscan`` alert only.
- :func:`syn_burst` — a high-rate SYN flood; a ``synflood`` alert only.
"""

import uuid

from app.models.enums import Protocol, SourceType
from app.models.packet_event import PacketEvent

# Distinct id namespaces per scenario. Because each scenario uses a distinct code,
# ids never collide across scenarios regardless of their counters.
SCENARIO_CODES: dict[str, int] = {"normal": 1, "port_scan": 2, "syn_burst": 3}

_MAX_SCENARIO_CODE = 1 << 12
_MAX_COUNTER = 1 << 62


def deterministic_uuid4(scenario_code: int, counter: int) -> uuid.UUID:
    """Build a valid UUIDv4 that injectively encodes ``(scenario_code, counter)``.

    ``scenario_code`` occupies bits 64-75 and ``counter`` bits 0-61 of the 128-bit
    value; neither overlaps the version (bits 76-79) or variant (bits 62-63) fields
    that ``version=4`` forces. Distinct inputs therefore yield distinct UUIDs with
    no reliance on probabilistic uniqueness.
    """
    if not 0 <= scenario_code < _MAX_SCENARIO_CODE:
        raise ValueError(f"scenario_code must be in [0, {_MAX_SCENARIO_CODE})")
    if not 0 <= counter < _MAX_COUNTER:
        raise ValueError(f"counter must be in [0, {_MAX_COUNTER})")
    value = (scenario_code << 64) | counter
    return uuid.UUID(int=value, version=4)


class _IdIssuer:
    """Issues successive deterministic UUIDv4 strings for one scenario."""

    def __init__(self, scenario_code: int) -> None:
        self._scenario_code = scenario_code
        self._counter = 0

    def next(self) -> str:
        value = deterministic_uuid4(self._scenario_code, self._counter)
        self._counter += 1
        return str(value)


def make_event(
    *,
    ts: float,
    src_ip: str,
    dst_ip: str,
    protocol: Protocol = "TCP",
    src_port: int | None = None,
    dst_port: int | None = None,
    tcp_flags: str | None = None,
    packet_length: int = 64,
    source_type: SourceType = "synthetic",
    event_id: str | None = None,
    ingest_batch_id: str | None = None,
) -> PacketEvent:
    """Build one :class:`PacketEvent`, defaulting to a fresh random id when unset."""
    return PacketEvent(
        event_id=event_id or str(uuid.uuid4()),
        ts=ts,
        source_type=source_type,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol,
        tcp_flags=tcp_flags,
        packet_length=packet_length,
        ingest_batch_id=ingest_batch_id,
    )


def syn(
    client: str,
    server: str,
    dport: int,
    ts: float,
    *,
    sport: int = 40000,
    source_type: SourceType = "synthetic",
    event_id: str | None = None,
) -> PacketEvent:
    """A connection-initiating SYN from ``client`` to ``server``."""
    return make_event(
        ts=ts,
        src_ip=client,
        src_port=sport,
        dst_ip=server,
        dst_port=dport,
        protocol="TCP",
        tcp_flags="S",
        source_type=source_type,
        event_id=event_id,
    )


def synack(
    client: str,
    server: str,
    dport: int,
    ts: float,
    *,
    sport: int = 40000,
    source_type: SourceType = "synthetic",
    event_id: str | None = None,
) -> PacketEvent:
    """The server's SYN-ACK reply (reversed 4-tuple of the initiating SYN)."""
    return make_event(
        ts=ts,
        src_ip=server,
        src_port=dport,
        dst_ip=client,
        dst_port=sport,
        protocol="TCP",
        tcp_flags="SA",
        source_type=source_type,
        event_id=event_id,
    )


def ack(
    client: str,
    server: str,
    dport: int,
    ts: float,
    *,
    sport: int = 40000,
    source_type: SourceType = "synthetic",
    event_id: str | None = None,
) -> PacketEvent:
    """The client's final ACK completing the handshake."""
    return make_event(
        ts=ts,
        src_ip=client,
        src_port=sport,
        dst_ip=server,
        dst_port=dport,
        protocol="TCP",
        tcp_flags="A",
        source_type=source_type,
        event_id=event_id,
    )


def rst(
    client: str,
    server: str,
    dport: int,
    ts: float,
    *,
    sport: int = 40000,
    source_type: SourceType = "synthetic",
    event_id: str | None = None,
) -> PacketEvent:
    """A RST from the server toward the client (reversed 4-tuple)."""
    return make_event(
        ts=ts,
        src_ip=server,
        src_port=dport,
        dst_ip=client,
        dst_port=sport,
        protocol="TCP",
        tcp_flags="R",
        source_type=source_type,
        event_id=event_id,
    )


def udp(
    src_ip: str,
    dst_ip: str,
    ts: float,
    *,
    src_port: int = 5353,
    dst_port: int = 53,
    source_type: SourceType = "synthetic",
    event_id: str | None = None,
) -> PacketEvent:
    """A UDP datagram (protocol variety; ignored by both detectors)."""
    return make_event(
        ts=ts,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol="UDP",
        source_type=source_type,
        event_id=event_id,
    )


def icmp(
    src_ip: str,
    dst_ip: str,
    ts: float,
    *,
    source_type: SourceType = "synthetic",
    event_id: str | None = None,
) -> PacketEvent:
    """An ICMP message (protocol variety; ignored by both detectors)."""
    return make_event(
        ts=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol="ICMP",
        source_type=source_type,
        event_id=event_id,
    )


def normal_traffic(
    *,
    start_ts: float = 500.0,
    client: str = "10.0.0.50",
    server: str = "10.0.0.10",
    num_connections: int = 5,
    source_type: SourceType = "synthetic",
) -> list[PacketEvent]:
    """Benign completed handshakes to a few ports, plus UDP/ICMP — triggers nothing."""
    ids = _IdIssuer(SCENARIO_CODES["normal"])
    ports = [80, 443, 22, 8080, 53]
    events: list[PacketEvent] = []
    ts = start_ts
    for i in range(num_connections):
        dport = ports[i % len(ports)]
        sport = 40000 + i
        for builder in (syn, synack, ack):
            events.append(
                builder(
                    client,
                    server,
                    dport,
                    ts,
                    sport=sport,
                    source_type=source_type,
                    event_id=ids.next(),
                )
            )
            ts += 0.05
        ts += 0.4
    events.append(udp(client, server, ts, source_type=source_type, event_id=ids.next()))
    ts += 0.1
    events.append(icmp(client, server, ts, source_type=source_type, event_id=ids.next()))
    return events


def port_scan(
    *,
    start_ts: float = 1000.0,
    client: str = "10.0.0.50",
    server: str = "10.0.0.10",
    num_ports: int = 20,
    step_s: float = 0.2,
    first_port: int = 1000,
    source_type: SourceType = "synthetic",
) -> list[PacketEvent]:
    """One source probing ``num_ports`` distinct ports — triggers ``portscan`` only."""
    ids = _IdIssuer(SCENARIO_CODES["port_scan"])
    events: list[PacketEvent] = []
    ts = start_ts
    for i in range(num_ports):
        events.append(
            syn(
                client,
                server,
                first_port + i,
                ts,
                sport=40000 + i,
                source_type=source_type,
                event_id=ids.next(),
            )
        )
        ts += step_s
    return events


def syn_burst(
    *,
    start_ts: float = 2000.0,
    server: str = "10.0.0.10",
    dport: int = 80,
    num_syns: int = 120,
    step_s: float = 0.01,
    source_type: SourceType = "synthetic",
) -> list[PacketEvent]:
    """A high-rate SYN flood on a single port from many sources — ``synflood`` only."""
    ids = _IdIssuer(SCENARIO_CODES["syn_burst"])
    events: list[PacketEvent] = []
    ts = start_ts
    for i in range(num_syns):
        client = f"10.1.{(i // 250) % 250}.{i % 250 + 1}"
        events.append(
            syn(
                client,
                server,
                dport,
                ts,
                sport=40000 + (i % 20000),
                source_type=source_type,
                event_id=ids.next(),
            )
        )
        ts += step_s
    return events


def default_scenarios(*, source_type: SourceType = "synthetic") -> list[PacketEvent]:
    """Concatenate the three canonical scenarios; ids are globally unique."""
    return [
        *normal_traffic(source_type=source_type),
        *port_scan(source_type=source_type),
        *syn_burst(source_type=source_type),
    ]
