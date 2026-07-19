"""PCAP replay ingestion (Phase 5): stream a capture into the event pipeline.

This is the project's first real ingestion path. It parses a locally generated
PCAP with Scapy and normalises each frame into the existing
:class:`~app.models.packet_event.PacketEvent`, feeding batches through
:meth:`~app.alerts.pipeline.EventPipeline.process_batch` — the same seam the
synthetic generator and the HTTP ingest route use — so detection, alert gating,
storage and statistics are reused unchanged.

Contract highlights (see ``docs/SECURITY_REQUIREMENTS.md`` and
``docs/DETECTION_RULES.md`` §2.1):

- **Provenance is forced.** Every emitted event carries
  ``source_type = "replay"``; no public parameter can override it.
- **Metadata only.** The 5-tuple, TCP flags, wire length and capture timestamp
  are extracted; the packet object (and any payload) is then discarded. No
  payload is ever retained, persisted or logged.
- **Event time is preserved.** ``PacketEvent.ts`` is the packet's capture
  timestamp. Pacing (``speed``) only sleeps between deliveries; it never alters
  timestamps, so accelerated and real-time replays are alert-identical.
- **Streaming with bounds.** The capture is read one record at a time with
  ``PcapReader`` (never ``rdpcap``), under a pre-checked file-size cap and a
  physical-record cap; memory stays bounded and no per-run delta list is kept.
- **Hardened parsing.** Non-IPv4 frames (IPv6, ARP, other L2) are counted and
  dropped; VLAN (802.1Q) tags are traversed; non-first IPv4 fragments and
  frames with missing L4 headers become events with null ports/flags; a
  dissection exception drops only that frame. A stream failure after at least
  one good record ends the run as ``truncated`` (earlier committed batches
  remain); failures before any record raise :class:`ReplayError`.

Scapy is imported at module level, but this module is deliberately **not**
imported by :mod:`app.ingest` or the served API, so the backend runs without
Scapy installed; only the replay path (tests, ``scripts/replay_pcap.py``)
loads it.
"""

import logging
import math
import struct
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from pydantic import ValidationError
from scapy.error import Scapy_Exception
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6  # noqa: F401  (imported to bind IPv6 dissection)
from scapy.packet import Packet
from scapy.utils import PcapReader

from app.alerts.pipeline import EventPipeline
from app.models.enums import Protocol, SourceType
from app.models.packet_event import PacketEvent

logger = logging.getLogger(__name__)

# Provenance of every event this module emits. A module-level constant (not a
# parameter): replayed traffic must never be able to masquerade as synthetic or
# live, so there is deliberately no way to inject a different value.
REPLAY_SOURCE_TYPE: Final[SourceType] = "replay"

# IANA protocol numbers normalised to the documented Protocol union. Used both
# when an L4 layer is present and when it is absent (fragments, truncated
# headers), so the protocol column stays truthful even without ports.
_IP_PROTO_TO_NAME: Final[dict[int, Protocol]] = {6: "TCP", 17: "UDP", 1: "ICMP"}

# One typed outcome per physical record, expressed as a Literal alias in the
# same style as app.models.enums.
ConversionOutcome = Literal["emitted", "unsupported", "invalid", "parse_error"]

ReplayOutcome = Literal["completed", "packet_limit_reached", "truncated"]

# Builds an event_id from the zero-based record index. Injectable so tests can
# make identities deterministic; the default is a fresh random UUIDv4 that
# ignores the index. Never derived from file paths.
EventIdFactory = Callable[[int], str]


def _random_event_id(index: int) -> str:
    """Default id source: a fresh random UUIDv4 (``index`` is deliberately unused)."""
    return str(uuid.uuid4())


class ReplayError(Exception):
    """A file-level replay failure: nothing (or no valid record) could be read.

    Raised for a missing, non-regular, unreadable or oversized input file, an
    invalid capture header, or a stream failure before any valid record. Once at
    least one record has been read, stream failures are reported as the
    ``truncated`` outcome instead, because earlier batches may already be
    committed.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Conversion:
    """The typed result of normalising one physical record."""

    outcome: ConversionOutcome
    event: PacketEvent | None = None


@dataclass(frozen=True)
class ReplayResult:
    """Summary of one replay run. Deliberately holds counts, never deltas.

    ``packets_read`` counts physical records accepted for conversion (including
    dropped frames) and never exceeds the configured cap; a discarded lookahead
    record used only to distinguish ``completed`` from ``packet_limit_reached``
    is not included.
    """

    outcome: ReplayOutcome
    packets_read: int
    events_emitted: int
    dropped_unsupported: int
    dropped_invalid: int
    dropped_parse: int
    alerts_created: int
    alerts_updated: int


def event_from_packet(
    pkt: Packet,
    *,
    index: int,
    event_id_factory: EventIdFactory | None = None,
) -> Conversion:
    """Normalise one Scapy frame into a replay :class:`PacketEvent`.

    Pure per-frame logic: no counters are mutated here — the caller increments
    its summary counters from the returned :class:`Conversion` outcome.

    Outcome mapping:

    - no IPv4 layer anywhere in the frame (IPv6, ARP, other L2) → ``unsupported``;
    - a dissection exception while reading layers/fields → ``parse_error``;
    - a non-finite/non-positive capture timestamp, or field values the
      ``PacketEvent`` schema refuses → ``invalid``;
    - otherwise → ``emitted`` with a validated event.

    VLAN tags need no special casing: Scapy's layer traversal looks through
    802.1Q (including stacked tags) when locating the IPv4 layer. Non-first
    fragments (``frag > 0``) and frames whose L4 header is missing or truncated
    keep null ports/flags with the protocol taken from the IP protocol number.
    """
    make_id = event_id_factory or _random_event_id
    try:
        ip = pkt.getlayer(IP)
        if ip is None:
            return Conversion("unsupported")

        ts = float(pkt.time)
        wirelen = getattr(pkt, "wirelen", None)
        length = wirelen if isinstance(wirelen, int) and wirelen >= 0 else len(pkt)

        protocol: Protocol = _IP_PROTO_TO_NAME.get(int(ip.proto), "OTHER")
        src_port: int | None = None
        dst_port: int | None = None
        tcp_flags: str | None = None
        # A non-first fragment carries no L4 header; whatever bytes follow the
        # IP header belong mid-stream to the original datagram, so ports and
        # flags stay null and only the protocol number is trusted.
        if int(ip.frag) == 0:
            tcp = ip.getlayer(TCP)
            udp = ip.getlayer(UDP)
            if protocol == "TCP" and tcp is not None:
                src_port = int(tcp.sport)
                dst_port = int(tcp.dport)
                # An empty flag string (a TCP "null" packet) is represented as
                # None: the schema requires present flag strings to be non-empty.
                tcp_flags = str(tcp.flags) or None
            elif protocol == "UDP" and udp is not None:
                src_port = int(udp.sport)
                dst_port = int(udp.dport)
        src_ip = str(ip.src)
        dst_ip = str(ip.dst)
    except Exception:
        # Any dissection failure affects this frame only; the stream continues.
        return Conversion("parse_error")

    if not math.isfinite(ts) or ts <= 0:
        return Conversion("invalid")
    try:
        event = PacketEvent(
            event_id=make_id(index),
            ts=ts,
            source_type=REPLAY_SOURCE_TYPE,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            tcp_flags=tcp_flags,
            packet_length=length,
        )
    except ValidationError:
        return Conversion("invalid")
    return Conversion("emitted", event)


def _validated_path(path: str | Path, *, max_file_bytes: int) -> Path:
    """Resolve and pre-check the capture path before it is opened.

    The size cap is enforced via ``stat`` here, before any byte is read, so an
    oversized file is refused without streaming it.
    """
    resolved = Path(path).resolve()
    if not resolved.exists():
        raise ReplayError(f"capture file does not exist: {resolved}")
    if not resolved.is_file():
        raise ReplayError(f"capture path is not a regular file: {resolved}")
    size = resolved.stat().st_size
    if size > max_file_bytes:
        raise ReplayError(
            f"capture file is {size} bytes, above the REPLAY_MAX_FILE_BYTES "
            f"limit of {max_file_bytes}"
        )
    return resolved


def replay_pcap(
    path: str | Path,
    pipeline: EventPipeline,
    *,
    speed: float | None = None,
    batch_size: int,
    max_packets: int,
    max_file_bytes: int,
    max_sleep_s: float,
    sleep: Callable[[float], None] = time.sleep,
    event_id_factory: EventIdFactory | None = None,
) -> ReplayResult:
    """Stream one capture through ``pipeline`` and summarise the run.

    Args:
        path: Capture file to replay (pre-checked: regular file, size cap).
        pipeline: The existing event pipeline; batches are handed to
            ``process_batch`` and its deltas are counted, then discarded.
        speed: ``None`` (default) replays as fast as possible in batches of
            ``batch_size``. A finite value ``> 0`` paces delivery: each event is
            processed individually after sleeping the inter-packet timestamp gap
            divided by ``speed`` (negative gaps sleep zero; each sleep is capped
            at ``max_sleep_s``). Pacing never modifies event timestamps.
        batch_size: Events per pipeline batch when unpaced.
        max_packets: Cap on physical records read (including dropped frames).
        max_file_bytes: Cap on the capture file size, checked before opening.
        max_sleep_s: Upper clamp on one pacing sleep.
        sleep: Injectable sleep for deterministic tests.
        event_id_factory: Optional deterministic event-id source for tests.

    Raises:
        ReplayError: For file-level failures and stream failures before any
            valid record (see the class docstring).
        ValueError: If ``speed`` is supplied but not finite and positive, so a
            mistyped pace fails loudly instead of replaying at a surprise rate.
    """
    if speed is not None and (not math.isfinite(speed) or speed <= 0):
        raise ValueError(f"speed must be finite and > 0 (got {speed})")

    resolved = _validated_path(path, max_file_bytes=max_file_bytes)

    packets_read = 0
    events_emitted = 0
    dropped_unsupported = 0
    dropped_invalid = 0
    dropped_parse = 0
    alerts_created = 0
    alerts_updated = 0
    outcome: ReplayOutcome = "completed"

    batch: list[PacketEvent] = []
    previous_ts: float | None = None

    def flush(events: list[PacketEvent]) -> None:
        nonlocal alerts_created, alerts_updated
        if not events:
            return
        deltas = pipeline.process_batch(events)
        alerts_created += sum(1 for d in deltas if d.type == "alert.created")
        alerts_updated += sum(1 for d in deltas if d.type == "alert.updated")
        events.clear()  # the delta list goes out of scope here; only counts survive

    # Own the file object explicitly: PcapReader opens its own descriptor when
    # handed a path and leaks it if the header parse raises, so we open the file,
    # hand the object over, and guarantee both are closed on every path.
    try:
        raw_file = resolved.open("rb")
    except OSError as exc:
        raise ReplayError(f"cannot open capture file: {exc}") from exc

    reader: PcapReader | None = None
    try:
        try:
            # Scapy's type stub types the argument as ``str``, but the runtime
            # also accepts an open binary file — which we require so the caller
            # owns and deterministically closes the descriptor. Stub limitation.
            reader = PcapReader(raw_file)  # type: ignore[arg-type]
        except (Scapy_Exception, EOFError, ValueError, struct.error) as exc:
            # A parse failure of the global header — never KeyboardInterrupt or
            # SystemExit (BaseException), which must propagate uncaught.
            raise ReplayError(f"not a readable capture file: {exc}") from exc

        while True:
            if packets_read >= max_packets:
                # One lookahead read decides whether the capture genuinely ended
                # at the cap. The looked-ahead record is discarded: it is not
                # converted, not processed and not counted in packets_read. A
                # read failure here still proves data exists beyond the cap, so
                # it reports the cap, not truncation.
                try:
                    next(reader)
                    outcome = "packet_limit_reached"
                except StopIteration:
                    outcome = "completed"
                except Exception:
                    outcome = "packet_limit_reached"
                break
            try:
                pkt = next(reader)
            except StopIteration:
                outcome = "completed"
                break
            except Exception as exc:
                if packets_read == 0:
                    raise ReplayError(f"capture stream failed before any record: {exc}") from exc
                # Mid-stream truncation/corruption: keep everything already read
                # (earlier batches may already be committed) and report it.
                outcome = "truncated"
                break

            index = packets_read
            packets_read += 1
            conversion = event_from_packet(pkt, index=index, event_id_factory=event_id_factory)
            event = conversion.event
            if conversion.outcome == "unsupported":
                dropped_unsupported += 1
                continue
            if conversion.outcome == "invalid":
                dropped_invalid += 1
                continue
            if conversion.outcome == "parse_error" or event is None:
                dropped_parse += 1
                continue
            events_emitted += 1

            if speed is None:
                batch.append(event)
                if len(batch) >= batch_size:
                    flush(batch)
            else:
                # Paced delivery is genuinely per-packet: batch size 1, with the
                # timestamp gap (never the timestamps themselves) driving sleep.
                if previous_ts is not None:
                    gap = event.ts - previous_ts
                    delay = min(max(gap, 0.0) / speed, max_sleep_s)
                    if delay > 0:
                        sleep(delay)
                previous_ts = event.ts
                flush([event])

        # Whatever was read before completion/cap/truncation still counts: the
        # run's final (possibly partial) batch is processed on every outcome.
        flush(batch)
    finally:
        # reader.close() closes the shared descriptor; raw_file.close() is then a
        # harmless idempotent no-op. On a construction failure reader is None and
        # only raw_file needs closing — so no descriptor ever leaks.
        if reader is not None:
            reader.close()
        raw_file.close()

    logger.info(
        "replayed %s: outcome=%s packets_read=%d emitted=%d "
        "dropped_unsupported=%d dropped_invalid=%d dropped_parse=%d "
        "alerts_created=%d alerts_updated=%d",
        resolved.name,
        outcome,
        packets_read,
        events_emitted,
        dropped_unsupported,
        dropped_invalid,
        dropped_parse,
        alerts_created,
        alerts_updated,
    )
    return ReplayResult(
        outcome=outcome,
        packets_read=packets_read,
        events_emitted=events_emitted,
        dropped_unsupported=dropped_unsupported,
        dropped_invalid=dropped_invalid,
        dropped_parse=dropped_parse,
        alerts_created=alerts_created,
        alerts_updated=alerts_updated,
    )
