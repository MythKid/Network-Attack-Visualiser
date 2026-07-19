"""Unit tests for the PCAP replay ingester (Phase 5).

Covers the typed per-frame conversion contract (emitted / unsupported / invalid
/ parse_error), the hardening corpus (VLAN, fragments, IPv6/ARP dropping,
missing L4, truncated frames), forced ``replay`` provenance, streaming limits
and cap semantics, pacing, and resource cleanup. Every capture used here is
crafted locally with Scapy and written only to ``tmp_path`` — nothing is
committed and nothing is downloaded.
"""

import gc
import inspect
import sqlite3
import uuid
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, ClassVar, cast

import pytest
from pydantic import ValidationError
from scapy.error import Scapy_Exception
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
from scapy.layers.l2 import ARP, Dot1Q, Ether
from scapy.packet import Packet, Raw
from scapy.utils import wrpcap

from app.alerts.engine import AlertDelta
from app.alerts.pipeline import EventPipeline
from app.config import Settings
from app.ingest import pcap_replay
from app.ingest.pcap_replay import (
    REPLAY_SOURCE_TYPE,
    ReplayError,
    ReplayResult,
    event_from_packet,
    replay_pcap,
)
from app.models.packet_event import PacketEvent
from tests.factories import make_alert

# --------------------------------------------------------------------------- #
# Frame builders (deterministic capture timestamps; local only)
# --------------------------------------------------------------------------- #

CLIENT = "10.0.0.50"
SERVER = "10.0.0.10"


def stamp(pkt: Packet, ts: float = 1000.0) -> Packet:
    """Give a crafted frame a deterministic capture timestamp."""
    pkt.time = ts
    return pkt


def tcp_syn(ts: float = 1000.0, *, dport: int = 80, flags: str = "S") -> Packet:
    frame = Ether() / IP(src=CLIENT, dst=SERVER) / TCP(sport=40000, dport=dport, flags=flags)
    return stamp(frame, ts)


def write_pcap(path: Path, packets: Sequence[Packet]) -> Path:
    wrpcap(str(path), list(packets))
    return path


# --------------------------------------------------------------------------- #
# Test doubles
# --------------------------------------------------------------------------- #


class SpyPipeline:
    """Records every batch it is handed and returns scripted deltas."""

    def __init__(self, scripted_deltas: list[list[AlertDelta]] | None = None) -> None:
        self.batches: list[list[PacketEvent]] = []
        self._scripted = scripted_deltas or []

    def process_batch(self, events: Sequence[PacketEvent]) -> list[AlertDelta]:
        self.batches.append(list(events))  # copy: the driver clears its list after flush
        if self._scripted:
            return self._scripted.pop(0)
        return []


class FailingPipeline:
    """Raises a storage-style error on the first batch."""

    def process_batch(self, events: Sequence[PacketEvent]) -> list[AlertDelta]:
        raise sqlite3.OperationalError("simulated storage failure")


def as_pipeline(spy: object) -> EventPipeline:
    """Type-cast a duck-typed test double to the pipeline interface."""
    return cast(EventPipeline, spy)


def run_replay(
    path: Path,
    pipeline: object,
    *,
    speed: float | None = None,
    batch_size: int = 100,
    max_packets: int = 10_000,
    max_file_bytes: int = 5_000_000,
    max_sleep_s: float = 2.0,
    sleep: Callable[[float], None] | None = None,
) -> ReplayResult:
    """Invoke ``replay_pcap`` with small-test defaults for every limit."""
    extra: dict[str, Any] = {} if sleep is None else {"sleep": sleep}
    return replay_pcap(
        path,
        as_pipeline(pipeline),
        speed=speed,
        batch_size=batch_size,
        max_packets=max_packets,
        max_file_bytes=max_file_bytes,
        max_sleep_s=max_sleep_s,
        **extra,
    )


def install_fake_reader(monkeypatch: pytest.MonkeyPatch, script: list[object]) -> type[Any]:
    """Replace ``PcapReader`` with a scripted double.

    ``script`` items are yielded in order; an ``Exception`` instance is raised
    instead of yielded; exhaustion raises ``StopIteration``. Instances record
    whether ``close()`` ran, so cleanup is assertable on every path.
    """

    class FakeReader:
        instances: ClassVar[list["FakeReader"]] = []

        def __init__(self, path: str) -> None:
            self._index = 0
            self.closed = False
            FakeReader.instances.append(self)

        def __next__(self) -> Packet:
            if self._index >= len(script):
                raise StopIteration
            item = script[self._index]
            self._index += 1
            if isinstance(item, Exception):
                raise item
            return cast(Packet, item)

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr(pcap_replay, "PcapReader", FakeReader)
    return FakeReader


@pytest.fixture
def dummy_path(tmp_path: Path) -> Path:
    """A small real file for path validation when the reader is faked."""
    path = tmp_path / "dummy.pcap"
    path.write_bytes(b"placeholder")
    return path


# --------------------------------------------------------------------------- #
# Conversion: supported IPv4 traffic
# --------------------------------------------------------------------------- #


def test_tcp_syn_maps_all_fields() -> None:
    pkt = tcp_syn(1234.5, dport=443)
    conversion = event_from_packet(pkt, index=0)
    assert conversion.outcome == "emitted"
    event = conversion.event
    assert event is not None
    assert event.ts == 1234.5
    assert event.source_type == "replay"
    assert (event.src_ip, event.dst_ip) == (CLIENT, SERVER)
    assert (event.src_port, event.dst_port) == (40000, 443)
    assert event.protocol == "TCP"
    assert event.tcp_flags == "S"
    assert event.packet_length == len(pkt)


def test_tcp_null_packet_flags_become_none() -> None:
    conversion = event_from_packet(tcp_syn(flags=""), index=0)
    assert conversion.outcome == "emitted"
    assert conversion.event is not None
    assert conversion.event.tcp_flags is None
    assert conversion.event.protocol == "TCP"


def test_udp_maps_ports_without_flags() -> None:
    pkt = stamp(Ether() / IP(src=CLIENT, dst=SERVER) / UDP(sport=5353, dport=53))
    conversion = event_from_packet(pkt, index=0)
    assert conversion.outcome == "emitted"
    event = conversion.event
    assert event is not None
    assert event.protocol == "UDP"
    assert (event.src_port, event.dst_port) == (5353, 53)
    assert event.tcp_flags is None


def test_icmp_has_no_ports() -> None:
    pkt = stamp(Ether() / IP(src=CLIENT, dst=SERVER) / ICMP())
    conversion = event_from_packet(pkt, index=0)
    assert conversion.outcome == "emitted"
    event = conversion.event
    assert event is not None
    assert event.protocol == "ICMP"
    assert event.src_port is None and event.dst_port is None


def test_unknown_l4_protocol_maps_to_other() -> None:
    pkt = stamp(Ether() / IP(src=CLIENT, dst=SERVER, proto=99) / Raw(b"\x00\x01"))
    conversion = event_from_packet(pkt, index=0)
    assert conversion.outcome == "emitted"
    event = conversion.event
    assert event is not None
    assert event.protocol == "OTHER"
    assert event.src_port is None and event.dst_port is None


def test_missing_l4_header_keeps_null_ports() -> None:
    # proto says TCP but no TCP header follows: representable per the schema.
    pkt = stamp(Ether() / IP(src=CLIENT, dst=SERVER, proto=6))
    conversion = event_from_packet(pkt, index=0)
    assert conversion.outcome == "emitted"
    event = conversion.event
    assert event is not None
    assert event.protocol == "TCP"
    assert event.src_port is None and event.dst_port is None and event.tcp_flags is None


def test_wirelen_preferred_over_len() -> None:
    pkt = tcp_syn()
    pkt.wirelen = 150
    conversion = event_from_packet(pkt, index=0)
    assert conversion.event is not None
    assert conversion.event.packet_length == 150


def test_invalid_wirelen_falls_back_to_len() -> None:
    pkt = tcp_syn()
    pkt.wirelen = -1
    conversion = event_from_packet(pkt, index=0)
    assert conversion.event is not None
    assert conversion.event.packet_length == len(pkt)


# --------------------------------------------------------------------------- #
# Conversion: VLAN and fragments
# --------------------------------------------------------------------------- #


def test_vlan_tag_is_traversed() -> None:
    pkt = stamp(Ether() / Dot1Q(vlan=10) / IP(src=CLIENT, dst=SERVER) / TCP(dport=22, flags="S"))
    conversion = event_from_packet(pkt, index=0)
    assert conversion.outcome == "emitted"
    assert conversion.event is not None
    assert conversion.event.protocol == "TCP"
    assert conversion.event.dst_port == 22


def test_stacked_vlan_tags_are_traversed() -> None:
    pkt = stamp(
        Ether() / Dot1Q(vlan=10) / Dot1Q(vlan=20) / IP(src=CLIENT, dst=SERVER) / UDP(dport=53)
    )
    conversion = event_from_packet(pkt, index=0)
    assert conversion.outcome == "emitted"
    assert conversion.event is not None
    assert conversion.event.protocol == "UDP"


def test_non_first_fragment_nulls_ports() -> None:
    pkt = stamp(Ether() / IP(src=CLIENT, dst=SERVER, proto=6, frag=100) / Raw(b"mid-datagram"))
    conversion = event_from_packet(pkt, index=0)
    assert conversion.outcome == "emitted"
    event = conversion.event
    assert event is not None
    assert event.protocol == "TCP"
    assert event.src_port is None and event.dst_port is None and event.tcp_flags is None


def test_first_fragment_parses_l4_normally() -> None:
    pkt = stamp(Ether() / IP(src=CLIENT, dst=SERVER, flags="MF", frag=0) / TCP(dport=80, flags="S"))
    conversion = event_from_packet(pkt, index=0)
    assert conversion.outcome == "emitted"
    assert conversion.event is not None
    assert conversion.event.dst_port == 80


# --------------------------------------------------------------------------- #
# Conversion: unsupported / invalid / parse_error
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "frame",
    [
        Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(dport=80, flags="S"),
        Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / ICMPv6EchoRequest(),
        Ether() / Dot1Q(vlan=10) / IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(dport=53),
    ],
    ids=["ipv6-tcp", "ipv6-icmpv6", "vlan-over-ipv6"],
)
def test_ipv6_is_safely_dropped_as_unsupported(frame: Packet) -> None:
    conversion = event_from_packet(stamp(frame), index=0)
    assert conversion.outcome == "unsupported"
    assert conversion.event is None


def test_arp_is_unsupported() -> None:
    conversion = event_from_packet(stamp(Ether() / ARP(pdst=SERVER)), index=0)
    assert conversion.outcome == "unsupported"
    assert conversion.event is None


def test_truncated_frame_bytes_are_dropped_not_raised() -> None:
    # A frame cut inside the IP header dissects as Ether/Raw: no IPv4 layer.
    full = bytes(Ether() / IP(src=CLIENT, dst=SERVER) / TCP(dport=80, flags="S"))
    conversion = event_from_packet(stamp(Ether(full[:20])), index=0)
    assert conversion.outcome == "unsupported"


@pytest.mark.parametrize("bad_ts", [float("nan"), float("inf"), 0.0, -5.0])
def test_non_finite_or_nonpositive_ts_is_invalid(bad_ts: float) -> None:
    conversion = event_from_packet(tcp_syn(bad_ts), index=0)
    assert conversion.outcome == "invalid"
    assert conversion.event is None


def test_dissection_exception_is_parse_error() -> None:
    class ExplodingFrame:
        time = 1000.0

        def getlayer(self, layer: object) -> object:
            raise RuntimeError("simulated dissector crash")

    conversion = event_from_packet(cast(Packet, ExplodingFrame()), index=0)
    assert conversion.outcome == "parse_error"
    assert conversion.event is None


def test_schema_rejection_is_invalid() -> None:
    class BadIpLayer:
        src = "not-an-ip"
        dst = SERVER
        proto = 6
        frag = 0

        def getlayer(self, layer: object) -> object:
            return None

    class BadFrame:
        time = 1000.0
        wirelen = 60

        def getlayer(self, layer: object) -> object:
            return BadIpLayer()

    conversion = event_from_packet(cast(Packet, BadFrame()), index=0)
    assert conversion.outcome == "invalid"
    assert conversion.event is None


# --------------------------------------------------------------------------- #
# Forced provenance and event identity
# --------------------------------------------------------------------------- #


def test_replay_source_type_constant() -> None:
    assert REPLAY_SOURCE_TYPE == "replay"


def test_no_public_source_type_parameter_exists() -> None:
    for fn in (event_from_packet, replay_pcap):
        assert "source_type" not in inspect.signature(fn).parameters


def test_every_emitted_event_is_replay_provenance() -> None:
    corpus = [
        tcp_syn(),
        stamp(Ether() / IP(src=CLIENT, dst=SERVER) / UDP(dport=53)),
        stamp(Ether() / IP(src=CLIENT, dst=SERVER) / ICMP()),
        stamp(Ether() / Dot1Q(vlan=1) / IP(src=CLIENT, dst=SERVER) / TCP(dport=81, flags="S")),
    ]
    for index, frame in enumerate(corpus):
        conversion = event_from_packet(frame, index=index)
        assert conversion.outcome == "emitted"
        assert conversion.event is not None
        assert conversion.event.source_type == "replay"


def test_default_event_ids_are_random_uuid4() -> None:
    first = event_from_packet(tcp_syn(), index=0).event
    second = event_from_packet(tcp_syn(), index=0).event
    assert first is not None and second is not None
    assert first.event_id != second.event_id
    assert uuid.UUID(first.event_id).version == 4


def test_event_id_factory_is_injectable_by_index() -> None:
    def factory(index: int) -> str:
        return str(uuid.UUID(int=index, version=4))

    conversion = event_from_packet(tcp_syn(), index=7, event_id_factory=factory)
    assert conversion.event is not None
    assert conversion.event.event_id == str(uuid.UUID(int=7, version=4))


# --------------------------------------------------------------------------- #
# Driver: counting, batching and pacing
# --------------------------------------------------------------------------- #


def test_counters_follow_conversion_outcomes(tmp_path: Path) -> None:
    frames = [
        tcp_syn(1000.0),
        stamp(Ether() / ARP(pdst=SERVER), 1000.1),  # unsupported
        stamp(Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(), 1000.2),  # unsupported
        stamp(Ether() / IP(src=CLIENT, dst=SERVER) / UDP(dport=53), 1000.3),
    ]
    path = write_pcap(tmp_path / "mixed.pcap", frames)
    spy = SpyPipeline()
    result = run_replay(path, spy)
    assert result.outcome == "completed"
    assert result.packets_read == 4
    assert result.events_emitted == 2
    assert result.dropped_unsupported == 2
    assert result.dropped_invalid == 0
    assert result.dropped_parse == 0


def test_unpaced_mode_batches_by_configured_size(tmp_path: Path) -> None:
    frames = [tcp_syn(1000.0 + i, dport=1000 + i) for i in range(5)]
    path = write_pcap(tmp_path / "five.pcap", frames)
    spy = SpyPipeline()
    result = run_replay(path, spy, batch_size=2)
    assert result.events_emitted == 5
    assert [len(batch) for batch in spy.batches] == [2, 2, 1]


def test_alert_delta_counts_are_kept_but_deltas_are_not(tmp_path: Path) -> None:
    frames = [tcp_syn(1000.0 + i, dport=1000 + i) for i in range(3)]
    path = write_pcap(tmp_path / "three.pcap", frames)
    scripted = [
        [
            AlertDelta(type="alert.created", alert=make_alert()),
            AlertDelta(type="alert.updated", alert=make_alert()),
        ]
    ]
    spy = SpyPipeline(scripted_deltas=scripted)
    result = run_replay(path, spy, batch_size=10)
    assert result.alerts_created == 1
    assert result.alerts_updated == 1
    # The result is counts only: no delta (and no alert object) is retained.
    assert not any(hasattr(result, name) for name in ("deltas", "alerts"))


def test_paced_mode_processes_one_event_per_batch_and_sleeps_gaps(tmp_path: Path) -> None:
    frames = [tcp_syn(100.0), tcp_syn(101.0, dport=81), tcp_syn(103.0, dport=82)]
    path = write_pcap(tmp_path / "paced.pcap", frames)
    spy = SpyPipeline()
    slept: list[float] = []
    result = run_replay(path, spy, speed=2.0, batch_size=50, sleep=slept.append)
    assert result.events_emitted == 3
    assert [len(batch) for batch in spy.batches] == [1, 1, 1]
    assert slept == [0.5, 1.0]  # (101-100)/2 and (103-101)/2; no sleep before the first
    # Pacing must never rewrite the captured timestamps.
    assert [batch[0].ts for batch in spy.batches] == [100.0, 101.0, 103.0]


def test_paced_negative_gap_sleeps_zero(tmp_path: Path) -> None:
    frames = [tcp_syn(100.0), tcp_syn(99.0, dport=81)]
    path = write_pcap(tmp_path / "reordered.pcap", frames)
    spy = SpyPipeline()
    slept: list[float] = []
    run_replay(path, spy, speed=1.0, sleep=slept.append)
    assert slept == []  # a zero delay is skipped, never a negative sleep


def test_paced_sleep_is_clamped_to_max(tmp_path: Path) -> None:
    frames = [tcp_syn(100.0), tcp_syn(500.0, dport=81)]
    path = write_pcap(tmp_path / "gap.pcap", frames)
    spy = SpyPipeline()
    slept: list[float] = []
    run_replay(path, spy, speed=1.0, max_sleep_s=2.0, sleep=slept.append)
    assert slept == [2.0]


@pytest.mark.parametrize("bad_speed", [0.0, -1.0, float("nan"), float("inf")])
def test_invalid_speed_is_rejected(tmp_path: Path, bad_speed: float) -> None:
    path = write_pcap(tmp_path / "one.pcap", [tcp_syn()])
    with pytest.raises(ValueError, match="speed"):
        run_replay(path, SpyPipeline(), speed=bad_speed)


# --------------------------------------------------------------------------- #
# Driver: file-level failures (ReplayError) and truncation
# --------------------------------------------------------------------------- #


def test_missing_file_raises_replay_error(tmp_path: Path) -> None:
    with pytest.raises(ReplayError, match="does not exist"):
        run_replay(tmp_path / "absent.pcap", SpyPipeline())


def test_directory_raises_replay_error(tmp_path: Path) -> None:
    with pytest.raises(ReplayError, match="not a regular file"):
        run_replay(tmp_path, SpyPipeline())


def test_oversized_file_raises_replay_error_before_reading(tmp_path: Path) -> None:
    path = write_pcap(tmp_path / "big.pcap", [tcp_syn()])
    with pytest.raises(ReplayError, match="REPLAY_MAX_FILE_BYTES"):
        run_replay(path, SpyPipeline(), max_file_bytes=10)


@pytest.mark.parametrize("content", [b"", b"this is not a capture file at all"])
def test_unreadable_or_invalid_header_raises_replay_error(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "junk.pcap"
    path.write_bytes(content)
    with pytest.raises(ReplayError):
        run_replay(path, SpyPipeline())


def test_stream_failure_before_any_record_raises_replay_error(
    monkeypatch: pytest.MonkeyPatch, dummy_path: Path
) -> None:
    install_fake_reader(monkeypatch, [Scapy_Exception("corrupt first record")])
    with pytest.raises(ReplayError, match="before any record"):
        run_replay(dummy_path, SpyPipeline())


def test_stream_failure_after_a_record_is_truncated_outcome(
    monkeypatch: pytest.MonkeyPatch, dummy_path: Path
) -> None:
    install_fake_reader(monkeypatch, [tcp_syn(1000.0), Scapy_Exception("cut mid-record")])
    spy = SpyPipeline()
    result = run_replay(dummy_path, spy)
    assert result.outcome == "truncated"
    assert result.packets_read == 1
    assert result.events_emitted == 1
    # Everything read before the failure is still delivered to the pipeline.
    assert [len(batch) for batch in spy.batches] == [1]


def test_physically_truncated_capture_never_crashes(tmp_path: Path) -> None:
    """Characterisation: a byte-truncated pcap must end without an exception.

    Scapy's reader treats a trailing partial record as end-of-stream, so the
    run may legitimately finish as ``completed`` with only the intact records;
    an observed mid-stream reader failure would report ``truncated``. Either
    way: no crash, and only fully-read records are processed.
    """
    intact = tmp_path / "intact.pcap"
    write_pcap(intact, [tcp_syn(1000.0), tcp_syn(1001.0, dport=81), tcp_syn(1002.0, dport=82)])
    data = intact.read_bytes()
    truncated = tmp_path / "truncated.pcap"
    truncated.write_bytes(data[: len(data) - 30])  # cut inside the final record
    spy = SpyPipeline()
    result = run_replay(truncated, spy)
    # Safety contract, independent of how Scapy represents the trailing partial
    # record (an EOF that finishes `completed`, or a yielded raw/unsupported frame
    # that is dropped and counted): no crash, and only the intact records reach
    # the pipeline as valid events.
    assert result.outcome in ("completed", "truncated")
    assert result.events_emitted == 2  # exactly the two fully-read IPv4 records
    dropped = result.dropped_unsupported + result.dropped_invalid + result.dropped_parse
    assert result.packets_read == result.events_emitted + dropped  # internal consistency
    assert result.packets_read >= 2
    # No malformed event ever reaches the pipeline.
    assert sum(len(batch) for batch in spy.batches) == 2


# --------------------------------------------------------------------------- #
# Driver: packet-cap semantics
# --------------------------------------------------------------------------- #


def test_cap_with_exact_eof_is_completed(tmp_path: Path) -> None:
    frames = [tcp_syn(1000.0 + i, dport=1000 + i) for i in range(3)]
    path = write_pcap(tmp_path / "exact.pcap", frames)
    result = run_replay(path, SpyPipeline(), max_packets=3)
    assert result.outcome == "completed"
    assert result.packets_read == 3


def test_cap_with_more_records_is_packet_limit_reached(tmp_path: Path) -> None:
    frames = [tcp_syn(1000.0 + i, dport=1000 + i) for i in range(4)]
    path = write_pcap(tmp_path / "over.pcap", frames)
    spy = SpyPipeline()
    result = run_replay(path, spy, max_packets=3)
    assert result.outcome == "packet_limit_reached"
    # The discarded lookahead record is neither processed nor counted.
    assert result.packets_read == 3
    assert result.events_emitted == 3
    assert sum(len(batch) for batch in spy.batches) == 3


def test_cap_counts_dropped_frames_as_physical_records(tmp_path: Path) -> None:
    frames = [
        stamp(Ether() / ARP(pdst=SERVER), 1000.0),  # dropped, but a physical record
        tcp_syn(1000.1),
        tcp_syn(1000.2, dport=81),
    ]
    path = write_pcap(tmp_path / "arp-first.pcap", frames)
    result = run_replay(path, SpyPipeline(), max_packets=2)
    assert result.outcome == "packet_limit_reached"
    assert result.packets_read == 2
    assert result.events_emitted == 1
    assert result.dropped_unsupported == 1


# --------------------------------------------------------------------------- #
# Resource cleanup
# --------------------------------------------------------------------------- #


@pytest.mark.filterwarnings("error::ResourceWarning")
def test_reader_is_closed_after_success(tmp_path: Path) -> None:
    path = write_pcap(tmp_path / "ok.pcap", [tcp_syn()])
    run_replay(path, SpyPipeline())
    gc.collect()  # an unclosed reader file would surface as an error here


@pytest.mark.filterwarnings("error::ResourceWarning")
def test_reader_is_closed_when_pipeline_fails(
    monkeypatch: pytest.MonkeyPatch, dummy_path: Path
) -> None:
    fake_cls = install_fake_reader(monkeypatch, [tcp_syn(1000.0)])
    with pytest.raises(sqlite3.OperationalError):
        run_replay(dummy_path, FailingPipeline(), batch_size=1)
    assert fake_cls.instances[-1].closed
    gc.collect()


def test_reader_is_closed_on_every_scripted_path(
    monkeypatch: pytest.MonkeyPatch, dummy_path: Path
) -> None:
    scripts: list[list[object]] = [
        [tcp_syn(1000.0)],  # completed
        [tcp_syn(1000.0), Scapy_Exception("cut")],  # truncated
    ]
    for script in scripts:
        fake_cls = install_fake_reader(monkeypatch, script)
        run_replay(dummy_path, SpyPipeline())
        assert fake_cls.instances[-1].closed


# --------------------------------------------------------------------------- #
# Replay settings
# --------------------------------------------------------------------------- #


def test_replay_settings_documented_defaults() -> None:
    settings = Settings(_env_file=None)
    assert settings.replay_max_file_bytes == 50_000_000
    assert settings.replay_max_packets == 1_000_000
    assert settings.replay_batch_size == 500
    assert settings.replay_max_sleep_s == 2.0


@pytest.mark.parametrize(
    "field",
    ["replay_max_file_bytes", "replay_max_packets", "replay_batch_size"],
)
def test_replay_settings_reject_non_positive_values(field: str) -> None:
    kwargs: dict[str, Any] = {field: 0}
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **kwargs)


def test_replay_settings_reject_non_finite_sleep() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, replay_max_sleep_s=float("inf"))


# --------------------------------------------------------------------------- #
# Ingest package stays Scapy-free
# --------------------------------------------------------------------------- #


def test_importing_app_ingest_does_not_import_scapy() -> None:
    import importlib
    import subprocess
    import sys

    importlib.import_module("app.ingest")  # sanity: the package itself imports
    snippet = "import app.ingest, sys; sys.exit(1 if 'scapy' in sys.modules else 0)"
    proc = subprocess.run(
        [sys.executable, "-c", snippet],
        cwd=str(Path(__file__).resolve().parents[1]),
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr.decode()
