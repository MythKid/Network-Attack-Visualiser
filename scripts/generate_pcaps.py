#!/usr/bin/env python3
"""Generate the Phase 5 scenario PCAPs locally and unprivileged.

Crafting and writing PCAP files needs no privileges (only sending or sniffing
does), so this runs from a clean clone as an ordinary user. The scenarios reuse
the deterministic synthetic builders (:mod:`app.ingest.synthetic`) as the single
source of truth, so a generated capture triggers exactly the same detectors as
the equivalent synthetic stream — without duplicating any scenario logic. Each
frame keeps the synthetic event's timestamp as its capture time, which the
replay ingester preserves as canonical logical event time.

The output PCAPs are **never committed** (``.gitignore`` blocks ``*.pcap``) and
are **never downloaded** — they are produced here, on demand.

Usage (from the repository root)::

    python scripts/generate_pcaps.py [--out-dir captures]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Run from a clean clone without installing the package: make the in-repo `app`
# package importable, matching pytest's `pythonpath = ["backend"]`.
_BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402
from scapy.packet import Packet, Raw  # noqa: E402
from scapy.utils import wrpcap  # noqa: E402

from app.ingest.synthetic import normal_traffic, port_scan, syn_burst  # noqa: E402
from app.models.packet_event import PacketEvent  # noqa: E402

DEFAULT_OUT_DIR = "captures"

# Protocol number used for the OTHER placeholder; kept off the well-known set so
# the replay parser normalises it to "OTHER".
_OTHER_IP_PROTO = 99

# Fixed locally-administered MAC addresses. Setting both ends explicitly keeps
# frame generation fully deterministic and offline — without a destination MAC,
# Scapy would attempt a host ARP/route lookup (`getmacbyip`) while serialising.
# The replay parser reads only the IP layer, so these values never affect events.
_SRC_MAC = "02:00:00:00:00:01"
_DST_MAC = "02:00:00:00:00:02"


def event_to_frame(event: PacketEvent) -> Packet:
    """Render one synthetic :class:`PacketEvent` into a Scapy frame.

    The frame carries the event's 5-tuple, TCP flags and capture timestamp so
    that replaying it reproduces an equivalent event. No payload is added.
    """
    ip = IP(src=event.src_ip, dst=event.dst_ip)
    layer: Packet
    if event.protocol == "TCP":
        layer = TCP(
            sport=event.src_port or 0,
            dport=event.dst_port or 0,
            flags=event.tcp_flags or "",
        )
    elif event.protocol == "UDP":
        layer = UDP(sport=event.src_port or 0, dport=event.dst_port or 0)
    elif event.protocol == "ICMP":
        layer = ICMP()
    else:
        ip.proto = _OTHER_IP_PROTO
        layer = Raw(b"")
    frame = Ether(src=_SRC_MAC, dst=_DST_MAC) / ip / layer
    frame.time = event.ts
    return frame


def build_scenarios() -> dict[str, list[Packet]]:
    """Build the three canonical scenarios as lists of Scapy frames."""
    return {
        "normal_traffic": [event_to_frame(e) for e in normal_traffic()],
        "port_scan": [event_to_frame(e) for e in port_scan()],
        "syn_burst": [event_to_frame(e) for e in syn_burst()],
    }


def write_scenarios(out_dir: str | Path) -> dict[str, Path]:
    """Write every scenario PCAP into ``out_dir``, returning the written paths."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    for name, frames in build_scenarios().items():
        path = out / f"{name}.pcap"
        wrpcap(str(path), frames)
        written[name] = path
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the Phase 5 scenario PCAPs.")
    parser.add_argument(
        "--out-dir",
        default=DEFAULT_OUT_DIR,
        help=f"Directory to write the scenario PCAPs into (default: {DEFAULT_OUT_DIR}/).",
    )
    args = parser.parse_args(argv)

    written = write_scenarios(args.out_dir)
    for name, path in written.items():
        print(f"wrote {name:<15} -> {path} ({path.stat().st_size} bytes)")
    print(f"{len(written)} scenario PCAP(s) written to {Path(args.out_dir)}/ (git-ignored).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
