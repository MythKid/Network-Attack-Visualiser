"""Ingest sources that normalise input into :class:`~app.models.packet_event.PacketEvent`.

Phase 2 provides only the deterministic synthetic generator
(:mod:`app.ingest.synthetic`). PCAP replay and the live sidecar sensor are
introduced in later approved phases (see ``docs/DEVELOPMENT_PHASES.md``).
"""
