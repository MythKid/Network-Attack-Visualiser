"""Ingest sources that normalise input into :class:`~app.models.packet_event.PacketEvent`.

Phase 2 provides the deterministic synthetic generator
(:mod:`app.ingest.synthetic`); Phase 5 adds the PCAP replay ingester
(:mod:`app.ingest.pcap_replay`), which parses captures with Scapy and emits
``source_type="replay"`` events into the same pipeline. Neither module is
imported here, so importing :mod:`app.ingest` never pulls in Scapy. The live
sidecar sensor is introduced in a later approved phase (see
``docs/DEVELOPMENT_PHASES.md``).
"""
