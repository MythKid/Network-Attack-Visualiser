"""The :class:`PacketEvent` transport DTO.

A ``PacketEvent`` is the normalised, source-agnostic representation of one
observed packet (see ``docs/ALERT_SCHEMA.md`` §1). Synthetic, PCAP-replay and
live-capture ingestion all produce ``PacketEvent`` objects, so detectors never
depend on how an event was produced.

Privacy is enforced by the type: there is **no payload field**, so payloads and
any credentials within them cannot flow through detection, storage or the API.
"""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.enums import Protocol, SourceType
from app.models.json_types import IPStr, Port, PositiveFiniteFloat, TcpFlagsStr, UUIDv4Str


class PacketEvent(BaseModel):
    """One normalised, metadata-only observed packet.

    The schema deliberately keeps ports and ``tcp_flags`` nullable so events from
    incomplete parsing (e.g. a captured frame without an L4 header) remain
    representable. Detectors ignore events that are missing a field they require
    rather than the schema rejecting them.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: UUIDv4Str = Field(description="Sensor/ingester-assigned UUIDv4 identifier.")
    ts: PositiveFiniteFloat = Field(description="Capture/emit epoch time; drives detector windows.")
    source_type: SourceType = Field(description="Provenance of the event.")
    src_ip: IPStr = Field(description="Source IP address.")
    src_port: Port | None = Field(default=None, description="Source port; null for non-TCP/UDP.")
    dst_ip: IPStr = Field(description="Destination IP address.")
    dst_port: Port | None = Field(
        default=None, description="Destination port; null for non-TCP/UDP."
    )
    protocol: Protocol = Field(description="Normalised L4 protocol.")
    tcp_flags: TcpFlagsStr | None = Field(
        default=None, description="TCP control-flag string; null if not TCP."
    )
    packet_length: Annotated[int, Field(ge=0)] = Field(description="Bytes on the wire.")
    ingest_batch_id: UUIDv4Str | None = Field(
        default=None, description="UUIDv4 correlating one ingest POST batch, if any."
    )

    @model_validator(mode="after")
    def _check_protocol_consistency(self) -> "PacketEvent":
        """Enforce only the approved 'must-be-null' relationships between fields.

        TCP flags belong to TCP alone, and non-TCP/UDP protocols carry no ports.
        We do **not** require TCP/UDP ports or TCP flags to be present, so
        incompletely-parsed events remain valid.
        """
        if self.protocol != "TCP" and self.tcp_flags is not None:
            raise ValueError("tcp_flags may only be set when protocol is TCP")
        if self.protocol in ("ICMP", "OTHER") and (
            self.src_port is not None or self.dst_port is not None
        ):
            raise ValueError("ICMP/OTHER events must not carry ports")
        return self
