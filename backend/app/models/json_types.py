"""Shared value types and reusable field validators for the domain schemas.

These are defined once and applied across :mod:`app.models.packet_event`,
:mod:`app.models.candidate_alert` and :mod:`app.models.alert` so identity,
address, timestamp, TCP-flag and JSON-compatibility rules stay consistent.

``FiniteJsonValue`` constrains ``evidence`` and ``threshold_snapshot`` to strictly
JSON-serialisable, fully finite content, so neither an arbitrary Python object nor
a non-finite number can ever be stored on an alert.
"""

import ipaddress
import math
import uuid
from typing import Annotated

from pydantic import AfterValidator, Field, JsonValue, StringConstraints

__all__ = [
    "TCP_FLAG_LETTERS",
    "Confidence",
    "DedupKeyStr",
    "FiniteFloat",
    "FiniteJsonValue",
    "IPStr",
    "JsonValue",
    "NonEmptyStr",
    "Port",
    "PositiveFiniteFloat",
    "TcpFlagsStr",
    "UUIDv4Str",
]

# Recognised single-letter TCP control flags (FIN, SYN, RST, PSH, ACK, URG, ECE,
# CWR, NS, plus the reserved W bit as sometimes emitted by tooling). Flag strings
# are validated and normalised to upper case, never carrying packet data.
TCP_FLAG_LETTERS = frozenset("FSRPAUECNW")

_HEX_DIGITS = frozenset("0123456789abcdef")


def _to_uuidv4_str(value: str) -> str:
    """Validate that ``value`` is a UUID version 4, returning its canonical form."""
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValueError("must be a valid UUID string") from exc
    if parsed.version != 4:
        raise ValueError("must be a UUID version 4")
    return str(parsed)


def _to_ip_str(value: str) -> str:
    """Validate an IPv4/IPv6 address string, returning its canonical form."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError("must be a valid IPv4 or IPv6 address") from exc


def _to_tcp_flags(value: str) -> str:
    """Normalise a TCP flag string to upper case and reject unknown letters."""
    normalised = value.strip().upper()
    if not normalised:
        raise ValueError("tcp_flags must not be empty when present")
    illegal = sorted(set(normalised) - TCP_FLAG_LETTERS)
    if illegal:
        raise ValueError(f"tcp_flags contains invalid letters: {''.join(illegal)}")
    return normalised


def _to_dedup_key(value: str) -> str:
    """Validate a deduplication key as a 40-character lowercase hex (SHA-1) digest."""
    normalised = value.strip().lower()
    if len(normalised) != 40 or any(ch not in _HEX_DIGITS for ch in normalised):
        raise ValueError("dedup_key must be a 40-character lowercase hex (sha1) string")
    return normalised


def _finite(value: float) -> float:
    """Reject non-finite floats (``NaN`` / ``±inf``)."""
    if not math.isfinite(value):
        raise ValueError("must be a finite number")
    return value


def _finite_positive(value: float) -> float:
    """Reject non-finite or non-positive floats."""
    if not math.isfinite(value):
        raise ValueError("must be a finite number")
    if value <= 0:
        raise ValueError("must be a positive number")
    return value


def _reject_non_finite_json(value: JsonValue) -> JsonValue:
    """Reject ``NaN``/``±inf`` anywhere inside a JSON value, at any nesting depth.

    Pydantic's ``JsonValue`` accepts non-finite floats and serialises them to
    ``null``, which would silently destroy evidence rather than refuse it. Nesting
    is walked iteratively, so deeply nested input cannot exhaust the stack.
    """
    unvisited: list[JsonValue] = [value]
    while unvisited:
        item = unvisited.pop()
        if isinstance(item, float) and not math.isfinite(item):
            raise ValueError("must not contain non-finite numbers (NaN or Infinity)")
        if isinstance(item, dict):
            unvisited.extend(item.values())
        elif isinstance(item, list):
            unvisited.extend(item)
    return value


# A UUIDv4 identity stored as its canonical string form.
UUIDv4Str = Annotated[str, AfterValidator(_to_uuidv4_str)]
# A validated IP address stored as a canonical string.
IPStr = Annotated[str, AfterValidator(_to_ip_str)]
# A trimmed, non-empty string (blank/whitespace-only rejected).
NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
# A validated, upper-cased TCP flag string.
TcpFlagsStr = Annotated[str, AfterValidator(_to_tcp_flags)]
# A 40-character lowercase hex deduplication key (SHA-1 shape).
DedupKeyStr = Annotated[str, AfterValidator(_to_dedup_key)]
# A TCP/UDP port number.
Port = Annotated[int, Field(ge=0, le=65535)]
# Heuristic confidence, capped at 0.95 (never 1.0).
Confidence = Annotated[float, Field(ge=0.0, le=0.95)]
# A finite epoch-seconds timestamp.
FiniteFloat = Annotated[float, AfterValidator(_finite)]
# A strictly positive, finite epoch-seconds timestamp.
PositiveFiniteFloat = Annotated[float, AfterValidator(_finite_positive)]
# A JSON value guaranteed free of non-finite numbers at every nesting depth.
FiniteJsonValue = Annotated[JsonValue, AfterValidator(_reject_non_finite_json)]
