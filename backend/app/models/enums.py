"""Shared enumerated string types for the domain schemas.

These mirror the enumerated unions defined in ``docs/ALERT_SCHEMA.md`` and are
expressed as ``Literal`` aliases (consistent with :mod:`app.config`), so they
serialise to plain strings and are validated at model construction.
"""

from typing import Literal

# Provenance of a packet/alert; also drives the dashboard banner and is part of
# every detector-state key so provenances never share an evidence window.
SourceType = Literal["synthetic", "replay", "live"]

# Normalised L4 protocol.
Protocol = Literal["TCP", "UDP", "ICMP", "OTHER"]

# Alert severity band.
Severity = Literal["low", "medium", "high", "critical"]

# Alert category.
Category = Literal["reconnaissance", "dos"]

# AI-explanation lifecycle state (populated only by the later AI phase).
AIStatus = Literal["none", "generated", "fallback", "error"]

# Ordinal ranking of severities, used to decide whether an alert escalates.
SEVERITY_ORDER: dict[Severity, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}
