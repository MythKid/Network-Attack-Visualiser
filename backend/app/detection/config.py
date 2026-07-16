"""Typed configuration for the detection engine and detectors.

``PortScanConfig`` / ``SynFloodConfig`` are the immutable threshold sets the
detectors consume; tests construct them directly. ``DetectionSettings`` maps the
eleven documented environment variables (``docs/DETECTION_RULES.md`` §8) onto those
configs, following the same bare ``UPPER_SNAKE`` convention as :mod:`app.config`.

Cooldown values are loaded and validated here for completeness but are consumed by
the Phase 3 Alert Engine, not by the detectors.
"""

from pydantic import BaseModel, ConfigDict, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.models.json_types import PositiveFiniteFloat


class PortScanConfig(BaseModel):
    """Thresholds consumed by :class:`~app.detection.portscan.PortScanDetector`.

    Every duration is a :data:`PositiveFiniteFloat`: an infinite window or TTL would
    silently disable expiry, and ``NaN`` would make every window comparison false,
    so non-finite thresholds are refused rather than acted upon.
    """

    model_config = ConfigDict(frozen=True)

    window_s: PositiveFiniteFloat = Field(description="Sliding window length (seconds).")
    min_ports: int = Field(ge=1, description="Distinct ports that trigger an alert.")
    critical_ports: int = Field(ge=1, description="Fan-out at/above which severity is critical.")
    state_ttl_s: PositiveFiniteFloat = Field(description="Idle-key state expiry (seconds).")

    @model_validator(mode="after")
    def _check_bands(self) -> "PortScanConfig":
        if self.critical_ports <= 2 * self.min_ports:
            raise ValueError("critical_ports must be greater than 2 x min_ports")
        return self

    @property
    def max_event_age_s(self) -> float:
        """Oldest event age this detector can use (its sliding window)."""
        return self.window_s


class SynFloodConfig(BaseModel):
    """Thresholds consumed by :class:`~app.detection.synflood.SynFloodDetector`.

    As with :class:`PortScanConfig`, non-finite windows, TTLs and ratios are refused.
    """

    model_config = ConfigDict(frozen=True)

    window_s: PositiveFiniteFloat = Field(description="Sliding window length (seconds).")
    min_count: int = Field(ge=1, description="SYNs in-window required to consider a flood.")
    max_completion_ratio: PositiveFiniteFloat = Field(
        le=1, description="Completion ratio below which traffic is suspicious."
    )
    handshake_ttl_s: PositiveFiniteFloat = Field(
        description="Pending-entry (half-open) expiry (seconds)."
    )
    state_ttl_s: PositiveFiniteFloat = Field(description="Idle-key state expiry (seconds).")

    @property
    def max_event_age_s(self) -> float:
        """Oldest event age this detector can use.

        A SYN matters only within ``window_s``, but a matching SYN-ACK/ACK/RST can
        still progress a pending entry for up to ``handshake_ttl_s``.
        """
        return max(self.window_s, self.handshake_ttl_s)


class DetectionSettings(BaseSettings):
    """Environment-driven detection thresholds with documented laboratory defaults.

    Environment input is untrusted: ``float`` happily parses ``"inf"`` and ``"nan"``,
    so every duration and ratio is a :data:`PositiveFiniteFloat` and non-finite
    values are rejected on load rather than reaching a detector.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    portscan_window_s: PositiveFiniteFloat = Field(default=10.0)
    portscan_min_ports: int = Field(default=15, ge=1)
    portscan_critical_ports: int = Field(default=100, ge=1)
    portscan_state_ttl_s: PositiveFiniteFloat = Field(default=60.0)
    portscan_cooldown_s: PositiveFiniteFloat = Field(default=60.0)

    syn_window_s: PositiveFiniteFloat = Field(default=5.0)
    syn_min_count: int = Field(default=100, ge=1)
    syn_max_completion_ratio: PositiveFiniteFloat = Field(default=0.2, le=1)
    handshake_ttl_s: PositiveFiniteFloat = Field(default=10.0)
    syn_state_ttl_s: PositiveFiniteFloat = Field(default=30.0)
    syn_cooldown_s: PositiveFiniteFloat = Field(default=60.0)

    @model_validator(mode="after")
    def _check_bands(self) -> "DetectionSettings":
        if self.portscan_critical_ports <= 2 * self.portscan_min_ports:
            raise ValueError("PORTSCAN_CRITICAL_PORTS must be greater than 2 x PORTSCAN_MIN_PORTS")
        return self

    def to_portscan_config(self) -> PortScanConfig:
        """Build the immutable portscan threshold set."""
        return PortScanConfig(
            window_s=self.portscan_window_s,
            min_ports=self.portscan_min_ports,
            critical_ports=self.portscan_critical_ports,
            state_ttl_s=self.portscan_state_ttl_s,
        )

    def to_synflood_config(self) -> SynFloodConfig:
        """Build the immutable synflood threshold set."""
        return SynFloodConfig(
            window_s=self.syn_window_s,
            min_count=self.syn_min_count,
            max_completion_ratio=self.syn_max_completion_ratio,
            handshake_ttl_s=self.handshake_ttl_s,
            state_ttl_s=self.syn_state_ttl_s,
        )
