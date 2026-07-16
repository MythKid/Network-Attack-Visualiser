"""Shared fixtures and helpers for the Phase 2 detection tests.

Everything here is deterministic and clock-free: time is expressed purely as the
``ts`` on events and the ``now`` passed to detectors, so window/TTL boundaries are
crossed by exact amounts with no reliance on wall-clock timing or ``sleep``.
"""

import pytest

from app.detection import (
    DetectionEngine,
    DetectionSettings,
    PortScanConfig,
    PortScanDetector,
    SynFloodConfig,
    SynFloodDetector,
)


class FakeClock:
    """A simple monotonic logical clock for building event timestamps."""

    def __init__(self, start: float = 1000.0) -> None:
        self.t = start

    def tick(self, dt: float = 1.0) -> float:
        """Advance by ``dt`` and return the new time."""
        self.t += dt
        return self.t

    def now(self) -> float:
        return self.t


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def settings() -> DetectionSettings:
    """Detection thresholds at their documented defaults (no ambient .env)."""
    return DetectionSettings(_env_file=None)


@pytest.fixture
def portscan_config(settings: DetectionSettings) -> PortScanConfig:
    return settings.to_portscan_config()


@pytest.fixture
def synflood_config(settings: DetectionSettings) -> SynFloodConfig:
    return settings.to_synflood_config()


@pytest.fixture
def portscan(portscan_config: PortScanConfig) -> PortScanDetector:
    return PortScanDetector(portscan_config)


@pytest.fixture
def synflood(synflood_config: SynFloodConfig) -> SynFloodDetector:
    return SynFloodDetector(synflood_config)


@pytest.fixture
def engine(portscan: PortScanDetector, synflood: SynFloodDetector) -> DetectionEngine:
    """An engine running both detectors, deriving its window from them."""
    return DetectionEngine([portscan, synflood])
