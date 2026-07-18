"""Shared fixtures and helpers for the backend test suite.

Everything here is deterministic and clock-free: time is expressed purely as the
``ts`` on events and the ``now`` passed to detectors and the Alert Engine, so
window/TTL/cooldown boundaries are crossed by exact amounts with no reliance on
wall-clock timing or ``sleep``.
"""

import contextlib
import itertools
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.config import Settings
from app.detection import (
    DetectionEngine,
    DetectionSettings,
    PortScanConfig,
    PortScanDetector,
    SynFloodConfig,
    SynFloodDetector,
)
from app.main import create_app
from app.storage import AlertRepository, Database, EventStatsRepository, connect, initialise_schema
from tests.factories import TEST_SENSOR_TOKEN

# A factory for isolated, lifespan-started test clients with setting overrides.
ClientFactory = Callable[..., TestClient]


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


# --------------------------------------------------------------------------- #
# Phase 3 — storage fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture
def database() -> Iterator[Database]:
    """An initialised in-memory database (journal mode is irrelevant here)."""
    connection = connect(":memory:")
    initialise_schema(connection)
    db = Database(connection)
    yield db
    db.close()


@pytest.fixture
def alert_repository(database: Database) -> AlertRepository:
    """An alert repository over the in-memory database, without a row cap."""
    return AlertRepository(database, max_rows=None)


@pytest.fixture
def stats_repository(database: Database) -> EventStatsRepository:
    """An event-stats repository over the same in-memory database."""
    return EventStatsRepository(database)


# --------------------------------------------------------------------------- #
# Phase 3 — API fixtures (isolated app + lifespan-started TestClient)
# --------------------------------------------------------------------------- #


@pytest.fixture
def make_client(tmp_path: Path) -> Iterator[ClientFactory]:
    """Build lifespan-started test clients over isolated tmp databases.

    Each call constructs a fresh application from explicit ``Settings`` (never
    the ambient environment), with a per-client database file and the shared
    test sensor token; keyword overrides adjust any setting. Every client's
    lifespan is exited on fixture teardown.
    """
    with contextlib.ExitStack() as stack:
        counter = itertools.count()

        def _make(**overrides: Any) -> TestClient:
            params: dict[str, Any] = {
                "database_path": str(tmp_path / f"api-{next(counter)}.sqlite3"),
                "sensor_token": SecretStr(TEST_SENSOR_TOKEN),
            }
            params.update(overrides)
            settings = Settings(_env_file=None, **params)
            application = create_app(settings, DetectionSettings(_env_file=None))
            return stack.enter_context(TestClient(application))

        yield _make


@pytest.fixture
def client(make_client: ClientFactory) -> TestClient:
    """A default lifespan-started client (auth token configured, default limits)."""
    return make_client()
