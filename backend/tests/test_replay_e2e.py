"""End-to-end and integration tests for PCAP replay (Phase 5).

Covers: generate -> replay -> the expected alert in SQLite for both scenarios;
acceleration invariance of alerts and statistics; the three repeated-replay
scenarios (characterised against the real engine, not predetermined); REST
visibility of externally-committed replay rows through an already-open app; the
absence of WebSocket deltas from a separate replay process; and the CLI exit
codes. Every capture is generated locally into ``tmp_path``.
"""

import asyncio
import importlib.util
import json
import threading
import time
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import uvicorn
import websockets
from pydantic import SecretStr
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap
from starlette.testclient import TestClient

from app.alerts.engine import AlertEngine
from app.alerts.pipeline import EventPipeline
from app.config import Settings
from app.detection import (
    DetectionEngine,
    DetectionSettings,
    PortScanDetector,
    SynFloodDetector,
)
from app.ingest.pcap_replay import ReplayError, ReplayResult, replay_pcap
from app.main import create_app
from app.storage import (
    AlertRepository,
    Database,
    EventStatsRepository,
    connect,
    initialise_schema,
)
from tests.factories import TEST_SENSOR_TOKEN, sequential_id_factory

REPO_ROOT = Path(__file__).resolve().parents[2]
COOLDOWNS = {"portscan": 60.0, "synflood": 60.0}
ALLOWED_ORIGIN = "http://localhost:5173"
STARTUP_DEADLINE_S = 15.0
NEGATIVE_WS_TIMEOUT_S = 1.5


def _load_script(name: str) -> ModuleType:
    path = REPO_ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"_scripts_{name}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@dataclass
class Parts:
    pipeline: EventPipeline
    repository: AlertRepository
    stats: EventStatsRepository
    detection: DetectionEngine


def _make_parts(database: Database, *, id_start: int = 0) -> Parts:
    """A full in-process pipeline with a handle on its detection engine.

    ``id_start`` seeds this pipeline's deterministic ``alert_id`` factory. Two
    pipelines sharing one database must use disjoint seeds so their generated
    ``alert_id`` values never collide against the ``alerts.alert_id`` PRIMARY KEY
    (each independent process/pipeline mints its own ids; the rows may still share
    a ``dedup_key``).
    """
    ds = DetectionSettings(_env_file=None)
    detection = DetectionEngine(
        [PortScanDetector(ds.to_portscan_config()), SynFloodDetector(ds.to_synflood_config())]
    )
    repository = AlertRepository(database, max_rows=None)
    stats = EventStatsRepository(database)
    engine = AlertEngine(repository, COOLDOWNS, id_factory=sequential_id_factory(id_start))
    pipeline = EventPipeline(
        detection=detection,
        alerts=engine,
        alert_repository=repository,
        stats=stats,
        database=database,
    )
    return Parts(pipeline, repository, stats, detection)


def _memory_db() -> Database:
    connection = connect(":memory:")
    initialise_schema(connection)
    return Database(connection)


def _file_db(path: Path) -> Database:
    connection = connect(str(path))
    initialise_schema(connection)
    return Database(connection)


def _replay(path: Path, pipeline: EventPipeline, **overrides: object) -> ReplayResult:
    params: dict[str, object] = {
        "batch_size": 500,
        "max_packets": 1_000_000,
        "max_file_bytes": 50_000_000,
        "max_sleep_s": 2.0,
    }
    params.update(overrides)
    return replay_pcap(path, pipeline, **params)  # type: ignore[arg-type]


@pytest.fixture(scope="module")
def generator() -> ModuleType:
    return _load_script("generate_pcaps")


@pytest.fixture
def scenarios(generator: ModuleType, tmp_path: Path) -> dict[str, Path]:
    written: dict[str, Path] = generator.write_scenarios(tmp_path / "captures")
    return written


# --------------------------------------------------------------------------- #
# Acceptance: generate -> replay -> expected alert
# --------------------------------------------------------------------------- #


def test_port_scan_pcap_produces_portscan_alert(scenarios: dict[str, Path]) -> None:
    db = _memory_db()
    try:
        parts = _make_parts(db)
        result = _replay(scenarios["port_scan"], parts.pipeline)
        assert result.outcome == "completed"
        assert result.alerts_created == 1
        items, total = parts.repository.list()
        assert total == 1
        alert = items[0]
        assert alert.detector_id == "portscan"
        assert alert.category == "reconnaissance"
        assert alert.source_type == "replay"
        # The detector latches at the moment the threshold is crossed, so the
        # single alert's evidence reflects the configured trigger count
        # (PORTSCAN_MIN_PORTS), not the scenario's larger total port count.
        threshold = DetectionSettings(_env_file=None).portscan_min_ports
        assert alert.evidence["distinct_port_count"] == threshold
        # Every scenario record was nonetheless replayed and counted in statistics.
        assert result.events_emitted == result.packets_read
        packets, _ = parts.stats.totals()
        assert packets == result.events_emitted > threshold
    finally:
        db.close()


def test_syn_burst_pcap_produces_synflood_alert(scenarios: dict[str, Path]) -> None:
    db = _memory_db()
    try:
        parts = _make_parts(db)
        result = _replay(scenarios["syn_burst"], parts.pipeline)
        assert result.outcome == "completed"
        detectors = {item.detector_id for item in parts.repository.list()[0]}
        assert "synflood" in detectors
        synflood = next(i for i in parts.repository.list()[0] if i.detector_id == "synflood")
        assert synflood.category == "dos"
        assert synflood.source_type == "replay"
    finally:
        db.close()


def test_normal_traffic_pcap_produces_no_alert(scenarios: dict[str, Path]) -> None:
    db = _memory_db()
    try:
        parts = _make_parts(db)
        result = _replay(scenarios["normal_traffic"], parts.pipeline)
        assert result.alerts_created == 0
        assert parts.repository.count() == 0
        # Benign traffic is still counted in statistics.
        packets, _ = parts.stats.totals()
        assert packets == len(list(_iter_pcap(scenarios["normal_traffic"])))
    finally:
        db.close()


def _iter_pcap(path: Path) -> Iterator[object]:
    from scapy.utils import PcapReader

    with PcapReader(str(path)) as reader:
        yield from reader


# --------------------------------------------------------------------------- #
# Acceleration invariance (alerts AND statistics)
# --------------------------------------------------------------------------- #


def test_acceleration_invariance_alerts_and_statistics(scenarios: dict[str, Path]) -> None:
    unpaced_db = _memory_db()
    paced_db = _memory_db()
    try:
        unpaced = _make_parts(unpaced_db)
        paced = _make_parts(paced_db)
        slept: list[float] = []

        unpaced_result = _replay(scenarios["port_scan"], unpaced.pipeline, speed=None)
        paced_result = _replay(
            scenarios["port_scan"], paced.pipeline, speed=1.0, sleep=slept.append
        )

        assert slept, "paced replay should have slept between packets"
        assert (unpaced_result.alerts_created, unpaced_result.alerts_updated) == (
            paced_result.alerts_created,
            paced_result.alerts_updated,
        )

        def alert_fingerprint(repo: AlertRepository) -> list[tuple[object, ...]]:
            items, _ = repo.list()
            return sorted(
                (a.detector_id, a.dedup_key, a.severity, a.occurrence_count, a.source_type)
                for a in items
            )

        assert alert_fingerprint(unpaced.repository) == alert_fingerprint(paced.repository)
        assert unpaced.stats.totals() == paced.stats.totals()
        assert unpaced.stats.protocol_distribution() == paced.stats.protocol_distribution()
    finally:
        unpaced_db.close()
        paced_db.close()


# --------------------------------------------------------------------------- #
# Repeated replay: characterised against the real engine
# --------------------------------------------------------------------------- #


def test_immediate_second_replay_same_pipeline(scenarios: dict[str, Path]) -> None:
    """A second pass over the same timestamps re-counts stats but adds no new row.

    Nothing is too-late (the scan fits inside the detection window), so every
    event is re-processed and re-counted in statistics; but the second pass falls
    inside the alert cooldown, so it can only ever reinforce the existing row —
    never create a second one.
    """
    db = _memory_db()
    try:
        parts = _make_parts(db)
        first = _replay(scenarios["port_scan"], parts.pipeline)
        assert first.alerts_created == 1
        packets_after_first, _ = parts.stats.totals()

        second = _replay(scenarios["port_scan"], parts.pipeline)
        assert second.alerts_created == 0  # cooldown gate: no new row can be created
        assert parts.repository.count() == 1
        assert parts.detection.dropped_late == 0  # in-window, so nothing dropped as late
        packets_after_second, _ = parts.stats.totals()
        assert packets_after_second == 2 * packets_after_first  # every event re-counted
    finally:
        db.close()


def test_replay_after_time_advance_drops_events_as_late(
    scenarios: dict[str, Path], tmp_path: Path
) -> None:
    """Advancing logical time beyond the window pushes a re-replay past too-late."""
    db = _memory_db()
    try:
        parts = _make_parts(db)
        _replay(scenarios["port_scan"], parts.pipeline)
        rows_before = parts.repository.count()

        # A single far-future replay SYN advances the replay clock well beyond
        # any detector window.
        future = tmp_path / "future.pcap"
        frame = Ether() / IP(src="10.0.0.50", dst="10.0.0.10") / TCP(dport=80, flags="S")
        frame.time = 2_000.0
        wrpcap(str(future), [frame])
        _replay(future, parts.pipeline)

        again = _replay(scenarios["port_scan"], parts.pipeline)
        assert again.alerts_created == 0 and again.alerts_updated == 0
        assert parts.repository.count() == rows_before
        # Every one of the 20 re-fed scan SYNs is now older than HWM - window.
        assert parts.detection.dropped_late == 20
    finally:
        db.close()


def test_fresh_pipeline_same_database_creates_duplicate_dedup_row(
    scenarios: dict[str, Path], tmp_path: Path
) -> None:
    """A fresh process (empty gate + empty HWM) re-fires and inserts a 2nd row."""
    db_path = tmp_path / "shared.sqlite3"
    first_db = _file_db(db_path)
    try:
        first = _make_parts(first_db)
        _replay(scenarios["port_scan"], first.pipeline)
        assert first.repository.count() == 1
        first_key = first.repository.list()[0][0].dedup_key
    finally:
        first_db.close()

    second_db = _file_db(db_path)
    try:
        # A distinct alert-id seed models an independent process minting its own
        # ids; without it both pipelines would emit alert_id 0 and collide on the
        # shared alerts.alert_id PRIMARY KEY.
        second = _make_parts(second_db, id_start=1000)
        second_result = _replay(scenarios["port_scan"], second.pipeline)
        assert second_result.alerts_created == 1  # fresh gate: a create, not an update
        items, total = second.repository.list()
        assert total == 2  # two rows now share one dedup_key (index is non-unique)
        assert {a.dedup_key for a in items} == {first_key}
        assert all(a.occurrence_count == 1 for a in items)
    finally:
        second_db.close()


# --------------------------------------------------------------------------- #
# REST visibility of externally-committed replay rows
# --------------------------------------------------------------------------- #


def test_rest_sees_replay_committed_by_a_separate_connection(
    scenarios: dict[str, Path], tmp_path: Path
) -> None:
    db_path = tmp_path / "rest.sqlite3"
    settings = Settings(
        _env_file=None,
        database_path=str(db_path),
        sensor_token=SecretStr(TEST_SENSOR_TOKEN),
    )
    app = create_app(settings, DetectionSettings(_env_file=None))
    with TestClient(app) as client:  # app A opens its connection to db_path here
        replay_db = _file_db(db_path)  # a separate connection to the same file
        try:
            parts = _make_parts(replay_db)
            result = _replay(scenarios["port_scan"], parts.pipeline)
            assert result.alerts_created == 1
        finally:
            replay_db.close()

        response = client.get("/api/v1/alerts", params={"source_type": "replay"})
        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 1
        assert body["items"][0]["detector_id"] == "portscan"
        assert body["items"][0]["source_type"] == "replay"


# --------------------------------------------------------------------------- #
# No WebSocket delta is published from a separate replay process
# --------------------------------------------------------------------------- #


@dataclass
class LiveServer:
    base: str
    db_path: Path


@pytest.fixture
def live_server(tmp_path: Path) -> Iterator[LiveServer]:
    db_path = tmp_path / "live.sqlite3"
    settings = Settings(
        _env_file=None,
        database_path=str(db_path),
        sensor_token=SecretStr(TEST_SENSOR_TOKEN),
        cors_allow_origins=(ALLOWED_ORIGIN,),
    )
    application = create_app(settings, DetectionSettings(_env_file=None))
    config = uvicorn.Config(application, host="127.0.0.1", port=0, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + STARTUP_DEADLINE_S
        while not server.started:
            if time.monotonic() > deadline or not thread.is_alive():
                raise RuntimeError("uvicorn did not start within the deadline")
            time.sleep(0.02)
        port = server.servers[0].sockets[0].getsockname()[1]
        yield LiveServer(base=f"127.0.0.1:{port}", db_path=db_path)
    finally:
        server.should_exit = True
        thread.join(timeout=STARTUP_DEADLINE_S)
        assert not thread.is_alive()


def test_separate_process_replay_publishes_no_ws_delta_but_is_visible_via_rest(
    live_server: LiveServer, scenarios: dict[str, Path]
) -> None:
    async def scenario() -> None:
        async with websockets.connect(
            f"ws://{live_server.base}/api/v1/ws/alerts",
            additional_headers={"Origin": ALLOWED_ORIGIN},
        ) as websocket:
            # Replay through a SEPARATE connection to the same database file.
            replay_db = _file_db(live_server.db_path)
            try:
                parts = _make_parts(replay_db)
                result = await asyncio.to_thread(_replay, scenarios["port_scan"], parts.pipeline)
                assert result.alerts_created == 1
            finally:
                replay_db.close()

            # No delta may arrive: the replay process has no broadcaster. Bounded
            # wait so the negative assertion can never hang.
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(websocket.recv(), timeout=NEGATIVE_WS_TIMEOUT_S)

        # The row is still visible through the already-open server over REST.
        def fetch() -> dict[str, Any]:
            url = f"http://{live_server.base}/api/v1/alerts?source_type=replay"
            with urllib.request.urlopen(url) as response:
                data: dict[str, Any] = json.loads(response.read().decode("utf-8"))
                return data

        body = await asyncio.to_thread(fetch)
        assert body["total"] == 1
        assert body["items"][0]["source_type"] == "replay"

    asyncio.run(asyncio.wait_for(scenario(), timeout=STARTUP_DEADLINE_S * 2))


# --------------------------------------------------------------------------- #
# CLI exit codes
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def cli() -> ModuleType:
    return _load_script("replay_pcap")


def _alerts_in_db(db_path: Path) -> list[tuple[str, str]]:
    connection = connect(str(db_path))
    try:
        rows = connection.execute("SELECT detector_id, source_type FROM alerts").fetchall()
        return [(r["detector_id"], r["source_type"]) for r in rows]
    finally:
        connection.close()


def test_cli_completed_returns_zero_and_persists(
    cli: ModuleType, scenarios: dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "cli.sqlite3"
    monkeypatch.setenv("DATABASE_PATH", str(db_path))
    rc = cli.main([str(scenarios["port_scan"])])
    assert rc == 0
    assert ("portscan", "replay") in _alerts_in_db(db_path)


def test_cli_packet_limit_returns_three(
    cli: ModuleType, scenarios: dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "cli.sqlite3"))
    monkeypatch.setenv("REPLAY_MAX_PACKETS", "2")  # the port-scan pcap has 20 records
    rc = cli.main([str(scenarios["port_scan"])])
    assert rc == 3


def test_cli_missing_file_returns_five(
    cli: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "cli.sqlite3"))
    rc = cli.main([str(tmp_path / "does-not-exist.pcap")])
    assert rc == 5


def test_cli_invalid_speed_is_argparse_exit_two(
    cli: ModuleType, scenarios: dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "cli.sqlite3"))
    with pytest.raises(SystemExit) as excinfo:
        cli.main([str(scenarios["port_scan"]), "--speed", "0"])
    assert excinfo.value.code == 2


@pytest.mark.parametrize(
    ("outcome", "expected_code"),
    [("completed", 0), ("packet_limit_reached", 3), ("truncated", 4)],
)
def test_cli_maps_outcomes_to_exit_codes(
    cli: ModuleType,
    scenarios: dict[str, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    outcome: str,
    expected_code: int,
) -> None:
    """Deterministically exercise the outcome->exit-code mapping with a stub."""
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "cli.sqlite3"))
    stub = ReplayResult(
        outcome=outcome,  # type: ignore[arg-type]
        packets_read=1,
        events_emitted=1,
        dropped_unsupported=0,
        dropped_invalid=0,
        dropped_parse=0,
        alerts_created=0,
        alerts_updated=0,
    )
    monkeypatch.setattr(cli, "replay_pcap", lambda *a, **k: stub)
    rc = cli.main([str(scenarios["port_scan"])])
    assert rc == expected_code


def test_cli_replay_error_returns_five_via_stub(
    cli: ModuleType, scenarios: dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "cli.sqlite3"))

    def boom(*args: object, **kwargs: object) -> ReplayResult:
        raise ReplayError("simulated file-level failure")

    monkeypatch.setattr(cli, "replay_pcap", boom)
    rc = cli.main([str(scenarios["port_scan"])])
    assert rc == 5
