"""Real-server WebSocket verification: uvicorn + the real ``websockets`` client.

Starlette's TestClient fakes the WebSocket transport in-process, so its tests
pass even when the server cannot perform a genuine upgrade (plain uvicorn ships
no WebSocket protocol implementation). This module is the executable proof that
the pinned ``websockets`` dependency makes real upgrades work: a real uvicorn
server on an ephemeral loopback port, a real client socket, a real alert pushed
end to end.

Isolation: the app is built from explicit ``Settings`` over a ``tmp_path``
database — never ``get_settings()``, the ambient ``.env`` or ``data/``.
Startup is polled (never a fixed sleep) and teardown is guaranteed by the
fixture's ``finally``.
"""

import asyncio
import json
import threading
import time
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import uvicorn
import websockets
from pydantic import SecretStr
from websockets.exceptions import InvalidStatus

from app.config import Settings
from app.detection import DetectionSettings
from app.ingest.synthetic import port_scan
from app.main import create_app
from tests.factories import TEST_SENSOR_TOKEN, ingest_payload

ALLOWED_ORIGIN = "http://localhost:5173"
STARTUP_DEADLINE_S = 15.0
SCENARIO_TIMEOUT_S = 15.0


@pytest.fixture
def live_server(tmp_path: Path) -> Iterator[str]:
    """A real uvicorn server on 127.0.0.1:<ephemeral>, torn down afterwards."""
    settings = Settings(
        _env_file=None,
        database_path=str(tmp_path / "live.sqlite3"),  # never data/nav.sqlite3
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
            if time.monotonic() > deadline:
                raise RuntimeError("uvicorn did not start within the deadline")
            if not thread.is_alive():
                raise RuntimeError("uvicorn exited during startup")
            time.sleep(0.02)
        port = server.servers[0].sockets[0].getsockname()[1]
        yield f"127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=STARTUP_DEADLINE_S)
        assert not thread.is_alive(), "uvicorn thread failed to shut down"


def _post_ingest(base: str, events: Any) -> int:
    request = urllib.request.Request(
        f"http://{base}/api/v1/ingest/events",
        data=json.dumps(ingest_payload(events)).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Sensor-Token": TEST_SENSOR_TOKEN},
        method="POST",
    )
    with urllib.request.urlopen(request) as response:
        return int(response.status)


def test_real_upgrade_delivers_a_real_alert(live_server: str) -> None:
    """Upgrade succeeds over a genuine socket and a pushed delta arrives."""

    async def scenario() -> None:
        async with websockets.connect(
            f"ws://{live_server}/api/v1/ws/alerts",
            additional_headers={"Origin": ALLOWED_ORIGIN},
        ) as websocket:
            status = await asyncio.to_thread(_post_ingest, live_server, port_scan(num_ports=20))
            assert status == 202
            raw = await asyncio.wait_for(websocket.recv(), timeout=SCENARIO_TIMEOUT_S)
            envelope = json.loads(raw)
            assert envelope["type"] == "alert.created"
            assert envelope["alert"]["detector_id"] == "portscan"

    asyncio.run(asyncio.wait_for(scenario(), timeout=SCENARIO_TIMEOUT_S * 2))


def test_real_upgrade_refuses_disallowed_origin(live_server: str) -> None:
    """A disallowed Origin is rejected at the handshake, on the real wire."""

    async def scenario() -> None:
        with pytest.raises(InvalidStatus) as excinfo:
            async with websockets.connect(
                f"ws://{live_server}/api/v1/ws/alerts",
                additional_headers={"Origin": "http://evil.example"},
            ):
                pass  # pragma: no cover - the handshake never completes
        assert excinfo.value.response.status_code == 403

    asyncio.run(asyncio.wait_for(scenario(), timeout=SCENARIO_TIMEOUT_S))


def test_real_upgrade_refuses_missing_origin(live_server: str) -> None:
    async def scenario() -> None:
        with pytest.raises(InvalidStatus) as excinfo:
            async with websockets.connect(f"ws://{live_server}/api/v1/ws/alerts"):
                pass  # pragma: no cover - the handshake never completes
        assert excinfo.value.response.status_code == 403

    asyncio.run(asyncio.wait_for(scenario(), timeout=SCENARIO_TIMEOUT_S))
