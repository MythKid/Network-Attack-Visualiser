"""FastAPI application factory for the Network Attack Visualiser backend.

The factory (:func:`create_app`) builds a configured application from a
:class:`~app.config.Settings` instance, keeping application creation,
configuration and routing cleanly separated. The Phase 3 pipeline — database,
repositories, detection engine, alert engine, event pipeline and broadcaster —
is assembled in the application lifespan, so tests construct isolated
applications (with isolated databases) simply by passing explicit settings.

Run locally from the repository root (so the root ``.env`` is loaded)::

    uvicorn --app-dir backend app.main:app
    PYTHONPATH=backend python -m app.main
"""

import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from starlette.concurrency import run_in_threadpool
from starlette.middleware.cors import CORSMiddleware

from app.alerts.broadcaster import AlertBroadcaster
from app.alerts.engine import AlertEngine
from app.alerts.pipeline import EventPipeline
from app.api import alerts as alerts_api
from app.api import health, ingest, stats, ws
from app.api.middleware import IngestGuardMiddleware
from app.config import Settings, get_settings
from app.detection import (
    DetectionEngine,
    DetectionSettings,
    PortScanDetector,
    SynFloodDetector,
)
from app.storage.alerts import AlertRepository
from app.storage.database import Database, connect, initialise_schema
from app.storage.stats import EventStatsRepository

INGEST_PATH = "/api/v1/ingest/events"


def _build_database(database_path: str) -> Database:
    """Open the SQLite connection and apply the schema (startup-only, blocking).

    If schema initialisation fails the just-opened connection is closed before
    the error propagates, so a failed startup leaks no file handle or lock.
    """
    connection = connect(database_path)
    try:
        initialise_schema(connection)
    except BaseException:
        connection.close()
        raise
    return Database(connection)


def create_app(
    settings: Settings | None = None,
    detection_settings: DetectionSettings | None = None,
) -> FastAPI:
    """Build and configure the FastAPI application.

    Args:
        settings: Configuration to use. When ``None`` (the default) the cached
            :func:`app.config.get_settings` value is used. Passing an explicit
            ``Settings`` lets tests construct isolated applications without
            mutating global state.
        detection_settings: Detection thresholds; defaults to loading the
            documented environment variables.

    Returns:
        A configured :class:`fastapi.FastAPI` instance.
    """
    if settings is None:
        settings = get_settings()
    if detection_settings is None:
        detection_settings = DetectionSettings()

    # detector_id -> cooldown seconds, read off the detector classes so the
    # mapping can never drift from the wired detectors (DETECTION_RULES §5).
    cooldowns: dict[str, float] = {
        PortScanDetector.detector_id: detection_settings.portscan_cooldown_s,
        SynFloodDetector.detector_id: detection_settings.syn_cooldown_s,
    }

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # Startup-only blocking work is deliberately offloaded so no sqlite3
        # call ever runs on the event loop, matching the request-path policy.
        database = await run_in_threadpool(_build_database, settings.database_path)
        detection = DetectionEngine(
            [
                PortScanDetector(detection_settings.to_portscan_config()),
                SynFloodDetector(detection_settings.to_synflood_config()),
            ]
        )
        alert_repository = AlertRepository(database, max_rows=settings.alert_max_rows)
        stats_repository = EventStatsRepository(database)
        alert_engine = AlertEngine(alert_repository, cooldowns)
        app.state.database = database
        app.state.alert_repository = alert_repository
        app.state.stats_repository = stats_repository
        app.state.detector_ids = tuple(cooldowns)
        app.state.pipeline = EventPipeline(
            detection=detection,
            alerts=alert_engine,
            alert_repository=alert_repository,
            stats=stats_repository,
            database=database,
        )
        app.state.broadcaster = AlertBroadcaster(max_queue=settings.ws_max_queue)
        try:
            yield
        finally:
            await run_in_threadpool(database.close)

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        debug=settings.environment == "development",
        lifespan=lifespan,
    )
    app.state.settings = settings
    # Wall clock for the live-event skew check only — injected on app state so
    # tests can control it; nothing else in the pipeline reads a real clock.
    app.state.wall_clock = time.time

    # Ingest guard (size cap + token, both pre-parse) innermost, CORS outermost.
    app.add_middleware(
        IngestGuardMiddleware,
        max_body_bytes=settings.ingest_max_body_bytes,
        path=INGEST_PATH,
        sensor_token=settings.sensor_token,
    )
    # Exact allowlist, no wildcard, no credentials; only the methods and headers
    # the dashboard actually uses (SEC_REQ §4.2). WebSocket upgrades are
    # validated separately in app.api.ws — CORS middleware does not cover them.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_allow_origins),
        allow_credentials=False,
        allow_methods=["GET"],
        allow_headers=["Content-Type"],
    )

    app.include_router(health.router)
    app.include_router(alerts_api.router)
    app.include_router(stats.router)
    app.include_router(ingest.router)
    app.include_router(ws.router)
    return app


app = create_app()


def main() -> None:
    """Run the development server bound to the configured host and port."""
    import uvicorn

    settings = get_settings()
    uvicorn.run(app, host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
