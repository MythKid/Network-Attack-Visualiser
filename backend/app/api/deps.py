"""Typed accessors for the application state assembled at startup.

Reading from ``app.state`` binds handlers to the exact objects the lifespan
built, so tests can construct isolated applications without touching global
state — the same pattern :func:`app.api.health.get_app_settings` established.
"""

from typing import cast

from fastapi import Request, WebSocket

from app.alerts.broadcaster import AlertBroadcaster
from app.alerts.pipeline import EventPipeline
from app.config import Settings
from app.storage.alerts import AlertRepository
from app.storage.database import Database
from app.storage.stats import EventStatsRepository


def get_pipeline(request: Request) -> EventPipeline:
    """The event pipeline built at startup."""
    return cast(EventPipeline, request.app.state.pipeline)


def get_broadcaster(request: Request) -> AlertBroadcaster:
    """The alert broadcaster built at startup."""
    return cast(AlertBroadcaster, request.app.state.broadcaster)


def get_broadcaster_ws(websocket: WebSocket) -> AlertBroadcaster:
    """The alert broadcaster, from a WebSocket handshake."""
    return cast(AlertBroadcaster, websocket.app.state.broadcaster)


def get_settings_ws(websocket: WebSocket) -> Settings:
    """The application settings, from a WebSocket handshake."""
    return cast(Settings, websocket.app.state.settings)


def get_database(request: Request) -> Database:
    """The shared database (connection + lock owner)."""
    return cast(Database, request.app.state.database)


def get_alert_repository(request: Request) -> AlertRepository:
    """The alert repository over the shared database."""
    return cast(AlertRepository, request.app.state.alert_repository)


def get_stats_repository(request: Request) -> EventStatsRepository:
    """The event-stats repository over the shared database."""
    return cast(EventStatsRepository, request.app.state.stats_repository)


def get_detector_ids(request: Request) -> tuple[str, ...]:
    """The detector ids wired into the pipeline (drives stats zero-filling)."""
    return cast(tuple[str, ...], request.app.state.detector_ids)
