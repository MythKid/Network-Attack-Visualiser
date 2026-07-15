"""Health-check route.

Exposes ``GET /health`` for liveness checks and to surface the running
application version. The handler reads configuration from the application state
populated by the factory, so it always reflects the exact ``Settings`` the app
was built with.
"""

from typing import Annotated, cast

from fastapi import APIRouter, Depends, Request

from app.api.schemas import HealthResponse
from app.config import Settings

router = APIRouter(tags=["health"])


def get_app_settings(request: Request) -> Settings:
    """Return the :class:`Settings` stored on the application at startup.

    Reading from ``app.state`` binds the handler to the exact configuration the
    factory was built with, so tests can inject settings without mutating global
    state or the cached ``get_settings`` accessor.
    """
    return cast(Settings, request.app.state.settings)


@router.get("/health", response_model=HealthResponse, summary="Liveness and version check")
async def health(settings: Annotated[Settings, Depends(get_app_settings)]) -> HealthResponse:
    """Report that the service is running and expose the configured version."""
    return HealthResponse(status="ok", version=settings.app_version)
