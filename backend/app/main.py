"""FastAPI application factory for the Network Attack Visualiser backend.

The factory (:func:`create_app`) builds a configured application from a
:class:`~app.config.Settings` instance, keeping application creation, configuration
and routing cleanly separated. A module-level ``app`` is provided for ASGI servers,
and a small ``main`` entry point runs the development server.

Run locally from the repository root (so the root ``.env`` is loaded)::

    uvicorn --app-dir backend app.main:app
    PYTHONPATH=backend python -m app.main
"""

from fastapi import FastAPI

from app.api import health
from app.config import Settings, get_settings


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build and configure the FastAPI application.

    Args:
        settings: Configuration to use. When ``None`` (the default) the cached
            :func:`app.config.get_settings` value is used. Passing an explicit
            ``Settings`` lets tests construct isolated applications without
            mutating global state.

    Returns:
        A configured :class:`fastapi.FastAPI` instance.
    """
    if settings is None:
        settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        debug=settings.environment == "development",
    )
    app.state.settings = settings
    app.include_router(health.router)
    return app


app = create_app()


def main() -> None:
    """Run the development server bound to the configured host and port."""
    import uvicorn

    settings = get_settings()
    uvicorn.run(app, host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
