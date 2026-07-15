"""Unit tests for the FastAPI application factory (``app.main``)."""

from fastapi import FastAPI

from app.config import Settings
from app.main import create_app


def test_create_app_returns_fastapi_instance() -> None:
    """The factory returns a configured FastAPI application."""
    assert isinstance(create_app(), FastAPI)


def test_app_metadata_reflects_settings() -> None:
    """OpenAPI title and version are taken from the injected settings."""
    settings = Settings(_env_file=None, app_name="Meta NAV", app_version="1.2.3")

    application = create_app(settings)

    assert application.title == "Meta NAV"
    assert application.version == "1.2.3"


def test_factory_stores_settings_on_state() -> None:
    """The injected settings are stored on the application state for handlers."""
    settings = Settings(_env_file=None)

    application = create_app(settings)

    assert application.state.settings is settings
