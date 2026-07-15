"""Application configuration for the Network Attack Visualiser backend.

Settings are loaded from environment variables (and an optional ``.env`` file at
the repository root), with documented, validated defaults. No secrets are read
into source code here; secret-bearing settings are introduced only in the later
phases that require them (for example the sensor ingest token in Phase 3).

Environment variables use bare ``UPPER_SNAKE`` names with no prefix (for example
``APP_NAME``, ``PORT``), matching the naming convention used across the design
documentation.
"""

from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, StringConstraints
from pydantic_settings import BaseSettings, SettingsConfigDict

from app import __version__

# A trimmed, non-empty string: surrounding whitespace is stripped and the result
# must contain at least one character, so blank or whitespace-only values are
# rejected with a clear validation error instead of being silently accepted.
NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]

# Recognised deployment environments. An unknown value fails validation.
Environment = Literal["development", "test", "production"]


class Settings(BaseSettings):
    """Typed, environment-driven application settings.

    Defaults are safe for local development. Every field is validated on load, so
    an invalid value (for example an out-of-range port or an unknown environment)
    fails fast with an explicit error instead of producing undefined behaviour.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: NonEmptyStr = Field(
        default="Network Attack Visualiser",
        description="Human-readable application name, surfaced as the API/OpenAPI title.",
    )
    app_version: NonEmptyStr = Field(
        default=__version__,
        description=(
            "Version reported by GET /health and the OpenAPI schema. Defaults to the "
            "packaged app.__version__; the APP_VERSION environment variable overrides it."
        ),
    )
    environment: Environment = Field(
        default="development",
        description="Deployment environment; drives FastAPI's debug flag.",
    )
    host: NonEmptyStr = Field(
        default="127.0.0.1",
        description="Interface the development server binds to (loopback by default).",
    )
    port: int = Field(
        default=8000,
        ge=1,
        le=65535,
        description="TCP port the development server binds to.",
    )


@lru_cache
def get_settings() -> Settings:
    """Return a process-wide cached :class:`Settings` instance.

    Caching keeps configuration loaded once per process. It is used only at
    application construction (not per request); tests that need isolation build
    ``Settings`` directly or call ``get_settings.cache_clear()``.
    """
    return Settings()
