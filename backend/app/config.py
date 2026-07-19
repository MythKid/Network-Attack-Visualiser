"""Application configuration for the Network Attack Visualiser backend.

Settings are loaded from environment variables (and an optional ``.env`` file at
the repository root), with documented, validated defaults. Secret-bearing settings
(``SENSOR_TOKEN``) are typed as :class:`~pydantic.SecretStr` so they can never
reach a log line or repr, and have no default: the ingest endpoint fails closed
when no token is configured.

Environment variables use bare ``UPPER_SNAKE`` names with no prefix (for example
``APP_NAME``, ``PORT``), matching the naming convention used across the design
documentation.
"""

from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, SecretStr, StringConstraints, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from app import __version__
from app.models.json_types import PositiveFiniteFloat

# A trimmed, non-empty string: surrounding whitespace is stripped and the result
# must contain at least one character, so blank or whitespace-only values are
# rejected with a clear validation error instead of being silently accepted.
NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]

# Recognised deployment environments. An unknown value fails validation.
Environment = Literal["development", "test", "production"]

# Minimum length for a configured sensor token: short shared secrets are
# guessable, and a misconfigured empty token must fail loudly, never work.
MIN_SENSOR_TOKEN_LENGTH = 16


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

    # ------------------------------------------------------------------ #
    # Phase 3 — alert pipeline (storage, ingest, CORS, WebSocket)
    # ------------------------------------------------------------------ #

    database_path: NonEmptyStr = Field(
        default="data/nav.sqlite3",
        description=(
            "SQLite database path. ':memory:' is accepted for ephemeral use; for "
            "file paths the parent directory is created on startup. The file is "
            "ephemeral lab data and is git-ignored."
        ),
    )
    cors_allow_origins: Annotated[tuple[str, ...], NoDecode] = Field(
        default=("http://localhost:5173", "http://127.0.0.1:5173"),
        description=(
            "Exact browser-origin allowlist for REST CORS and the WebSocket "
            "handshake, comma-separated. Wildcards are rejected."
        ),
    )
    sensor_token: SecretStr | None = Field(
        default=None,
        description=(
            "Shared secret the sensor presents in X-Sensor-Token. No default: when "
            "unset, the ingest endpoint fails closed with HTTP 503."
        ),
    )
    ingest_max_batch: int = Field(
        default=200,
        ge=1,
        description="Maximum events per ingest request; larger batches are rejected (413).",
    )
    ingest_max_body_bytes: int = Field(
        default=262_144,
        ge=1,
        description="Maximum ingest request-body size in bytes, enforced before parsing (413).",
    )
    max_clock_skew_s: PositiveFiniteFloat = Field(
        default=300.0,
        description=(
            "Maximum |event ts - backend wall clock| accepted for live events. "
            "Synthetic and replay events carry controlled timestamps and are exempt."
        ),
    )
    alert_max_rows: int = Field(
        default=10_000,
        ge=1,
        description=(
            "Rolling cap on stored alert rows; the oldest-recorded rows beyond the "
            "cap are pruned inside each ingest transaction."
        ),
    )
    ws_max_queue: int = Field(
        default=100,
        ge=1,
        description=(
            "Bounded per-subscriber WebSocket delta queue; a subscriber that falls "
            "this far behind is disconnected (close code 1013) to re-sync via REST."
        ),
    )

    # ------------------------------------------------------------------ #
    # Phase 5 — PCAP replay (in-process ingester; see docs/SECURITY_REQUIREMENTS.md)
    # ------------------------------------------------------------------ #

    replay_max_file_bytes: int = Field(
        default=50_000_000,
        ge=1,
        description=(
            "Maximum PCAP file size accepted by the replay ingester, checked via "
            "os.stat before opening; a larger file raises ReplayError."
        ),
    )
    replay_max_packets: int = Field(
        default=1_000_000,
        ge=1,
        description=(
            "Maximum physical PCAP records read for replay (including dropped "
            "frames). Reaching it with more records remaining ends the run as "
            "'packet_limit_reached' (incomplete)."
        ),
    )
    replay_batch_size: int = Field(
        default=500,
        ge=1,
        description=(
            "Number of replay events per pipeline batch when running unpaced "
            "(speed is None). Paced replay (speed set) processes one event per batch."
        ),
    )
    replay_max_sleep_s: PositiveFiniteFloat = Field(
        default=2.0,
        description=(
            "Upper clamp on a single inter-packet pacing sleep during paced "
            "replay; the captured event timestamp is never changed by pacing."
        ),
    )

    @field_validator("cors_allow_origins", mode="before")
    @classmethod
    def _split_and_check_origins(cls, value: object) -> tuple[str, ...]:
        """Parse a comma-separated allowlist and refuse permissive entries.

        ``NoDecode`` disables pydantic-settings' JSON pre-decoding for this field,
        so the raw environment string arrives here intact. A wildcard origin would
        silently disable the browser-facing trust boundary, so it is rejected
        rather than accepted, and every entry must look like a real web origin.
        """
        if isinstance(value, str):
            origins = tuple(part.strip() for part in value.split(",") if part.strip())
        elif isinstance(value, (tuple, list)):
            origins = tuple(str(part).strip() for part in value)
        else:
            raise ValueError("CORS_ALLOW_ORIGINS must be a comma-separated string")
        if not origins:
            raise ValueError("CORS_ALLOW_ORIGINS must contain at least one origin")
        for origin in origins:
            if "*" in origin:
                raise ValueError("wildcard CORS origins are not permitted")
            if not origin.startswith(("http://", "https://")):
                raise ValueError(f"CORS origin {origin!r} must start with http:// or https://")
        return origins

    @field_validator("sensor_token")
    @classmethod
    def _check_sensor_token(cls, value: SecretStr | None) -> SecretStr | None:
        """Refuse dangerously short (or empty) tokens instead of accepting them."""
        if value is not None and len(value.get_secret_value()) < MIN_SENSOR_TOKEN_LENGTH:
            raise ValueError(f"SENSOR_TOKEN must be at least {MIN_SENSOR_TOKEN_LENGTH} characters")
        return value


@lru_cache
def get_settings() -> Settings:
    """Return a process-wide cached :class:`Settings` instance.

    Caching keeps configuration loaded once per process. It is used only at
    application construction (not per request); tests that need isolation build
    ``Settings`` directly or call ``get_settings.cache_clear()``.
    """
    return Settings()
