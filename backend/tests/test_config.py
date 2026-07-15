"""Unit tests for application configuration (``app.config``).

Tests are deterministic and isolated: ``Settings`` is constructed with
``_env_file=None`` so no ambient ``.env`` file is read, and environment
variables are controlled per test via ``monkeypatch``. Invalid inputs are
supplied through the environment (as a real deployment would) so the tests also
exercise the env-loading path.
"""

import pytest
from pydantic import ValidationError

import app
from app.config import Settings, get_settings

_CONFIG_ENV_VARS = ("APP_NAME", "APP_VERSION", "ENVIRONMENT", "HOST", "PORT")


def test_defaults_match_documented_values(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no environment overrides, ``Settings`` uses the documented defaults."""
    for var in _CONFIG_ENV_VARS:
        monkeypatch.delenv(var, raising=False)

    settings = Settings(_env_file=None)

    assert settings.app_name == "Network Attack Visualiser"
    assert settings.app_version == app.__version__
    assert settings.environment == "development"
    assert settings.host == "127.0.0.1"
    assert settings.port == 8000


def test_environment_variables_override_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bare ``UPPER_SNAKE`` environment variables override the defaults."""
    monkeypatch.setenv("APP_NAME", "Custom NAV")
    monkeypatch.setenv("PORT", "9000")
    monkeypatch.setenv("ENVIRONMENT", "production")

    settings = Settings(_env_file=None)

    assert settings.app_name == "Custom NAV"
    assert settings.port == 9000
    assert settings.environment == "production"


def test_invalid_port_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """A port outside the 1-65535 range fails validation."""
    monkeypatch.setenv("PORT", "70000")

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_invalid_environment_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unknown ``ENVIRONMENT`` value fails validation."""
    monkeypatch.setenv("ENVIRONMENT", "staging")

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_whitespace_only_string_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Whitespace-only string settings are rejected (not silently accepted)."""
    monkeypatch.setenv("APP_NAME", "   ")

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_empty_string_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty string setting is rejected."""
    monkeypatch.setenv("HOST", "")

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_get_settings_is_cached() -> None:
    """``get_settings`` returns the same cached instance until the cache is cleared."""
    get_settings.cache_clear()
    try:
        first = get_settings()
        second = get_settings()
        assert first is second
    finally:
        get_settings.cache_clear()
