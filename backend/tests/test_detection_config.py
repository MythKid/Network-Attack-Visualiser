"""Tests for detection thresholds and their environment mapping."""

import pytest
from pydantic import ValidationError

from app.detection.config import DetectionSettings, PortScanConfig, SynFloodConfig

_DETECTION_ENV_VARS = (
    "PORTSCAN_WINDOW_S",
    "PORTSCAN_MIN_PORTS",
    "PORTSCAN_CRITICAL_PORTS",
    "PORTSCAN_STATE_TTL_S",
    "PORTSCAN_COOLDOWN_S",
    "SYN_WINDOW_S",
    "SYN_MIN_COUNT",
    "SYN_MAX_COMPLETION_RATIO",
    "HANDSHAKE_TTL_S",
    "SYN_STATE_TTL_S",
    "SYN_COOLDOWN_S",
)


def test_there_are_eleven_detection_variables() -> None:
    assert len(_DETECTION_ENV_VARS) == 11


def test_defaults_match_documented_values(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _DETECTION_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    settings = DetectionSettings(_env_file=None)

    assert settings.portscan_window_s == 10.0
    assert settings.portscan_min_ports == 15
    assert settings.portscan_critical_ports == 100
    assert settings.portscan_state_ttl_s == 60.0
    assert settings.portscan_cooldown_s == 60.0
    assert settings.syn_window_s == 5.0
    assert settings.syn_min_count == 100
    assert settings.syn_max_completion_ratio == 0.2
    assert settings.handshake_ttl_s == 10.0
    assert settings.syn_state_ttl_s == 30.0
    assert settings.syn_cooldown_s == 60.0


def test_environment_overrides_apply(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PORTSCAN_MIN_PORTS", "25")
    monkeypatch.setenv("PORTSCAN_CRITICAL_PORTS", "200")
    monkeypatch.setenv("SYN_WINDOW_S", "7.5")

    settings = DetectionSettings(_env_file=None)

    assert settings.portscan_min_ports == 25
    assert settings.portscan_critical_ports == 200
    assert settings.syn_window_s == 7.5


@pytest.mark.parametrize(
    ("var", "value"),
    [
        ("PORTSCAN_WINDOW_S", "0"),
        ("PORTSCAN_MIN_PORTS", "0"),
        ("PORTSCAN_STATE_TTL_S", "-1"),
        ("SYN_MAX_COMPLETION_RATIO", "0"),
        ("SYN_MAX_COMPLETION_RATIO", "1.5"),
        ("SYN_MIN_COUNT", "0"),
        ("HANDSHAKE_TTL_S", "0"),
    ],
)
def test_invalid_values_rejected(monkeypatch: pytest.MonkeyPatch, var: str, value: str) -> None:
    monkeypatch.setenv(var, value)
    with pytest.raises(ValidationError):
        DetectionSettings(_env_file=None)


_FLOAT_ENV_VARS = (
    "PORTSCAN_WINDOW_S",
    "PORTSCAN_STATE_TTL_S",
    "PORTSCAN_COOLDOWN_S",
    "SYN_WINDOW_S",
    "SYN_MAX_COMPLETION_RATIO",
    "HANDSHAKE_TTL_S",
    "SYN_STATE_TTL_S",
    "SYN_COOLDOWN_S",
)


@pytest.mark.parametrize("var", _FLOAT_ENV_VARS)
@pytest.mark.parametrize("value", ["nan", "inf", "-inf", "Infinity", "-Infinity"])
def test_non_finite_environment_values_rejected(
    monkeypatch: pytest.MonkeyPatch, var: str, value: str
) -> None:
    """`float()` parses "inf"/"nan", so every duration and ratio must refuse them.

    An infinite window or TTL would silently disable expiry, and NaN makes every
    window comparison false — both are unusable, so they are rejected on load.
    """
    monkeypatch.setenv(var, value)
    with pytest.raises(ValidationError):
        DetectionSettings(_env_file=None)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_portscan_config_rejects_non_finite(bad: float) -> None:
    with pytest.raises(ValidationError):
        PortScanConfig(window_s=bad, min_ports=15, critical_ports=100, state_ttl_s=60)
    with pytest.raises(ValidationError):
        PortScanConfig(window_s=10, min_ports=15, critical_ports=100, state_ttl_s=bad)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
@pytest.mark.parametrize("field", ["window_s", "max_completion_ratio", "handshake_ttl_s"])
def test_synflood_config_rejects_non_finite(bad: float, field: str) -> None:
    kwargs: dict = {
        "window_s": 5.0,
        "min_count": 100,
        "max_completion_ratio": 0.2,
        "handshake_ttl_s": 10.0,
        "state_ttl_s": 30.0,
    }
    kwargs[field] = bad
    with pytest.raises(ValidationError):
        SynFloodConfig(**kwargs)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_synflood_config_rejects_non_finite_state_ttl(bad: float) -> None:
    with pytest.raises(ValidationError):
        SynFloodConfig(
            window_s=5.0,
            min_count=100,
            max_completion_ratio=0.2,
            handshake_ttl_s=10.0,
            state_ttl_s=bad,
        )


def test_cross_field_rule_enforced_in_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """PORTSCAN_CRITICAL_PORTS must exceed 2 x PORTSCAN_MIN_PORTS."""
    monkeypatch.setenv("PORTSCAN_MIN_PORTS", "60")
    monkeypatch.setenv("PORTSCAN_CRITICAL_PORTS", "100")  # 100 <= 2*60
    with pytest.raises(ValidationError):
        DetectionSettings(_env_file=None)


def test_cross_field_rule_enforced_in_portscan_config() -> None:
    with pytest.raises(ValidationError):
        PortScanConfig(window_s=10, min_ports=60, critical_ports=100, state_ttl_s=60)


def test_converters_produce_detector_configs() -> None:
    settings = DetectionSettings(_env_file=None)

    portscan = settings.to_portscan_config()
    synflood = settings.to_synflood_config()

    assert isinstance(portscan, PortScanConfig)
    assert isinstance(synflood, SynFloodConfig)
    assert portscan.window_s == 10.0
    assert portscan.critical_ports == 100
    assert synflood.window_s == 5.0
    assert synflood.min_count == 100
    assert synflood.max_completion_ratio == 0.2
    # Derived acceptance horizons.
    assert portscan.max_event_age_s == 10.0
    assert synflood.max_event_age_s == 10.0  # max(5, 10)
