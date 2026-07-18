"""``POST /api/v1/ingest/events`` contract tests: auth, limits, skew, boundary."""

import asyncio
import concurrent.futures
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.alerts.engine import AlertDelta, AlertEngine
from app.ingest.synthetic import make_event, port_scan
from app.models.enums import SourceType
from tests.conftest import ClientFactory
from tests.factories import auth_headers, ingest_payload

WALL_NOW = 1_700_000_000.0

# Never valid JSON: used to prove the token check precedes body parsing.
MALFORMED_JSON = b'{"events": [ this is not json'


def post_malformed(client: TestClient, headers: dict[str, str]) -> Any:
    return client.post(
        "/api/v1/ingest/events",
        content=MALFORMED_JSON,
        headers={"Content-Type": "application/json", **headers},
    )


def alert_total(client: TestClient) -> int:
    return int(client.get("/api/v1/alerts").json()["total"])


def event_total(client: TestClient) -> int:
    return int(client.get("/api/v1/stats").json()["totals"]["event_count"])


# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #


def test_successful_ingest_creates_a_visible_alert(client: TestClient) -> None:
    response = client.post(
        "/api/v1/ingest/events",
        json=ingest_payload(port_scan(num_ports=20)),
        headers=auth_headers(),
    )
    assert response.status_code == 202
    assert response.json() == {"accepted": 20, "alerts_created": 1, "alerts_updated": 0}
    assert alert_total(client) == 1


def test_missing_token_is_401(client: TestClient) -> None:
    response = client.post("/api/v1/ingest/events", json=ingest_payload(port_scan(num_ports=5)))
    assert response.status_code == 401
    assert alert_total(client) == 0


def test_wrong_token_is_401(client: TestClient) -> None:
    response = client.post(
        "/api/v1/ingest/events",
        json=ingest_payload(port_scan(num_ports=5)),
        headers={"X-Sensor-Token": "wrong-token-with-length"},
    )
    assert response.status_code == 401


def test_unconfigured_token_fails_closed_with_503(make_client: ClientFactory) -> None:
    """No SENSOR_TOKEN configured -> the endpoint is unavailable, never open."""
    unconfigured = make_client(sensor_token=None)
    response = unconfigured.post(
        "/api/v1/ingest/events",
        json=ingest_payload(port_scan(num_ports=5)),
        headers=auth_headers(),  # even a 'correct-looking' token cannot pass
    )
    assert response.status_code == 503


# --------------------------------------------------------------------------- #
# Token enforcement precedes body parsing (malformed JSON as the probe)
# --------------------------------------------------------------------------- #


def test_malformed_json_without_token_is_401_not_a_parse_error(client: TestClient) -> None:
    """The token verdict must arrive before the body is ever JSON-decoded."""
    assert post_malformed(client, {}).status_code == 401


def test_malformed_json_with_wrong_token_is_401(client: TestClient) -> None:
    assert post_malformed(client, {"X-Sensor-Token": "wrong-token-with-length"}).status_code == 401


def test_malformed_json_unconfigured_is_503(make_client: ClientFactory) -> None:
    unconfigured = make_client(sensor_token=None)
    assert post_malformed(unconfigured, auth_headers()).status_code == 503


def test_malformed_json_with_correct_token_reaches_schema_validation(
    client: TestClient,
) -> None:
    """Only an authenticated request may earn a body-parse verdict (422)."""
    assert post_malformed(client, auth_headers()).status_code == 422


def test_declared_oversize_precedes_the_token_check(make_client: ClientFactory) -> None:
    """Documented precedence: Content-Length over the cap -> 413 even unauthenticated."""
    small_cap = make_client(ingest_max_body_bytes=64)
    response = small_cap.post(
        "/api/v1/ingest/events",
        content=b"x" * 200,  # Content-Length: 200 > 64; no token supplied
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413


# --------------------------------------------------------------------------- #
# Limits and validation
# --------------------------------------------------------------------------- #


def test_oversized_batch_is_413_and_nothing_ingested(make_client: ClientFactory) -> None:
    capped = make_client(ingest_max_batch=5)
    response = capped.post(
        "/api/v1/ingest/events",
        json=ingest_payload(port_scan(num_ports=6)),
        headers=auth_headers(),
    )
    assert response.status_code == 413
    assert alert_total(capped) == 0
    assert event_total(capped) == 0


def test_malformed_batch_is_422_and_nothing_partially_ingested(client: TestClient) -> None:
    events = ingest_payload(port_scan(num_ports=20))
    events["events"][3]["src_ip"] = "not-an-ip"  # type: ignore[index]
    response = client.post("/api/v1/ingest/events", json=events, headers=auth_headers())
    assert response.status_code == 422
    assert alert_total(client) == 0
    assert event_total(client) == 0  # stats untouched too


def test_oversized_and_malformed_batch_is_422_not_413(make_client: ClientFactory) -> None:
    """Documented precedence: schema validation runs before the batch cap."""
    capped = make_client(ingest_max_batch=5)
    events = ingest_payload(port_scan(num_ports=6))
    events["events"][0]["protocol"] = "CARRIER-PIGEON"  # type: ignore[index]
    response = capped.post("/api/v1/ingest/events", json=events, headers=auth_headers())
    assert response.status_code == 422


def test_empty_batch_is_422(client: TestClient) -> None:
    response = client.post("/api/v1/ingest/events", json={"events": []}, headers=auth_headers())
    assert response.status_code == 422


def test_unknown_body_fields_are_rejected(client: TestClient) -> None:
    payload = ingest_payload(port_scan(num_ports=5))
    payload["mystery"] = True
    response = client.post("/api/v1/ingest/events", json=payload, headers=auth_headers())
    assert response.status_code == 422


def test_declared_oversized_body_is_413_before_parsing(make_client: ClientFactory) -> None:
    """A truthful Content-Length over the cap is rejected without reading."""
    small_cap = make_client(ingest_max_body_bytes=512)
    response = small_cap.post(
        "/api/v1/ingest/events",
        json=ingest_payload(port_scan(num_ports=20)),  # well over 512 bytes
        headers=auth_headers(),
    )
    assert response.status_code == 413
    assert alert_total(small_cap) == 0


def test_chunked_oversized_body_is_413_via_byte_counting(make_client: ClientFactory) -> None:
    """No Content-Length at all: the authoritative byte counter must cap it."""
    small_cap = make_client(ingest_max_body_bytes=512)

    def chunks() -> Iterator[bytes]:
        yield b'{"events": ['
        yield b"x" * 2048  # never valid JSON; the cap must fire before parsing
        yield b"]}"

    response = small_cap.post(
        "/api/v1/ingest/events",
        content=chunks(),
        headers={**auth_headers(), "Content-Type": "application/json"},
    )
    assert response.status_code == 413


# --------------------------------------------------------------------------- #
# Live clock-skew rejection
# --------------------------------------------------------------------------- #


def _pinned_clock_client(make_client: ClientFactory) -> TestClient:
    pinned = make_client()
    pinned.app.state.wall_clock = lambda: WALL_NOW  # type: ignore[attr-defined]
    return pinned


def test_skewed_live_event_is_422(make_client: ClientFactory) -> None:
    pinned = _pinned_clock_client(make_client)
    skewed = make_event(
        ts=WALL_NOW + 400.0,  # beyond MAX_CLOCK_SKEW_S=300
        src_ip="10.0.0.50",
        dst_ip="10.0.0.10",
        source_type="live",
    )
    response = pinned.post(
        "/api/v1/ingest/events", json=ingest_payload([skewed]), headers=auth_headers()
    )
    assert response.status_code == 422
    assert event_total(pinned) == 0


def test_live_event_within_skew_is_accepted(make_client: ClientFactory) -> None:
    pinned = _pinned_clock_client(make_client)
    fresh = make_event(
        ts=WALL_NOW + 250.0,
        src_ip="10.0.0.50",
        dst_ip="10.0.0.10",
        source_type="live",
    )
    response = pinned.post(
        "/api/v1/ingest/events", json=ingest_payload([fresh]), headers=auth_headers()
    )
    assert response.status_code == 202
    assert event_total(pinned) == 1


def test_synthetic_and_replay_events_are_exempt_from_skew(make_client: ClientFactory) -> None:
    """Controlled logical timestamps (1970-era) must pass untouched."""
    pinned = _pinned_clock_client(make_client)
    ancient_synthetic = make_event(
        ts=1000.0, src_ip="10.0.0.50", dst_ip="10.0.0.10", source_type="synthetic"
    )
    ancient_replay = make_event(
        ts=1000.0, src_ip="10.0.0.50", dst_ip="10.0.0.10", source_type="replay"
    )
    response = pinned.post(
        "/api/v1/ingest/events",
        json=ingest_payload([ancient_synthetic, ancient_replay]),
        headers=auth_headers(),
    )
    assert response.status_code == 202


# --------------------------------------------------------------------------- #
# Post-commit publication boundary
# --------------------------------------------------------------------------- #


def test_publication_failure_after_commit_still_returns_202(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A committed ingest must never become a 500 because publication broke."""
    broadcaster = client.app.state.broadcaster  # type: ignore[attr-defined]

    async def explode(delta: AlertDelta) -> None:
        raise RuntimeError("simulated publication failure")

    monkeypatch.setattr(broadcaster, "publish", explode)
    response = client.post(
        "/api/v1/ingest/events",
        json=ingest_payload(port_scan(num_ports=20)),
        headers=auth_headers(),
    )
    assert response.status_code == 202
    assert response.json()["alerts_created"] == 1
    assert alert_total(client) == 1  # the row is durably there and queryable
    assert "publication failed" in caplog.text


def test_gate_cleanup_failure_after_commit_still_returns_202(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A committed ingest must never become a 500 because gate cleanup failed."""

    def explode(self: AlertEngine, source_type: SourceType, now: float) -> None:
        raise RuntimeError("simulated gate cleanup failure")

    monkeypatch.setattr(AlertEngine, "expire", explode)
    response = client.post(
        "/api/v1/ingest/events",
        json=ingest_payload(port_scan(num_ports=20)),
        headers=auth_headers(),
    )
    assert response.status_code == 202
    assert response.json() == {"accepted": 20, "alerts_created": 1, "alerts_updated": 0}
    assert alert_total(client) == 1  # committed and queryable despite the failure
    assert "gate sweep failed after a committed batch" in caplog.text


def _is_cancellation(exc: BaseException) -> bool:
    """True if ``exc`` is (or wraps) a cancellation, unwrapping exception groups."""
    if isinstance(exc, (asyncio.CancelledError, concurrent.futures.CancelledError)):
        return True
    if isinstance(exc, BaseExceptionGroup):
        return any(_is_cancellation(sub) for sub in exc.exceptions)
    return False


def test_cancellation_in_publication_is_never_suppressed(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The post-commit boundary catches Exception only — cancellation propagates.

    Swallowing CancelledError there would break task teardown; the request must
    NOT complete with a 202 (nor a 500) — the cancellation escapes, while the
    committed row remains queryable afterwards.
    """
    broadcaster = client.app.state.broadcaster  # type: ignore[attr-defined]

    async def cancel_out(delta: AlertDelta) -> None:
        raise asyncio.CancelledError

    monkeypatch.setattr(broadcaster, "publish", cancel_out)
    with pytest.raises(BaseException) as excinfo:
        client.post(
            "/api/v1/ingest/events",
            json=ingest_payload(port_scan(num_ports=20)),
            headers=auth_headers(),
        )
    assert _is_cancellation(excinfo.value), repr(excinfo.value)
    assert alert_total(client) == 1  # the commit itself stood


# --------------------------------------------------------------------------- #
# Accepted-count semantics
# --------------------------------------------------------------------------- #


def test_detector_dropped_too_late_event_still_counts_in_accepted_and_stats(
    client: TestClient,
) -> None:
    """`accepted` counts the whole validated batch, detector drops included.

    The trailing event's ts (900) is far older than the scan's high-water mark
    minus the widest detector window, so detection drops it as too-late — yet
    it was accepted into the pipeline and belongs in traffic statistics.
    """
    events = [
        *port_scan(num_ports=20),  # ts 1000.0 .. 1003.8
        make_event(ts=900.0, src_ip="10.0.0.60", dst_ip="10.0.0.10", source_type="synthetic"),
    ]
    response = client.post(
        "/api/v1/ingest/events", json=ingest_payload(events), headers=auth_headers()
    )
    assert response.status_code == 202
    body = response.json()
    assert body["accepted"] == 21  # all 21, including the dropped one
    assert body["alerts_created"] == 1
    assert event_total(client) == 21  # statistics count it too
    detection = client.app.state.pipeline._detection  # type: ignore[attr-defined]
    assert detection.dropped_late == 1  # and detection really did drop it
