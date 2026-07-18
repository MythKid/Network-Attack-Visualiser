"""``WS /api/v1/ws/alerts`` behaviour through the in-process TestClient.

The TestClient fakes the WebSocket transport, so protocol-level reality (a real
upgrade over a real socket) is covered separately by ``test_ws_live_server.py``;
these tests cover the application behaviour: origin policy, delta delivery,
no-history, stray messages and subscription cleanup — plus handler-task
contracts (overflow close code, disconnect races, cancellation) exercised
against a recording fake socket, because a live sender drains its queue too
fast for overflow to be forced deterministically end to end.
"""

import asyncio
import time
from typing import Any, cast

import pytest
from fastapi import WebSocket
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.alerts.broadcaster import AlertSubscription
from app.api.ws import _sender, _watcher
from app.ingest.synthetic import port_scan
from tests.factories import auth_headers, ingest_payload

WS_PATH = "/api/v1/ws/alerts"
ALLOWED_ORIGIN = "http://localhost:5173"
CLEANUP_DEADLINE_S = 5.0


def ingest_scan(
    client: TestClient, *, start_ts: float = 1000.0, client_ip: str = "10.0.0.50"
) -> None:
    response = client.post(
        "/api/v1/ingest/events",
        json=ingest_payload(port_scan(start_ts=start_ts, client=client_ip, num_ports=20)),
        headers=auth_headers(),
    )
    assert response.status_code == 202


def subscriber_count(client: TestClient) -> int:
    return int(client.app.state.broadcaster.subscriber_count)  # type: ignore[attr-defined]


def wait_for_subscribers(client: TestClient, expected: int) -> None:
    """Poll (with a hard deadline) for the handler's async cleanup to land."""
    deadline = time.monotonic() + CLEANUP_DEADLINE_S
    while time.monotonic() < deadline:
        if subscriber_count(client) == expected:
            return
        time.sleep(0.01)
    raise AssertionError(
        f"subscriber_count never reached {expected} (still {subscriber_count(client)})"
    )


def test_new_alert_is_pushed_as_created(client: TestClient) -> None:
    with client.websocket_connect(WS_PATH, headers={"Origin": ALLOWED_ORIGIN}) as websocket:
        ingest_scan(client)
        envelope = websocket.receive_json()
        assert envelope["type"] == "alert.created"
        assert envelope["alert"]["detector_id"] == "portscan"
        assert envelope["alert"]["occurrence_count"] == 1


def test_reinforcement_is_pushed_as_updated(client: TestClient) -> None:
    with client.websocket_connect(WS_PATH, headers={"Origin": ALLOWED_ORIGIN}) as websocket:
        ingest_scan(client, start_ts=1000.0)
        assert websocket.receive_json()["type"] == "alert.created"
        # Re-armed second burst inside the 60s cooldown -> update, same row.
        ingest_scan(client, start_ts=1014.0)
        envelope = websocket.receive_json()
        assert envelope["type"] == "alert.updated"
        assert envelope["alert"]["occurrence_count"] == 2


def test_connect_replays_no_history(client: TestClient) -> None:
    """A fresh socket sees only deltas published after it connected."""
    ingest_scan(client, client_ip="10.0.0.50")  # before anyone is connected
    with client.websocket_connect(WS_PATH, headers={"Origin": ALLOWED_ORIGIN}) as websocket:
        ingest_scan(client, client_ip="10.0.0.51")  # a different dedup key
        first_message = websocket.receive_json()
        assert first_message["type"] == "alert.created"
        assert first_message["alert"]["src_ip"] == "10.0.0.51"  # the NEW alert, not history


def test_disallowed_origin_is_refused_before_accept(client: TestClient) -> None:
    with (
        pytest.raises(WebSocketDisconnect) as excinfo,
        client.websocket_connect(WS_PATH, headers={"Origin": "http://evil.example"}),
    ):
        pass  # pragma: no cover - the upgrade never completes
    assert excinfo.value.code == 1008


def test_missing_origin_is_refused_before_accept(client: TestClient) -> None:
    with pytest.raises(WebSocketDisconnect) as excinfo, client.websocket_connect(WS_PATH):
        pass  # pragma: no cover - the upgrade never completes
    assert excinfo.value.code == 1008


def test_reconnect_works(client: TestClient) -> None:
    with client.websocket_connect(WS_PATH, headers={"Origin": ALLOWED_ORIGIN}) as websocket:
        ingest_scan(client, client_ip="10.0.0.50")
        assert websocket.receive_json()["type"] == "alert.created"
    with client.websocket_connect(WS_PATH, headers={"Origin": ALLOWED_ORIGIN}) as websocket:
        ingest_scan(client, client_ip="10.0.0.51")
        assert websocket.receive_json()["type"] == "alert.created"


def test_stray_client_message_does_not_close_the_socket(client: TestClient) -> None:
    with client.websocket_connect(WS_PATH, headers={"Origin": ALLOWED_ORIGIN}) as websocket:
        websocket.send_text("client-side keepalive")  # ignored, never fatal
        ingest_scan(client)
        assert websocket.receive_json()["type"] == "alert.created"


def test_idle_disconnect_unregisters_the_subscription(client: TestClient) -> None:
    """The watcher task must observe a silent client's departure.

    No alert is published at any point, so a send failure can never be the
    detection mechanism — only the disconnect watcher can free the entry.
    """
    with client.websocket_connect(WS_PATH, headers={"Origin": ALLOWED_ORIGIN}):
        wait_for_subscribers(client, 1)
    wait_for_subscribers(client, 0)  # freed without any publish having happened


# --------------------------------------------------------------------------- #
# Handler-task contracts (sender/watcher against a recording fake socket)
# --------------------------------------------------------------------------- #

WAIT_S = 5.0


class FakeWebSocket:
    """Records sends/closes; optionally raises on send; replays receive messages."""

    def __init__(
        self,
        *,
        send_error: Exception | None = None,
        messages: list[dict[str, Any]] | None = None,
    ) -> None:
        self.sent: list[str] = []
        self.closed_with: int | None = None
        self._send_error = send_error
        self._messages = list(messages or [])

    async def send_text(self, payload: str) -> None:
        if self._send_error is not None:
            raise self._send_error
        self.sent.append(payload)

    async def close(self, code: int = 1000, reason: str | None = None) -> None:
        self.closed_with = code

    async def receive(self) -> dict[str, Any]:
        return self._messages.pop(0)


def test_sender_closes_1013_at_the_websocket_layer_on_overflow() -> None:
    """Overflow must produce an actual close(code=1013) on the socket.

    (That next_or_overflow() returns None is necessary but not sufficient —
    this asserts the sender converts it into the documented close code.)
    """

    async def scenario() -> None:
        subscription = AlertSubscription(max_queue=1)
        subscription.offer("first")
        subscription.offer("second")  # overflows the size-1 queue
        fake = FakeWebSocket()
        group_ended: list[bool] = []
        await _sender(cast(WebSocket, fake), subscription, lambda: group_ended.append(True))
        assert fake.closed_with == 1013
        assert fake.sent == []  # overflow priority: no stale delta was sent first
        assert group_ended == [True]  # the group's cancel ran -> watcher would stop

    asyncio.run(scenario())


def test_sender_treats_disconnect_race_on_send_as_normal_completion() -> None:
    """A client vanishing mid-send is the normal end of the stream.

    The sender must return (ending the task group cleanly via its finished
    callback), not raise — a raise here would surface as an unhandled
    task-group error for an entirely ordinary disconnect race.
    """

    async def scenario() -> None:
        subscription = AlertSubscription(max_queue=4)
        subscription.offer("payload")
        fake = FakeWebSocket(send_error=WebSocketDisconnect(code=1001))
        group_ended: list[bool] = []
        await _sender(cast(WebSocket, fake), subscription, lambda: group_ended.append(True))
        assert fake.closed_with is None  # no bogus close after the client left
        assert group_ended == [True]

    asyncio.run(scenario())


def test_sender_never_suppresses_cancellation() -> None:
    """Cancelling the sender (as the task group does) must propagate cleanly."""

    async def scenario() -> None:
        subscription = AlertSubscription(max_queue=4)
        fake = FakeWebSocket()
        group_ended: list[bool] = []
        task = asyncio.create_task(
            _sender(cast(WebSocket, fake), subscription, lambda: group_ended.append(True))
        )
        await asyncio.sleep(0)  # let the sender park on the empty queue
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=WAIT_S)
        assert group_ended == [True]  # cleanup ran, yet cancellation still escaped
        assert fake.closed_with is None

    asyncio.run(scenario())


def test_watcher_ignores_stray_frames_then_finishes_on_disconnect() -> None:
    async def scenario() -> None:
        fake = FakeWebSocket(
            messages=[
                {"type": "websocket.receive", "text": "keepalive"},  # ignored
                {"type": "websocket.disconnect", "code": 1000},  # normal end
            ]
        )
        group_ended: list[bool] = []
        await _watcher(cast(WebSocket, fake), lambda: group_ended.append(True))
        assert group_ended == [True]

    asyncio.run(scenario())
