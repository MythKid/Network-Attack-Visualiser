"""The live alert feed: ``WS /api/v1/ws/alerts``.

CORS middleware does not apply to WebSocket upgrades, so the handshake
``Origin`` is validated here against the same allowlist and refused **before**
``accept()`` (SEC_REQ §4.2). The channel carries deltas only — history comes
from REST — so connecting never replays anything.

The handler runs two concurrent tasks under an anyio task group:

- a **sender**, draining the subscription queue to the socket; and
- a **watcher**, whose only job is to observe the client disconnect — without
  it, an idle client that vanishes would leak its subscription forever,
  because no delta ever arrives to make a send fail.

Whichever task finishes first cancels the group's scope, which cancels the
sibling; the ``subscribe()`` context manager then unregisters the subscription
on every exit path. The group is anyio's (not ``asyncio.TaskGroup``) because
Starlette's request lifecycle is managed by anyio cancel scopes, and the two
cancellation systems must not be mixed — a stdlib task group here corrupts the
outer scope's cancellation bookkeeping. ``CancelledError`` is never caught.
"""

import contextlib
import logging
from collections.abc import Callable

import anyio
from fastapi import APIRouter, WebSocket
from starlette.websockets import WebSocketDisconnect

from app.alerts.broadcaster import AlertSubscription
from app.api.deps import get_broadcaster_ws, get_settings_ws

logger = logging.getLogger(__name__)

router = APIRouter(tags=["websocket"])

# 1008: policy violation (origin refused); 1013: try again later (overflow).
WS_POLICY_VIOLATION = 1008
WS_TRY_AGAIN_LATER = 1013

# Send-side errors that simply mean "the client is gone". They are the normal
# completion path for a disconnect race (client vanishes with a send or close
# in flight), not failures to surface.
_EXPECTED_DISCONNECT: tuple[type[Exception], ...] = (WebSocketDisconnect,)


async def _sender(
    websocket: WebSocket, subscription: AlertSubscription, finished: Callable[[], None]
) -> None:
    """Drain deltas to the client; on overflow, close 1013 for a REST re-sync."""
    try:
        while True:
            payload = await subscription.next_or_overflow()
            if payload is None:
                # Suppress double-close/late-close races: the socket may already
                # be closing underneath us, which is the outcome we want anyway.
                with contextlib.suppress(RuntimeError, *_EXPECTED_DISCONNECT):
                    await websocket.close(code=WS_TRY_AGAIN_LATER)
                return
            try:
                await websocket.send_text(payload)
            except _EXPECTED_DISCONNECT:
                return
    finally:
        finished()  # ends the group: the watcher is cancelled


async def _watcher(websocket: WebSocket, finished: Callable[[], None]) -> None:
    """Observe the client: finish on disconnect, ignore anything it sends."""
    try:
        while True:
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                return
            # The channel is server->client only; a stray client frame (e.g. an
            # application-level keepalive) must not cost a dashboard its feed.
            logger.debug("ignoring unexpected client WebSocket message: %s", message["type"])
    finally:
        finished()  # ends the group: the sender is cancelled


@router.websocket("/api/v1/ws/alerts")
async def alerts_websocket(websocket: WebSocket) -> None:
    """Stream ``alert.created`` / ``alert.updated`` envelopes to one dashboard."""
    settings = get_settings_ws(websocket)
    origin = websocket.headers.get("origin")
    if origin is None or origin not in settings.cors_allow_origins:
        # Refused before accept(): the upgrade fails (HTTP 403 on the wire).
        await websocket.close(code=WS_POLICY_VIOLATION)
        return

    await websocket.accept()
    broadcaster = get_broadcaster_ws(websocket)
    async with broadcaster.subscribe() as subscription, anyio.create_task_group() as task_group:
        finished = task_group.cancel_scope.cancel
        task_group.start_soon(_sender, websocket, subscription, finished)
        task_group.start_soon(_watcher, websocket, finished)
