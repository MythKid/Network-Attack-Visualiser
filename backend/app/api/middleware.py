"""Pure-ASGI ingest guards: body-size cap and sensor authentication.

Both checks must run **before FastAPI reads or parses the request body**.
FastAPI reads and JSON-decodes the body *before* solving route dependencies,
so a dependency-based token check cannot guarantee the documented order: a
malformed JSON body would earn an unauthenticated caller a parse error instead
of a 401, leaking endpoint shape and breaking the token-before-schema contract.
``BaseHTTPMiddleware`` is equally unsuitable for the size cap — it buffers the
request body, which is exactly the buffering the cap exists to prevent.

Enforcement precedence (documented in ``docs/API.md`` §6 and asserted by
tests), applied only to POSTs on the ingest path:

1. Declared ``Content-Length`` above the cap → **413**, without reading a
   single body byte (a cheap fast path; absent or dishonest declarations fall
   through to the authoritative counter below).
2. No ``SENSOR_TOKEN`` configured → **503** — the endpoint fails closed.
3. Missing or incorrect ``X-Sensor-Token`` → **401**, compared in constant
   time over raw bytes (``hmac.compare_digest``).
4. The authenticated request proceeds: every received chunk is counted and the
   cap enforced mid-stream (chunked or lying requests included); JSON/schema
   validation then happens in the route layer.
"""

import hmac
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from pydantic import SecretStr
from starlette.exceptions import HTTPException as StarletteHTTPException

# Minimal structural ASGI types; avoids importing private starlette aliases.
Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

_413_DETAIL = "request body exceeds the configured maximum size"


class _BodyTooLarge(StarletteHTTPException):
    """Unwind signal: the counted body exceeded the cap mid-stream.

    Subclassing HTTPException matters: the overflow is raised from inside the
    app's own body read, and FastAPI re-raises HTTPExceptions untouched (any
    other exception there is flattened into a generic 400), so the exception
    middleware renders the honest 413. The fallback handler below covers the
    path where it propagates all the way out instead.
    """

    def __init__(self) -> None:
        super().__init__(status_code=413, detail=_413_DETAIL)


async def _send_json(send: Send, status: int, detail: str) -> None:
    body = f'{{"detail":"{detail}"}}'.encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": body})


def _header_value(scope: Scope, name: bytes) -> bytes | None:
    """The raw value of the first ``name`` header, or None if absent."""
    for header_name, value in scope.get("headers", ()):
        if header_name == name:
            return bytes(value)
    return None


def _declared_content_length(scope: Scope) -> int | None:
    """The Content-Length header as an int, or None if absent/malformed.

    A malformed or negative declaration is ignored here rather than rejected:
    the authoritative byte counter still caps the actual body.
    """
    raw = _header_value(scope, b"content-length")
    if raw is None:
        return None
    try:
        declared = int(raw)
    except ValueError:
        return None
    return declared if declared >= 0 else None


class IngestGuardMiddleware:
    """Size-caps and authenticates one POST path before the app touches it."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_body_bytes: int,
        path: str,
        sensor_token: SecretStr | None,
    ) -> None:
        if max_body_bytes < 1:
            raise ValueError("max_body_bytes must be at least 1")
        self._app = app
        self._max = max_body_bytes
        self._path = path
        self._sensor_token = sensor_token

    def _token_status(self, scope: Scope) -> int | None:
        """None when authenticated; otherwise the refusal status (503/401)."""
        if self._sensor_token is None:
            return 503  # fail closed: unauthenticatable, never open
        supplied = _header_value(scope, b"x-sensor-token")
        expected = self._sensor_token.get_secret_value().encode("utf-8")
        if supplied is None or not hmac.compare_digest(supplied, expected):
            return 401
        return None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Scoped narrowly: only POST to the ingest path. Reads, /health and the
        # WebSocket upgrade pass through untouched.
        if (
            scope["type"] != "http"
            or scope.get("method") != "POST"
            or scope.get("path") != self._path
        ):
            await self._app(scope, receive, send)
            return

        declared = _declared_content_length(scope)
        if declared is not None and declared > self._max:
            await _send_json(send, 413, _413_DETAIL)
            return

        token_status = self._token_status(scope)
        if token_status == 503:
            await _send_json(send, 503, "ingest is not configured on this server")
            return
        if token_status == 401:
            await _send_json(send, 401, "missing or invalid sensor token")
            return

        received = 0
        response_started = False

        async def counting_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self._max:
                    raise _BodyTooLarge
            return message

        async def counting_send(message: Message) -> None:
            nonlocal response_started
            response_started = True
            await send(message)

        try:
            await self._app(scope, counting_receive, counting_send)
        except _BodyTooLarge:
            # Only respond if nothing has been sent yet; sending after
            # http.response.start would be an ASGI protocol violation, so a
            # mid-response overflow tears the connection down instead.
            if not response_started:
                await _send_json(send, 413, _413_DETAIL)
