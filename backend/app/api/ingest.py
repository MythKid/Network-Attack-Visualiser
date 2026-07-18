"""The authenticated ingest endpoint: ``POST /api/v1/ingest/events``.

Enforcement order (deviation from the SEC_REQ §5.1 listing order is documented
in ``docs/API.md``): body-size cap (ASGI middleware, before parsing) → sensor
token → schema validation → batch cap → live clock-skew check. All of it runs
before any event reaches a detector.

Retry contract (``docs/API.md``): ingest is **non-idempotent and retry-unsafe**.
A 500 means the batch rolled back but detector state already consumed the
events; a timeout may hide a successful commit. Sensors must not blindly retry
either. Conversely, once the batch transaction commits, **no publication-layer
failure may turn the ingest into a 500** — that would instruct the sensor to
retry a committed batch and double-count statistics — so post-commit failures
are logged and the committed success response is returned; REST remains
authoritative and ``asyncio.CancelledError`` always propagates.
"""

import asyncio
import hmac
import logging
from collections.abc import Callable, Sequence
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from app.api.deps import get_broadcaster, get_pipeline
from app.api.health import get_app_settings
from app.api.schemas import IngestRequest, IngestResponse
from app.models.packet_event import PacketEvent

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["ingest"])


async def require_sensor_token(
    request: Request,
    x_sensor_token: Annotated[str | None, Header()] = None,
) -> None:
    """Authenticate the sensor, failing closed when no token is configured.

    **Defence in depth.** The authoritative check is
    :class:`~app.api.middleware.IngestGuardMiddleware`, which enforces the token
    *before FastAPI reads or parses the body* (FastAPI decodes the body before
    solving dependencies, so this dependency alone could not guarantee the
    documented token-before-schema order). This dependency is retained so the
    route stays fail-closed even if the middleware were ever mis-wired.

    No configured token means ingest cannot be authenticated at all → 503 (the
    endpoint is unavailable, never open). The comparison is constant-time over
    UTF-8 bytes (``hmac.compare_digest`` on ``str`` demands ASCII), so a timing
    side-channel cannot leak the secret.
    """
    settings = get_app_settings(request)
    if settings.sensor_token is None:
        raise HTTPException(status_code=503, detail="ingest is not configured on this server")
    if x_sensor_token is None or not hmac.compare_digest(
        x_sensor_token.encode("utf-8"),
        settings.sensor_token.get_secret_value().encode("utf-8"),
    ):
        raise HTTPException(status_code=401, detail="missing or invalid sensor token")


def reject_skewed_live_events(
    events: Sequence[PacketEvent], *, now: float, max_skew_s: float
) -> None:
    """Reject live events whose timestamps are unreasonable against wall time.

    Only ``source_type == "live"`` is checked: synthetic and replay events carry
    deliberately controlled logical timestamps and are exempt (SEC_REQ §5.1).
    Non-finite timestamps cannot reach here — the ``PacketEvent`` schema already
    rejects them.
    """
    for event in events:
        if event.source_type == "live" and abs(event.ts - now) > max_skew_s:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"live event {event.event_id} timestamp is skewed more than "
                    f"{max_skew_s} seconds from server time"
                ),
            )


@router.post(
    "/ingest/events",
    status_code=202,
    response_model=IngestResponse,
    dependencies=[Depends(require_sensor_token)],
    summary="Ingest one batch of packet events (sensor-authenticated)",
)
async def ingest_events(request: Request, payload: IngestRequest) -> IngestResponse:
    """Run one batch through the pipeline and broadcast the surviving deltas."""
    settings = get_app_settings(request)
    events = payload.events
    if len(events) > settings.ingest_max_batch:
        raise HTTPException(
            status_code=413,
            detail=f"batch exceeds INGEST_MAX_BATCH ({settings.ingest_max_batch} events)",
        )
    wall_clock: Callable[[], float] = request.app.state.wall_clock
    reject_skewed_live_events(events, now=wall_clock(), max_skew_s=settings.max_clock_skew_s)

    pipeline = get_pipeline(request)
    deltas = await run_in_threadpool(pipeline.process_batch, events)

    # ---------------- COMMIT BOUNDARY ----------------
    # The batch is durably committed. The response is computed before any
    # publication so it stays correct even if publication fails entirely.
    response = IngestResponse(
        accepted=len(events),
        alerts_created=sum(1 for delta in deltas if delta.type == "alert.created"),
        alerts_updated=sum(1 for delta in deltas if delta.type == "alert.updated"),
    )
    broadcaster = get_broadcaster(request)
    try:
        for delta in deltas:
            await broadcaster.publish(delta)
    except asyncio.CancelledError:
        raise  # cancellation is not a publication failure; never suppressed
    except Exception:
        logger.exception("post-commit publication failed; the ingest itself succeeded")
    return response
