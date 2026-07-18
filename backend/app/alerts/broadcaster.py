"""Live alert-delta broadcasting to WebSocket subscribers.

The channel carries deltas only (``docs/ALERT_SCHEMA.md`` §5): history comes
from REST, so no subscriber ever receives a replay on connect. Delivery is
best-effort by design — REST remains authoritative — and each subscriber has a
bounded queue: a consumer that falls behind is closed (code 1013) to re-sync
via REST rather than silently skipping deltas, because a skipped delta would
desynchronise the client's ``alert_id``-keyed view with no way to notice.

Everything here runs on the event loop. ``publish`` is awaited from routes;
the (worker-thread) pipeline never publishes — it returns deltas. A future
thread-side publisher would need ``loop.call_soon_threadsafe``.
"""

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from app.alerts.engine import AlertDelta

logger = logging.getLogger(__name__)


class AlertSubscription:
    """One dashboard's delta stream: a bounded queue plus an overflow flag.

    The overflow flag is a side channel, not a queued sentinel: overflow is
    precisely the state in which the queue can accept nothing more, so a
    sentinel would need the very capacity that is exhausted.

    A parked consumer can never miss the flag, by invariant: overflow is only
    ever set when a put finds the queue **full**, and a consumer parked in
    ``get()`` implies the queue is **empty** — so the first offer wakes it long
    before overflow is possible, and once overflow is set the consumer is
    returned ``None`` on its very next call and never parks again. This keeps
    :meth:`next_or_overflow` a single plain ``await`` with no racer tasks,
    which is exactly what makes it clean under ``TaskGroup`` cancellation.
    """

    def __init__(self, max_queue: int) -> None:
        self._queue: asyncio.Queue[str] = asyncio.Queue(maxsize=max_queue)
        self._overflow = asyncio.Event()

    def offer(self, payload: str) -> None:
        """Enqueue a payload without blocking; mark overflow when full."""
        if self._overflow.is_set():
            return  # already condemned; delivering more would only reorder the close
        try:
            self._queue.put_nowait(payload)
        except asyncio.QueueFull:
            self._overflow.set()

    async def next_or_overflow(self) -> str | None:
        """Return the next payload, or ``None`` once this subscriber overflowed.

        Overflow wins ties: if a payload is queued and the overflow flag is
        set, the subscriber is closed for a REST re-sync rather than being fed
        further deltas from a stream already known to be incomplete.
        """
        if self._overflow.is_set():
            return None
        payload = await self._queue.get()
        if self._overflow.is_set():
            return None  # overflow raced in while this payload was retrieved
        return payload


class AlertBroadcaster:
    """Fans committed alert deltas out to all live subscriptions."""

    def __init__(self, *, max_queue: int = 100) -> None:
        if max_queue < 1:
            raise ValueError("max_queue must be at least 1")
        self._max_queue = max_queue
        self._subscriptions: set[AlertSubscription] = set()

    @asynccontextmanager
    async def subscribe(self) -> AsyncIterator[AlertSubscription]:
        """Register a subscription; ALWAYS unregister it on exit, however that happens."""
        subscription = AlertSubscription(self._max_queue)
        self._subscriptions.add(subscription)
        try:
            yield subscription
        finally:
            self._subscriptions.discard(subscription)

    async def publish(self, delta: AlertDelta) -> None:
        """Offer one committed delta to every subscriber (never blocks on a slow one).

        The envelope is serialised once and shared. Per-subscriber failures are
        isolated and logged so one broken subscriber cannot starve the rest;
        ``asyncio.CancelledError`` is never caught here.
        """
        envelope = {"type": delta.type, "alert": delta.alert.model_dump(mode="json")}
        payload = json.dumps(envelope, allow_nan=False, separators=(",", ":"))
        for subscription in tuple(self._subscriptions):
            try:
                subscription.offer(payload)
            except Exception:
                logger.exception("failed to offer an alert delta to a subscriber")

    @property
    def subscriber_count(self) -> int:
        """Number of currently registered subscriptions."""
        return len(self._subscriptions)
