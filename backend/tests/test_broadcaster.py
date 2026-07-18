"""Broadcaster and subscription tests (fan-out, overflow priority, cleanup).

Async behaviour is exercised via ``asyncio.run`` inside synchronous tests, so
no async pytest plugin is required and every coroutine is fully awaited.
"""

import asyncio
import json

from app.alerts.broadcaster import AlertBroadcaster, AlertSubscription
from app.alerts.engine import AlertDelta
from tests.factories import make_alert

WAIT_S = 5.0


def _delta(**kwargs: object) -> AlertDelta:
    return AlertDelta(type="alert.created", alert=make_alert(**kwargs))  # type: ignore[arg-type]


def test_publish_fans_out_to_every_subscriber() -> None:
    async def scenario() -> None:
        broadcaster = AlertBroadcaster(max_queue=4)
        async with broadcaster.subscribe() as first, broadcaster.subscribe() as second:
            assert broadcaster.subscriber_count == 2
            await broadcaster.publish(_delta())
            payload_one = await asyncio.wait_for(first.next_or_overflow(), timeout=WAIT_S)
            payload_two = await asyncio.wait_for(second.next_or_overflow(), timeout=WAIT_S)
            assert payload_one == payload_two
            assert payload_one is not None
            envelope = json.loads(payload_one)
            assert envelope["type"] == "alert.created"
            assert envelope["alert"]["occurrence_count"] == 1
        assert broadcaster.subscriber_count == 0

    asyncio.run(scenario())


def test_unsubscribed_client_stops_receiving() -> None:
    async def scenario() -> None:
        broadcaster = AlertBroadcaster(max_queue=4)
        async with broadcaster.subscribe() as kept:
            async with broadcaster.subscribe():
                assert broadcaster.subscriber_count == 2
            assert broadcaster.subscriber_count == 1
            await broadcaster.publish(_delta())
            assert await asyncio.wait_for(kept.next_or_overflow(), timeout=WAIT_S) is not None

    asyncio.run(scenario())


def test_no_history_on_subscribe() -> None:
    """A new subscriber receives only deltas published after it joined."""

    async def scenario() -> None:
        broadcaster = AlertBroadcaster(max_queue=4)
        await broadcaster.publish(_delta())  # published to nobody
        async with broadcaster.subscribe() as subscription:
            await broadcaster.publish(_delta(occurrence_count=2))
            payload = await asyncio.wait_for(subscription.next_or_overflow(), timeout=WAIT_S)
            assert payload is not None
            assert json.loads(payload)["alert"]["occurrence_count"] == 2
            assert subscription._queue.empty()

    asyncio.run(scenario())


def test_overflow_condemns_only_the_slow_subscriber() -> None:
    async def scenario() -> None:
        broadcaster = AlertBroadcaster(max_queue=1)
        async with broadcaster.subscribe() as slow, broadcaster.subscribe() as fast:
            await broadcaster.publish(_delta())
            # The fast consumer drains; the slow one leaves its queue full.
            assert await asyncio.wait_for(fast.next_or_overflow(), timeout=WAIT_S) is not None
            await broadcaster.publish(_delta())  # overflows `slow` (queue already full)
            assert await asyncio.wait_for(fast.next_or_overflow(), timeout=WAIT_S) is not None
            assert await asyncio.wait_for(slow.next_or_overflow(), timeout=WAIT_S) is None

    asyncio.run(scenario())


def test_overflow_takes_priority_over_a_queued_payload() -> None:
    """With a payload AND the overflow signal both ready, overflow must win.

    Sending further deltas to a subscriber known to have an incomplete stream
    would present a silently wrong feed; close-and-resync is the honest path.
    """

    async def scenario() -> None:
        subscription = AlertSubscription(max_queue=1)
        subscription.offer("first")  # fills the queue
        subscription.offer("second")  # overflows: signal set, payload still queued
        result = await asyncio.wait_for(subscription.next_or_overflow(), timeout=WAIT_S)
        assert result is None  # the queued 'first' is deliberately not delivered

    asyncio.run(scenario())


def test_parked_consumer_observes_an_overflow_burst() -> None:
    """A consumer parked on an empty queue must still see overflow.

    Overflow can only be set when a put finds the queue FULL, so a burst that
    overflows while the consumer is parked necessarily queued a payload first;
    the wake-up then yields None (overflow priority), never a partial stream.
    """

    async def scenario() -> None:
        subscription = AlertSubscription(max_queue=1)
        parked = asyncio.create_task(subscription.next_or_overflow())
        await asyncio.sleep(0)  # let the consumer park on the empty queue
        subscription.offer("first")  # wakes the getter and fills the queue
        subscription.offer("second")  # overflows before the consumer runs
        assert await asyncio.wait_for(parked, timeout=WAIT_S) is None

    asyncio.run(scenario())


def test_parked_consumer_receives_a_normal_offer() -> None:
    async def scenario() -> None:
        subscription = AlertSubscription(max_queue=4)
        parked = asyncio.create_task(subscription.next_or_overflow())
        await asyncio.sleep(0)
        subscription.offer("only")
        assert await asyncio.wait_for(parked, timeout=WAIT_S) == "only"

    asyncio.run(scenario())


def test_offers_after_overflow_are_dropped() -> None:
    async def scenario() -> None:
        subscription = AlertSubscription(max_queue=1)
        subscription.offer("a")
        subscription.offer("b")  # overflow
        subscription.offer("c")  # dropped outright
        assert subscription._queue.qsize() == 1

    asyncio.run(scenario())
