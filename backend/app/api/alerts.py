"""Alert read endpoints: ``GET /api/v1/alerts`` and ``GET /api/v1/alerts/{id}``.

Both handlers are deliberately synchronous ``def`` routes: FastAPI runs them on
its worker threadpool, so the blocking sqlite3 work inside never executes on
the event loop (the Phase 3 threadpool policy — see ``docs/API.md``).

Ordering is **recording order** (newest first), not event time: ``created_at``
is logical event time, and synthetic/replay/live timelines are not comparable,
so recording order is the only honest merged feed. Filter by ``source_type``
for one coherent event-time series.
"""

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import UUID4

from app.api.deps import get_alert_repository
from app.api.schemas import AlertListResponse
from app.models.alert import Alert
from app.models.enums import Category, Severity, SourceType
from app.storage.alerts import AlertRepository

router = APIRouter(prefix="/api/v1", tags=["alerts"])

# The V1 detectors; an unknown detector_id filter is a 422, not an empty page.
DetectorId = Literal["portscan", "synflood"]


@router.get(
    "/alerts",
    response_model=AlertListResponse,
    summary="List alerts (filterable, paginated, newest-recorded first)",
)
def list_alerts(
    repository: Annotated[AlertRepository, Depends(get_alert_repository)],
    severity: Annotated[Severity | None, Query()] = None,
    detector_id: Annotated[DetectorId | None, Query()] = None,
    source_type: Annotated[SourceType | None, Query()] = None,
    category: Annotated[Category | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AlertListResponse:
    """One page of alerts plus the total matching the same filters."""
    items, total = repository.list(
        severity=severity,
        detector_id=detector_id,
        source_type=source_type,
        category=category,
        limit=limit,
        offset=offset,
    )
    return AlertListResponse(items=items, total=total, limit=limit, offset=offset)


@router.get(
    "/alerts/{alert_id}",
    response_model=Alert,
    summary="Fetch one alert by id",
)
def get_alert(
    alert_id: UUID4,
    repository: Annotated[AlertRepository, Depends(get_alert_repository)],
) -> Alert:
    """The full alert record, or 404 if it does not exist (e.g. pruned)."""
    alert = repository.get(str(alert_id))
    if alert is None:
        raise HTTPException(status_code=404, detail="alert not found")
    return alert
