"""Typed response models for the API layer."""

from typing import Literal

from pydantic import BaseModel


class HealthResponse(BaseModel):
    """Response body for ``GET /health``.

    ``status`` is a fixed literal so a healthy response is unambiguous, and
    ``version`` echoes the configured application version.
    """

    status: Literal["ok"]
    version: str
