from __future__ import annotations

from datetime import datetime, timezone
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field


class IRISBaseModel(BaseModel):
    """Base schema with common serialization settings."""

    model_config = ConfigDict(
        populate_by_name=True,
        use_enum_values=True,
        extra="ignore",
        str_strip_whitespace=True,
    )


class TimestampedModel(IRISBaseModel):
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class InvestigationScopedModel(IRISBaseModel):
    investigation_id: str


class ErrorResponse(IRISBaseModel):
    detail: str
    code: str | None = None


T = TypeVar("T")


class PaginationMeta(IRISBaseModel):
    total: int
    limit: int
    offset: int


class PaginatedResponse(IRISBaseModel, Generic[T]):
    items: list[T]
    pagination: PaginationMeta