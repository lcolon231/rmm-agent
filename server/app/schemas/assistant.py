# SPDX-License-Identifier: AGPL-3.0-only
"""Strict assistant inputs. The selected client is never a model argument."""
from typing import Annotated, Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, StringConstraints


class StrictInput(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ConversationCreate(StrictInput):
    client_id: UUID


class RunCreate(StrictInput):
    request_id: UUID
    message: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=4000)]


class EndpointSearch(StrictInput):
    status: Literal["online", "offline", "pending"] | None
    search: Annotated[str, StringConstraints(max_length=100)] | None
    page: int = Field(ge=1, le=1000, strict=True)


class EndpointInput(StrictInput):
    endpoint_id: UUID


Section = Literal["system", "cpu", "memory", "storage", "network", "installed_software"]


class InventoryInput(EndpointInput):
    section: Section


class HistoryInput(InventoryInput):
    page: int = Field(ge=1, le=100, strict=True)


class ScopePage(StrictInput):
    page: int = Field(ge=1, le=1000, strict=True)


class AlertsInput(ScopePage):
    endpoint_id: UUID | None
