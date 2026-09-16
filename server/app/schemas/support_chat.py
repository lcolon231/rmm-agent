# SPDX-License-Identifier: AGPL-3.0-only
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class MessageIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    body: str = Field(min_length=1, max_length=8192)


class NoticeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    notice_version: str = Field(min_length=1, max_length=32)


class MessageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    seq: int
    sender: str
    body: str
    created_at: datetime
