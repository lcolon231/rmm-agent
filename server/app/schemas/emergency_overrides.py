# SPDX-License-Identifier: AGPL-3.0-only
"""Justified emergency override contracts (issue #65).

Same discipline as ``app/schemas/approvals.py``: ``extra="forbid"``, bounded
strings, and a **mandatory justification** with a higher floor than an
approval reason. The override is the one place where a single person's word
replaces a second reviewer, so the word has to be a sentence.
"""
from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from app.core.emergency_overrides import (
    MAX_JUSTIFICATION_BYTES,
    MAX_TTL_SECONDS,
    MIN_JUSTIFICATION_BYTES,
    MIN_TTL_SECONDS,
)
from app.models.models import CommandKind, EmergencyOverrideStatus


def _validate_prose(value: str, *, minimum: int, maximum: int, label: str) -> str:
    """Bounded, printable prose; refused rather than rewritten.

    Control characters are rejected instead of stripped because the text is
    shown to reviewers and digested into the audit chain, and silently editing
    it would make the stored digest disagree with what was typed.
    """
    text = value.strip()
    size = len(text.encode("utf-8"))
    if not minimum <= size <= maximum:
        raise ValueError(f"{label} must contain {minimum}-{maximum} UTF-8 bytes")
    if any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise ValueError(f"{label} must be printable")
    return text


def _validate_justification(value: str) -> str:
    return _validate_prose(
        value,
        minimum=MIN_JUSTIFICATION_BYTES,
        maximum=MAX_JUSTIFICATION_BYTES,
        label="justification",
    )


def _validate_note(value: str) -> str:
    # Review notes and revoke reasons share the approval-reason bounds: a
    # sign-off needs a basis, but not an essay.
    return _validate_prose(value, minimum=10, maximum=MAX_JUSTIFICATION_BYTES, label="note")


class EmergencyOverrideActivate(BaseModel):
    """The exact command the activator takes sole responsibility for.

    ``payload`` is validated by the dispatch rules in the handler, so an
    override can never be minted for a payload the dispatcher would refuse.
    """

    model_config = ConfigDict(extra="forbid")

    agent_id: Annotated[str, StringConstraints(min_length=1, max_length=36)]
    kind: CommandKind
    payload: dict = Field(default_factory=dict)
    justification: str
    ttl_seconds: int | None = Field(default=None, ge=MIN_TTL_SECONDS, le=MAX_TTL_SECONDS)

    _justification = field_validator("justification")(_validate_justification)


class EmergencyOverrideRevoke(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str

    _reason = field_validator("reason")(_validate_note)


class EmergencyOverrideReview(BaseModel):
    model_config = ConfigDict(extra="forbid")

    note: str

    _note = field_validator("note")(_validate_note)


class EmergencyOverrideOut(BaseModel):
    """List view. Carries the binding digest and the review state, not the payload."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    agent_id: str
    client_id: str | None
    site_id: str | None
    kind: CommandKind
    status: EmergencyOverrideStatus
    payload_sha256: str
    policy_id: str | None
    required_approvals: int
    activated_by_email: str
    activated_by_operator_id: str | None
    justification: str
    created_at: datetime
    expires_at: datetime
    consumed_at: datetime | None
    revoked_at: datetime | None
    revoked_by_email: str | None
    notified_at: datetime | None
    notification_error: str | None
    notified_recipient_count: int
    reviewed_at: datetime | None
    reviewed_by_email: str | None


class EmergencyOverrideDetail(EmergencyOverrideOut):
    payload: dict
    payload_keys: list[str]
    revoke_reason: str | None
    review_note: str | None
    consumed_command_id: str | None
