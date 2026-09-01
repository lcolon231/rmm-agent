# SPDX-License-Identifier: AGPL-3.0-only
"""Request and response contracts for sessions and break-glass (issue #69)."""
from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints

Reason = Annotated[
    str, StringConstraints(min_length=3, max_length=500, strip_whitespace=True)
]
Label = Annotated[
    str, StringConstraints(min_length=3, max_length=120, strip_whitespace=True)
]


class SessionOut(BaseModel):
    """One session in an inventory listing.

    Deliberately excludes anything that could be replayed: no token, no `sid`
    beyond the opaque row id the owner already controls, and no credential.
    ``source_ip`` and ``user_agent`` are present because recognising an
    unfamiliar device is the entire point of an inventory.
    """

    model_config = ConfigDict(from_attributes=True)

    id: str
    created_at: datetime
    last_seen_at: datetime
    absolute_expires_at: datetime
    auth_methods: str
    source_ip: str | None
    user_agent: str | None
    is_break_glass: bool
    ended_at: datetime | None
    end_reason: str | None
    #: True for the session making this request, so a client can label it
    #: "this device" and warn before revoking it.
    is_current: bool = False


class SessionRevoke(BaseModel):
    reason: Reason


class SessionRevokeResult(BaseModel):
    revoked: int


class SessionRefreshOut(BaseModel):
    """A renewed access token for an existing session."""

    access_token: str
    token_type: str = "bearer"
    #: The unchanged hard ceiling, so a client can show when re-authentication
    #: will be required no matter how active the session stays.
    absolute_expires_at: datetime


# --------------------------------------------------------------------------- #
# Break-glass
# --------------------------------------------------------------------------- #
class BreakGlassCreate(BaseModel):
    label: Label
    reason: Reason


class BreakGlassRotate(BaseModel):
    reason: Reason


class BreakGlassDisable(BaseModel):
    disabled: bool
    reason: Reason


class BreakGlassAccountOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    label: str
    #: Non-authenticating digest, so two sealed envelopes can be told apart
    #: without opening either.
    credential_fingerprint: str
    created_at: datetime
    created_by_email: str | None
    rotated_at: datetime | None
    last_activated_at: datetime | None
    activation_count: int
    disabled_at: datetime | None
    disabled_reason: str | None


class BreakGlassCredentialOut(BaseModel):
    """The one and only time a credential exists outside the sealed envelope."""

    account: BreakGlassAccountOut
    credential: str


class BreakGlassActivateRequest(BaseModel):
    credential: Annotated[str, StringConstraints(min_length=8, max_length=200)]
    #: Mandatory. An emergency with no stated justification is the thing a
    #: reviewer most needs to notice.
    reason: Reason


class BreakGlassActivationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    account_id: str
    session_id: str | None
    activated_at: datetime
    source_ip: str | None
    user_agent: str | None
    reason: str
    reviewed_at: datetime | None
    reviewed_by_email: str | None
    review_note: str | None


class BreakGlassReview(BaseModel):
    note: Reason


class BreakGlassStatusOut(BaseModel):
    enabled: bool
    account_count: int
    #: Surfaced prominently: an unreviewed activation is an open incident.
    unreviewed_activations: int
