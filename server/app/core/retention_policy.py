# SPDX-License-Identifier: AGPL-3.0-only
"""Tenant-specific retention policy: inheritance, platform bounds, versioning (#88).

A tenant's effective retention for each category is resolved in three steps:

1. the tenant override, if the tenant has set one (``tenant``), otherwise
2. the platform default from :class:`Settings` (``default``), then
3. clamped into the platform floor/ceiling at *enforcement* time (``floor`` /
   ``ceiling``), so a floor raised after an override was saved still wins.

``0`` means "keep forever" (the category is not pruned). It counts as the
longest possible retention, so it always satisfies a floor and only satisfies
a ceiling of ``0`` (no ceiling). Ceilings bound tenant overrides only; the
platform default is the operator's own choice and is checked against the floor.

The evidence category is different in kind: it is the default ``retention_days``
for *new* vault records and reuses the evidence vault's own floor/ceiling. It is
never retroactive -- an immutable object's retain-until cannot be shortened.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.core import audit
from app.core.config import Settings, settings
from app.models.models import TenantRetentionPolicy


@dataclass(frozen=True)
class Category:
    name: str  # also the TenantRetentionPolicy column and API field
    unit: str  # "days" | "count"
    default_attr: str
    min_attr: str
    max_attr: str
    allow_forever: bool = True


CATEGORIES: tuple[Category, ...] = (
    Category("telemetry_days", "days", "telemetry_retention_days",
             "retention_min_telemetry_days", "retention_max_telemetry_days"),
    Category("command_output_days", "days", "command_output_retention_days",
             "retention_min_command_output_days", "retention_max_command_output_days"),
    Category("command_record_days", "days", "command_record_retention_days",
             "retention_min_command_record_days", "retention_max_command_record_days"),
    Category("inventory_history_per_section", "count", "inventory_history_per_section",
             "retention_min_inventory_history_per_section",
             "retention_max_inventory_history_per_section"),
    Category("alert_days", "days", "alert_retention_days",
             "retention_min_alert_days", "retention_max_alert_days"),
    Category("notification_days", "days", "notification_retention_days",
             "retention_min_notification_days", "retention_max_notification_days"),
    Category("evidence_default_days", "days", "evidence_vault_retention_days",
             "evidence_vault_retention_days", "evidence_vault_max_retention_days",
             allow_forever=False),
)
CATEGORY_NAMES: tuple[str, ...] = tuple(c.name for c in CATEGORIES)


class RetentionPolicyError(Exception):
    def __init__(self, code: str, status_code: int, category: str | None = None):
        super().__init__(code)
        self.code = code
        self.status_code = status_code
        self.category = category


class RetentionConfigurationError(RuntimeError):
    """Platform retention settings are contradictory; the server must not start."""


def _bounds(category: Category, s: Settings) -> tuple[int, int]:
    floor = max(1, getattr(s, category.min_attr))
    ceiling = getattr(s, category.max_attr)
    return floor, ceiling


def validate_settings(s: Settings = settings) -> None:
    """Fail closed at startup on contradictory platform bounds."""
    for category in CATEGORIES:
        floor, ceiling = _bounds(category, s)
        default = getattr(s, category.default_attr)
        if ceiling and ceiling < floor:
            raise RetentionConfigurationError(
                f"{category.max_attr} ({ceiling}) is below {category.min_attr} ({floor})"
            )
        if default > 0 and default < floor:
            raise RetentionConfigurationError(
                f"{category.default_attr} ({default}) is below {category.min_attr} ({floor})"
            )


def _longer_than(value: int, other: int) -> bool:
    """``value`` retains strictly longer than ``other`` (0 is forever)."""
    if value == 0:
        return other != 0
    return other != 0 and value > other


def clamp(category: Category, value: int, s: Settings = settings) -> tuple[int, str | None]:
    """Clamp ``value`` into the platform bounds. Returns (value, clamp source)."""
    floor, ceiling = _bounds(category, s)
    if value != 0 and value < floor:
        return floor, "floor"
    if ceiling and _longer_than(value, ceiling):
        return ceiling, "ceiling"
    return value, None


@dataclass(frozen=True)
class EffectiveValue:
    value: int
    source: str  # default | tenant | floor | ceiling
    override: int | None
    platform_default: int
    minimum: int
    maximum: int  # 0 = no ceiling


@dataclass(frozen=True)
class EffectivePolicy:
    client_id: str | None
    version: int  # 0 = no tenant row (everything inherited)
    values: dict[str, EffectiveValue]
    set_by: str | None = None
    updated_at: datetime | None = None

    def value(self, name: str) -> int:
        return self.values[name].value


def resolve(row: TenantRetentionPolicy | None, client_id: str | None,
            s: Settings = settings) -> EffectivePolicy:
    values: dict[str, EffectiveValue] = {}
    for category in CATEGORIES:
        floor, ceiling = _bounds(category, s)
        default = getattr(s, category.default_attr)
        override = getattr(row, category.name) if row is not None else None
        if override is None:
            # The platform default is not bound by tenant ceilings; startup
            # validation already guarantees a positive default meets the floor.
            values[category.name] = EffectiveValue(
                default, "default", None, default, floor, ceiling
            )
            continue
        value, clamped = clamp(category, override, s)
        values[category.name] = EffectiveValue(
            value, clamped or "tenant", override, default, floor, ceiling
        )
    return EffectivePolicy(
        client_id=client_id,
        version=row.version if row is not None else 0,
        values=values,
        set_by=row.set_by if row is not None else None,
        updated_at=row.updated_at if row is not None else None,
    )


async def effective_policy(db: AsyncSession, client_id: str,
                           s: Settings = settings) -> EffectivePolicy:
    return resolve(await db.get(TenantRetentionPolicy, client_id), client_id, s)


def validate_update(values: dict[str, int | None], s: Settings = settings) -> None:
    """Reject overrides outside the platform bounds (422)."""
    by_name = {c.name: c for c in CATEGORIES}
    for name, value in values.items():
        category = by_name.get(name)
        if category is None:
            raise RetentionPolicyError("retention_category_unknown", 422, name)
        if value is None:
            continue
        if value < 0 or (value == 0 and not category.allow_forever):
            raise RetentionPolicyError("retention_value_invalid", 422, name)
        floor, ceiling = _bounds(category, s)
        if value != 0 and value < floor:
            raise RetentionPolicyError("retention_below_minimum", 422, name)
        if ceiling and _longer_than(value, ceiling):
            raise RetentionPolicyError("retention_above_maximum", 422, name)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _snapshot(row: TenantRetentionPolicy | None) -> list[int | None]:
    return [getattr(row, name) if row is not None else None for name in CATEGORY_NAMES]


async def set_policy(
    db: AsyncSession,
    *,
    client_id: str,
    values: dict[str, int | None],
    expected_version: int,
    actor_email: str,
    actor_user_id: str | None,
    request_meta: dict,
    s: Settings = settings,
) -> TenantRetentionPolicy:
    """Replace the tenant's overrides. Omitted categories inherit.

    ``expected_version`` is the version the caller read (0 when no policy
    exists); a mismatch is a lost-update conflict (409). Caller commits.
    """
    validate_update(values, s)
    row = await db.get(TenantRetentionPolicy, client_id)
    current = row.version if row is not None else 0
    if expected_version != current:
        raise RetentionPolicyError("retention_policy_conflict", 409)
    previous = _snapshot(row)
    if row is None:
        row = TenantRetentionPolicy(client_id=client_id, version=0)
        db.add(row)
    for name in CATEGORY_NAMES:
        setattr(row, name, values.get(name))
    row.version = current + 1
    row.set_by = actor_email
    row.updated_at = _now()
    await audit.record(
        db,
        action="tenant.retention_policy_set",
        actor=actor_email,
        actor_user_id=actor_user_id,
        organization_id=client_id,
        detail={
            "client_id": client_id,
            "version": row.version,
            "previous_version": current,
            "categories": list(CATEGORY_NAMES),
            "values": _snapshot(row),
            "previous_values": previous,
        },
        **request_meta,
    )
    return row


async def clear_policy(
    db: AsyncSession,
    *,
    client_id: str,
    expected_version: int,
    actor_email: str,
    actor_user_id: str | None,
    request_meta: dict,
) -> None:
    """Clear every override so each category inherits. Caller commits.

    The row is kept with all-NULL overrides and a bumped version rather than
    deleted: versions then only ever increase, so a stale writer holding a
    pre-clear version can never collide with a recreated row (no ABA).
    """
    row = await db.get(TenantRetentionPolicy, client_id)
    if row is None:
        raise RetentionPolicyError("retention_policy_not_found", 404)
    if expected_version != row.version:
        raise RetentionPolicyError("retention_policy_conflict", 409)
    previous = _snapshot(row)
    previous_version = row.version
    for name in CATEGORY_NAMES:
        setattr(row, name, None)
    row.version = previous_version + 1
    row.set_by = actor_email
    row.updated_at = _now()
    await audit.record(
        db,
        action="tenant.retention_policy_cleared",
        actor=actor_email,
        actor_user_id=actor_user_id,
        organization_id=client_id,
        detail={
            "client_id": client_id,
            "version": row.version,
            "previous_version": previous_version,
            "categories": list(CATEGORY_NAMES),
            "previous_values": previous,
        },
        **request_meta,
    )
