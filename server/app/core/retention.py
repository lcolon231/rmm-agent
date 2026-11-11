# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded storage growth: retention pruning and observable capacity.

Issue #114 bounded the high-volume data classes globally; issue #88 makes that
retention tenant-specific. Responsibilities:

* :func:`prune_expired` runs once per sweep. For every tenant (client) it
  resolves the effective policy (:mod:`app.core.retention_policy` -- tenant
  override, else platform default, clamped to platform floors/ceilings) and
  prunes that tenant's telemetry, command output, terminal command records
  (which include scheduled-task run history), inventory history, resolved
  alerts, and terminal notification deliveries. Data classes that are not
  tenant-configurable (check results, assistant, support chat, relay receipts)
  are then pruned globally as before.

* A tenant under an active tenant-wide legal hold is **not pruned at all**; the
  sweep records ``retention.purge_suspended`` instead.

* Every tenant runs in its own SAVEPOINT. A failure rolls back only that
  tenant's work, is recorded as ``retention.purge_failed`` (exception class
  only), and the sweep continues; selection is cutoff-based, so the next sweep
  retries idempotently.

* Deletion proof: each non-empty purge of one table for one tenant appends a
  ``retention.purged`` audit event with the cutoff, policy version/source, row
  count, and ``ids_sha256`` -- SHA-256 over the affected primary keys sorted
  ascending, each followed by ``\\n``. No content is recorded. One
  ``retention.sweep_completed`` event closes every sweep.

It remains **audit-safe by construction**: nothing here deletes or edits an
``AuditEvent``, ``AuditAnchor``, or ``AnchorPublication``; it only appends, so
hash-chain and external-anchor verification stay reproducible.

* :func:`storage_status` reports per-class counts, oldest-age, backlog, host disk
  headroom, and unpublished-anchor lag, with threshold-breach flags an operator
  can alert on. It never mutates anything.
"""
from __future__ import annotations

import hashlib
import shutil
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import anchor_publish, audit, evidence_vault, monitoring, retention_policy
from app.core.config import Settings, settings
from app.models.models import (
    Agent,
    AgentInventorySnapshot,
    AgentUpdateAttempt,
    Alert,
    AlertEmailAttempt,
    AlertEmailDelivery,
    AlertEvent,
    AlertObservation,
    AlertState,
    AlertWebhookAttempt,
    AlertWebhookDelivery,
    AuditEvent,
    CheckResult,
    Client,
    Command,
    CommandStatus,
    EmailDeliveryStatus,
    Heartbeat,
    RelayForwardReceipt,
    Site,
    SupportConversation,
    SupportConversationStatus,
    SupportMessage,
    TenantRetentionPolicy,
    WebhookDeliveryStatus,
)

_TERMINAL_COMMANDS = (CommandStatus.succeeded, CommandStatus.failed, CommandStatus.expired)
_TERMINAL_EMAIL = (
    EmailDeliveryStatus.sent, EmailDeliveryStatus.failed, EmailDeliveryStatus.suppressed
)
_TERMINAL_WEBHOOK = (
    WebhookDeliveryStatus.delivered,
    WebhookDeliveryStatus.failed,
    WebhookDeliveryStatus.suppressed,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat()


def ids_digest(ids) -> str:
    """The deletion-proof digest: SHA-256 over sorted ids, newline-terminated."""
    h = hashlib.sha256()
    for value in sorted(ids):
        h.update(str(value).encode("utf-8") + b"\n")
    return h.hexdigest()


@dataclass
class TenantPruneOutcome:
    client_id: str
    status: str  # pruned | suspended | failed
    counts: dict[str, int] = field(default_factory=dict)
    error: str | None = None


@dataclass
class PruneResult:
    heartbeats_deleted: int
    command_outputs_cleared: int
    inventory_snapshots_deleted: int = 0
    check_results_deleted: int = 0
    assistant_conversations_deleted: int = 0
    support_chat_messages_deleted: int = 0
    support_chat_conversations_deleted: int = 0
    relay_receipts_deleted: int = 0
    command_records_deleted: int = 0
    alerts_deleted: int = 0
    notifications_deleted: int = 0
    tenants: list[TenantPruneOutcome] = field(default_factory=list)

    @property
    def tenants_suspended(self) -> int:
        return sum(1 for t in self.tenants if t.status == "suspended")

    @property
    def tenants_failed(self) -> int:
        return sum(1 for t in self.tenants if t.status == "failed")


@dataclass
class _Purge:
    """One table's purge for one tenant, before it is audited."""

    category: str
    table: str
    operation: str  # deleted | cleared
    rows: int
    ids_sha256: str
    dependent_rows: int = 0
    cutoff: datetime | None = None
    keep_per_section: int | None = None
    truncated: bool = False


async def _drain(db: AsyncSession, candidates, id_column, act, s: Settings):
    """Apply ``act(ids)`` to ``candidates`` in id-ordered, bounded batches.

    Each batch takes the smallest remaining ids, so the concatenation of all
    batches is globally sorted -- the same order :func:`ids_digest` uses.
    ``act`` must remove its ids from ``candidates`` (delete, or clear the
    column the candidate filter tests), or the loop would not terminate.
    Returns (ids, dependent_rows, truncated).
    """
    cap = s.retention_max_rows_per_sweep
    done: list = []
    dependents = 0
    while len(done) < cap:
        limit = min(s.retention_batch_size, cap - len(done))
        ids = [row[0] for row in (
            await db.execute(candidates.order_by(id_column).limit(limit))
        ).all()]
        if not ids:
            return done, dependents, False
        dependents += await act(ids) or 0
        done.extend(ids)
        if len(ids) < limit:
            return done, dependents, False
    # Cap reached: more may remain; the next sweep continues.
    more = (await db.execute(candidates.limit(1))).first() is not None
    return done, dependents, more


async def _rowcount(db: AsyncSession, stmt) -> int:
    result = await db.execute(stmt, execution_options={"synchronize_session": False})
    return result.rowcount or 0


def _tenant_agents(client_id: str):
    return (
        select(Agent.id)
        .join(Site, Site.id == Agent.site_id)
        .where(Site.client_id == client_id)
    )


async def _prune_telemetry(db, client_id, days, now, s) -> list[_Purge]:
    cutoff = now - timedelta(days=days)
    candidates = select(Heartbeat.id).where(
        Heartbeat.agent_id.in_(_tenant_agents(client_id)), Heartbeat.ts < cutoff
    )

    async def act(ids):
        await _rowcount(db, delete(Heartbeat).where(Heartbeat.id.in_(ids)))

    ids, _, truncated = await _drain(db, candidates, Heartbeat.id, act, s)
    return [_Purge("telemetry_days", "heartbeats", "deleted", len(ids),
                   ids_digest(ids), cutoff=cutoff, truncated=truncated)] if ids else []


async def _prune_command_output(db, client_id, days, now, s) -> list[_Purge]:
    cutoff = now - timedelta(days=days)
    candidates = select(Command.id).where(
        Command.agent_id.in_(_tenant_agents(client_id)),
        Command.completed_at.is_not(None),
        Command.completed_at < cutoff,
        or_(Command.stdout.is_not(None), Command.stderr.is_not(None)),
    )

    async def act(ids):
        await _rowcount(
            db, update(Command).where(Command.id.in_(ids)).values(stdout=None, stderr=None)
        )

    ids, _, truncated = await _drain(db, candidates, Command.id, act, s)
    return [_Purge("command_output_days", "commands", "cleared", len(ids),
                   ids_digest(ids), cutoff=cutoff, truncated=truncated)] if ids else []


async def _prune_command_records(db, client_id, days, now, s) -> list[_Purge]:
    """Delete terminal command rows (including scheduled-task runs) by age.

    Only terminal rows qualify -- a queued or running command is live work,
    whatever its age. References that are ``ON DELETE SET NULL`` in the schema
    are nulled explicitly so behaviour does not depend on the database
    enforcing foreign keys.
    """
    cutoff = now - timedelta(days=days)
    candidates = select(Command.id).where(
        Command.agent_id.in_(_tenant_agents(client_id)),
        Command.status.in_(_TERMINAL_COMMANDS),
        Command.created_at < cutoff,
    )

    async def act(ids):
        await _rowcount(
            db, update(Command).where(Command.parent_command_id.in_(ids))
            .values(parent_command_id=None)
        )
        await _rowcount(
            db, update(AgentUpdateAttempt).where(AgentUpdateAttempt.command_id.in_(ids))
            .values(command_id=None)
        )
        await _rowcount(db, delete(Command).where(Command.id.in_(ids)))

    ids, _, truncated = await _drain(db, candidates, Command.id, act, s)
    return [_Purge("command_record_days", "commands", "deleted", len(ids),
                   ids_digest(ids), cutoff=cutoff, truncated=truncated)] if ids else []


async def _delete_alert_dependents(db, alert_ids) -> int:
    email = select(AlertEmailDelivery.id).where(AlertEmailDelivery.alert_id.in_(alert_ids))
    webhook = select(AlertWebhookDelivery.id).where(
        AlertWebhookDelivery.alert_id.in_(alert_ids)
    )
    n = await _rowcount(db, delete(AlertEmailAttempt).where(AlertEmailAttempt.delivery_id.in_(email)))
    n += await _rowcount(db, delete(AlertEmailDelivery).where(AlertEmailDelivery.alert_id.in_(alert_ids)))
    n += await _rowcount(
        db, delete(AlertWebhookAttempt).where(AlertWebhookAttempt.delivery_id.in_(webhook))
    )
    n += await _rowcount(
        db, delete(AlertWebhookDelivery).where(AlertWebhookDelivery.alert_id.in_(alert_ids))
    )
    n += await _rowcount(db, delete(AlertObservation).where(AlertObservation.alert_id.in_(alert_ids)))
    n += await _rowcount(db, delete(AlertEvent).where(AlertEvent.alert_id.in_(alert_ids)))
    return n


async def _prune_alerts(db, client_id, days, now, s) -> list[_Purge]:
    """Delete *resolved* alerts resolved before the cutoff, with their history.

    Open and acknowledged alerts are live incidents and never qualify. A later
    recurrence simply opens a fresh alert identity.
    """
    cutoff = now - timedelta(days=days)
    candidates = select(Alert.id).where(
        Alert.agent_id.in_(_tenant_agents(client_id)),
        Alert.state == AlertState.resolved,
        Alert.resolved_at.is_not(None),
        Alert.resolved_at < cutoff,
    )

    async def act(ids):
        dependents = await _delete_alert_dependents(db, ids)
        await _rowcount(db, delete(Alert).where(Alert.id.in_(ids)))
        return dependents

    ids, dependents, truncated = await _drain(db, candidates, Alert.id, act, s)
    return [_Purge("alert_days", "alerts", "deleted", len(ids), ids_digest(ids),
                   dependent_rows=dependents, cutoff=cutoff,
                   truncated=truncated)] if ids else []


async def _prune_notifications(db, client_id, days, now, s) -> list[_Purge]:
    """Delete terminal email/webhook deliveries (and attempts) by age.

    Pending, sending, and retrying deliveries are still in flight and never
    qualify.
    """
    cutoff = now - timedelta(days=days)
    tenant_alerts = select(Alert.id).where(Alert.agent_id.in_(_tenant_agents(client_id)))
    purges: list[_Purge] = []
    for model, attempt, statuses, table in (
        (AlertEmailDelivery, AlertEmailAttempt, _TERMINAL_EMAIL, "alert_email_deliveries"),
        (AlertWebhookDelivery, AlertWebhookAttempt, _TERMINAL_WEBHOOK,
         "alert_webhook_deliveries"),
    ):
        candidates = select(model.id).where(
            model.alert_id.in_(tenant_alerts),
            model.status.in_(statuses),
            model.created_at < cutoff,
        )

        async def act(ids, model=model, attempt=attempt):
            n = await _rowcount(db, delete(attempt).where(attempt.delivery_id.in_(ids)))
            await _rowcount(db, delete(model).where(model.id.in_(ids)))
            return n

        ids, dependents, truncated = await _drain(db, candidates, model.id, act, s)
        if ids:
            purges.append(_Purge("notification_days", table, "deleted", len(ids),
                                 ids_digest(ids), dependent_rows=dependents,
                                 cutoff=cutoff, truncated=truncated))
    return purges


async def _prune_inventory(db, client_id, keep, s) -> list[_Purge]:
    ids = await _prune_inventory_history(db, keep, agents=_tenant_agents(client_id))
    return [_Purge("inventory_history_per_section", "agent_inventory_snapshots",
                   "deleted", len(ids), ids_digest(ids),
                   keep_per_section=keep)] if ids else []


async def _prune_tenant(db, client_id, policy, now, s) -> list[_Purge]:
    purges: list[_Purge] = []
    if (days := policy.value("telemetry_days")) > 0:
        purges += await _prune_telemetry(db, client_id, days, now, s)
    if (days := policy.value("command_output_days")) > 0:
        purges += await _prune_command_output(db, client_id, days, now, s)
    if (days := policy.value("command_record_days")) > 0:
        purges += await _prune_command_records(db, client_id, days, now, s)
    if (keep := policy.value("inventory_history_per_section")) > 0:
        purges += await _prune_inventory(db, client_id, keep, s)
    # Notifications before alerts: an alert purge removes its own deliveries,
    # and doing notifications first keeps the per-table proof unambiguous.
    if (days := policy.value("notification_days")) > 0:
        purges += await _prune_notifications(db, client_id, days, now, s)
    if (days := policy.value("alert_days")) > 0:
        purges += await _prune_alerts(db, client_id, days, now, s)
    return purges


async def _record_purge(db, client_id, policy, purge: _Purge) -> None:
    value = policy.values[purge.category]
    await audit.record(
        db,
        action="retention.purged",
        organization_id=client_id,
        detail={
            "client_id": client_id,
            "category": purge.category,
            "table": purge.table,
            "operation": purge.operation,
            "cutoff": _iso(purge.cutoff) if purge.cutoff else None,
            "keep_per_section": purge.keep_per_section,
            "policy_version": policy.version,
            "policy_source": value.source,
            "rows": purge.rows,
            "dependent_rows": purge.dependent_rows,
            "ids_sha256": purge.ids_sha256,
            "truncated": purge.truncated,
        },
    )


_RESULT_FIELDS = {
    ("telemetry_days", "heartbeats"): "heartbeats_deleted",
    ("command_output_days", "commands"): "command_outputs_cleared",
    ("command_record_days", "commands"): "command_records_deleted",
    ("inventory_history_per_section", "agent_inventory_snapshots"): "inventory_snapshots_deleted",
    ("alert_days", "alerts"): "alerts_deleted",
    ("notification_days", "alert_email_deliveries"): "notifications_deleted",
    ("notification_days", "alert_webhook_deliveries"): "notifications_deleted",
}


async def _prune_tenants(db: AsyncSession, s: Settings, now: datetime, result: PruneResult):
    client_ids = (await db.execute(select(Client.id).order_by(Client.id))).scalars().all()
    rows = {
        row.client_id: row
        for row in (await db.execute(select(TenantRetentionPolicy))).scalars().all()
    }
    for client_id in client_ids:
        policy = retention_policy.resolve(rows.get(client_id), client_id, s)
        if await evidence_vault.tenant_hold_active(db, client_id):
            await audit.record(
                db,
                action="retention.purge_suspended",
                organization_id=client_id,
                detail={
                    "client_id": client_id,
                    "reason": "tenant_legal_hold",
                    "policy_version": policy.version,
                },
            )
            result.tenants.append(TenantPruneOutcome(client_id, "suspended"))
            continue
        try:
            async with db.begin_nested():
                purges = await _prune_tenant(db, client_id, policy, now, s)
                for purge in purges:
                    await _record_purge(db, client_id, policy, purge)
        except Exception as exc:  # isolate one tenant's failure from the rest
            await audit.record(
                db,
                action="retention.purge_failed",
                organization_id=client_id,
                detail={
                    "client_id": client_id,
                    "error_class": type(exc).__name__,
                    "policy_version": policy.version,
                },
            )
            result.tenants.append(TenantPruneOutcome(client_id, "failed",
                                                     error=type(exc).__name__))
            continue
        counts: dict[str, int] = {}
        for purge in purges:
            name = _RESULT_FIELDS[(purge.category, purge.table)]
            counts[name] = counts.get(name, 0) + purge.rows
            setattr(result, name, getattr(result, name) + purge.rows)
        result.tenants.append(TenantPruneOutcome(client_id, "pruned", counts))


async def prune_expired(
    db: AsyncSession, s: Settings = settings, now: datetime | None = None
) -> PruneResult:
    """Run one retention sweep: per-tenant policies, then global classes.

    Caller owns the surrounding transaction/commit. A retention value of 0
    disables that class's pruning (keep forever).
    """
    now = now or _now()
    result = PruneResult(heartbeats_deleted=0, command_outputs_cleared=0)
    await _prune_tenants(db, s, now, result)
    # A tenant under legal hold is exempt from the global classes too, so the
    # hold suspends *all* pruning of that tenant's data.
    held = [t.client_id for t in result.tenants if t.status == "suspended"]
    held_agents = (
        select(Agent.id).join(Site, Site.id == Agent.site_id).where(Site.client_id.in_(held))
        if held else None
    )

    if s.check_result_history_per_key > 0:
        result.check_results_deleted = await monitoring.prune_check_results(
            db, s.check_result_history_per_key, exclude_agents=held_agents
        )

    from app.core.assistant.service import prune as prune_assistant
    result.assistant_conversations_deleted = await prune_assistant(db, now)

    if s.support_chat_retention_days > 0:
        (
            result.support_chat_messages_deleted,
            result.support_chat_conversations_deleted,
        ) = await _prune_support_chat(
            db, now - timedelta(days=s.support_chat_retention_days), exclude_clients=held
        )
    # Relay forward receipts are the replay guard (issue #87). The setting's
    # floor of one day keeps every receipt well past the accepted clock-skew
    # plus store-and-forward window, so pruning never reopens a replay.
    relay_cutoff = now - timedelta(days=max(1, s.relay_receipt_retention_days))
    result.relay_receipts_deleted = await _rowcount(
        db, delete(RelayForwardReceipt).where(RelayForwardReceipt.received_at < relay_cutoff)
    )

    await audit.record(
        db,
        action="retention.sweep_completed",
        detail={
            "swept_at": _iso(now),
            "tenants": len(result.tenants),
            "tenants_suspended": result.tenants_suspended,
            "tenants_failed": result.tenants_failed,
            "heartbeats_deleted": result.heartbeats_deleted,
            "command_outputs_cleared": result.command_outputs_cleared,
            "command_records_deleted": result.command_records_deleted,
            "inventory_snapshots_deleted": result.inventory_snapshots_deleted,
            "alerts_deleted": result.alerts_deleted,
            "notifications_deleted": result.notifications_deleted,
            "check_results_deleted": result.check_results_deleted,
            "support_chat_conversations_deleted": result.support_chat_conversations_deleted,
            "relay_receipts_deleted": result.relay_receipts_deleted,
        },
    )
    return result


async def _prune_support_chat(
    db: AsyncSession, cutoff: datetime, exclude_clients: list[str] | None = None
) -> tuple[int, int]:
    """Delete transcripts of support conversations closed before `cutoff`.

    Message bodies are incidental PHI with no minimum retention (issue #237), so
    they age out; the conversation's lifecycle audit events never held a body
    and are untouched. Only *closed* conversations qualify: an open one is live
    support, whatever its age. Messages go first, then the emptied rows.
    """
    expired = select(SupportConversation.id).where(
        SupportConversation.status == SupportConversationStatus.closed,
        SupportConversation.closed_at.is_not(None),
        SupportConversation.closed_at < cutoff,
    )
    if exclude_clients:
        expired = expired.where(SupportConversation.client_id.not_in(exclude_clients))
    messages = await db.execute(
        delete(SupportMessage).where(SupportMessage.conversation_id.in_(expired)),
        execution_options={"synchronize_session": False},
    )
    conversations = await db.execute(
        delete(SupportConversation).where(SupportConversation.id.in_(expired)),
        execution_options={"synchronize_session": False},
    )
    return messages.rowcount or 0, conversations.rowcount or 0


async def _prune_inventory_history(db: AsyncSession, keep: int, agents=None) -> list[str]:
    """Keep the newest `keep` snapshots per (agent, section); return deleted ids.

    ``agents`` optionally scopes the prune to a subquery of agent ids (one
    tenant's agents, issue #88).

    The newest row is never a candidate for deletion, whatever `keep` is set
    to: it is the endpoint's *current* reported state rather than history, and
    removing it would make a managed machine indistinguishable from one that
    never reported at all.

    Pruning is done per group rather than by a global age cutoff because
    sections change at wildly different rates — hardware almost never, software
    on every patch cycle — and an age rule would either keep nothing useful for
    the slow ones or unbounded history for the fast ones.
    """
    keep = max(1, keep)
    groups_query = (
        select(
            AgentInventorySnapshot.agent_id,
            AgentInventorySnapshot.section,
            func.count().label("total"),
        )
        .group_by(AgentInventorySnapshot.agent_id, AgentInventorySnapshot.section)
        .having(func.count() > keep)
    )
    if agents is not None:
        groups_query = groups_query.where(AgentInventorySnapshot.agent_id.in_(agents))
    groups = (await db.execute(groups_query)).all()

    deleted: list[str] = []
    for agent_id, section, _total in groups:
        ordered = (
            select(AgentInventorySnapshot.id)
            .where(
                AgentInventorySnapshot.agent_id == agent_id,
                AgentInventorySnapshot.section == section,
            )
            .order_by(
                AgentInventorySnapshot.received_at.desc(),
                AgentInventorySnapshot.id.desc(),
            )
        )
        # Materialize the expired ids: a correlated LIMIT/OFFSET subquery
        # inside DELETE is not portable across SQLite and PostgreSQL.
        expired = [row[0] for row in (await db.execute(ordered.offset(keep))).all()]
        if not expired:
            continue
        await _rowcount(
            db,
            delete(AgentInventorySnapshot).where(AgentInventorySnapshot.id.in_(expired)),
        )
        deleted.extend(expired)
    return deleted


async def _age_seconds(db: AsyncSession, column) -> float | None:
    oldest = (await db.execute(select(func.min(column)))).scalar_one_or_none()
    if oldest is None:
        return None
    if oldest.tzinfo is None:
        oldest = oldest.replace(tzinfo=timezone.utc)
    return (_now() - oldest).total_seconds()


async def storage_status(db: AsyncSession, s: Settings = settings) -> dict:
    """Observable capacity/backlog for every persistent data class, plus
    threshold-breach alert flags. Read-only."""
    heartbeat_count = (
        await db.execute(select(func.count()).select_from(Heartbeat))
    ).scalar_one()
    command_count = (
        await db.execute(select(func.count()).select_from(Command))
    ).scalar_one()
    command_output_count = (
        await db.execute(
            select(func.count())
            .select_from(Command)
            .where(or_(Command.stdout.is_not(None), Command.stderr.is_not(None)))
        )
    ).scalar_one()
    audit_count = (
        await db.execute(select(func.count()).select_from(AuditEvent))
    ).scalar_one()
    inventory_count = (
        await db.execute(select(func.count()).select_from(AgentInventorySnapshot))
    ).scalar_one()
    inventory_bytes = (
        await db.execute(select(func.sum(AgentInventorySnapshot.byte_size)))
    ).scalar_one() or 0
    check_result_count = (
        await db.execute(select(func.count()).select_from(CheckResult))
    ).scalar_one()

    tenant_overrides = (
        await db.execute(
            select(func.count()).select_from(TenantRetentionPolicy).where(
                or_(*(
                    getattr(TenantRetentionPolicy, name).is_not(None)
                    for name in retention_policy.CATEGORY_NAMES
                ))
            )
        )
    ).scalar_one()

    pub = await anchor_publish.publication_status(db, s)

    # Host disk headroom for logs/backups (and a local DB). A missing path is
    # reported rather than raised, so status never fails closed on this.
    disk_free = disk_total = None
    try:
        usage = shutil.disk_usage(s.retention_disk_path)
        disk_free, disk_total = usage.free, usage.total
    except OSError:
        pass

    heartbeat_alert = heartbeat_count > s.heartbeat_backlog_alert
    command_alert = command_count > s.command_backlog_alert
    disk_alert = disk_free is not None and disk_free < s.disk_free_alert_bytes
    anchor_alert = pub.lag_alert

    status = {
        "retention_policy": {
            "telemetry_retention_days": s.telemetry_retention_days,
            "command_output_retention_days": s.command_output_retention_days,
            "support_chat_retention_days": s.support_chat_retention_days,
            # Platform defaults for the #88 classes (0 = keep forever); a
            # tenant may override any of them within the platform bounds.
            "command_record_retention_days": s.command_record_retention_days,
            "alert_retention_days": s.alert_retention_days,
            "notification_retention_days": s.notification_retention_days,
            "tenant_policies_overridden": tenant_overrides,
        },
        "heartbeats": {
            "count": heartbeat_count,
            "oldest_age_seconds": await _age_seconds(db, Heartbeat.ts),
            "backlog_alert": heartbeat_alert,
        },
        "commands": {
            "count": command_count,
            "with_output": command_output_count,
            "backlog_alert": command_alert,
        },
        "audit": {
            # Audit data is append-only and never pruned; exposed for capacity
            # planning, not for retention.
            "event_count": audit_count,
            "oldest_age_seconds": await _age_seconds(db, AuditEvent.ts),
        },
        "inventory": {
            # Snapshots are append-only per section and only written when a
            # section's content changes, so growth tracks real hardware churn
            # rather than heartbeat frequency. The limit shown is the platform
            # default; a tenant policy (#88) may override it.
            "snapshot_count": inventory_count,
            "total_bytes": inventory_bytes,
            "oldest_age_seconds": await _age_seconds(
                db, AgentInventorySnapshot.received_at
            ),
            "history_per_section_limit": s.inventory_history_per_section,
        },
        "check_results": {
            "count": check_result_count,
            "oldest_age_seconds": await _age_seconds(db, CheckResult.received_at),
            "history_per_key_limit": s.check_result_history_per_key,
        },
        "anchor_publication": {
            "backend": pub.backend,
            "pending": pub.pending,
            "oldest_unpublished_age_seconds": pub.oldest_unpublished_age_seconds,
            "lag_alert": anchor_alert,
        },
        "disk": {
            "path": s.retention_disk_path,
            "free_bytes": disk_free,
            "total_bytes": disk_total,
            "free_alert": disk_alert,
        },
    }
    status["alert"] = bool(
        heartbeat_alert or command_alert or disk_alert or anchor_alert
    )
    return status


# asdict is re-exported for callers that want the dataclass form of PruneResult.
__all__ = ["PruneResult", "prune_expired", "storage_status", "asdict"]
