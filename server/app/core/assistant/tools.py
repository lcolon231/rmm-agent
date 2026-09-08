# SPDX-License-Identifier: AGPL-3.0-only
"""Closed registry of read-only adapters. No dynamic dispatch, HTTP or SQL from AI."""
from dataclasses import asdict
from datetime import timedelta

from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import func, select

from app.api import management
from app.core import inventory_diff, patch_compliance
from app.core.assistant import policy
from app.core.config import settings
from app.core.tenant_scope import agent_client_filter
from app.models.models import Agent, AgentStatus, AgentTrustState, Alert, AlertState, MonitoringPolicyRevision, Site
from app.schemas import assistant as schema
from app.schemas.inventory import InventorySection
from app.schemas.monitoring import CheckDefinition

REGISTRY = {
    "list_endpoints": (schema.EndpointSearch, "Search endpoints in the selected client. Filter offline for offline questions. 25 rows/page."),
    "endpoint_detail": (schema.EndpointInput, "Endpoint identity and latest telemetry with freshness. No live collection."),
    "inventory": (schema.InventoryInput, "Latest reported hardware or software section; missing is not empty."),
    "inventory_history": (schema.HistoryInput, "Retained changes in one inventory section, newest first; 5 snapshots/page."),
    "inventory_changes": (schema.InventoryInput, "Compare the latest two snapshots using the existing inventory diff engine."),
    "active_alerts": (schema.AlertsInput, "Open and acknowledged monitoring alerts with observed value, state and timestamps. 25/page."),
    "patch_compliance": (schema.ScopePage, "Patch compliance summary for 25 endpoints/page; explicitly partial if further pages exist."),
}


def definitions():
    return [{"type": "function", "name": name, "description": description,
             "parameters": model.model_json_schema(), "strict": True}
            for name, (model, description) in REGISTRY.items()]


def parse(name, arguments):
    if not isinstance(name, str) or name not in REGISTRY or not isinstance(arguments, str) or len(arguments) > 4096:
        raise ValueError("invalid_tool")
    try:
        return REGISTRY[name][0].model_validate_json(arguments)
    except (ValidationError, ValueError):
        raise ValueError("invalid_arguments") from None


# Reviewed payload vocabulary. No serials, addresses, user identity, paths,
# free-form errors, command output or nested unclassified fields are passed on.
PAYLOAD_FIELDS = frozenset("manufacturer model chassis bios_vendor bios_version bios_release_date name architecture physical_cores logical_cores max_clock_mhz total_bytes modules capacity_bytes speed_mhz slot part_number disks volumes size_bytes media_type bus_type mount_point filesystem free_bytes adapters adapter_type speed_bps dhcp_enabled entries version publisher install_date scope".split())


def project(value, depth=0):
    if depth > 8:
        return None
    if isinstance(value, dict):
        return {k: project(v, depth + 1) for k, v in value.items() if k in PAYLOAD_FIELDS}
    if isinstance(value, list):
        return [project(v, depth + 1) for v in value]  # size bound applied atomically below
    if isinstance(value, str):
        return policy.clean_text(value, 255)
    return value if value is None or isinstance(value, (int, float, bool)) else None


def fields(value, names):
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return {k: policy.clean_text(value[k], 255) if isinstance(value[k], str) else value[k]
            for k in names.split() if k in value}


def snapshot(row):
    data = fields(row, "id section status collected_at received_at")
    data["payload"] = project(row.payload)
    data["note"] = "Snapshot is retained when content changes; collection age is not heartbeat freshness. Sensitive fields omitted."
    return data


async def execute(name, args, db, operator, conversation):
    client_id = conversation.client_id
    endpoint_id = str(args.endpoint_id) if getattr(args, "endpoint_id", None) else None
    sources = []

    async def source(agent_id):
        agent = await policy.endpoint(db, operator, client_id, agent_id)
        entry = {"endpoint_id": agent.id, "label": policy.clean_text(agent.hostname, 255),
                 "href": f"/endpoints/{agent.id}", "last_seen_at": agent.last_seen_at,
                 "observed_at": policy.now()}
        if not any(s["endpoint_id"] == agent.id for s in sources):
            sources.append(entry)

    if endpoint_id:
        await source(endpoint_id)

    if name == "list_endpoints":
        response = await management.list_endpoints(
            operator=operator, client_id=client_id, site_id=None,
            status=AgentStatus(args.status) if args.status else None,
            search=args.search or None, sort="hostname", direction="asc",
            page=args.page, page_size=25, db=db,
        )
        items = []
        for row in response.items:
            await source(row.id)
            items.append(fields(row, "id hostname os os_version status last_seen_at"))
        data = {"items": items, "page": args.page, "total": response.total,
                "has_more": args.page * 25 < response.total,
                "status_basis": "NodeLink recorded status; last_seen_at is the last received heartbeat."}
    elif name == "endpoint_detail":
        response = await management.get_endpoint_detail(endpoint_id, operator, history_hours=24, history_limit=10, db=db)
        data = fields(response, "id hostname os os_version agent_version status last_seen_at telemetry_freshness stale_after_seconds history_truncated")
        data["current_telemetry"] = fields(response.current_telemetry, "ts cpu_percent mem_percent disk_percent uptime_seconds") if response.current_telemetry else None
        data["telemetry"] = [fields(row, "ts cpu_percent mem_percent disk_percent uptime_seconds") for row in response.telemetry]
    elif name == "inventory":
        response = await management.get_endpoint_inventory(endpoint_id, operator, db)
        selected = next((row for row in response.sections if row.section.value == args.section), None)
        data = {"section": args.section, "missing": selected is None, "snapshot": snapshot(selected) if selected else None}
    elif name in ("inventory_history", "inventory_changes"):
        response = await management.get_inventory_history(
            endpoint_id, InventorySection(args.section), operator,
            page=args.page if name == "inventory_history" else 1,
            page_size=5 if name == "inventory_history" else 2, db=db,
        )
        if name == "inventory_history":
            data = {"items": [snapshot(row) for row in response.items], "total": response.total,
                    "page": args.page, "has_more": args.page * 5 < response.total}
        else:
            comparable = len(response.items) == 2
            data = {"comparable": comparable, "note": "Changes cover only the disclosed fields. Fewer than two snapshots cannot be compared."}
            if comparable:
                after, before = response.items
                diff = inventory_diff.diff_payloads(args.section, project(before.payload), project(after.payload))
                data.update(before=snapshot(before), after=snapshot(after), diff=diff,
                            summary=inventory_diff.summarize_diff(diff))
    elif name == "active_alerts":
        conditions = [Site.client_id == client_id, agent_client_filter(operator),
                      Agent.trust_state != AgentTrustState.revoked,
                      Alert.state.in_([AlertState.open, AlertState.acknowledged])]
        if endpoint_id:
            conditions.append(Alert.agent_id == endpoint_id)
        query = select(Alert).join(Agent, Alert.agent_id == Agent.id).join(Site).where(*conditions)
        total = await db.scalar(select(func.count()).select_from(query.subquery())) or 0
        rows = (await db.execute(query.order_by(Alert.last_observed_at.desc(), Alert.id)
                                .offset((args.page - 1) * 25).limit(25))).scalars().all()
        items = []
        for row in rows:
            await source(row.agent_id)
            item = {k: getattr(row, k) for k in "id agent_id state last_result_status last_value occurrence_count opened_at last_observed_at last_evaluated_at".split()}
            item["check_key"] = policy.clean_text(row.check_key, 64)
            revision = await db.get(MonitoringPolicyRevision, row.policy_revision_id)
            raw = next((check for check in revision.checks if check.get("key") == row.check_key), None) if revision else None
            definition = CheckDefinition.model_validate(raw) if raw else None
            item["check"] = None if definition is None else {
                "type": definition.type.value, "threshold": definition.threshold.model_dump(mode="json") if definition.threshold else None,
                "hysteresis": definition.hysteresis.model_dump(), "schedule": definition.schedule.model_dump(),
            }
            items.append(item)
        data = {"items": items, "total": total, "page": args.page, "has_more": args.page * 25 < total,
                "explanation": "Open means monitoring observed a failure; acknowledged means an operator acknowledged it, not that it recovered. last_value is observed, not a root cause. Missing or old observations cannot establish current health."}
    elif name == "patch_compliance":
        query = select(Agent).join(Site).where(Site.client_id == client_id,
                    agent_client_filter(operator), Agent.trust_state != AgentTrustState.revoked)
        total = await db.scalar(select(func.count()).select_from(query.subquery())) or 0
        agents = (await db.execute(query.order_by(Agent.id).offset((args.page - 1) * 25).limit(25))).scalars().all()
        rows = []
        for agent in agents:
            await source(agent.id)
            rows.append(await patch_compliance.endpoint_compliance(db, agent, policy.now(),
                stale_after=timedelta(hours=settings.patch_compliance_stale_after_hours)))
        data = {"summary": asdict(patch_compliance.summarize(rows, truncated=total > len(rows))),
                "items": [fields(asdict(row), "agent_id state scanned_at total_missing approved_missing deferred_missing denied_missing") for row in rows],
                "page": args.page, "total": total, "has_more": args.page * 25 < total,
                "note": "Summary covers this page only. Exempt means no effective policy; unknown is not compliant."}
    else:
        raise ValueError("invalid_tool")
    outcome = "observed"
    if ((name == "inventory" and data["missing"])
            or (name == "inventory_history" and not data["items"])
            or (name == "inventory_changes" and not data["comparable"])
            or (name == "endpoint_detail" and data["current_telemetry"] is None)):
        outcome = "missing"
    snapshots = ([data["snapshot"]] if name == "inventory" and data["snapshot"] else
                 data["items"] if name == "inventory_history" else
                 [data["before"], data["after"]] if name == "inventory_changes" and data["comparable"] else [])
    if any(row["status"] != "ok" for row in snapshots):
        outcome = "partial"
    result = {"tool": name, "outcome": outcome, "observed_at": policy.now(), "data": data, "sources": sources}
    # Reject oversized evidence atomically: never imply a silently shortened inventory is complete.
    if len(policy.encoded(result).encode()) > policy.MAX_RESULT_BYTES:
        return {"tool": name, "outcome": "too_large", "data": {"note": "Evidence exceeded the assistant limit. Open the endpoint's native inventory view."}, "sources": sources[:1]}
    return result
