# SPDX-License-Identifier: AGPL-3.0-only
"""Route-table guard for the tenant access module (issue #327).

Every route whose path carries a tenant-owned id must depend on
:func:`app.api.tenant_access.tenant_access`, so a new by-id handler cannot
quietly skip the tenant gate. The exceptions live in one reviewed allowlist,
each with its reason. Routes not yet migrated are listed too; migrating a
route means deleting its entry, and the second test makes sure nobody forgets.
"""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_tenant_access.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import re  # noqa: E402

from fastapi.dependencies.models import Dependant  # noqa: E402
from fastapi.routing import APIRoute  # noqa: E402

from app.api.tenant_access import is_tenant_access_dependency  # noqa: E402
from app.main import app  # noqa: E402

TENANT_ID_PARAMS = {"agent_id", "client_id", "site_id", "alert_id"}

_NOT_YET = "not yet migrated (#327)"

ALLOWLIST: dict[tuple[str, str], str] = {
    # Justified exceptions.
    ("POST", "/api/v1/auth/operators/{operator_id}/client-memberships/{client_id}/revoke"):
        "platform-admin membership administration; client_id names the grant, "
        "not a resource the caller acts inside",
    ("POST", "/api/v1/agents/{agent_id}/commands"):
        "audits tenant.access_denied before its 404; needs a denial-audit hook",
    # Migration backlog: clients and sites.
    ("GET", "/api/v1/clients/{client_id}"): _NOT_YET,
    ("GET", "/api/v1/sites/{site_id}"): _NOT_YET,
    ("POST", "/api/v1/sites/{site_id}/installer-package"): _NOT_YET,
    # Migration backlog: alerts.
    ("GET", "/api/v1/monitoring/alerts/{alert_id}"): _NOT_YET,
    ("POST", "/api/v1/monitoring/alerts/{alert_id}/acknowledge"): _NOT_YET,
    ("POST", "/api/v1/monitoring/alerts/{alert_id}/assign"): _NOT_YET,
    ("POST", "/api/v1/monitoring/alerts/{alert_id}/comments"): _NOT_YET,
    ("POST", "/api/v1/monitoring/alerts/{alert_id}/resolve"): _NOT_YET,
    ("GET", "/api/v1/monitoring/alerts/{alert_id}/email-deliveries"): _NOT_YET,
    ("GET", "/api/v1/monitoring/alerts/{alert_id}/webhook-deliveries"): _NOT_YET,
    # Migration backlog: other route files.
    ("POST", "/api/v1/agents/{agent_id}/shell-sessions"): _NOT_YET,
    ("GET", "/api/v1/agents/{agent_id}/shell-sessions/{session_id}"): _NOT_YET,
    ("POST", "/api/v1/agents/{agent_id}/shell-sessions/{session_id}/input"): _NOT_YET,
    ("GET", "/api/v1/agents/{agent_id}/shell-sessions/{session_id}/output"): _NOT_YET,
    ("POST", "/api/v1/agents/{agent_id}/shell-sessions/{session_id}/close"): _NOT_YET,
    ("GET", "/api/v1/agents/{agent_id}/remote-desktop/availability"): _NOT_YET,
    ("POST", "/api/v1/agents/{agent_id}/remote-desktop/launches"): _NOT_YET,
    ("GET", "/api/v1/agents/{agent_id}/remote-desktop/launches/{launch_id}"): _NOT_YET,
    ("POST", "/api/v1/agents/{agent_id}/remote-desktop/launches/{launch_id}/close"):
        _NOT_YET,
    ("GET", "/api/v1/clients/{client_id}/region-policy"): _NOT_YET,
    ("PUT", "/api/v1/clients/{client_id}/region-policy"): _NOT_YET,
    ("DELETE", "/api/v1/clients/{client_id}/region-policy"): _NOT_YET,
    ("GET", "/api/v1/clients/{client_id}/retention-policy"): _NOT_YET,
    ("PUT", "/api/v1/clients/{client_id}/retention-policy"): _NOT_YET,
    ("DELETE", "/api/v1/clients/{client_id}/retention-policy"): _NOT_YET,
}


def _tenant_routes() -> dict[tuple[str, str], APIRoute]:
    routes = {}
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        if not TENANT_ID_PARAMS & set(re.findall(r"{(\w+)}", route.path)):
            continue
        for method in route.methods:
            routes[(method, route.path)] = route
    return routes


def _depends_on_tenant_access(dependant: Dependant) -> bool:
    return any(
        is_tenant_access_dependency(dep.call) or _depends_on_tenant_access(dep)
        for dep in dependant.dependencies
    )


def test_every_tenant_id_route_depends_on_tenant_access():
    ungated = sorted(
        key
        for key, route in _tenant_routes().items()
        if key not in ALLOWLIST and not _depends_on_tenant_access(route.dependant)
    )
    assert ungated == [], (
        "These routes take a tenant-owned id but do not depend on "
        "tenant_access(...); gate them, or add a justified ALLOWLIST entry."
    )


def test_allowlist_has_no_stale_entries():
    routes = _tenant_routes()
    stale = sorted(
        key
        for key in ALLOWLIST
        if key not in routes or _depends_on_tenant_access(routes[key].dependant)
    )
    assert stale == [], "Remove these ALLOWLIST entries: gone or already migrated."


def test_guard_detects_a_tenant_access_dependency():
    """The walker itself must work, or both tests above pass vacuously."""
    gated = _tenant_routes()[("GET", "/api/v1/agents/{agent_id}")]
    assert _depends_on_tenant_access(gated.dependant)
