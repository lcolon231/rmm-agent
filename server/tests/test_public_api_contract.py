# SPDX-License-Identifier: AGPL-3.0-only
"""The committed public API contract matches the running code (issue #72).

* The OpenAPI document is regenerated and compared byte-for-byte.
* Every registry route is mounted, and stable list routes honour the v1
  page/page_size pagination contract.
* A compatibility gate refuses breaking changes to stable operations against
  the committed baseline (removed operations, removed response fields, newly
  required request inputs).
* Production hides the live schema browser unless explicitly opted in.
"""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_public_api_contract.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import json  # noqa: E402
from datetime import date  # noqa: E402

import pytest  # noqa: E402

from app.core import public_api, public_contracts  # noqa: E402
from app.main import app  # noqa: E402

COMMITTED = json.loads(public_contracts.OPENAPI_PATH.read_text(encoding="utf-8"))
DOC = (public_contracts.REPO_ROOT / "docs" / "PUBLIC-API.md").read_text(encoding="utf-8")


def _generated() -> dict:
    return json.loads(public_contracts.render(public_contracts.build_openapi(app)))


def test_committed_openapi_is_current():
    assert _generated() == COMMITTED, (
        "docs/api/openapi-v1.json is stale; run "
        "`python scripts/export_public_contracts.py` and review the diff"
    )


def test_registry_has_no_duplicates_and_every_route_is_documented():
    keys = [(r.method, r.path) for r in public_api.PUBLIC_ROUTES]
    assert len(keys) == len(set(keys))
    for route in public_api.PUBLIC_ROUTES:
        assert route.stability in (public_api.STABLE, public_api.BETA)
        assert f"`{route.method} {route.path}`" in DOC, route


def test_stable_list_routes_follow_the_pagination_contract():
    for route in public_api.PUBLIC_ROUTES:
        if route.pagination is None:
            continue
        if route.stability == public_api.STABLE:
            assert route.pagination == public_api.PAGINATION_PAGE, route
        if route.pagination != public_api.PAGINATION_PAGE:
            continue
        op = COMMITTED["paths"][route.path][route.method.lower()]
        params = {p["name"]: p for p in op.get("parameters", []) if p["in"] == "query"}
        assert params["page"]["schema"]["minimum"] == 1
        assert params["page_size"]["schema"]["minimum"] == 1
        assert params["page_size"]["schema"]["maximum"] <= 100
        ref = op["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
        body = COMMITTED["components"]["schemas"][ref.rsplit("/", 1)[1]]
        assert {"items", "page", "page_size", "total"} <= set(body["properties"])


def test_idempotent_routes_advertise_their_mechanism():
    for route in public_api.PUBLIC_ROUTES:
        op = COMMITTED["paths"][route.path][route.method.lower()]
        if route.idempotency == public_api.IDEMPOTENCY_HEADER:
            assert any(
                p["in"] == "header" and p["name"] == "Idempotency-Key"
                for p in op.get("parameters", [])
            ), route
        elif route.idempotency == public_api.IDEMPOTENCY_REQUEST_ID:
            ref = op["requestBody"]["content"]["application/json"]["schema"]["$ref"]
            body = COMMITTED["components"]["schemas"][ref.rsplit("/", 1)[1]]
            assert "request_id" in body["required"], route
        elif route.mutating:
            pytest.fail(f"mutating public route without idempotency: {route}")


def test_every_operation_declares_the_shared_failures():
    for path, operations in COMMITTED["paths"].items():
        for method, op in operations.items():
            assert {"401", "403", "404", "429"} <= set(op["responses"]), (method, path)
            assert "Retry-After" in op["responses"]["429"]["headers"]
            assert not any(
                p["name"].lower() == "authorization" for p in op.get("parameters", [])
            )
    assert COMMITTED["components"]["securitySchemes"]["bearerAuth"]["scheme"] == "bearer"


def _required_response_fields(spec: dict, schema: dict, seen=None) -> set[str]:
    seen = seen or set()
    if "$ref" in schema:
        name = schema["$ref"].rsplit("/", 1)[1]
        if name in seen:
            return set()
        return _required_response_fields(spec, spec["components"]["schemas"][name], seen | {name})
    return set(schema.get("properties", {}))


def _breaking_changes(baseline: dict, candidate: dict) -> list[str]:
    problems = []
    for path, operations in baseline["paths"].items():
        for method, old in operations.items():
            if old.get("x-nodelink-stability") != public_api.STABLE:
                continue
            new = candidate["paths"].get(path, {}).get(method)
            if new is None:
                problems.append(f"removed {method.upper()} {path}")
                continue
            old_required = {p["name"] for p in old.get("parameters", []) if p.get("required")}
            new_required = {p["name"] for p in new.get("parameters", []) if p.get("required")}
            for name in sorted(new_required - old_required):
                problems.append(f"new required parameter {name} on {method.upper()} {path}")
            old_ok = old["responses"].get("200", {}).get("content", {}).get("application/json", {})
            new_ok = new["responses"].get("200", {}).get("content", {}).get("application/json", {})
            if old_ok:
                lost = _required_response_fields(baseline, old_ok["schema"]) - _required_response_fields(
                    candidate, new_ok.get("schema", {})
                )
                for name in sorted(lost):
                    problems.append(f"response field {name} removed from {method.upper()} {path}")
    return problems


def test_no_breaking_change_to_stable_operations():
    assert _breaking_changes(COMMITTED, _generated()) == []


def test_compatibility_gate_catches_breaking_changes():
    """The gate itself works: removing a route or a field is reported."""
    candidate = json.loads(json.dumps(COMMITTED))
    del candidate["paths"]["/api/v1/agents/{agent_id}"]["get"]
    candidate["components"]["schemas"]["CommandOut"]["properties"].pop("status")
    problems = _breaking_changes(COMMITTED, candidate)
    assert "removed GET /api/v1/agents/{agent_id}" in problems
    assert any("response field status removed" in p for p in problems)


def test_deprecation_headers_follow_rfc_9745_and_8594():
    route = public_api.PublicRoute(
        "GET", "/api/v1/example", deprecated_on=date(2027, 1, 1), sunset_on=date(2027, 7, 1)
    )
    headers = public_api.deprecation_headers(route)
    assert headers["Deprecation"] == "@1798761600"
    assert headers["Sunset"] == "Thu, 01 Jul 2027 00:00:00 GMT"
    assert 'rel="deprecation"' in headers["Link"]
    for deprecated in public_api.deprecations():
        assert deprecated.sunset_on is not None
        assert (deprecated.sunset_on - deprecated.deprecated_on).days >= public_api.DEPRECATION_MINIMUM_DAYS


def test_openapi_browser_is_off_in_production():
    from app.core.config import Settings
    from app.main import openapi_urls

    hidden = openapi_urls(Settings(environment="production", expose_openapi=False))
    assert hidden == {"openapi_url": None, "docs_url": None, "redoc_url": None}
    shown = openapi_urls(Settings(environment="production", expose_openapi=True))
    assert shown["openapi_url"] == "/openapi.json"
    assert openapi_urls(Settings(environment="development"))["docs_url"] == "/docs"
