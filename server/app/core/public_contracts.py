# SPDX-License-Identifier: AGPL-3.0-only
"""Generate the published public-API artifacts from code (issue #72).

* ``docs/api/openapi-v1.json`` -- the OpenAPI document for exactly the routes
  in :mod:`app.core.public_api`, with the token security scheme, the shared
  error envelope, and the rate-limit / idempotency headers.
* ``contracts/test-vectors/webhook-event-v1.json`` -- one signed delivery per
  catalog event, produced by the same payload and header code the sender uses.

Both are committed and diffed by tests, so the published contract cannot drift
from the implementation silently. Regenerate with
``python scripts/export_public_contracts.py``.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

from fastapi import FastAPI

from app.core import public_api, webhook_catalog
from app.core.webhook_notifications import signature_for, signed_headers

REPO_ROOT = Path(__file__).resolve().parents[3]
OPENAPI_PATH = REPO_ROOT / "docs" / "api" / "openapi-v1.json"
WEBHOOK_VECTORS_PATH = REPO_ROOT / "contracts" / "test-vectors" / "webhook-event-v1.json"

_ERROR_SCHEMA = {
    "title": "Error",
    "type": "object",
    "required": ["detail"],
    "properties": {
        "detail": {
            "description": (
                "Human-readable message, or a coded object. Clients branch on "
                "`code`, never on message text."
            ),
            "anyOf": [
                {"type": "string"},
                {
                    "type": "object",
                    "required": ["code"],
                    "properties": {
                        "code": {"type": "string"},
                        "message": {"type": "string"},
                    },
                    "additionalProperties": True,
                },
                {"type": "array", "items": {"type": "object"}},
            ],
        }
    },
}

_RATE_LIMIT_HEADERS = {
    "Retry-After": {"description": "Seconds until the budget refills.", "schema": {"type": "integer"}},
    "RateLimit-Limit": {"description": "Requests allowed per 60 s window.", "schema": {"type": "integer"}},
    "RateLimit-Remaining": {"description": "Requests left in the window.", "schema": {"type": "integer"}},
    "RateLimit-Reset": {"description": "Seconds until the window resets.", "schema": {"type": "integer"}},
}


def _error(description: str, headers: dict | None = None) -> dict:
    response = {
        "description": description,
        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}},
    }
    if headers:
        response["headers"] = headers
    return response


def _collect_refs(node, found: set[str]) -> None:
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/components/schemas/"):
            found.add(ref.rsplit("/", 1)[1])
        for value in node.values():
            _collect_refs(value, found)
    elif isinstance(node, list):
        for value in node:
            _collect_refs(value, found)


def build_openapi(app: FastAPI) -> dict:
    full = copy.deepcopy(app.openapi())
    paths: dict[str, dict] = {}
    for route in public_api.PUBLIC_ROUTES:
        operation = full["paths"].get(route.path, {}).get(route.method.lower())
        if operation is None:
            raise LookupError(f"public route not mounted: {route.method} {route.path}")
        operation = copy.deepcopy(operation)
        # Authentication is the security scheme, not a free-form header.
        operation["parameters"] = [
            param
            for param in operation.get("parameters", [])
            if not (param.get("in") == "header" and param.get("name", "").lower() == "authorization")
        ]
        if not operation["parameters"]:
            operation.pop("parameters")
        operation["tags"] = ["public-v1"]
        operation["x-nodelink-stability"] = route.stability
        if route.pagination:
            operation["x-nodelink-pagination"] = route.pagination
        if route.idempotency:
            operation["x-nodelink-idempotency"] = route.idempotency
        if route.deprecated_on is not None:
            operation["deprecated"] = True
            operation["x-nodelink-sunset"] = (
                route.sunset_on.isoformat() if route.sunset_on else None
            )
        responses = operation.setdefault("responses", {})
        responses.setdefault("401", _error("Missing, invalid, expired, revoked, or out-of-scope credential."))
        responses.setdefault("403", _error("Authenticated, but the role or client-role ceiling forbids this."))
        responses.setdefault("404", _error("Not found, or not visible in the caller's tenant."))
        responses.setdefault("429", _error("API token request budget exhausted.", _RATE_LIMIT_HEADERS))
        paths.setdefault(route.path, {})[route.method.lower()] = operation

    used: set[str] = set()
    _collect_refs(paths, used)
    all_schemas = full.get("components", {}).get("schemas", {})
    pending = set(used)
    while pending:
        name = pending.pop()
        nested: set[str] = set()
        _collect_refs(all_schemas.get(name, {}), nested)
        for item in nested - used:
            used.add(item)
            pending.add(item)
    schemas = {name: all_schemas[name] for name in sorted(used) if name in all_schemas}
    schemas["Error"] = _ERROR_SCHEMA

    return {
        "openapi": full["openapi"],
        "info": {
            "title": "NodeLink Public API",
            "version": public_api.API_REVISION,
            "description": (
                f"Versioned public API {public_api.API_VERSION}. Contract, "
                "pagination, idempotency, rate limits, and deprecation policy: "
                "docs/PUBLIC-API.md. Webhook events: docs/WEBHOOK-EVENTS.md."
            ),
            "license": {"name": "AGPL-3.0-only"},
        },
        "servers": [{"url": "/"}],
        "security": [{"bearerAuth": []}],
        "paths": dict(sorted(paths.items())),
        "components": {
            "schemas": schemas,
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": (
                        "A tenant-scoped API token (`nlk_...`), or an operator "
                        "session JWT. API tokens are accepted only on these routes."
                    ),
                }
            },
        },
    }


def build_webhook_vectors() -> dict:
    vectors = []
    for event in webhook_catalog.CATALOG:
        body = webhook_catalog.example_body(event)
        raw = webhook_catalog.canonical_json(body)
        signature = signature_for(
            webhook_catalog.VECTOR_SECRET, raw.encode("utf-8"), webhook_catalog.VECTOR_TIMESTAMP
        )
        vectors.append(
            {
                "event_type": event.event_type,
                "subscription_value": event.source.value,
                "schema_version": event.schema_version,
                "since": event.since,
                "description": event.description,
                "body": raw,
                "headers": signed_headers(
                    delivery_id=body["delivery_id"],
                    event_id=body["event_id"],
                    timestamp=webhook_catalog.VECTOR_TIMESTAMP,
                    signature=signature,
                    secret_version_id=webhook_catalog.VECTOR_SECRET_VERSION_ID,
                ),
            }
        )
    return {
        "contract": "webhook-event-v1",
        "notes": (
            "Test-only secret. Signature is HMAC-SHA256 over "
            "'v1.' + X-NodeLink-Timestamp + '.' + the exact raw body bytes, "
            "hex-encoded and prefixed 'v1='."
        ),
        "api_version": webhook_catalog.WEBHOOK_API_VERSION,
        "secret": webhook_catalog.VECTOR_SECRET,
        "timestamp": webhook_catalog.VECTOR_TIMESTAMP,
        "vectors": vectors,
    }


def render(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
