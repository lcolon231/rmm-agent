# SPDX-License-Identifier: AGPL-3.0-only
"""The versioned public API surface (issue #72) -- the one registry.

Everything under ``/api/v1`` is reachable by the dashboard with an operator
JWT, but only the routes listed here are the *public* contract: the only
routes an API token may call, the only routes exported to the committed
OpenAPI document (``docs/api/openapi-v1.json``), and the only routes covered by
the compatibility and deprecation policy in ``docs/PUBLIC-API.md``.

Adding a route here is a compatibility promise. Removing one, or making a
breaking change to a ``stable`` one, requires the deprecation window below;
``beta`` routes may still change shape between revisions.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
from email.utils import format_datetime

#: Major version, carried in the path (``/api/v1``). A breaking change to a
#: stable route ships as ``/api/v2`` alongside v1, never in place.
API_VERSION = "v1"

#: Date-stamped revision of the v1 contract. Bumped for every additive change
#: to the public surface (new route, new optional field), mirroring the
#: webhook ``api_version`` convention. Sent as ``NodeLink-API-Version``.
API_REVISION = "2026-11-12"

#: Minimum days between a route's ``Deprecation`` date and its ``Sunset``.
DEPRECATION_MINIMUM_DAYS = 180

STABLE = "stable"
BETA = "beta"

#: Pagination styles a public list route may use. ``page`` is the v1 contract
#: (``page``/``page_size`` in, ``items``/``page``/``page_size``/``total`` out);
#: ``limit`` is tolerated only on ``beta`` routes until they conform.
PAGINATION_PAGE = "page"
PAGINATION_LIMIT = "limit"

#: How a mutating route is made safely retryable.
IDEMPOTENCY_HEADER = "header"  # ``Idempotency-Key`` request header
IDEMPOTENCY_REQUEST_ID = "request_id"  # body ``request_id`` replay

PREFIX = f"/api/{API_VERSION}"


@dataclass(frozen=True)
class PublicRoute:
    method: str
    path: str  # route template as FastAPI matches it, e.g. /api/v1/agents/{agent_id}
    stability: str = STABLE
    pagination: str | None = None
    idempotency: str | None = None
    deprecated_on: date | None = None
    sunset_on: date | None = None

    @property
    def mutating(self) -> bool:
        return self.method not in ("GET", "HEAD", "OPTIONS")


PUBLIC_ROUTES: tuple[PublicRoute, ...] = (
    PublicRoute("GET", f"{PREFIX}/api-version"),
    PublicRoute("GET", f"{PREFIX}/endpoints", pagination=PAGINATION_PAGE),
    PublicRoute("GET", f"{PREFIX}/endpoints/{{endpoint_id}}"),
    PublicRoute("GET", f"{PREFIX}/endpoints/{{endpoint_id}}/inventory"),
    PublicRoute("GET", f"{PREFIX}/agents/{{agent_id}}"),
    PublicRoute(
        "POST", f"{PREFIX}/agents/{{agent_id}}/commands",
        idempotency=IDEMPOTENCY_HEADER,
    ),
    PublicRoute(
        "GET", f"{PREFIX}/agents/{{agent_id}}/commands", pagination=PAGINATION_PAGE
    ),
    PublicRoute("GET", f"{PREFIX}/agents/{{agent_id}}/commands/{{command_id}}"),
    PublicRoute(
        "GET", f"{PREFIX}/monitoring/alerts",
        stability=BETA, pagination=PAGINATION_LIMIT,
    ),
    PublicRoute("GET", f"{PREFIX}/monitoring/alerts/{{alert_id}}"),
    PublicRoute(
        "POST", f"{PREFIX}/monitoring/alerts/{{alert_id}}/acknowledge",
        idempotency=IDEMPOTENCY_REQUEST_ID,
    ),
    PublicRoute(
        "POST", f"{PREFIX}/monitoring/alerts/{{alert_id}}/resolve",
        idempotency=IDEMPOTENCY_REQUEST_ID,
    ),
)

_BY_KEY: dict[tuple[str, str], PublicRoute] = {
    (route.method, route.path): route for route in PUBLIC_ROUTES
}


def lookup(method: str, path_template: str | None) -> PublicRoute | None:
    """The registry entry for a matched route template, or ``None``."""
    if path_template is None:
        return None
    return _BY_KEY.get((method.upper(), path_template))


def deprecations() -> list[PublicRoute]:
    return [route for route in PUBLIC_ROUTES if route.deprecated_on is not None]


def deprecation_headers(route: PublicRoute) -> dict[str, str]:
    """RFC 9745 ``Deprecation`` and RFC 8594 ``Sunset`` headers for a route."""
    headers: dict[str, str] = {}
    if route.deprecated_on is not None:
        # RFC 9745: a structured-field date, "@<epoch seconds>".
        headers["Deprecation"] = f"@{int(_midnight_utc(route.deprecated_on).timestamp())}"
        headers["Link"] = '</docs/PUBLIC-API.md#deprecation-policy>; rel="deprecation"'
    if route.sunset_on is not None:
        # RFC 8594: an HTTP-date.
        headers["Sunset"] = format_datetime(_midnight_utc(route.sunset_on), usegmt=True)
    return headers


def _midnight_utc(value: date) -> datetime:
    return datetime(value.year, value.month, value.day, tzinfo=timezone.utc)


def version_document() -> dict:
    """Body of ``GET /api/v1/api-version`` -- what a client can negotiate."""
    from app.core.webhook_catalog import SUPPORTED_WEBHOOK_API_VERSIONS

    return {
        "api_version": API_VERSION,
        "api_revision": API_REVISION,
        "webhook_api_versions": list(SUPPORTED_WEBHOOK_API_VERSIONS),
        "deprecations": [
            {
                "method": route.method,
                "path": route.path,
                "deprecated_on": route.deprecated_on.isoformat()
                if route.deprecated_on else None,
                "sunset_on": route.sunset_on.isoformat() if route.sunset_on else None,
            }
            for route in deprecations()
        ],
    }
