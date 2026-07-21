# SPDX-License-Identifier: AGPL-3.0-only
"""Client IP derivation with explicit, opt-in proxy trust.

By default the direct socket peer is the client: any X-Forwarded-For header a
caller sends is ignored, so it cannot be spoofed to dodge per-IP rate limits
or pollute audit records. Behind the documented TLS-terminating proxy every
caller shares the proxy's address, which collapses per-IP limiting to one
bucket — deployments in that topology set TRUST_PROXY_HEADERS=true, and MUST
ensure the app port is reachable only through the proxy (see
docs/DEPLOYMENT-TLS.md), because trusting the header from arbitrary peers
reintroduces spoofing.
"""
from __future__ import annotations

from fastapi import Request

from app.core.config import settings


def client_ip(request: Request) -> str:
    direct = request.client.host if request.client else "unknown"
    if not settings.trust_proxy_headers:
        return direct
    forwarded = request.headers.get("x-forwarded-for", "")
    if not forwarded:
        return direct
    # The rightmost entry is the peer our trusted immediate proxy actually
    # saw; anything left of it is caller-controlled and untrustworthy.
    candidate = forwarded.split(",")[-1].strip()
    return candidate or direct
