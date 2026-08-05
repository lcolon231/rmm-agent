# SPDX-License-Identifier: AGPL-3.0-only
"""Durable, versioned, SSRF-safe signed webhook delivery (#46).

Destinations are HTTPS-only. Every attempt resolves all A/AAAA records,
rejects the complete result when any address is not globally routable, and
connects directly to one validated address while preserving TLS SNI and
hostname verification. Redirects and response bodies are never followed.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import socket
import ssl
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol
from urllib.parse import SplitResult, urlsplit, urlunsplit

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import metrics
from app.core.config import Settings, settings
from app.core.database import AsyncSessionLocal
from app.models.models import (
    Alert,
    AlertEvent,
    AlertWebhookAttempt,
    AlertWebhookDelivery,
    WebhookAttemptStatus,
    WebhookDeliveryStatus,
    WebhookEndpoint,
    WebhookSecretVersion,
)

WEBHOOK_API_VERSION = "2026-08-05"
SIGNATURE_VERSION = "v1"
MAX_PAYLOAD_BYTES = 64 * 1024
MAX_RESPONSE_HEADER_BYTES = 16 * 1024
SUPPORTED_EVENT_TYPES = frozenset(
    {
        "opened",
        "reopened",
        "acknowledged",
        "manual_resolution",
        "automatic_recovery",
        "policy_revised",
        "policy_deleted",
        "policy_superseded",
    }
)
_DNS_NAME = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$"
)
_SAFE_ERROR_CODE = re.compile(r"^[a-z0-9_-]{1,100}$")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _iso_z(value: datetime) -> str:
    return _utc(value).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class WebhookError(RuntimeError):
    """Sanitized destination, transport, or secret failure."""

    def __init__(
        self,
        code: str,
        *,
        state: str = "unavailable",
        retryable: bool,
        http_status: int | None = None,
    ):
        safe_code = code.lower()
        if not _SAFE_ERROR_CODE.fullmatch(safe_code):
            safe_code = "webhook_error"
        super().__init__(safe_code)
        self.code = safe_code
        self.state = state
        self.retryable = retryable
        self.http_status = http_status


@dataclass(frozen=True)
class Destination:
    url: str
    host: str
    port: int
    request_target: str
    addresses: tuple[str, ...] = ()


def normalize_destination(url: str) -> Destination:
    """Parse a destination without performing DNS or exposing it in errors."""
    value = url.strip()
    if not value or len(value) > 2_048 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise WebhookError("invalid_url", state="invalid", retryable=False)
    try:
        parsed = urlsplit(value)
        port = parsed.port
        hostname = parsed.hostname
    except ValueError as exc:
        raise WebhookError("invalid_url", state="invalid", retryable=False) from exc
    if parsed.scheme.lower() != "https":
        raise WebhookError("unsupported_scheme", state="unsupported", retryable=False)
    if parsed.username is not None or parsed.password is not None:
        raise WebhookError("userinfo_not_allowed", state="unsupported", retryable=False)
    if parsed.fragment:
        raise WebhookError("fragment_not_allowed", state="unsupported", retryable=False)
    if not hostname:
        raise WebhookError("missing_hostname", state="invalid", retryable=False)
    if port not in (None, 443):
        raise WebhookError("unsupported_port", state="unsupported", retryable=False)
    try:
        host = hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise WebhookError("invalid_hostname", state="invalid", retryable=False) from exc
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
        if not _DNS_NAME.fullmatch(host) or host == "localhost" or host.endswith(".local"):
            raise WebhookError("invalid_hostname", state="invalid", retryable=False)
    if literal is not None and not literal.is_global:
        raise WebhookError("private_address", state="invalid", retryable=False)

    path = parsed.path or "/"
    target = path + (f"?{parsed.query}" if parsed.query else "")
    authority = f"[{host}]" if literal is not None and literal.version == 6 else host
    canonical = urlunsplit(SplitResult("https", authority, path, parsed.query, ""))
    return Destination(canonical, host, 443, target)


async def validate_destination(
    url: str, config: Settings = settings
) -> Destination:
    """Resolve and validate every address to prevent mixed/DNS-rebinding targets."""
    destination = normalize_destination(url)
    try:
        literal = ipaddress.ip_address(destination.host)
    except ValueError:
        literal = None
    if literal is not None:
        return Destination(**{**destination.__dict__, "addresses": (str(literal),)})

    loop = asyncio.get_running_loop()
    try:
        answers = await asyncio.wait_for(
            loop.getaddrinfo(
                destination.host,
                destination.port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            ),
            timeout=config.webhook_dns_timeout_seconds,
        )
    except (asyncio.TimeoutError, OSError, socket.gaierror) as exc:
        raise WebhookError(
            "dns_unavailable", state="unavailable", retryable=True
        ) from exc
    addresses: set[str] = set()
    for answer in answers:
        try:
            address = ipaddress.ip_address(answer[4][0])
        except (ValueError, IndexError) as exc:
            raise WebhookError(
                "invalid_dns_answer", state="invalid", retryable=False
            ) from exc
        if not address.is_global:
            raise WebhookError("private_address", state="invalid", retryable=False)
        addresses.add(str(address))
    if not addresses:
        raise WebhookError("dns_unavailable", state="unavailable", retryable=True)
    return Destination(
        destination.url,
        destination.host,
        destination.port,
        destination.request_target,
        tuple(sorted(addresses, key=lambda item: (ipaddress.ip_address(item).version, item))),
    )


def mask_destination(url: str) -> str:
    """Return a diagnostics-safe origin without path or query values."""
    try:
        destination = normalize_destination(url)
    except WebhookError:
        return "invalid destination"
    host = destination.host
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None and literal.version == 6:
        host = f"[{host}]"
    elif "." in host:
        labels = host.split(".")
        if len(labels) > 2:
            host = "*." + ".".join(labels[-2:])
    return f"https://{host}/…"


def _decode_encryption_key(config: Settings) -> bytes:
    value = config.webhook_secret_encryption_key or ""
    try:
        key = base64.b64decode(value, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise WebhookError(
            "encryption_key_unavailable", state="unavailable", retryable=True
        ) from exc
    if len(key) != 32:
        raise WebhookError(
            "encryption_key_unavailable", state="unavailable", retryable=True
        )
    return key


def encryption_key_configured(config: Settings = settings) -> bool:
    try:
        _decode_encryption_key(config)
    except WebhookError:
        return False
    return True


def generate_endpoint_secret() -> str:
    return "whsec_" + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")


def _secret_aad(endpoint_id: str, secret_id: str, version: int) -> bytes:
    return f"nodelink-webhook:{endpoint_id}:{secret_id}:{version}".encode("ascii")


def encrypt_secret(
    secret: str,
    *,
    endpoint_id: str,
    secret_id: str,
    version: int,
    config: Settings = settings,
) -> str:
    key = _decode_encryption_key(config)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(
        nonce, secret.encode("ascii"), _secret_aad(endpoint_id, secret_id, version)
    )
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def decrypt_secret(
    encrypted: str,
    *,
    endpoint_id: str,
    secret_id: str,
    version: int,
    config: Settings = settings,
) -> str:
    key = _decode_encryption_key(config)
    try:
        raw = base64.b64decode(encrypted, altchars=b"-_", validate=True)
        if len(raw) < 29:
            raise ValueError("ciphertext too short")
        plaintext = AESGCM(key).decrypt(
            raw[:12], raw[12:], _secret_aad(endpoint_id, secret_id, version)
        )
        return plaintext.decode("ascii")
    except Exception as exc:
        if isinstance(exc, WebhookError):
            raise
        raise WebhookError(
            "secret_decryption_failed", state="unavailable", retryable=True
        ) from exc


def signature_for(secret: str, payload: bytes, timestamp: int) -> str:
    signed = f"{SIGNATURE_VERSION}.{timestamp}.".encode("ascii") + payload
    digest = hmac.new(secret.encode("ascii"), signed, hashlib.sha256).hexdigest()
    return f"{SIGNATURE_VERSION}={digest}"


def build_payload(
    alert: Alert, event: AlertEvent, *, delivery_id: str
) -> str:
    body = {
        "api_version": WEBHOOK_API_VERSION,
        "delivery_id": delivery_id,
        "event_id": event.id,
        "event_type": f"monitoring.alert.{event.event_type.value}",
        "occurred_at": _iso_z(event.created_at),
        "data": {
            "alert": {
                "id": alert.id,
                "endpoint_id": alert.agent_id,
                "policy_id": alert.policy_id,
                "policy_revision_id": alert.policy_revision_id,
                "check_key": alert.check_key,
                "generation": event.generation,
                "from_state": event.from_state.value if event.from_state else None,
                "to_state": event.to_state.value if event.to_state else alert.state.value,
                "result_status": alert.last_result_status.value,
                "last_value": alert.last_value,
            }
        },
    }
    payload = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    if len(payload.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        raise WebhookError("payload_too_large", state="invalid", retryable=False)
    return payload


async def enqueue_alert_event(
    db: AsyncSession,
    alert: Alert,
    event: AlertEvent,
    config: Settings = settings,
) -> int:
    """Snapshot one safe payload per active endpoint in the caller transaction."""
    if event.event_type.value not in SUPPORTED_EVENT_TYPES:
        return 0
    endpoints = list(
        (
            await db.execute(
                select(WebhookEndpoint).where(
                    WebhookEndpoint.enabled.is_(True),
                    WebhookEndpoint.deleted_at.is_(None),
                )
            )
        ).scalars().all()
    )
    endpoints = [
        endpoint
        for endpoint in endpoints
        if event.event_type.value in set(endpoint.event_types or [])
    ]
    if not endpoints:
        return 0
    secret_rows = list(
        (
            await db.execute(
                select(WebhookSecretVersion).where(
                    WebhookSecretVersion.endpoint_id.in_(
                        [endpoint.id for endpoint in endpoints]
                    )
                )
            )
        ).scalars().all()
    )
    secrets_by_version = {
        (item.endpoint_id, item.version): item for item in secret_rows
    }
    suppressed = (
        event.event_type.value in {"opened", "reopened"}
        and alert.suppression_window_id is not None
    )
    queued = 0
    for endpoint in endpoints:
        secret_version = secrets_by_version.get(
            (endpoint.id, endpoint.current_secret_version)
        )
        if secret_version is None:
            metrics.increment("webhook_configuration_error_total")
            continue
        delivery_id = str(uuid.uuid4())
        payload = build_payload(alert, event, delivery_id=delivery_id)
        occurred_at = _utc(event.created_at)
        db.add(
            AlertWebhookDelivery(
                id=delivery_id,
                endpoint_id=endpoint.id,
                secret_version_id=secret_version.id,
                alert_id=alert.id,
                alert_event_id=event.id,
                generation=event.generation,
                event_type=event.event_type,
                destination_url=endpoint.url,
                payload=payload,
                signature_timestamp=int(occurred_at.timestamp()),
                status=(
                    WebhookDeliveryStatus.suppressed
                    if suppressed
                    else WebhookDeliveryStatus.pending
                ),
                max_attempts=config.webhook_max_attempts,
                next_attempt_at=occurred_at,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        queued += 1
    metrics.increment(
        "webhook_suppressed_total" if suppressed else "webhook_queued_total",
        queued,
    )
    return queued


class WebhookSender(Protocol):
    async def send(self, delivery: AlertWebhookDelivery, secret: str) -> int: ...


class PinnedHTTPSWebhookSender:
    def __init__(self, config: Settings = settings):
        self._config = config
        self._ssl_context = ssl.create_default_context()

    async def send(self, delivery: AlertWebhookDelivery, secret: str) -> int:
        destination = await validate_destination(
            delivery.destination_url, self._config
        )
        address = destination.addresses[0]
        payload = delivery.payload.encode("utf-8")
        signature = signature_for(secret, payload, delivery.signature_timestamp)
        try:
            literal_host = ipaddress.ip_address(destination.host)
        except ValueError:
            literal_host = None
        host_header = (
            f"[{destination.host}]"
            if literal_host is not None and literal_host.version == 6
            else destination.host
        )
        headers = {
            "Host": host_header,
            "User-Agent": "NodeLink-Webhooks/1",
            "Content-Type": "application/json",
            "Content-Length": str(len(payload)),
            "Connection": "close",
            "Idempotency-Key": f"nodelink-webhook/{delivery.id}",
            "X-NodeLink-Webhook-Version": WEBHOOK_API_VERSION,
            "X-NodeLink-Event-Id": delivery.alert_event_id,
            "X-NodeLink-Delivery-Id": delivery.id,
            "X-NodeLink-Timestamp": str(delivery.signature_timestamp),
            "X-NodeLink-Signature": signature,
            "X-NodeLink-Key-Id": delivery.secret_version_id,
        }
        request = (
            f"POST {destination.request_target} HTTP/1.1\r\n"
            + "".join(f"{name}: {value}\r\n" for name, value in headers.items())
            + "\r\n"
        ).encode("ascii") + payload
        timeout = self._config.webhook_request_timeout_seconds
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    address,
                    destination.port,
                    ssl=self._ssl_context,
                    server_hostname=destination.host,
                    ssl_handshake_timeout=timeout,
                    limit=MAX_RESPONSE_HEADER_BYTES,
                ),
                timeout=timeout,
            )
            writer.write(request)
            await asyncio.wait_for(writer.drain(), timeout=timeout)
            status_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            header_bytes = len(status_line)
            if not status_line.endswith(b"\n") or len(status_line) > 4_096:
                raise WebhookError(
                    "invalid_http_response", retryable=True
                )
            try:
                status_parts = status_line.decode("iso-8859-1").strip().split(" ", 2)
                if len(status_parts) < 2:
                    raise ValueError("missing HTTP status")
                protocol, status_text = status_parts[:2]
                status_code = int(status_text)
            except (UnicodeDecodeError, ValueError) as exc:
                raise WebhookError(
                    "invalid_http_response", retryable=True
                ) from exc
            if protocol not in {"HTTP/1.0", "HTTP/1.1"} or not 100 <= status_code <= 599:
                raise WebhookError("invalid_http_response", retryable=True)
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=timeout)
                header_bytes += len(line)
                if header_bytes > MAX_RESPONSE_HEADER_BYTES or not line:
                    raise WebhookError("invalid_http_response", retryable=True)
                if line in {b"\r\n", b"\n"}:
                    break
            if 200 <= status_code < 300:
                return status_code
            retryable = status_code in {408, 425, 429} or status_code >= 500
            raise WebhookError(
                f"http_{status_code}",
                state="unavailable" if retryable else "invalid",
                retryable=retryable,
                http_status=status_code,
            )
        except WebhookError:
            raise
        except (asyncio.TimeoutError, OSError, ssl.SSLError, ValueError) as exc:
            raise WebhookError("network_error", retryable=True) from exc
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass


@dataclass(frozen=True)
class DeliveryRun:
    claimed: int = 0
    delivered: int = 0
    retrying: int = 0
    failed: int = 0


async def _recover_expired_claims(
    db: AsyncSession, config: Settings, now: datetime
) -> int:
    cutoff = now - timedelta(seconds=config.webhook_claim_timeout_seconds)
    deliveries = list(
        (
            await db.execute(
                select(AlertWebhookDelivery)
                .where(
                    AlertWebhookDelivery.status == WebhookDeliveryStatus.sending,
                    AlertWebhookDelivery.claimed_at < cutoff,
                )
                .order_by(
                    AlertWebhookDelivery.claimed_at, AlertWebhookDelivery.id
                )
                .limit(config.webhook_batch_size)
                .with_for_update(skip_locked=True)
            )
        ).scalars().all()
    )
    if not deliveries:
        return 0
    attempts = list(
        (
            await db.execute(
                select(AlertWebhookAttempt).where(
                    AlertWebhookAttempt.delivery_id.in_(
                        [item.id for item in deliveries]
                    ),
                    AlertWebhookAttempt.status == WebhookAttemptStatus.sending,
                )
            )
        ).scalars().all()
    )
    attempts_by_delivery = {item.delivery_id: item for item in attempts}
    for delivery in deliveries:
        retrying = delivery.attempt_count < delivery.max_attempts
        delivery.status = (
            WebhookDeliveryStatus.retrying
            if retrying
            else WebhookDeliveryStatus.failed
        )
        if retrying:
            delivery.next_attempt_at = now
        delivery.claimed_at = None
        delivery.last_error_code = "worker_lease_expired"
        delivery.updated_at = now
        attempt = attempts_by_delivery.get(delivery.id)
        if attempt is not None:
            attempt.status = (
                WebhookAttemptStatus.retrying
                if retrying
                else WebhookAttemptStatus.failed
            )
            attempt.error_code = "worker_lease_expired"
            attempt.completed_at = now
    return len(deliveries)


async def _claim_due(
    config: Settings, now: datetime
) -> list[tuple[AlertWebhookDelivery, str]]:
    async with AsyncSessionLocal() as db:
        recovered = await _recover_expired_claims(db, config, now)
        if recovered:
            metrics.increment("webhook_claim_recovered_total", recovered)
            await db.flush()
        rows = list(
            (
                await db.execute(
                    select(AlertWebhookDelivery)
                    .where(
                        AlertWebhookDelivery.status.in_(
                            [
                                WebhookDeliveryStatus.pending,
                                WebhookDeliveryStatus.retrying,
                            ]
                        ),
                        AlertWebhookDelivery.next_attempt_at <= now,
                    )
                    .order_by(
                        AlertWebhookDelivery.next_attempt_at,
                        AlertWebhookDelivery.created_at,
                        AlertWebhookDelivery.id,
                    )
                    .limit(config.webhook_batch_size)
                    .with_for_update(skip_locked=True)
                )
            ).scalars().all()
        )
        claimed: list[tuple[AlertWebhookDelivery, str]] = []
        for delivery in rows:
            delivery.status = WebhookDeliveryStatus.sending
            delivery.attempt_count += 1
            delivery.claimed_at = now
            delivery.updated_at = now
            attempt_id = str(uuid.uuid4())
            db.add(
                AlertWebhookAttempt(
                    id=attempt_id,
                    delivery_id=delivery.id,
                    attempt_number=delivery.attempt_count,
                    status=WebhookAttemptStatus.sending,
                    created_at=now,
                )
            )
            claimed.append((delivery, attempt_id))
        await db.commit()
        return claimed


def _retry_delay(config: Settings, attempt_number: int) -> int:
    return min(
        config.webhook_backoff_max_seconds,
        config.webhook_backoff_base_seconds * (2 ** max(0, attempt_number - 1)),
    )


async def _load_secret(
    delivery: AlertWebhookDelivery, config: Settings
) -> str:
    async with AsyncSessionLocal() as db:
        endpoint = await db.get(WebhookEndpoint, delivery.endpoint_id)
        if endpoint is None or not endpoint.enabled or endpoint.deleted_at is not None:
            raise WebhookError(
                "endpoint_disabled", state="invalid", retryable=False
            )
        secret_version = await db.get(
            WebhookSecretVersion, delivery.secret_version_id
        )
        if secret_version is None or secret_version.endpoint_id != endpoint.id:
            raise WebhookError(
                "secret_version_unavailable", state="unavailable", retryable=True
            )
        return decrypt_secret(
            secret_version.encrypted_secret,
            endpoint_id=endpoint.id,
            secret_id=secret_version.id,
            version=secret_version.version,
            config=config,
        )


async def _complete_attempt(
    delivery_id: str,
    attempt_id: str,
    *,
    http_status: int | None,
    error: WebhookError | None,
    config: Settings,
) -> WebhookDeliveryStatus:
    completed_at = _now()
    async with AsyncSessionLocal() as db:
        delivery = await db.scalar(
            select(AlertWebhookDelivery)
            .where(AlertWebhookDelivery.id == delivery_id)
            .with_for_update()
        )
        attempt = await db.get(AlertWebhookAttempt, attempt_id)
        if delivery is None or attempt is None:
            await db.rollback()
            return WebhookDeliveryStatus.failed
        if error is None:
            delivery.status = WebhookDeliveryStatus.delivered
            delivery.last_http_status = http_status
            delivery.last_error_code = None
            delivery.delivered_at = completed_at
            attempt.status = WebhookAttemptStatus.delivered
            attempt.http_status = http_status
        else:
            retrying = error.retryable and delivery.attempt_count < delivery.max_attempts
            delivery.status = (
                WebhookDeliveryStatus.retrying
                if retrying
                else WebhookDeliveryStatus.failed
            )
            delivery.last_http_status = error.http_status
            delivery.last_error_code = error.code
            attempt.status = (
                WebhookAttemptStatus.retrying
                if retrying
                else WebhookAttemptStatus.failed
            )
            attempt.http_status = error.http_status
            attempt.error_code = error.code
            if retrying:
                delivery.next_attempt_at = completed_at + timedelta(
                    seconds=_retry_delay(config, delivery.attempt_count)
                )
        delivery.claimed_at = None
        delivery.updated_at = completed_at
        attempt.completed_at = completed_at
        await db.commit()
        return delivery.status


async def process_due_deliveries(
    config: Settings = settings,
    *,
    sender: WebhookSender | None = None,
) -> DeliveryRun:
    """Process one bounded batch without holding locks during network I/O."""
    selected_sender = sender or PinnedHTTPSWebhookSender(config)
    claimed = await _claim_due(config, _now())
    delivered = retrying = failed = 0
    for delivery, attempt_id in claimed:
        try:
            secret = await _load_secret(delivery, config)
            http_status = await selected_sender.send(delivery, secret)
            outcome = await _complete_attempt(
                delivery.id,
                attempt_id,
                http_status=http_status,
                error=None,
                config=config,
            )
        except WebhookError as exc:
            outcome = await _complete_attempt(
                delivery.id,
                attempt_id,
                http_status=None,
                error=exc,
                config=config,
            )
        except Exception:
            outcome = await _complete_attempt(
                delivery.id,
                attempt_id,
                http_status=None,
                error=WebhookError("webhook_error", retryable=True),
                config=config,
            )
        if outcome == WebhookDeliveryStatus.delivered:
            delivered += 1
        elif outcome == WebhookDeliveryStatus.retrying:
            retrying += 1
        else:
            failed += 1
    metrics.increment("webhook_delivered_total", delivered)
    metrics.increment("webhook_retrying_total", retrying)
    metrics.increment("webhook_failed_total", failed)
    return DeliveryRun(
        claimed=len(claimed),
        delivered=delivered,
        retrying=retrying,
        failed=failed,
    )


async def delivery_counts(db: AsyncSession) -> dict[str, int]:
    rows = (
        await db.execute(
            select(
                AlertWebhookDelivery.status, func.count(AlertWebhookDelivery.id)
            ).group_by(AlertWebhookDelivery.status)
        )
    ).all()
    counts = {item.value: 0 for item in WebhookDeliveryStatus}
    counts.update({status.value: count for status, count in rows})
    return counts
