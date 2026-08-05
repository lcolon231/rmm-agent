# SPDX-License-Identifier: AGPL-3.0-only
"""Durable alert-transition email delivery through a provider boundary (#45).

Alert transitions only enqueue database rows. The scheduler claims a bounded
batch in a short transaction, performs provider calls without database locks,
and then records a sanitized outcome. Provider response bodies and API keys
never enter persistence, logs, metrics, or API responses.
"""
from __future__ import annotations

import html
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parseaddr
from typing import Protocol
from urllib.parse import urlparse

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import metrics
from app.core.config import Settings, settings
from app.core.database import AsyncSessionLocal
from app.models.models import (
    Alert,
    AlertEmailAttempt,
    AlertEmailDelivery,
    AlertEvent,
    EmailAttemptStatus,
    EmailDeliveryStatus,
)

_EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)
_SAFE_PROVIDER_CODE = re.compile(r"^[a-z0-9_-]{1,100}$")
_RESEND_ERROR_CODES = {
    "application_error",
    "concurrent_idempotent_requests",
    "internal_server_error",
    "invalid_access",
    "invalid_from_address",
    "invalid_idempotency_key",
    "invalid_idempotent_request",
    "invalid_parameter",
    "missing_api_key",
    "missing_required_field",
    "not_found",
    "rate_limit_exceeded",
    "restricted_api_key",
    "validation_error",
}
_TRANSITION_LABELS = {
    "opened": "opened",
    "reopened": "reopened",
    "acknowledged": "acknowledged",
    "manual_resolution": "resolved",
    "automatic_recovery": "recovered",
    "policy_revised": "resolved after policy revision",
    "policy_deleted": "resolved after policy deletion",
    "policy_superseded": "resolved after policy supersession",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _valid_email(value: str) -> bool:
    return len(value) <= 320 and _EMAIL_PATTERN.fullmatch(value) is not None


def configured_recipients(config: Settings = settings) -> tuple[str, ...]:
    """Return normalized recipients, or an empty tuple for invalid input."""
    values = tuple(
        dict.fromkeys(
            item.strip().lower()
            for item in config.email_alert_recipients.split(",")
            if item.strip()
        )
    )
    if not values or len(values) > 50 or any(not _valid_email(item) for item in values):
        return ()
    return values


def configuration_problems(config: Settings = settings) -> list[str]:
    """Return safe problem codes/descriptions without secret or address values."""
    provider = config.email_alert_provider.strip().lower()
    if provider not in {"disabled", "resend"}:
        return ["EMAIL_ALERT_PROVIDER must be disabled or resend"]
    if provider == "disabled":
        return []

    problems: list[str] = []
    api_key = config.email_alert_resend_api_key or ""
    if not api_key:
        problems.append("EMAIL_ALERT_RESEND_API_KEY is required for resend")
    elif not api_key.startswith("re_") or len(api_key) > 512:
        problems.append("EMAIL_ALERT_RESEND_API_KEY has an invalid format")
    sender = config.email_alert_sender or ""
    _, sender_address = parseaddr(sender)
    if len(sender) > 500 or not sender_address or not _valid_email(sender_address):
        problems.append("EMAIL_ALERT_SENDER must contain a valid email address")
    if len(config.email_alert_recipients) > 16_000:
        problems.append("EMAIL_ALERT_RECIPIENTS exceeds the configuration size limit")
    raw_recipients = [
        item.strip() for item in config.email_alert_recipients.split(",") if item.strip()
    ]
    if not raw_recipients:
        problems.append("EMAIL_ALERT_RECIPIENTS must contain at least one address")
    elif len(raw_recipients) > 50:
        problems.append("EMAIL_ALERT_RECIPIENTS cannot contain more than 50 addresses")
    elif any(not _valid_email(item) for item in raw_recipients):
        problems.append("EMAIL_ALERT_RECIPIENTS contains an invalid address")
    if config.email_alert_dashboard_base_url:
        parsed = urlparse(config.email_alert_dashboard_base_url)
        if (
            len(config.email_alert_dashboard_base_url) > 2_048
            or parsed.scheme not in {"http", "https"}
            or not parsed.hostname
        ):
            problems.append("EMAIL_ALERT_DASHBOARD_BASE_URL must be an absolute HTTP(S) URL")
    limits = (
        ("EMAIL_ALERT_POLL_INTERVAL_SECONDS", config.email_alert_poll_interval_seconds, 1, 3600),
        ("EMAIL_ALERT_BATCH_SIZE", config.email_alert_batch_size, 1, 100),
        ("EMAIL_ALERT_MAX_ATTEMPTS", config.email_alert_max_attempts, 1, 20),
        ("EMAIL_ALERT_BACKOFF_BASE_SECONDS", config.email_alert_backoff_base_seconds, 1, 3600),
        ("EMAIL_ALERT_BACKOFF_MAX_SECONDS", config.email_alert_backoff_max_seconds, 1, 86400),
        ("EMAIL_ALERT_CLAIM_TIMEOUT_SECONDS", config.email_alert_claim_timeout_seconds, 30, 3600),
        ("EMAIL_ALERT_REQUEST_TIMEOUT_SECONDS", config.email_alert_request_timeout_seconds, 1, 30),
    )
    for name, value, minimum, maximum in limits:
        if not minimum <= value <= maximum:
            problems.append(f"{name} must be between {minimum} and {maximum}")
    if config.email_alert_backoff_max_seconds < config.email_alert_backoff_base_seconds:
        problems.append(
            "EMAIL_ALERT_BACKOFF_MAX_SECONDS must be at least EMAIL_ALERT_BACKOFF_BASE_SECONDS"
        )
    return problems


def configuration_status(config: Settings = settings) -> dict:
    provider = config.email_alert_provider.strip().lower()
    problems = configuration_problems(config)
    return {
        "provider": provider,
        "enabled": provider != "disabled",
        "valid": not problems,
        "problems": problems,
        "recipient_count": len(configured_recipients(config)),
        "sender_configured": bool(config.email_alert_sender),
        "api_key_configured": bool(config.email_alert_resend_api_key),
    }


def mask_recipient(value: str) -> str:
    local, _, domain = value.partition("@")
    if not domain:
        return "***"
    return f"{local[:1]}***@{domain}"


def _render_message(
    alert: Alert, event: AlertEvent, config: Settings = settings
) -> tuple[str, str, str]:
    label = _TRANSITION_LABELS[event.event_type.value]
    subject = f"NodeLink alert {label}: {alert.check_key}"[:500]
    timestamp = _utc(event.created_at).isoformat()
    lines = [
        f"Alert {label}",
        "",
        f"Check: {alert.check_key}",
        f"Endpoint ID: {alert.agent_id}",
        f"Alert ID: {alert.id}",
        f"Generation: {event.generation}",
        f"State: {event.to_state.value if event.to_state else alert.state.value}",
        f"Last result: {alert.last_result_status.value}",
        f"Occurred at: {timestamp}",
    ]
    if alert.last_value is not None:
        lines.append(f"Last value: {alert.last_value:g}")
    if config.email_alert_dashboard_base_url:
        base = config.email_alert_dashboard_base_url.rstrip("/")
        lines.extend(("", f"Open alert: {base}/monitoring/alerts/{alert.id}"))
    lines.extend(("", "This message intentionally excludes check detail and operator comments."))
    text_body = "\n".join(lines)

    safe_label = html.escape(label)
    rows = [
        ("Check", alert.check_key),
        ("Endpoint ID", alert.agent_id),
        ("Alert ID", alert.id),
        ("Generation", str(event.generation)),
        ("State", event.to_state.value if event.to_state else alert.state.value),
        ("Last result", alert.last_result_status.value),
        ("Occurred at", timestamp),
    ]
    if alert.last_value is not None:
        rows.append(("Last value", f"{alert.last_value:g}"))
    table = "".join(
        "<tr><th align=\"left\">"
        + html.escape(key)
        + "</th><td>"
        + html.escape(value)
        + "</td></tr>"
        for key, value in rows
    )
    link = ""
    if config.email_alert_dashboard_base_url:
        href = (
            config.email_alert_dashboard_base_url.rstrip("/")
            + f"/monitoring/alerts/{alert.id}"
        )
        link = f'<p><a href="{html.escape(href, quote=True)}">Open alert</a></p>'
    html_body = (
        f"<h2>Alert {safe_label}</h2><table>{table}</table>{link}"
        "<p><small>This message intentionally excludes check detail and operator comments.</small></p>"
    )
    return subject, text_body, html_body


def enqueue_alert_event(
    db: AsyncSession,
    alert: Alert,
    event: AlertEvent,
    config: Settings = settings,
) -> int:
    """Queue a state-transition event inside the caller's transaction."""
    if event.event_type.value not in _TRANSITION_LABELS:
        return 0
    if config.email_alert_provider.strip().lower() == "disabled":
        return 0
    if configuration_problems(config):
        metrics.increment("email_alert_configuration_error_total")
        return 0
    recipients = configured_recipients(config)
    subject, text_body, html_body = _render_message(alert, event, config)
    queued_at = event.created_at
    suppressed = (
        event.event_type.value in {"opened", "reopened"}
        and alert.suppression_window_id is not None
    )
    for recipient in recipients:
        db.add(
            AlertEmailDelivery(
                id=str(uuid.uuid4()),
                alert_id=alert.id,
                alert_event_id=event.id,
                generation=event.generation,
                event_type=event.event_type,
                recipient=recipient,
                subject=subject,
                text_body=text_body,
                html_body=html_body,
                status=(
                    EmailDeliveryStatus.suppressed
                    if suppressed else EmailDeliveryStatus.pending
                ),
                max_attempts=config.email_alert_max_attempts,
                next_attempt_at=queued_at,
                created_at=queued_at,
                updated_at=queued_at,
            )
        )
    metrics.increment(
        "email_alert_suppressed_total" if suppressed else "email_alert_queued_total",
        len(recipients),
    )
    return len(recipients)


class EmailProvider(Protocol):
    async def send(self, delivery: AlertEmailDelivery) -> str: ...


class ProviderError(RuntimeError):
    def __init__(self, code: str, *, retryable: bool):
        safe_code = code.lower() if _SAFE_PROVIDER_CODE.fullmatch(code.lower()) else "provider_error"
        super().__init__(safe_code)
        self.code = safe_code
        self.retryable = retryable


class ResendEmailProvider:
    def __init__(self, config: Settings = settings):
        self._api_key = config.email_alert_resend_api_key or ""
        self._sender = config.email_alert_sender or ""
        self._timeout = config.email_alert_request_timeout_seconds

    async def send(self, delivery: AlertEmailDelivery) -> str:
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Idempotency-Key": f"alert-email/{delivery.id}",
        }
        payload = {
            "from": self._sender,
            "to": [delivery.recipient],
            "subject": delivery.subject,
            "text": delivery.text_body,
            "html": delivery.html_body,
        }
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    "https://api.resend.com/emails", headers=headers, json=payload
                )
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            raise ProviderError("network_error", retryable=True) from exc

        provider_code = ""
        try:
            body = response.json()
            candidate = body.get("name") if isinstance(body, dict) else None
            if isinstance(candidate, str) and candidate.lower() in _RESEND_ERROR_CODES:
                provider_code = candidate.lower()
        except ValueError:
            body = None
        if response.status_code >= 400:
            retryable = (
                response.status_code in {408, 425, 429}
                or response.status_code >= 500
                or provider_code == "concurrent_idempotent_requests"
            )
            raise ProviderError(
                provider_code or f"http_{response.status_code}", retryable=retryable
            )
        message_id = body.get("id") if isinstance(body, dict) else None
        try:
            safe_message_id = str(uuid.UUID(message_id)) if isinstance(message_id, str) else ""
        except ValueError:
            safe_message_id = ""
        if not safe_message_id:
            raise ProviderError("invalid_provider_response", retryable=True)
        return safe_message_id


def build_provider(config: Settings = settings) -> EmailProvider | None:
    if configuration_problems(config):
        return None
    if config.email_alert_provider.strip().lower() == "resend":
        return ResendEmailProvider(config)
    return None


@dataclass(frozen=True)
class DeliveryRun:
    claimed: int = 0
    sent: int = 0
    retrying: int = 0
    failed: int = 0


async def _recover_expired_claims(db: AsyncSession, config: Settings, now: datetime) -> int:
    cutoff = now - timedelta(seconds=config.email_alert_claim_timeout_seconds)
    deliveries = list(
        (
            await db.execute(
                select(AlertEmailDelivery)
                .where(
                    AlertEmailDelivery.status == EmailDeliveryStatus.sending,
                    AlertEmailDelivery.claimed_at < cutoff,
                )
                .order_by(AlertEmailDelivery.claimed_at, AlertEmailDelivery.id)
                .limit(config.email_alert_batch_size)
                .with_for_update(skip_locked=True)
            )
        ).scalars().all()
    )
    if not deliveries:
        return 0
    attempts = list(
        (
            await db.execute(
                select(AlertEmailAttempt).where(
                    AlertEmailAttempt.delivery_id.in_(
                        [item.id for item in deliveries]
                    ),
                    AlertEmailAttempt.status == EmailAttemptStatus.sending,
                )
            )
        ).scalars().all()
    )
    attempts_by_delivery = {item.delivery_id: item for item in attempts}
    for delivery in deliveries:
        retrying = delivery.attempt_count < delivery.max_attempts
        delivery.status = (
            EmailDeliveryStatus.retrying if retrying else EmailDeliveryStatus.failed
        )
        if retrying:
            delivery.next_attempt_at = now
        delivery.claimed_at = None
        delivery.last_error_code = "worker_lease_expired"
        delivery.updated_at = now
        attempt = attempts_by_delivery.get(delivery.id)
        if attempt is not None:
            attempt.status = (
                EmailAttemptStatus.retrying if retrying else EmailAttemptStatus.failed
            )
            attempt.error_code = "worker_lease_expired"
            attempt.completed_at = now
    return len(deliveries)


async def _claim_due(config: Settings, now: datetime) -> list[tuple[AlertEmailDelivery, str]]:
    async with AsyncSessionLocal() as db:
        recovered = await _recover_expired_claims(db, config, now)
        if recovered:
            metrics.increment("email_alert_claim_recovered_total", recovered)
            await db.flush()
        rows = list(
            (
                await db.execute(
                    select(AlertEmailDelivery)
                    .where(
                        AlertEmailDelivery.status.in_(
                            [EmailDeliveryStatus.pending, EmailDeliveryStatus.retrying]
                        ),
                        AlertEmailDelivery.next_attempt_at <= now,
                    )
                    .order_by(
                        AlertEmailDelivery.next_attempt_at,
                        AlertEmailDelivery.created_at,
                        AlertEmailDelivery.id,
                    )
                    .limit(config.email_alert_batch_size)
                    .with_for_update(skip_locked=True)
                )
            ).scalars().all()
        )
        claimed: list[tuple[AlertEmailDelivery, str]] = []
        for delivery in rows:
            delivery.status = EmailDeliveryStatus.sending
            delivery.attempt_count += 1
            delivery.claimed_at = now
            delivery.updated_at = now
            attempt_id = str(uuid.uuid4())
            db.add(
                AlertEmailAttempt(
                    id=attempt_id,
                    delivery_id=delivery.id,
                    attempt_number=delivery.attempt_count,
                    status=EmailAttemptStatus.sending,
                    created_at=now,
                )
            )
            claimed.append((delivery, attempt_id))
        await db.commit()
        return claimed


def _retry_delay(config: Settings, attempt_number: int) -> int:
    return min(
        config.email_alert_backoff_max_seconds,
        config.email_alert_backoff_base_seconds * (2 ** max(0, attempt_number - 1)),
    )


async def _complete_attempt(
    delivery_id: str,
    attempt_id: str,
    *,
    provider_message_id: str | None,
    error: ProviderError | None,
    config: Settings,
) -> EmailDeliveryStatus:
    completed_at = _now()
    async with AsyncSessionLocal() as db:
        delivery = await db.scalar(
            select(AlertEmailDelivery)
            .where(AlertEmailDelivery.id == delivery_id)
            .with_for_update()
        )
        attempt = await db.get(AlertEmailAttempt, attempt_id)
        if delivery is None or attempt is None:
            await db.rollback()
            return EmailDeliveryStatus.failed
        if provider_message_id is not None:
            delivery.status = EmailDeliveryStatus.sent
            delivery.provider_message_id = provider_message_id
            delivery.last_error_code = None
            delivery.sent_at = completed_at
            attempt.status = EmailAttemptStatus.sent
            attempt.provider_message_id = provider_message_id
        else:
            assert error is not None
            retrying = error.retryable and delivery.attempt_count < delivery.max_attempts
            delivery.status = (
                EmailDeliveryStatus.retrying if retrying else EmailDeliveryStatus.failed
            )
            delivery.last_error_code = error.code
            attempt.status = (
                EmailAttemptStatus.retrying if retrying else EmailAttemptStatus.failed
            )
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
    provider: EmailProvider | None = None,
) -> DeliveryRun:
    """Process one bounded batch. Safe to run concurrently across workers."""
    selected_provider = provider or build_provider(config)
    if selected_provider is None:
        return DeliveryRun()
    claimed = await _claim_due(config, _now())
    sent = retrying = failed = 0
    for delivery, attempt_id in claimed:
        try:
            provider_message_id = await selected_provider.send(delivery)
            outcome = await _complete_attempt(
                delivery.id,
                attempt_id,
                provider_message_id=provider_message_id,
                error=None,
                config=config,
            )
        except ProviderError as exc:
            outcome = await _complete_attempt(
                delivery.id,
                attempt_id,
                provider_message_id=None,
                error=exc,
                config=config,
            )
        except Exception:
            outcome = await _complete_attempt(
                delivery.id,
                attempt_id,
                provider_message_id=None,
                error=ProviderError("provider_error", retryable=True),
                config=config,
            )
        if outcome == EmailDeliveryStatus.sent:
            sent += 1
        elif outcome == EmailDeliveryStatus.retrying:
            retrying += 1
        else:
            failed += 1
    metrics.increment("email_alert_sent_total", sent)
    metrics.increment("email_alert_retrying_total", retrying)
    metrics.increment("email_alert_failed_total", failed)
    return DeliveryRun(claimed=len(claimed), sent=sent, retrying=retrying, failed=failed)


async def delivery_counts(db: AsyncSession) -> dict[str, int]:
    rows = (
        await db.execute(
            select(AlertEmailDelivery.status, func.count(AlertEmailDelivery.id)).group_by(
                AlertEmailDelivery.status
            )
        )
    ).all()
    counts = {item.value: 0 for item in EmailDeliveryStatus}
    counts.update({status.value: count for status, count in rows})
    return counts
