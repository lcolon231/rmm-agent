# SPDX-License-Identifier: AGPL-3.0-only
"""Fail-closed production configuration validation.

A deployment declares itself production by setting ENVIRONMENT=production.
From that moment the server refuses to start with any configuration that
would silently weaken its trust boundaries: debug mode, placeholder or weak
secrets, missing command-signing keys, or a plain-HTTP public URL. The checks
collect every violation before failing so an operator fixes one restart's
worth of problems, not one problem per restart.

Non-production environments (development, test) are exempt: local SQLite runs
and CI must keep working with throwaway secrets.
"""
from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from app.core.config import Settings

# Secrets that ship in examples, docs, or defaults. Matching is
# case-insensitive; any of these in production is an unconfigured deployment,
# not a weak choice.
_PLACEHOLDER_SECRETS = {
    "change_me_in_production",
    "changeme",
    "change-me",
    "secret",
    "secret-key",
    "dev",
    "development",
    "test",
    "test-secret",
    "password",
}

# Anything shorter cannot hold enough entropy to sign JWTs safely, whatever
# its content.
_MIN_SECRET_KEY_LENGTH = 32


class ProductionConfigError(RuntimeError):
    """Raised at startup when production configuration is unsafe."""

    def __init__(self, problems: list[str]):
        self.problems = problems
        joined = "\n  - ".join(problems)
        super().__init__(
            "Refusing to start: unsafe production configuration:\n  - " + joined
        )


def is_production(settings: Settings) -> bool:
    return settings.environment.strip().lower() == "production"


def production_config_problems(settings: Settings) -> list[str]:
    """Return every violated production requirement (empty = safe)."""
    from app.core.email_notifications import configuration_problems

    problems: list[str] = []

    if settings.debug:
        problems.append(
            "DEBUG=true is not allowed in production (auto create_all, "
            "permissive failure modes)"
        )

    if settings.enrollment_token_default_expiry_hours <= 0:
        problems.append("ENROLLMENT_TOKEN_DEFAULT_EXPIRY_HOURS must be positive")
    if settings.enrollment_token_max_expiry_days <= 0:
        problems.append("ENROLLMENT_TOKEN_MAX_EXPIRY_DAYS must be positive")
    if not 1 <= settings.enrollment_token_max_uses <= 1000:
        problems.append("ENROLLMENT_TOKEN_MAX_USES must be between 1 and 1000")
    if settings.enrollment_rate_limit_attempts <= 0:
        problems.append("ENROLLMENT_RATE_LIMIT_ATTEMPTS must be positive")

    secret = settings.secret_key.strip()
    if secret.lower() in _PLACEHOLDER_SECRETS:
        problems.append("SECRET_KEY is a known placeholder value; generate a real one")
    elif len(secret) < _MIN_SECRET_KEY_LENGTH:
        problems.append(
            f"SECRET_KEY is shorter than {_MIN_SECRET_KEY_LENGTH} characters; "
            'generate one with: python -c "import secrets; print(secrets.token_urlsafe(48))"'
        )

    if not settings.public_base_url:
        problems.append(
            "PUBLIC_BASE_URL is required in production and must be the HTTPS "
            "URL clients use to reach this deployment"
        )
    else:
        parsed = urlparse(settings.public_base_url)
        if parsed.scheme != "https":
            problems.append(
                f"PUBLIC_BASE_URL must use https:// (got {parsed.scheme or 'no'} scheme); "
                "see docs/DEPLOYMENT-TLS.md for the supported TLS termination topology"
            )
        elif not parsed.hostname:
            problems.append("PUBLIC_BASE_URL has no hostname")
        elif parsed.hostname in ("localhost", "127.0.0.1", "::1"):
            problems.append(
                "PUBLIC_BASE_URL points at loopback; production clients cannot "
                "reach it and TLS certificates cannot be issued for it"
            )

    if settings.command_signing_keyring_path:
        if not Path(settings.command_signing_keyring_path).is_file():
            problems.append(
                f"COMMAND_SIGNING_KEYRING_PATH ({settings.command_signing_keyring_path}) "
                "does not exist; commands cannot be signed"
            )
    elif not Path(settings.command_signing_key_path).is_file():
        problems.append(
            f"COMMAND_SIGNING_KEY_PATH ({settings.command_signing_key_path}) "
            "does not exist; generate keys with scripts/gen_command_keys.py"
        )

    # Multi-factor authentication (issue #67). A deployment that intends to run
    # MFA must be able to state the scope credentials are bound to. Resolving it
    # here, at startup, turns a misconfiguration into a refused boot rather than
    # a 503 the first time an operator reaches for their security key -- and,
    # worse, rather than credentials silently registered under a guessed scope.
    from app.core import mfa

    if mfa.enforcement_mode(settings) != mfa.ENFORCEMENT_OFF:
        try:
            party = mfa.relying_party(settings)
        except mfa.MfaConfigurationError as exc:
            problems.append(f"MFA is enabled but misconfigured: {exc}")
        else:
            insecure = sorted(
                origin for origin in party.origins if not origin.startswith("https://")
            )
            if insecure:
                problems.append(
                    "MFA_ALLOWED_ORIGINS must be https:// in production "
                    f"(got {', '.join(insecure)}); an http origin defeats the "
                    "origin binding that makes WebAuthn phishing-resistant"
                )

    problems.extend(configuration_problems(settings))
    if settings.email_alert_dashboard_base_url:
        dashboard_url = urlparse(settings.email_alert_dashboard_base_url)
        if dashboard_url.scheme != "https":
            problems.append(
                "EMAIL_ALERT_DASHBOARD_BASE_URL must use https:// in production"
            )

    return problems


def ensure_safe_production_config(settings: Settings) -> None:
    """Validate and fail closed. No-op outside production."""
    if not is_production(settings):
        return
    problems = production_config_problems(settings)
    if problems:
        raise ProductionConfigError(problems)
