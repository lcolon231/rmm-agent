"""Application configuration loaded from environment variables."""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- Core ---
    app_name: str = "NodeLink RMM"
    environment: str = "development"
    debug: bool = True

    # --- Database ---
    # Example: postgresql+asyncpg://rmm:rmm@localhost:5432/rmm
    database_url: str = "postgresql+asyncpg://rmm:rmm@localhost:5432/rmm"

    # --- Security ---
    # Used to sign server-issued JWTs (dashboard sessions + agent command tokens).
    # Generate with: python -c "import secrets; print(secrets.token_urlsafe(48))"
    secret_key: str = "CHANGE_ME_IN_PRODUCTION"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    # Ed25519 private key (PEM) used to SIGN commands sent to agents.
    # Agents hold the matching public key and verify every command before executing.
    # Generate a keypair with the helper in scripts/gen_command_keys.py
    command_signing_key_path: str = "command_signing_key.pem"

    # --- Agent policy ---
    heartbeat_interval_seconds: int = 60
    # Endpoint is flagged offline after this many missed heartbeats.
    offline_after_missed: int = 3

    @property
    def offline_threshold_seconds(self) -> int:
        return self.heartbeat_interval_seconds * self.offline_after_missed


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
