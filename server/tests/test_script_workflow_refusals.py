# SPDX-License-Identifier: AGPL-3.0-only
"""Refusal paths of the script library and scheduled-task APIs (issue #284).

Every test here drives one ``raise HTTPException`` branch that the happy-path
suites never reach: missing targets, configured ceilings, deprecated or
already-final state, a cron expression that can never fire, and the
``IntegrityError`` fallbacks that stand behind the application's own
pre-checks. Each asserts the status code and the stable detail/code a client
keys on.

The ``IntegrityError`` branches exist for a lost race (a concurrent writer
committing between the pre-check and the flush). SQLite cannot interleave two
writers inside one test, so those tests inject the database refusal at the
flush and assert the handler maps it to its documented conflict code.
"""
from __future__ import annotations

import base64
import os
from uuid import uuid4

os.environ.setdefault(
    "DATABASE_URL", "sqlite+aiosqlite:///./test_script_workflow_refusals.db"
)
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402

from app.api import script_library as script_library_api  # noqa: E402
from app.core import script_parameters  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import Client, Operator, OperatorRole, Site  # noqa: E402

ADMIN = "refusal-admin@nodelink.test"
ADMIN_LOGIN = "admin-password"
TEST_ENCRYPTION_KEY = base64.urlsafe_b64encode(
    b"script-parameter-test-key-32-byt"
).decode()
MISSING_ID = "00000000-0000-4000-8000-000000000000"
# Valid five-field syntax, but February never has a 30th: the scheduler's
# bounded search runs out and ``compute_next_run`` raises.
NEVER_FIRES = "0 0 30 2 *"


@pytest_asyncio.fixture
async def client(monkeypatch):
    monkeypatch.setattr(
        settings, "script_parameter_encryption_key", TEST_ENCRYPTION_KEY
    )
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add(
            Operator(
                email=ADMIN,
                password_hash=hash_password(ADMIN_LOGIN),
                role=OperatorRole.admin,
                is_platform_admin=True,
            )
        )
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://t/api/v1"
    ) as value:
        login = await value.post(
            "/auth/login", json={"email": ADMIN, "password": ADMIN_LOGIN}
        )
        assert login.status_code == 200, login.text
        value.headers["Authorization"] = f"Bearer {login.json()['access_token']}"
        yield value
    await engine.dispose()


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _script_body(name: str | None = None, **overrides) -> dict:
    body = {
        "name": name or f"Refusal script {uuid4().hex[:8]}",
        "language": "powershell",
        "content": "Restart-Service -Name Spooler",
        "supported_platforms": ["windows"],
    }
    body.update(overrides)
    return body


def _version_body(**overrides) -> dict:
    body = _script_body(**overrides)
    body.pop("name")
    return body


_ONE_PARAMETER = [
    {"key": "ServiceName", "label": "Service", "kind": "string", "required": True}
]


async def _create_script(client, **overrides) -> dict:
    response = await client.post("/script-library", json=_script_body(**overrides))
    assert response.status_code == 201, response.text
    return response.json()


async def _approve(client, script_id: str, version: int = 1) -> None:
    response = await client.post(
        f"/script-library/{script_id}/versions/{version}/review",
        json={"state": "approved", "reason": "Reviewed for refusal tests"},
    )
    assert response.status_code == 200, response.text


async def _deprecate(client, script: dict, request_id: str):
    return await client.post(
        f"/script-library/{script['id']}/deprecate",
        json={
            "expected_record_version": script["record_version"],
            "request_id": request_id,
            "reason": "Superseded by managed policy",
        },
    )


def _prepare(client, script_id: str, request_id: str, version: int = 1):
    return client.post(
        f"/script-library/{script_id}/versions/{version}/parameter-value-sets",
        json={"request_id": request_id, "values": {}},
    )


def _refuse_parameter_flush(monkeypatch) -> None:
    """Make the parameter-definition flush hit a unique constraint.

    Duplicating the first row's position stands in for the concurrent writer
    that wins the race the handler's ``IntegrityError`` branch exists for.
    """
    original = script_library_api._parameter_rows

    def duplicated(version, definitions):
        rows = original(version, definitions)
        twin = original(version, definitions[:1])[0]
        twin.key = f"{twin.key}Twin"
        return rows + [twin]

    monkeypatch.setattr(script_library_api, "_parameter_rows", duplicated)


async def _seed_site() -> str:
    async with AsyncSessionLocal() as db:
        org = Client(id=str(uuid4()), name=f"Refusal org {uuid4().hex[:6]}")
        site = Site(id=str(uuid4()), client_id=org.id, name="HQ")
        db.add_all([org, site])
        await db.commit()
        return site.id


def _task_body(target_type: str, target_id: str, **overrides) -> dict:
    body = {
        "name": "Nightly health check",
        "target_type": target_type,
        "target_id": target_id,
        "cron_expression": "0 2 * * *",
        "timezone": "UTC",
        "kind": "powershell",
        "payload": {"script": "Get-Process"},
    }
    body.update(overrides)
    return body


# --------------------------------------------------------------------------- #
# Script library: create
# --------------------------------------------------------------------------- #
async def test_create_refused_when_library_is_full(client, monkeypatch):
    monkeypatch.setattr(settings, "script_library_max_items", 1)
    await _create_script(client)

    response = await client.post("/script-library", json=_script_body())

    assert response.status_code == 409
    assert response.json()["detail"] == {"code": "script_library_limit_reached"}


async def test_create_refuses_a_case_insensitive_duplicate_name(client):
    await _create_script(client, name="Restart Spooler")

    response = await client.post(
        "/script-library", json=_script_body(name="RESTART SPOOLER")
    )

    assert response.status_code == 409
    assert response.json()["detail"] == {"code": "script_name_exists"}


async def test_create_refuses_content_over_the_configured_ceiling(client, monkeypatch):
    monkeypatch.setattr(settings, "script_library_max_content_bytes", 1_024)

    response = await client.post(
        "/script-library", json=_script_body(content="Write-Output 1\n" * 100)
    )

    assert response.status_code == 413
    assert response.json()["detail"] == {"code": "script_content_too_large"}


async def test_create_maps_a_lost_write_race_to_name_exists(client, monkeypatch):
    _refuse_parameter_flush(monkeypatch)

    response = await client.post(
        "/script-library", json=_script_body(parameters=_ONE_PARAMETER)
    )

    assert response.status_code == 409
    assert response.json()["detail"] == {"code": "script_name_exists"}


# --------------------------------------------------------------------------- #
# Script library: versions, review, deprecation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "suffix, body, detail",
    [
        ("/versions", _version_body(), "Script not found"),
        (
            "/versions/1/review",
            {"state": "approved", "reason": "Nothing to review"},
            "Script version not found",
        ),
        (
            "/deprecate",
            {
                "expected_record_version": 1,
                "request_id": "deprecate-missing",
                "reason": "Nothing to deprecate",
            },
            "Script not found",
        ),
        (
            "/versions/1/parameter-value-sets",
            {"request_id": "prepare-missing", "values": {}},
            "Script version not found",
        ),
    ],
    ids=["new-version", "review", "deprecate", "prepare-values"],
)
async def test_unknown_script_is_404(client, suffix, body, detail):
    response = await client.post(f"/script-library/{MISSING_ID}{suffix}", json=body)

    assert response.status_code == 404
    assert response.json()["detail"] == detail


async def test_new_version_refused_at_the_version_ceiling(client, monkeypatch):
    monkeypatch.setattr(settings, "script_library_max_versions_per_script", 1)
    script = await _create_script(client)

    response = await client.post(
        f"/script-library/{script['id']}/versions", json=_version_body()
    )

    assert response.status_code == 409
    assert response.json()["detail"] == {"code": "script_version_limit_reached"}


async def test_new_version_maps_a_lost_write_race_to_version_conflict(
    client, monkeypatch
):
    script = await _create_script(client)
    _refuse_parameter_flush(monkeypatch)

    response = await client.post(
        f"/script-library/{script['id']}/versions",
        json=_version_body(parameters=_ONE_PARAMETER),
    )

    assert response.status_code == 409
    assert response.json()["detail"] == {"code": "script_version_conflict"}


async def test_deprecating_twice_with_a_new_request_id_conflicts(client):
    script = await _create_script(client)
    assert (await _deprecate(client, script, "deprecate-first")).status_code == 200

    response = await _deprecate(client, script, "deprecate-second")

    assert response.status_code == 409
    assert response.json()["detail"] == {"code": "script_already_deprecated"}


# --------------------------------------------------------------------------- #
# Script library: preparing parameter values
# --------------------------------------------------------------------------- #
async def test_prepare_refused_for_a_deprecated_script(client):
    script = await _create_script(client)
    await _approve(client, script["id"])
    assert (await _deprecate(client, script, "deprecate-prepare")).status_code == 200

    response = await _prepare(client, script["id"], "prepare-deprecated")

    assert response.status_code == 409
    assert response.json()["detail"] == {"code": "script_deprecated"}


async def test_prepare_refused_at_the_per_version_set_ceiling(client, monkeypatch):
    monkeypatch.setattr(settings, "script_parameter_max_sets_per_version", 1)
    script = await _create_script(client)
    await _approve(client, script["id"])
    assert (await _prepare(client, script["id"], "prepare-first")).status_code == 201

    response = await _prepare(client, script["id"], "prepare-second")

    assert response.status_code == 409
    assert response.json()["detail"] == {"code": "parameter_value_set_limit_reached"}


async def test_prepare_maps_a_lost_write_race_to_request_conflict(client, monkeypatch):
    """A rejected value-set row is a request conflict, never a 500.

    A fingerprint of the wrong length trips the table's check constraint, which
    is the same ``IntegrityError`` a concurrent same-``request_id`` insert hits.
    """
    script = await _create_script(client)
    await _approve(client, script["id"])
    original = script_parameters.encrypt_values

    def short_fingerprint(values, **kwargs):
        encrypted, fingerprint = original(values, **kwargs)
        return encrypted, fingerprint[:8]

    monkeypatch.setattr(script_parameters, "encrypt_values", short_fingerprint)

    response = await _prepare(client, script["id"], "prepare-race")

    assert response.status_code == 409
    assert response.json()["detail"] == {"code": "parameter_request_conflict"}


# --------------------------------------------------------------------------- #
# Scheduled tasks
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "target_type, label", [("agent", "agent"), ("site", "site")]
)
async def test_schedule_refused_for_a_missing_target(client, target_type, label):
    response = await client.post(
        "/scheduled-tasks", json=_task_body(target_type, MISSING_ID)
    )

    assert response.status_code == 404
    assert response.json()["detail"] == f"Target {label} {MISSING_ID} not found"


async def test_schedule_refused_when_the_cron_never_fires(client):
    site_id = await _seed_site()

    response = await client.post(
        "/scheduled-tasks",
        json=_task_body("site", site_id, cron_expression=NEVER_FIRES),
    )

    assert response.status_code == 400
    assert response.json()["detail"].startswith("Failed to calculate next run time:")


async def test_update_refused_when_the_new_cron_never_fires(client):
    site_id = await _seed_site()
    created = await client.post("/scheduled-tasks", json=_task_body("site", site_id))
    assert created.status_code == 201, created.text

    response = await client.put(
        f"/scheduled-tasks/{created.json()['id']}",
        json={"cron_expression": NEVER_FIRES},
    )

    assert response.status_code == 400
    assert response.json()["detail"].startswith("Failed to calculate next run time:")


@pytest.mark.parametrize(
    "method, suffix, body",
    [
        ("PUT", "", {"name": "Renamed"}),
        ("DELETE", "", None),
        ("POST", "/toggle", None),
        ("POST", "/run-now", None),
    ],
    ids=["update", "delete", "toggle", "run-now"],
)
async def test_unknown_scheduled_task_is_404(client, method, suffix, body):
    response = await client.request(
        method, f"/scheduled-tasks/{MISSING_ID}{suffix}", json=body
    )

    assert response.status_code == 404
    assert response.json()["detail"] == f"Scheduled task {MISSING_ID} not found"
