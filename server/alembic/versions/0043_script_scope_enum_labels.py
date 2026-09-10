# SPDX-License-Identifier: AGPL-3.0-only
"""Normalize the scriptexecutionscope enum labels to the member values.

Revision ID: 0043
Revises: 0042

``Operator.script_execution_scope`` was mapped with a bare ``Enum(
ScriptExecutionScope)``, so SQLAlchemy persisted the member *names*
("global_") while migration 0010 created the Postgres type with the member
*values* ("global"). Granting a global script permission therefore failed on
Postgres with `invalid input value for enum scriptexecutionscope: "global_"`,
surfacing in the dashboard as a generic "operator action is unavailable".

The model now passes ``values_callable`` (matching MonitoringScope). This
revision repairs any database whose enum type was instead created from the
model by ``create_all`` -- the debug-stamped case that revision 0012 exists
for -- and so carries the "global_" label. Both paths converge on "global".
Forward-only.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0043"
down_revision = "0042"
branch_labels = None
depends_on = None

_TYPE = "scriptexecutionscope"


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        # SQLite stores the column as VARCHAR with no enforced label set; the
        # data fix below still applies to any row written by the old mapping.
        op.execute(
            sa.text(
                "UPDATE operators SET script_execution_scope = 'global' "
                "WHERE script_execution_scope = 'global_'"
            )
        )
        return

    labels = set(
        bind.execute(
            sa.text(
                "SELECT e.enumlabel FROM pg_enum e "
                "JOIN pg_type t ON t.oid = e.enumtypid WHERE t.typname = :name"
            ),
            {"name": _TYPE},
        ).scalars()
    )
    if not labels or "global" in labels:
        return
    if "global_" in labels:
        op.execute(sa.text(f"ALTER TYPE {_TYPE} RENAME VALUE 'global_' TO 'global'"))


def downgrade() -> None:
    raise RuntimeError(
        "NodeLink migrations are forward-only; restore a tested backup or apply a forward fix"
    )
