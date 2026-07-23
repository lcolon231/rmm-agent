# SPDX-License-Identifier: AGPL-3.0-only
"""Authorization policy for command dispatch (issue #111).

Not every command kind carries the same blast radius. Arbitrary-script kinds
(``powershell``, ``shell``) run operator-supplied code with the agent's
privileges and are therefore gated by an explicit per-operator grant
(``Operator.can_execute_scripts``) that is default-deny and *not* implied by any
role — not even ``admin``. Typed operations, whose payloads are constrained to a
narrow contract, are authorized by role alone.

Keeping the classification in one place means new typed operations added in
later milestones are authorized by role by default, and only kinds explicitly
listed here demand the elevated grant. Fail closed: an unknown kind is treated
as arbitrary.
"""
from __future__ import annotations

from app.models.models import CommandKind, Operator

# Kinds that execute operator-supplied code with no narrowing contract. These
# require the explicit script-execution grant in addition to operator role.
ARBITRARY_SCRIPT_KINDS: frozenset[CommandKind] = frozenset(
    {CommandKind.powershell, CommandKind.shell}
)

# Kinds whose payload is a constrained, typed contract; role authorization is
# sufficient. ``collect_inventory`` is the only typed kind today.
TYPED_KINDS: frozenset[CommandKind] = frozenset({CommandKind.collect_inventory})


def requires_script_permission(kind: CommandKind) -> bool:
    """True if dispatching *kind* needs the arbitrary-script grant.

    Fail closed: any kind not explicitly classified as typed is treated as an
    arbitrary script and requires the grant.
    """
    return kind not in TYPED_KINDS


def operator_may_dispatch(operator: Operator, kind: CommandKind) -> bool:
    """Authorize *operator* to dispatch a command of *kind*.

    The caller has already established operator-or-higher role. This adds the
    arbitrary-script gate on top: default-deny unless the operator holds the
    explicit grant.
    """
    if requires_script_permission(kind):
        return bool(operator.can_execute_scripts)
    return True
