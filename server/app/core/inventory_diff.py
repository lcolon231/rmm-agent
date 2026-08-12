# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic diffs between two inventory snapshots (issue #40).

The hard part is lists. A positional diff of a software list is worse than
useless: uninstalling one program shifts every entry after it, so a
single-program change renders as hundreds of modifications and the real event
is invisible. Every list is therefore diffed by *identity* — a declared key
that says what makes two elements "the same thing" — so the output names what
actually changed.

Everything here is pure. The inputs are two payload dicts and a section name;
there is no database access, which keeps the part that decides what a
technician sees testable without fixtures.
"""
from __future__ import annotations

from typing import Any

from app.schemas.inventory import InventorySection

#: (section, list field) -> the fields that identify one element.
#:
#: Identity is not the same as equality. Two software rows with the same name
#: and version are the same program even if their publisher string was
#: corrected; that is a *change*, not a removal plus an addition. Choosing the
#: key badly is what produces diffs nobody can read.
LIST_IDENTITIES: dict[tuple[str, str], tuple[str, ...]] = {
    (InventorySection.installed_software.value, "entries"): ("name", "version"),
    (InventorySection.storage.value, "disks"): ("serial", "model"),
    (InventorySection.storage.value, "volumes"): ("mount_point",),
    (InventorySection.network.value, "adapters"): ("mac_address", "name"),
    (InventorySection.memory.value, "modules"): ("slot",),
    (InventorySection.security_bitlocker.value, "volumes"): ("mount_point",),
    (InventorySection.security_defender.value, "third_party_products"): (),
    (InventorySection.windows_updates.value, "missing"): ("update_id",),
    (InventorySection.windows_updates.value, "installed"): ("update_id",),
    (InventorySection.installed_packages.value, "installed"): ("package_id",),
    (InventorySection.installed_packages.value, "upgradable"): ("package_id",),
}


def _identity(entry: Any, keys: tuple[str, ...]) -> tuple:
    """The identity tuple for one list element.

    Elements that are not objects (a bare product name, say) identify by their
    own value. An object missing every identity field falls back to its whole
    content, which degrades to add/remove rather than producing a wrong match.
    """
    if not isinstance(entry, dict):
        return ("__scalar__", _canonical(entry))
    if not keys:
        return ("__value__", _canonical(entry))
    identity = tuple(_canonical(entry.get(key)) for key in keys)
    if all(part is None for part in identity):
        return ("__value__", _canonical(entry))
    return identity


def _canonical(value: Any) -> Any:
    """A hashable, order-stable form for comparison."""
    if isinstance(value, dict):
        return tuple(sorted((key, _canonical(item)) for key, item in value.items()))
    if isinstance(value, list):
        return tuple(_canonical(item) for item in value)
    return value


def _field_changes(before: dict, after: dict) -> list[dict]:
    """Field-level changes between two objects, ordered by field name.

    Appearing and disappearing fields are reported as changes with a null on
    the missing side, because "the endpoint stopped reporting a serial number"
    is a real event — the section's own status explains whether that was a
    collection failure.
    """
    changes = []
    for field in sorted(set(before) | set(after)):
        old, new = before.get(field), after.get(field)
        if _canonical(old) != _canonical(new):
            changes.append({"field": field, "from": old, "to": new})
    return changes


def diff_payloads(section: str, before: dict, after: dict) -> dict:
    """Compare two payloads of the same section.

    Returns scalar field changes plus, for each list field, the elements added,
    removed, and changed. The result is deterministic: identical inputs always
    produce identical output, including ordering, so a stored or re-rendered
    diff never appears to shift on its own.
    """
    before = before or {}
    after = after or {}

    scalar_before: dict[str, Any] = {}
    scalar_after: dict[str, Any] = {}
    list_fields: set[str] = set()

    for source, target in ((before, scalar_before), (after, scalar_after)):
        for field, value in source.items():
            if isinstance(value, list):
                list_fields.add(field)
            else:
                target[field] = value

    list_changes: dict[str, dict] = {}
    for field in sorted(list_fields):
        keys = LIST_IDENTITIES.get((section, field), ())
        before_items = {
            _identity(item, keys): item for item in before.get(field, []) or []
        }
        after_items = {
            _identity(item, keys): item for item in after.get(field, []) or []
        }

        added = [after_items[key] for key in after_items if key not in before_items]
        removed = [before_items[key] for key in before_items if key not in after_items]
        changed = []
        for key in before_items:
            if key not in after_items:
                continue
            old, new = before_items[key], after_items[key]
            if _canonical(old) == _canonical(new):
                continue
            if isinstance(old, dict) and isinstance(new, dict):
                changed.append(
                    {
                        "identity": dict(zip(keys, key)) if keys else None,
                        "changes": _field_changes(old, new),
                    }
                )
            else:
                changed.append({"identity": None, "changes": [{"field": field, "from": old, "to": new}]})

        if not added and not removed and not changed:
            continue
        list_changes[field] = {
            # Sorted by canonical form so the same inputs always render the
            # same way, regardless of the order rows came back from the
            # database or the endpoint.
            "added": sorted(added, key=lambda item: str(_canonical(item))),
            "removed": sorted(removed, key=lambda item: str(_canonical(item))),
            "changed": sorted(changed, key=lambda item: str(_canonical(item))),
        }

    return {
        "field_changes": _field_changes(scalar_before, scalar_after),
        "list_changes": list_changes,
    }


def summarize_diff(diff: dict) -> dict:
    """Counts for a change timeline, so a caller can size a change without
    rendering it."""
    added = removed = changed = 0
    for entry in diff.get("list_changes", {}).values():
        added += len(entry.get("added", []))
        removed += len(entry.get("removed", []))
        changed += len(entry.get("changed", []))
    return {
        "fields_changed": len(diff.get("field_changes", [])),
        "items_added": added,
        "items_removed": removed,
        "items_changed": changed,
    }


def is_empty_diff(diff: dict) -> bool:
    return not diff.get("field_changes") and not diff.get("list_changes")
