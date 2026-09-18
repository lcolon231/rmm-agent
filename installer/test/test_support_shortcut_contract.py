# SPDX-License-Identifier: AGPL-3.0-only
from pathlib import Path


INSTALLER = Path(__file__).resolve().parents[1] / "NodeLinkAgent.iss"


def test_start_menu_support_shortcut_is_single_idempotent_chat_entry() -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    entry = (
        'Name: "{commonprograms}\\NodeLink Support"; '
        'Filename: "{app}\\rmm-agent.exe"; Parameters: "chat";'
    )
    assert source.count(entry) == 1
    assert 'Name: "{userprograms}\\NodeLink Support"' not in source


def test_start_menu_shortcut_is_not_elevated_or_persisted_manually() -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    line = next(
        item for item in source.splitlines()
        if 'Name: "{commonprograms}\\NodeLink Support"' in item
    )
    assert "runas" not in line.lower()
    assert "uninsneveruninstall" not in line.lower()
