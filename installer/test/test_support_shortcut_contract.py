# SPDX-License-Identifier: AGPL-3.0-only
from pathlib import Path
import unittest


INSTALLER = Path(__file__).resolve().parents[1] / "NodeLinkAgent.iss"


# CI collects these with `python -m unittest discover`, which only picks up
# TestCase classes; bare pytest-style functions here would silently never run.
class SupportShortcutContractTests(unittest.TestCase):
    def test_start_menu_support_shortcut_is_single_idempotent_chat_entry(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        entry = (
            'Name: "{commonprograms}\\NodeLink Support"; '
            'Filename: "{app}\\rmm-agent-tray.exe"; Parameters: "chat";'
        )
        self.assertEqual(source.count(entry), 1)
        self.assertNotIn('Name: "{userprograms}\\NodeLink Support"', source)

    def test_startup_support_shortcut_launches_gui_tray(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        entry = (
            'Name: "{commonstartup}\\NodeLink Support"; '
            'Filename: "{app}\\rmm-agent-tray.exe"; Parameters: "tray";'
        )
        self.assertEqual(source.count(entry), 1)

    def test_support_shortcuts_never_target_console_binary(self) -> None:
        # The console-subsystem rmm-agent.exe opens a console window that stays
        # up for the whole tray session (issue #322); only the GUI build may
        # back a user-facing shortcut.
        source = INSTALLER.read_text(encoding="utf-8")
        lines = [
            item for item in source.splitlines()
            if item.startswith("Name: ") and "NodeLink Support" in item
        ]
        self.assertEqual(len(lines), 2)
        for line in lines:
            self.assertNotIn('Filename: "{app}\\rmm-agent.exe"', line)

    def test_tray_binary_is_installed_and_version_checked(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertIn(
            'Source: "{#TrayExe}"; DestDir: "{app}"; DestName: "rmm-agent-tray.exe";',
            source,
        )
        self.assertIn(
            '#define TrayVersionCheck Exec(TrayExeToVerify, '
            '"version -expect " + MyVersion, SourcePath)',
            source,
        )

    def test_start_menu_shortcut_is_not_elevated_or_persisted_manually(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        line = next(
            item for item in source.splitlines()
            if 'Name: "{commonprograms}\\NodeLink Support"' in item
        )
        self.assertNotIn("runas", line.lower())
        self.assertNotIn("uninsneveruninstall", line.lower())


if __name__ == "__main__":
    unittest.main()
