# SPDX-License-Identifier: AGPL-3.0-only
from pathlib import Path
import re
import unittest


INSTALLER = Path(__file__).resolve().parents[1] / "NodeLinkAgent.iss"
REPO_ROOT = INSTALLER.parents[1]
BUILD_SCRIPT = REPO_ROOT / "agent" / "build.sh"
WORKFLOWS = REPO_ROOT / ".github" / "workflows"


def _shortcut_line(source: str, name: str) -> str:
    return next(
        item for item in source.splitlines()
        if item.startswith(rf'Name: "{name}\NodeLink Support"')
    )


# CI collects these with `python -m unittest discover`, which only picks up
# TestCase classes; bare pytest-style functions here would silently never run.
class SupportShortcutContractTests(unittest.TestCase):
    def test_start_menu_support_shortcut_is_single_idempotent_chat_entry(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        entry = (
            r'Name: "{commonprograms}\NodeLink Support"; '
            r'Filename: "{app}\rmm-agent-tray.exe"; Parameters: "chat";'
        )
        self.assertEqual(source.count(entry), 1)
        self.assertNotIn(r'Name: "{userprograms}\NodeLink Support"', source)

    def test_start_menu_shortcut_is_not_elevated_or_persisted_manually(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        line = _shortcut_line(source, "{commonprograms}")
        self.assertNotIn("runas", line.lower())
        self.assertNotIn("uninsneveruninstall", line.lower())

    def test_startup_tray_shortcut_launches_the_gui_build(self) -> None:
        """Issue #322: a console-subsystem tray opens a console (a Windows
        Terminal tab on Windows 11) at every logon."""
        source = INSTALLER.read_text(encoding="utf-8")
        entry = (
            r'Name: "{commonstartup}\NodeLink Support"; '
            r'Filename: "{app}\rmm-agent-tray.exe"; Parameters: "tray";'
        )
        self.assertEqual(source.count(entry), 1)

    def test_no_user_facing_shortcut_launches_the_console_build(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        for line in source.splitlines():
            if line.startswith("Name:") and "NodeLink Support" in line:
                self.assertNotIn(r'Filename: "{app}\rmm-agent.exe"', line)

    def test_installer_ships_the_gui_build_beside_the_console_build(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertIn(
            r'#define TrayExe "..\agent\bin\rmm-agent-tray-windows-amd64.exe"',
            source,
        )
        self.assertIn(
            'Source: "{#TrayExe}"; DestDir: "{app}"; DestName: "rmm-agent-tray.exe";',
            source,
        )
        # The service, CLI, and uninstall hook keep using the console build.
        self.assertIn('DestName: "rmm-agent.exe"', source)
        self.assertIn(r'UninstallDisplayIcon={app}\rmm-agent.exe', source)
        self.assertIn(r'Filename: "{app}\rmm-agent.exe"; Parameters: "uninstall"', source)

    def test_installer_refuses_an_unstamped_tray_binary(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertIn(
            '#define TrayVersionCheck Exec(TrayExeToVerify, "version -expect " + MyVersion, SourcePath)',
            source,
        )
        self.assertIn("#if TrayVersionCheck != 0", source)
        self.assertIn("#define TrayExeToVerify AddBackslash(SourcePath) + TrayExe", source)
        guard = source.index('#if VersionEnv != ""')
        self.assertLess(guard, source.index("#define TrayVersionCheck"))

    def test_gui_build_uses_the_windowsgui_subsystem_everywhere(self) -> None:
        script = BUILD_SCRIPT.read_text(encoding="utf-8")
        self.assertRegex(
            script,
            r'-ldflags "-H=windowsgui \$LDFLAGS" -o "\$OUT/rmm-agent-tray-windows-amd64\.exe"',
        )
        # The console build must stay console-subsystem for the CLI verbs.
        console = next(
            line for line in script.splitlines()
            if 'rmm-agent-windows-amd64.exe" ./cmd/agent' in line
        )
        self.assertNotIn("windowsgui", console)

        for name in ("ci.yml", "release.yml"):
            workflow = (WORKFLOWS / name).read_text(encoding="utf-8")
            builds = re.findall(r"go build .*rmm-agent-tray-windows-amd64[^ ]*\.exe", workflow)
            self.assertTrue(builds, name)
            for build in builds:
                self.assertIn("-H=windowsgui", build, name)
            # PowerShell neither waits for nor reports a GUI program's exit
            # code, so the version gate must wait on the process.
            self.assertIn(
                r"Start-Process -FilePath .\bin\rmm-agent-tray-windows-amd64.exe",
                workflow,
                name,
            )
            self.assertIn("-Wait -PassThru", workflow, name)


if __name__ == "__main__":
    unittest.main()
