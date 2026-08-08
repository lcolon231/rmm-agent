# SPDX-License-Identifier: AGPL-3.0-only

from pathlib import Path
import unittest


INSTALLER = Path(__file__).resolve().parents[1] / "NodeLinkAgent.iss"
PRODUCTION_URL = "https://nodelink-backend-733e.onrender.com"


class InstallerContractTests(unittest.TestCase):
    def test_production_installer_has_one_token_only_input(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")

        self.assertEqual(source.count("ConfigPage.Add("), 1)
        self.assertIn("ConfigPage.Add('Enrollment token:', False);", source)
        self.assertNotIn("Server URL:", source)
        self.assertNotIn("{param:ServerURL|", source)
        self.assertNotIn("/SERVERURL=", source)
        self.assertNotIn("ConfigPage.Values[1]", source)

    def test_config_uses_fixed_production_origin_and_token_parameter(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")

        self.assertIn(f'#define ProductionServerURL "{PRODUCTION_URL}"', source)
        self.assertIn('\"server_url\": \"{#ProductionServerURL}\"', source)
        self.assertIn("{param:Token|}", source)
        self.assertIn("No enrollment token provided (pass /TOKEN= for silent install)", source)

    def test_personalized_sidecar_token_is_supported_and_prompt_is_skipped(self) -> None:
        """A dashboard-personalized download supplies the token via a sidecar
        file so no token is ever typed (issue #9). The token page is skipped
        when the sidecar (or /TOKEN=) provides the value, and the sidecar is
        read from {src} — the folder Setup.exe runs from — not a fixed path."""
        source = INSTALLER.read_text(encoding="utf-8")

        self.assertIn('#define SidecarTokenFile "nodelink-enroll.token"', source)
        self.assertIn("function SidecarToken: String;", source)
        self.assertIn("{src}\\{#SidecarTokenFile}", source)
        # The prompt is skipped when a token is already available.
        self.assertIn("function ShouldSkipPage(PageID: Integer): Boolean;", source)
        # Precedence remains arg -> sidecar -> interactive input.
        self.assertIn("Result := SidecarToken;", source)

    def test_existing_enrollment_enters_tokenless_upgrade_mode(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")

        self.assertIn("procedure DetectInstallMode;", source)
        self.assertIn("function ValidateExistingEnrollment: Boolean;", source)
        self.assertIn("validate-upgrade -config", source)
        self.assertIn("DetectedInstallMode := InstallModeUpgrade;", source)
        self.assertIn("DetectedInstallMode <> InstallModeFresh", source)
        self.assertIn("existing enrollment will be preserved", source)

    def test_inconsistent_existing_identity_is_blocked_before_install(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")

        self.assertIn("function PrepareToInstall(var NeedsRestart: Boolean): String;", source)
        self.assertIn("if DetectedInstallMode = InstallModeBlocked then", source)
        self.assertIn("Setup will not modify this installation", source)
        self.assertIn("config.json is missing", source)
        self.assertIn("not ValidateExistingEnrollment", source)
        self.assertIn("could not be validated for a safe", source)

    def test_upgrade_preserves_runtime_state_and_reuses_existing_config(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")

        self.assertIn("Preserving existing token-free config.json during upgrade", source)
        self.assertIn("identity.json and config.json are being preserved", source)
        self.assertIn(
            "RunAgent('install -config \"' + ExpandConstant('{app}\\config.json') + '\"'",
            source,
        )
        # Runtime state is removed only by a deliberate registered uninstall,
        # never by the in-place upgrade code.
        self.assertEqual(source.count('Type: files; Name: "{app}\\identity.json"'), 1)
        self.assertEqual(source.count('Type: files; Name: "{app}\\config.json"'), 1)

    def test_upgrade_ui_is_distinct_from_fresh_enrollment(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")

        self.assertIn("procedure CurPageChanged(CurPageID: Integer);", source)
        self.assertIn("existing enrollment and configuration were preserved", source)
        self.assertIn("NodeLink installer mode: enrollment", source)
        self.assertIn("NodeLink installer mode: upgrade", source)

    def test_installer_refuses_an_unstamped_or_mismatched_agent_binary(self) -> None:
        """The wrapped binary must report NODELINK_VERSION (issue #179).

        The agent asserts its own build stamp, so compiling an installer around
        an unstamped (``0.1.0-dev``) or wrong-version binary fails at compile
        time instead of producing a release that misreports its version on
        every endpoint.
        """
        source = INSTALLER.read_text(encoding="utf-8")

        self.assertIn('#if VersionEnv != ""', source)
        self.assertIn(
            '#define AgentVersionCheck Exec(AgentExeToVerify, "version -expect " + MyVersion',
            source,
        )
        self.assertIn("#if AgentVersionCheck != 0", source)
        self.assertIn("#error The agent binary does not report NODELINK_VERSION", source)
        # The verified path is the same one [Files] embeds, resolved against
        # the script directory exactly like Inno resolves a relative Source.
        self.assertIn("#define AgentExeToVerify AddBackslash(SourcePath) + AgentExe", source)
        self.assertIn('Source: "{#AgentExe}"; DestDir: "{app}"', source)


if __name__ == "__main__":
    unittest.main()
