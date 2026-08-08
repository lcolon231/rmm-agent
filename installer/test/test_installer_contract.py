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


if __name__ == "__main__":
    unittest.main()
