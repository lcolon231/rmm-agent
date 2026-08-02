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


if __name__ == "__main__":
    unittest.main()
