# SPDX-License-Identifier: AGPL-3.0-only
"""Keep third-party license exceptions limited to the named imports."""
import unittest
from unittest.mock import patch

import check_license


class LicenseHeaderTests(unittest.TestCase):
    def test_expected_license_is_required_for_each_source(self):
        cases = [
            ("agent/example.go", "AGPL-3.0-only", True),
            ("agent/example.go", "MIT", False),
            (".agents/skills/idea-refine/scripts/idea-refine.sh", "MIT", True),
            (".claude/skills/idea-refine/scripts/idea-refine.sh", "MIT", True),
            (".agents/skills/idea-refine/scripts/idea-refine.sh", "AGPL-3.0-only", False),
            (".agents/skills/other.sh", "MIT", False),
            ("agent/example.go", "AGPL-3.0-only OR MIT", False),
        ]
        for name, identifier, expected in cases:
            with self.subTest(name=name, identifier=identifier):
                with patch.object(check_license.Path, "read_text", return_value=f"# SPDX-License-Identifier: {identifier}\n"):
                    self.assertEqual(check_license.has_spdx(check_license.ROOT / name), expected)


if __name__ == "__main__":
    unittest.main()
