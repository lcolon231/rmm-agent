# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import json

from app.core.structured_logging import structured_event


def test_structured_log_redacts_sensitive_values_recursively():
    event = structured_event(
        "enrollment.test",
        enrollment_token="nlenr_plaintext",
        headers={"Authorization": "Bearer agent-secret", "Accept": "application/json"},
        nested={"credential_fingerprint": "raw-fingerprint-value", "safe": "visible"},
    )

    assert "nlenr_plaintext" not in event
    assert "agent-secret" not in event
    assert "raw-fingerprint-value" not in event
    decoded = json.loads(event)
    assert decoded["enrollment_token"] == "[REDACTED]"
    assert decoded["headers"]["Authorization"] == "[REDACTED]"
    assert decoded["headers"]["Accept"] == "application/json"
    assert decoded["nested"]["safe"] == "visible"
