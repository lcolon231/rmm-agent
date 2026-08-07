# SPDX-License-Identifier: AGPL-3.0-only
"""Cross-platform typed parameter quoting and redaction contracts."""
from __future__ import annotations

import base64
from types import SimpleNamespace

import pytest

from app.core.config import Settings
from app.core import script_parameters
from app.models.models import ScriptParameterKind


def _definition(key: str, kind: ScriptParameterKind, **overrides):
    values = {
        "key": key,
        "kind": kind,
        "required": False,
        "has_default": False,
        "default_value": None,
        "min_length": None,
        "max_length": None,
        "minimum": None,
        "maximum": None,
        "choices": None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_prepare_values_enforces_types_choices_defaults_and_unknown_keys():
    definitions = [
        _definition("Name", ScriptParameterKind.string, required=True, max_length=20),
        _definition(
            "Count", ScriptParameterKind.number, has_default=True,
            default_value=2, minimum=1, maximum=5,
        ),
        _definition(
            "Mode", ScriptParameterKind.choice, choices=["safe", "force"]
        ),
        _definition("Token", ScriptParameterKind.secret, required=True, min_length=4),
    ]
    prepared = script_parameters.prepare_values(
        definitions,
        {"Name": "Spooler", "Mode": "safe", "Token": "s3cr3t"},
    )
    assert prepared.values == {
        "Name": "Spooler", "Count": 2, "Mode": "safe", "Token": "s3cr3t"
    }
    assert prepared.defaulted_keys == ("Count",)
    assert prepared.secret_keys == ("Token",)
    with pytest.raises(script_parameters.ScriptParameterError, match="choice_invalid"):
        script_parameters.prepare_values(
            definitions,
            {"Name": "Spooler", "Mode": "unsafe", "Token": "s3cr3t"},
        )
    with pytest.raises(script_parameters.ScriptParameterError, match="key_unknown"):
        script_parameters.prepare_values(
            definitions,
            {"Name": "Spooler", "Token": "s3cr3t", "Unexpected": True},
        )


def test_rendering_binds_literals_without_interpolating_script_tokens():
    hostile = "a'; Write-Output PWNED; #'\n$(touch /tmp/pwned)"
    powershell = script_parameters.render_script(
        "powershell",
        "Write-Output $NL_PARAM_Name",
        {"Name": hostile, "Enabled": True, "Count": 2.5},
    )
    assert "$NL_PARAM_Name = 'a''; Write-Output PWNED; #''" in powershell
    assert "$NL_PARAM_Enabled = $true" in powershell
    assert powershell.endswith("Write-Output $NL_PARAM_Name")

    shell = script_parameters.render_script(
        "shell", 'printf "%s" "$NL_PARAM_Name"', {"Name": hostile, "Enabled": False}
    )
    assert "NL_PARAM_Name='a'\"'\"'; Write-Output" in shell
    assert "NL_PARAM_Enabled='false'" in shell
    assert shell.endswith('printf "%s" "$NL_PARAM_Name"')
    assert "{{" not in powershell + shell


def test_encryption_is_authenticated_and_secret_output_is_redacted():
    key = base64.urlsafe_b64encode(b"k" * 32).decode()
    config = Settings(script_parameter_encryption_key=key)
    values = {"Name": "Spooler", "Token": "very-secret-token"}
    encrypted, fingerprint = script_parameters.encrypt_values(
        values,
        script_version_id="version-1",
        value_set_id="set-1",
        config=config,
    )
    assert "very-secret-token" not in encrypted
    assert len(fingerprint) == 64
    assert script_parameters.decrypt_values(
        encrypted,
        script_version_id="version-1",
        value_set_id="set-1",
        config=config,
    ) == values
    with pytest.raises(script_parameters.ScriptParameterError, match="decryption"):
        script_parameters.decrypt_values(
            encrypted[:-2] + "AA",
            script_version_id="version-1",
            value_set_id="set-1",
            config=config,
        )
    assert script_parameters.redact_secret_values(
        "token=very-secret-token", values, ["Token"]
    ) == "token=[redacted]"


@pytest.mark.parametrize(
    "key",
    [
        None,
        "",
        "not-base64!!",
        base64.urlsafe_b64encode(b"too-short").decode(),
        base64.urlsafe_b64encode(b"k" * 33).decode(),
    ],
)
def test_absent_or_malformed_key_is_unavailable_not_invalid(key):
    """Missing/short/corrupt key material must fail closed, never encrypt."""
    config = Settings(script_parameter_encryption_key=key)
    assert script_parameters.encryption_key_configured(config) is False
    for call in (
        lambda: script_parameters.encrypt_values(
            {"Name": "Spooler"},
            script_version_id="version-1",
            value_set_id="set-1",
            config=config,
        ),
        lambda: script_parameters.decrypt_values(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            script_version_id="version-1",
            value_set_id="set-1",
            config=config,
        ),
    ):
        with pytest.raises(script_parameters.ScriptParameterError) as raised:
            call()
        assert raised.value.state == "unavailable"
        assert raised.value.code.endswith("_unavailable")


def test_ciphertext_is_bound_to_its_version_value_set_and_key():
    """AAD and key separation make a relocated or foreign ciphertext unusable."""
    config = Settings(
        script_parameter_encryption_key=base64.urlsafe_b64encode(b"k" * 32).decode()
    )
    other = Settings(
        script_parameter_encryption_key=base64.urlsafe_b64encode(b"j" * 32).decode()
    )
    values = {"Token": "very-secret-token"}
    encrypted, fingerprint = script_parameters.encrypt_values(
        values, script_version_id="version-1", value_set_id="set-1", config=config
    )
    for kwargs, decrypt_config in (
        ({"script_version_id": "version-2", "value_set_id": "set-1"}, config),
        ({"script_version_id": "version-1", "value_set_id": "set-2"}, config),
        ({"script_version_id": "version-1", "value_set_id": "set-1"}, other),
    ):
        with pytest.raises(
            script_parameters.ScriptParameterError, match="decryption_unavailable"
        ):
            script_parameters.decrypt_values(
                encrypted, config=decrypt_config, **kwargs
            )
    # The keyed fingerprint is an idempotency witness, not a value oracle.
    _, same = script_parameters.encrypt_values(
        values, script_version_id="version-9", value_set_id="set-9", config=config
    )
    _, foreign = script_parameters.encrypt_values(
        values, script_version_id="version-1", value_set_id="set-1", config=other
    )
    assert same == fingerprint
    assert foreign != fingerprint
