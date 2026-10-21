# SPDX-License-Identifier: AGPL-3.0-only
"""The contracts/*.schema.json files are real, enforceable JSON Schemas.

Until this test they were only read as JSON for a const or two, so a typo in
a $ref or keyword would have published a schema no third-party verifier could
use. Each schema is checked against its metaschema, and the golden vectors are
checked against the schema they claim to follow.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

CONTRACTS = Path(__file__).resolve().parents[2] / "contracts"
VECTORS = CONTRACTS / "test-vectors"
SCHEMA_PATHS = sorted(CONTRACTS.glob("*.schema.json"))


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _validator(contract: str) -> Draft202012Validator:
    return Draft202012Validator(_load(CONTRACTS / f"{contract}.schema.json"))


def test_every_contract_has_a_schema_file():
    assert {path.name.removesuffix(".schema.json") for path in SCHEMA_PATHS} == {
        "command-v1",
        "command-v2",
        "command-v3",
        "evidence-bundle-v1",
        "evidence-package-v1",
    }


@pytest.mark.parametrize("path", SCHEMA_PATHS, ids=lambda path: path.name)
def test_schema_is_valid_draft_2020_12(path: Path):
    schema = _load(path)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    Draft202012Validator.check_schema(schema)


@pytest.mark.parametrize("contract", ["command-v1", "command-v2", "command-v3"])
def test_valid_command_vectors_conform_to_their_schema(contract: str):
    validator = _validator(contract)
    vectors = _load(VECTORS / f"{contract}.json")
    assert vectors["valid"]
    for case in vectors["valid"]:
        errors = list(validator.iter_errors(case["envelope"]))
        assert not errors, (case["name"], [error.message for error in errors])


def test_v3_schema_refuses_every_runtime_refusal():
    """The schema and both runtimes must agree on what is not a v3 envelope.

    Tampered cases are structurally valid (only the signature is wrong), so
    they must pass the schema; every invalid case must fail it.
    """
    validator = _validator("command-v3")
    vectors = _load(VECTORS / "command-v3.json")
    for case in vectors["tampered"]:
        assert validator.is_valid(case["envelope"]), case["name"]
    for case in vectors["invalid"]:
        assert not validator.is_valid(case["envelope"]), case["name"]


@pytest.mark.parametrize("contract", ["evidence-bundle-v1", "evidence-package-v1"])
def test_golden_evidence_vectors_conform_to_their_schema(contract: str):
    validator = _validator(contract)
    errors = list(validator.iter_errors(_load(VECTORS / f"{contract}.json")))
    assert not errors, [error.message for error in errors]
