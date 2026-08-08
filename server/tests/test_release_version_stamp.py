# SPDX-License-Identifier: AGPL-3.0-only
"""Release/installer version-stamp contract tests (issue #179).

A release artifact that was never stamped with ``-ldflags "-X main.version=..."``
reports the ``0.1.0-dev`` fallback forever. On the dashboard that endpoint looks
exactly like a stale agent, and on disk the binary is indistinguishable from a
local developer build — which is how an unstamped build once ended up replacing
an installed release.

These tests pin the wiring that makes that unpublishable: the build script and
both workflow jobs assert the embedded version against the release tag, and the
installer refuses at compile time to wrap a binary that disagrees with
``NODELINK_VERSION``.
"""
from __future__ import annotations

from pathlib import Path

SERVER_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVER_ROOT.parent
RELEASE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release.yml"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
BUILD_SCRIPT = REPO_ROOT / "agent" / "build.sh"
INSTALLER = REPO_ROOT / "installer" / "NodeLinkAgent.iss"
AGENT_MAIN = REPO_ROOT / "agent" / "cmd" / "agent" / "main.go"


def test_agent_exposes_a_version_assertion_the_release_can_call():
    source = AGENT_MAIN.read_text(encoding="utf-8")

    assert 'const unstampedVersion = "0.1.0-dev"' in source
    assert 'case "version":' in source
    assert 'fs.String("expect"' in source


def test_build_script_verifies_the_stamp_it_just_applied():
    script = BUILD_SCRIPT.read_text(encoding="utf-8")

    assert '-X main.version=${VERSION}' in script
    assert 'version --expect "$VERSION"' in script


def test_release_workflow_verifies_both_built_agents_against_the_tag():
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")

    # The cross-built release binary...
    assert './bin/rmm-agent-linux-amd64 version -expect "$VERSION"' in workflow
    # ...and the exact binary the Windows installer embeds.
    assert (
        ".\\bin\\rmm-agent-windows-amd64.exe version -expect "
        "${{ steps.version.outputs.version }}" in workflow
    )
    # Verification has to happen before the installer is compiled and before
    # anything is published, so both checks precede those steps.
    assert workflow.index("version -expect") < workflow.index("ISCC.exe")
    assert workflow.index("version -expect") < workflow.index(
        "softprops/action-gh-release@v2"
    )


def test_ci_compiles_the_installer_from_a_stamped_binary():
    """CI exercises the installer's compile-time guard on every run."""
    workflow = CI_WORKFLOW.read_text(encoding="utf-8")

    assert '-ldflags "-X main.version=0.0.0-ci"' in workflow
    assert ".\\bin\\rmm-agent-windows-amd64.exe version -expect 0.0.0-ci" in workflow
    assert "NODELINK_VERSION: 0.0.0-ci" in workflow


def test_installer_refuses_a_binary_that_disagrees_with_the_release_version():
    source = INSTALLER.read_text(encoding="utf-8")

    assert '#define AgentVersionCheck Exec(AgentExeToVerify, "version -expect " + MyVersion' in source
    assert "#if AgentVersionCheck != 0" in source
    assert "#error The agent binary does not report NODELINK_VERSION" in source
    # The guard is keyed to the same environment variable that names the
    # installer, so the file name, AppVersion, and embedded binary cannot drift
    # apart. It stays off only for a version-less local scratch compile.
    assert "#if VersionEnv != \"\"" in source
