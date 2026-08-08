// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  installerDownloadError,
  installerDownloadFilename,
  parseContentDispositionFilename,
} from "../src/lib/installer-download-core.ts";

test("parseContentDispositionFilename reads plain and extended forms", () => {
  assert.equal(
    parseContentDispositionFilename('attachment; filename="NodeLinkAgentSetup-0.1.2-abc.zip"'),
    "NodeLinkAgentSetup-0.1.2-abc.zip",
  );
  assert.equal(
    parseContentDispositionFilename("attachment; filename=plain.zip"),
    "plain.zip",
  );
  assert.equal(
    parseContentDispositionFilename("attachment; filename*=UTF-8''Node%20Link.zip"),
    "Node Link.zip",
  );
  assert.equal(parseContentDispositionFilename(null), null);
  assert.equal(parseContentDispositionFilename("attachment"), null);
});

test("installerDownloadFilename sanitizes and falls back to the site id", () => {
  // A well-formed header passes through unchanged.
  assert.equal(
    installerDownloadFilename('attachment; filename="NodeLinkAgentSetup-0.1.2-site9.zip"', "site9"),
    "NodeLinkAgentSetup-0.1.2-site9.zip",
  );
  // Path separators, quotes, and newlines are stripped — no header break/traversal.
  assert.equal(
    installerDownloadFilename('attachment; filename="../../etc/pa\r\nsswd"', "site9"),
    "....etcpasswd",
  );
  // Missing/unusable header falls back to a site-derived name.
  assert.equal(installerDownloadFilename(null, "site9"), "NodeLinkAgentSetup-site9.zip");
  assert.equal(
    installerDownloadFilename("attachment; filename=\"////\"", "site9"),
    "NodeLinkAgentSetup-site9.zip",
  );
});

test("installerDownloadError maps auth and fail-closed codes", () => {
  assert.deepEqual(installerDownloadError(401, null), {
    status: 401,
    message: "Sign in again to continue.",
  });
  assert.equal(installerDownloadError(403, null).status, 403);
  assert.equal(installerDownloadError(404, null).status, 404);

  assert.match(
    installerDownloadError(503, "installer_downloads_disabled").message,
    /not enabled/,
  );
  assert.match(
    installerDownloadError(503, "installer_artifact_unavailable").message,
    /missing/,
  );
  assert.match(
    installerDownloadError(503, "installer_artifact_integrity").message,
    /integrity/,
  );
  // Unknown code still yields a safe generic 503.
  assert.deepEqual(installerDownloadError(500, null), {
    status: 503,
    message: "The installer download is unavailable right now.",
  });
});
