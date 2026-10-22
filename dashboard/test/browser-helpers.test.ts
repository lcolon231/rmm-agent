// SPDX-License-Identifier: AGPL-3.0-only
// Browser-side helpers that had no test (issue #281): the shared clock, the
// installer download trigger and the WebAuthn capability hook.

import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import { createElement } from "react";
import { renderToString } from "react-dom/server";

import {
  browserTimeZone,
  clockSnapshot,
  readClock,
  serverTimeZone,
  subscribeToClock,
  subscribeToTimeZone,
} from "@/lib/dashboard-clock";
import { downloadInstallerPackage } from "@/lib/installer-download-client";
import { useWebAuthnSupport } from "@/lib/use-webauthn-support";
import { fakeApi, jsonResponse } from "./support/fake-api.ts";

// --------------------------------------------------------------------------- //
// dashboard-clock
// --------------------------------------------------------------------------- //
test("the shared clock ticks every 30s only while someone is subscribed", (t) => {
  t.mock.timers.enable({ apis: ["setInterval", "Date"], now: 1_000_000 });
  let first = 0;
  let second = 0;
  const unsubscribeFirst = subscribeToClock(() => first++);
  const unsubscribeSecond = subscribeToClock(() => second++);
  assert.equal(clockSnapshot(), 1_000_000);

  t.mock.timers.tick(29_999);
  assert.equal(first, 0);
  assert.equal(clockSnapshot(), 1_000_000, "the snapshot is stable between ticks");
  assert.equal(readClock(), 1_029_999, "an event handler reads the exact instant");

  t.mock.timers.tick(1);
  assert.deepEqual([first, second], [1, 1]);
  assert.equal(clockSnapshot(), 1_030_000);

  unsubscribeFirst();
  t.mock.timers.tick(30_000);
  assert.deepEqual([first, second], [1, 2]);

  unsubscribeSecond();
  t.mock.timers.tick(60_000);
  assert.deepEqual([first, second], [1, 2], "the interval stops with the last listener");
  assert.equal(clockSnapshot(), 1_060_000);

  // Resubscribing restarts the interval and refreshes the stale snapshot.
  const unsubscribeAgain = subscribeToClock(() => first++);
  assert.equal(clockSnapshot(), 1_120_000);
  t.mock.timers.tick(30_000);
  assert.equal(first, 2);
  unsubscribeAgain();
});

test("time zones: UTC on the server, the browser zone resolved once", (t) => {
  assert.equal(serverTimeZone(), "UTC");
  assert.equal(typeof subscribeToTimeZone(), "function");
  assert.equal(subscribeToTimeZone()(), undefined);

  // A runtime whose Intl cannot answer falls back to UTC, and the answer is
  // cached because a tab's zone cannot change while it is open.
  t.mock.method(Intl, "DateTimeFormat", () => {
    throw new RangeError("no Intl data");
  });
  assert.equal(browserTimeZone(), "UTC");
  t.mock.restoreAll();
  assert.equal(browserTimeZone(), "UTC");
});

// --------------------------------------------------------------------------- //
// installer-download-client
// --------------------------------------------------------------------------- //
type FakeAnchor = { href: string; download: string; clicked: boolean; removed: boolean; click(): void; remove(): void };

function fakeDocument(t: TestContext) {
  const anchors: FakeAnchor[] = [];
  const appended: FakeAnchor[] = [];
  const document = {
    createElement: (tag: string) => {
      assert.equal(tag, "a");
      const anchor: FakeAnchor = {
        href: "",
        download: "",
        clicked: false,
        removed: false,
        click() { this.clicked = true; },
        remove() { this.removed = true; },
      };
      anchors.push(anchor);
      return anchor;
    },
    body: { appendChild: (node: FakeAnchor) => appended.push(node) },
  };
  // Node has no `document` to mock.property over, so install and remove it.
  const scope = globalThis as { document?: unknown };
  scope.document = document;
  t.after(() => delete scope.document);
  const created = t.mock.method(URL, "createObjectURL", () => "blob:installer");
  const revoked = t.mock.method(URL, "revokeObjectURL", () => {});
  return { anchors, appended, created, revoked };
}

test("a successful download streams the ZIP to a named file and frees the blob", async (t) => {
  const dom = fakeDocument(t);
  const calls = fakeApi(t, () => new Response(new Uint8Array([0x50, 0x4b]), {
    status: 200,
    headers: { "Content-Disposition": "attachment; filename=\"nodelink-installer-hq.zip\"" },
  }));

  assert.equal(await downloadInstallerPackage("site/1"), null);
  assert.equal(calls[0].url, "/api/sites/site%2F1/installer-package");
  assert.equal(calls[0].method, "POST");
  assert.equal(dom.anchors.length, 1);
  const [anchor] = dom.anchors;
  assert.equal(anchor.href, "blob:installer");
  assert.equal(anchor.download, "nodelink-installer-hq.zip");
  assert.deepEqual([anchor.clicked, anchor.removed], [true, true]);
  assert.equal(dom.appended[0], anchor);
  assert.equal((dom.created.mock.calls[0].arguments[0] as Blob).size, 2);
  assert.deepEqual(dom.revoked.mock.calls[0].arguments, ["blob:installer"]);
});

test("an unreachable route reports that the service could not be reached", async (t) => {
  const dom = fakeDocument(t);
  fakeApi(t, () => {
    throw new TypeError("fetch failed");
  });
  assert.match((await downloadInstallerPackage("s1"))!, /could not be reached/);
  assert.equal(dom.anchors.length, 0);
});

test("a refused download shows the route's error, or a generic one", async (t) => {
  const dom = fakeDocument(t);
  let next: Response = jsonResponse(403, { error: "This site's token has expired." });
  fakeApi(t, () => next);
  assert.equal(await downloadInstallerPackage("s1"), "This site's token has expired.");

  next = new Response("<html>bad gateway</html>", { status: 502 });
  assert.equal(await downloadInstallerPackage("s1"), "The installer download is unavailable right now.");

  next = jsonResponse(500, { detail: "no error field" });
  assert.equal(await downloadInstallerPackage("s1"), "The installer download is unavailable right now.");
  assert.equal(dom.anchors.length, 0, "no download starts on failure");
});

// --------------------------------------------------------------------------- //
// use-webauthn-support
// --------------------------------------------------------------------------- //
test("WebAuthn support renders optimistically on the server", () => {
  function Probe() {
    return createElement("span", null, useWebAuthnSupport() ? "supported" : "unsupported");
  }
  // SSR has no window to ask; the controls render enabled and hydration corrects.
  assert.equal(renderToString(createElement(Probe)), "<span>supported</span>");
});
