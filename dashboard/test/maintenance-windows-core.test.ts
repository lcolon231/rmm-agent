// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import test from "node:test";

import {
  describeRecurrence,
  describeWindowState,
  formatDurationSeconds,
  formatWallTimeInput,
  formatWindowScope,
  formatWindowTarget,
  isMaintenanceWindowErrorCode,
  maintenanceWindowFromUnknown,
  maintenanceWindowListFromUnknown,
  maintenanceWindowPromptHref,
  powerWindowCoverage,
  safeReturnPath,
  validateMaintenanceWindowForm,
  validateMaintenanceWindowRequest,
  windowMatchesTarget,
  windowOpenAt,
  windowStateAt,
  zonedWallTimeToUtc,
  type MaintenanceWindow,
  type MaintenanceWindowFormInput,
} from "../src/lib/maintenance-windows-core.ts";

const NOW = Date.parse("2026-08-12T21:00:00Z");

const target = { agentId: "agent-1", siteId: "site-1", clientId: "client-1" };

function window(overrides: Partial<MaintenanceWindow> = {}): MaintenanceWindow {
  return {
    id: "window-1",
    name: "Reboot for KB5120708",
    scope: "agent",
    scope_id: "agent-1",
    starts_at: "2026-08-12T20:55:00Z",
    ends_at: "2026-08-12T22:00:00Z",
    timezone: "UTC",
    recurrence: null,
    created_by: "admin@example.test",
    created_at: "2026-08-12T20:55:00Z",
    ...overrides,
  };
}

// --------------------------------------------------------------------------- //
// Parsing
// --------------------------------------------------------------------------- //

test("maintenance windows parse only well-formed service responses", () => {
  const parsed = maintenanceWindowFromUnknown({
    id: "w1", name: "Nightly", scope: "site", scope_id: "site-1",
    starts_at: "2026-08-12T00:00:00Z", ends_at: "2026-09-12T00:00:00Z",
    timezone: "America/New_York",
    recurrence: { days: [4, 0], start: "02:00", duration_minutes: 120 },
    created_by: "operator@example.test", created_at: "2026-08-01T00:00:00Z",
  });
  assert.equal(parsed?.scope, "site");
  assert.deepEqual(parsed?.recurrence?.days, [0, 4], "recurrence days are normalized in order");

  assert.equal(maintenanceWindowFromUnknown({ ...window(), scope: "fleet" }), null);
  assert.equal(maintenanceWindowFromUnknown({ ...window(), starts_at: "not a date" }), null);
  assert.equal(
    maintenanceWindowFromUnknown({ ...window(), recurrence: { days: [9], start: "02:00", duration_minutes: 60 } }),
    null,
  );
  assert.equal(maintenanceWindowListFromUnknown([window(), { id: "bad" }]), null);
  assert.equal(maintenanceWindowListFromUnknown([window()])?.length, 1);
});

test("a window with no timezone falls back to UTC rather than being rejected", () => {
  const parsed = maintenanceWindowFromUnknown({ ...window(), timezone: undefined });
  assert.equal(parsed?.timezone, "UTC");
});

// --------------------------------------------------------------------------- //
// Scope and coverage
// --------------------------------------------------------------------------- //

test("scope matching mirrors the server's global/client/site/agent rule", () => {
  assert.equal(windowMatchesTarget(window({ scope: "global", scope_id: null }), target), true);
  assert.equal(windowMatchesTarget(window({ scope: "client", scope_id: "client-1" }), target), true);
  assert.equal(windowMatchesTarget(window({ scope: "client", scope_id: "client-2" }), target), false);
  assert.equal(windowMatchesTarget(window({ scope: "site", scope_id: "site-1" }), target), true);
  assert.equal(windowMatchesTarget(window({ scope: "agent", scope_id: "agent-2" }), target), false);
  assert.equal(
    windowMatchesTarget(window({ scope: "site", scope_id: "site-1" }), { ...target, siteId: null }),
    false,
  );
});

test("an endpoint-scoped window covers a power action whose delay fits inside it", () => {
  const coverage = powerWindowCoverage([window()], target, 60, NOW);
  assert.equal(coverage.status, "covered");
  assert.equal(coverage.window.id, "window-1");
  assert.equal(coverage.secondsRemaining, 3600);
});

test("coverage is refused when no window matches the endpoint", () => {
  const elsewhere = window({ id: "w2", scope: "agent", scope_id: "agent-9" });
  assert.equal(powerWindowCoverage([elsewhere], target, 60, NOW).status, "no_window");
  assert.equal(powerWindowCoverage([], target, 60, NOW).status, "no_window");
});

test("a delay that outlives the window is reported as insufficient, not covered", () => {
  const short = window({ ends_at: "2026-08-12T21:05:00Z" });
  const coverage = powerWindowCoverage([short], target, 3600, NOW);
  assert.equal(coverage.status, "delay_exceeds_window");
  assert.equal(coverage.secondsRemaining, 300);
  // Exactly reaching the closing instant is accepted, as the server accepts it.
  assert.equal(powerWindowCoverage([short], target, 300, NOW).status, "covered");
  assert.equal(powerWindowCoverage([short], target, 301, NOW).status, "delay_exceeds_window");
});

test("the earliest-ending window decides, matching the window the server signs against", () => {
  const long = window({ id: "w-long", scope: "global", scope_id: null, ends_at: "2026-08-13T06:00:00Z" });
  const short = window({ id: "w-short", ends_at: "2026-08-12T21:10:00Z" });
  const coverage = powerWindowCoverage([long, short], target, 1800, NOW);
  assert.equal(coverage.status, "delay_exceeds_window");
  assert.equal(coverage.window.id, "w-short");
});

test("windows outside their validity span are neither open nor covering", () => {
  const future = window({ starts_at: "2026-08-12T23:00:00Z", ends_at: "2026-08-13T01:00:00Z" });
  const past = window({ starts_at: "2026-08-12T10:00:00Z", ends_at: "2026-08-12T11:00:00Z" });
  assert.equal(windowOpenAt(future, NOW), false);
  assert.equal(windowOpenAt(past, NOW), false);
  assert.equal(windowStateAt(future, NOW), "upcoming");
  assert.equal(windowStateAt(past, NOW), "expired");
  assert.equal(windowStateAt(window(), NOW), "active");
  assert.equal(powerWindowCoverage([future, past], target, 60, NOW).status, "no_window");
});

test("recurring windows only cover the endpoint during an occurrence", () => {
  // 2026-08-12 is a Wednesday (ISO weekday 2 with Monday as 0).
  const recurring = window({
    starts_at: "2026-08-01T00:00:00Z",
    ends_at: "2026-09-01T00:00:00Z",
    recurrence: { days: [2], start: "20:30", duration_minutes: 120 },
  });
  assert.equal(windowOpenAt(recurring, NOW), true);
  assert.equal(windowOpenAt(recurring, Date.parse("2026-08-12T23:30:00Z")), false);
  assert.equal(windowStateAt(recurring, Date.parse("2026-08-12T23:30:00Z")), "between_occurrences");
  // An occurrence that began before local midnight is still matched.
  const overnight = window({
    starts_at: "2026-08-01T00:00:00Z",
    ends_at: "2026-09-01T00:00:00Z",
    recurrence: { days: [2], start: "23:00", duration_minutes: 180 },
  });
  assert.equal(windowOpenAt(overnight, Date.parse("2026-08-13T01:00:00Z")), true);
  assert.equal(windowOpenAt(overnight, Date.parse("2026-08-13T02:30:00Z")), false);
});

test("recurrence is evaluated in the window's own time zone", () => {
  const newYork = window({
    timezone: "America/New_York",
    starts_at: "2026-08-01T00:00:00Z",
    ends_at: "2026-09-01T00:00:00Z",
    recurrence: { days: [2], start: "18:00", duration_minutes: 60 },
  });
  // 18:00 in New York on Wednesday 12 August 2026 is 22:00 UTC (EDT, UTC-4).
  assert.equal(windowOpenAt(newYork, Date.parse("2026-08-12T22:30:00Z")), true);
  assert.equal(windowOpenAt(newYork, Date.parse("2026-08-12T18:30:00Z")), false);
});

// --------------------------------------------------------------------------- //
// Time-zone arithmetic
// --------------------------------------------------------------------------- //

test("wall times resolve to instants in the selected zone, across DST", () => {
  assert.equal(zonedWallTimeToUtc("2026-08-12T21:00", "UTC"), Date.parse("2026-08-12T21:00:00Z"));
  // EDT (UTC-4) in August, EST (UTC-5) in January.
  assert.equal(
    zonedWallTimeToUtc("2026-08-12T17:00", "America/New_York"),
    Date.parse("2026-08-12T21:00:00Z"),
  );
  assert.equal(
    zonedWallTimeToUtc("2026-01-12T17:00", "America/New_York"),
    Date.parse("2026-01-12T22:00:00Z"),
  );
  assert.equal(zonedWallTimeToUtc("not a time", "UTC"), null);
  assert.equal(zonedWallTimeToUtc("2026-08-12T21:00", "Mars/Olympus"), null);
});

test("instants round-trip back into the input format the form uses", () => {
  assert.equal(formatWallTimeInput(Date.parse("2026-08-12T21:07:00Z"), "UTC"), "2026-08-12T21:07");
  assert.equal(
    formatWallTimeInput(Date.parse("2026-08-12T21:07:00Z"), "America/New_York"),
    "2026-08-12T17:07",
  );
  // Seconds truncate downward, so "now" never resolves into the future.
  const truncated = zonedWallTimeToUtc(
    formatWallTimeInput(Date.parse("2026-08-12T21:07:45Z"), "UTC"),
    "UTC",
  );
  assert.ok(truncated !== null && truncated <= Date.parse("2026-08-12T21:07:45Z"));
});

// --------------------------------------------------------------------------- //
// Creation form
// --------------------------------------------------------------------------- //

const baseForm: MaintenanceWindowFormInput = {
  name: "Reboot for KB5120708",
  scope: "agent",
  scopeId: "agent-1",
  startsAt: "2026-08-12T21:00",
  endsAt: "2026-08-12T22:00",
  timeZone: "UTC",
};

test("a valid form produces the exact create request the service expects", () => {
  const result = validateMaintenanceWindowForm(baseForm, NOW);
  assert.equal(result.ok, true);
  assert.deepEqual(result.ok && result.request, {
    name: "Reboot for KB5120708",
    scope: "agent",
    scope_id: "agent-1",
    starts_at: "2026-08-12T21:00:00.000Z",
    ends_at: "2026-08-12T22:00:00.000Z",
    timezone: "UTC",
  });
});

test("creation validation refuses missing identity, scope targets, and inverted spans", () => {
  const cases: Array<[Partial<MaintenanceWindowFormInput>, RegExp]> = [
    [{ name: "   " }, /window name/],
    [{ name: "x".repeat(201) }, /window name/],
    [{ scopeId: "" }, /Choose the endpoint/],
    [{ scope: "global", scopeId: "agent-1" }, /takes no target/],
    [{ endsAt: "2026-08-12T21:00" }, /end after it starts/],
    [{ startsAt: "2026-08-12T22:00", endsAt: "2026-08-12T21:00" }, /end after it starts/],
    [{ startsAt: "", endsAt: "" }, /start and end date/],
    [{ timeZone: "Mars/Olympus" }, /IANA time zone/],
    [{ startsAt: "2026-08-01T00:00", endsAt: "2026-09-30T00:00" }, /limited to 30 days/],
    [{ startsAt: "2026-08-12T18:00", endsAt: "2026-08-12T19:00" }, /end in the future/],
  ];
  for (const [overrides, expected] of cases) {
    const result = validateMaintenanceWindowForm({ ...baseForm, ...overrides }, NOW);
    assert.equal(result.ok, false, `expected ${JSON.stringify(overrides)} to be refused`);
    assert.match(result.ok ? "" : result.error, expected);
  }
});

test("a global window needs no target and is accepted", () => {
  const result = validateMaintenanceWindowForm(
    { ...baseForm, scope: "global", scopeId: "" }, NOW,
  );
  assert.equal(result.ok, true);
  assert.equal(result.ok && result.request.scope_id, null);
});

test("a window prepared for a power action must already cover the whole delay", () => {
  const tooShort = validateMaintenanceWindowForm(
    { ...baseForm, startsAt: "2026-08-12T20:55", endsAt: "2026-08-12T21:05", requiredCoverageSeconds: 3600 },
    NOW,
  );
  assert.equal(tooShort.ok, false);
  assert.match(tooShort.ok ? "" : tooShort.error, /closes before the 1 hour delay/);

  const notYetOpen = validateMaintenanceWindowForm(
    { ...baseForm, startsAt: "2026-08-12T21:30", endsAt: "2026-08-12T23:00", requiredCoverageSeconds: 60 },
    NOW,
  );
  assert.equal(notYetOpen.ok, false);
  assert.match(notYetOpen.ok ? "" : notYetOpen.error, /already be open/);

  const sufficient = validateMaintenanceWindowForm(
    { ...baseForm, startsAt: "2026-08-12T20:55", endsAt: "2026-08-12T22:00", requiredCoverageSeconds: 60 },
    NOW,
  );
  assert.equal(sufficient.ok, true);
});

test("a window created from the refused dispatch makes the retry covered", () => {
  const created = validateMaintenanceWindowForm(
    { ...baseForm, startsAt: "2026-08-12T20:55", endsAt: "2026-08-12T22:00", requiredCoverageSeconds: 60 },
    NOW,
  );
  assert.equal(created.ok, true);
  assert.equal(powerWindowCoverage([], target, 60, NOW).status, "no_window");
  const persisted = window({
    ...(created.ok ? created.request : {}),
    id: "window-new",
    created_by: "admin@example.test",
    created_at: "2026-08-12T21:00:00Z",
    recurrence: null,
  });
  assert.equal(powerWindowCoverage([persisted], target, 60, NOW).status, "covered");
});

// --------------------------------------------------------------------------- //
// Proxy request validation
// --------------------------------------------------------------------------- //

const wireRequest = {
  name: "Reboot for KB5120708",
  scope: "agent",
  scope_id: "agent-1",
  starts_at: "2026-08-12T21:00:00.000Z",
  ends_at: "2026-08-12T22:00:00.000Z",
  timezone: "UTC",
};

test("the proxy re-validates the posted request instead of trusting the browser", () => {
  assert.equal(validateMaintenanceWindowRequest(wireRequest, NOW).ok, true);
  const rejected: Array<[unknown, RegExp]> = [
    [null, /malformed/],
    [{ ...wireRequest, recurrence: { days: [1] } }, /unsupported fields/],
    [{ ...wireRequest, scope: "fleet" }, /global, client, site, or endpoint/],
    [{ ...wireRequest, scope_id: null }, /Choose the endpoint/],
    [{ ...wireRequest, scope_id: 7 }, /global, client, site, or endpoint/],
    [{ ...wireRequest, starts_at: "yesterday" }, /start and end date/],
    [{ ...wireRequest, ends_at: "2026-08-12T20:00:00.000Z" }, /end after it starts/],
    [{ ...wireRequest, timezone: "Mars/Olympus" }, /IANA time zone/],
    [{ ...wireRequest, name: "" }, /window name/],
  ];
  for (const [body, expected] of rejected) {
    const result = validateMaintenanceWindowRequest(body, NOW);
    assert.equal(result.ok, false, `expected ${JSON.stringify(body)} to be refused`);
    assert.match(result.ok ? "" : result.error, expected);
  }
});

test("the proxy normalizes offsets to UTC instants before forwarding", () => {
  const result = validateMaintenanceWindowRequest(
    { ...wireRequest, starts_at: "2026-08-12T17:00:00-04:00", ends_at: "2026-08-12T19:00:00-04:00" },
    NOW,
  );
  assert.equal(result.ok, true);
  assert.equal(result.ok && result.request.starts_at, "2026-08-12T21:00:00.000Z");
  assert.equal(result.ok && result.request.ends_at, "2026-08-12T23:00:00.000Z");
});

// --------------------------------------------------------------------------- //
// Navigation from a refused dispatch
// --------------------------------------------------------------------------- //

test("only maintenance-window codes are treated as navigable", () => {
  assert.equal(isMaintenanceWindowErrorCode("power_operation_maintenance_window_required"), true);
  assert.equal(isMaintenanceWindowErrorCode("power_operation_delay_exceeds_maintenance_window"), true);
  assert.equal(isMaintenanceWindowErrorCode("patch_install_maintenance_window_required"), true);
  assert.equal(isMaintenanceWindowErrorCode("power_operation_user_consent_required"), false);
  assert.equal(isMaintenanceWindowErrorCode(undefined), false);
});

test("the refusal link prefills an endpoint-scoped window and carries the return path", () => {
  const href = maintenanceWindowPromptHref({
    endpointId: "agent-1",
    hostname: "WS-042",
    delaySeconds: 60,
    returnPath: "/endpoints/agent-1/commands",
  });
  const query = new URLSearchParams(href.slice(href.indexOf("?") + 1));
  assert.ok(href.startsWith("/maintenance-windows?"));
  assert.equal(query.get("scope"), "agent");
  assert.equal(query.get("scope_id"), "agent-1");
  assert.equal(query.get("cover_seconds"), "60");
  assert.equal(query.get("return"), "/endpoints/agent-1/commands");
  assert.match(query.get("name") ?? "", /WS-042/);
});

test("the return path never leaves this origin", () => {
  assert.equal(safeReturnPath("/endpoints/agent-1/commands"), "/endpoints/agent-1/commands");
  assert.equal(safeReturnPath("//evil.test/steal"), null);
  assert.equal(safeReturnPath("https://evil.test"), null);
  assert.equal(safeReturnPath("/endpoints\\@evil.test"), null);
  assert.equal(safeReturnPath("/endpoints/a b"), null);
  assert.equal(safeReturnPath(42), null);
  const promptWithHostileReturn = maintenanceWindowPromptHref({
    endpointId: "agent-1", hostname: "WS-042", returnPath: "//evil.test",
  });
  assert.equal(new URLSearchParams(promptWithHostileReturn.split("?")[1]).get("return"), null);
});

// --------------------------------------------------------------------------- //
// Presentation
// --------------------------------------------------------------------------- //

test("durations, states, scopes, and targets read the way an operator expects", () => {
  assert.equal(formatDurationSeconds(60), "1 minute");
  assert.equal(formatDurationSeconds(3600), "1 hour");
  assert.equal(formatDurationSeconds(5400), "1 hour 30 minutes");
  assert.equal(formatDurationSeconds(90_000), "1 day 1 hour");
  assert.equal(formatDurationSeconds(30), "30 seconds");
  assert.equal(formatDurationSeconds(0), "0 minutes");
  assert.equal(describeWindowState("between_occurrences"), "Between occurrences");
  assert.equal(formatWindowScope("agent"), "Endpoint");
  assert.equal(formatWindowScope("site"), "Site");
  assert.equal(describeRecurrence(null), "Absolute span");
  assert.match(describeRecurrence({ days: [0, 6], start: "02:00", duration_minutes: 90 }), /Mon, Sun at 02:00/);
  const names = new Map([["agent-1", "WS-042"]]);
  assert.equal(formatWindowTarget(window(), names), "WS-042");
  assert.equal(formatWindowTarget(window({ scope_id: "agent-x" }), names), "agent-x");
  assert.equal(formatWindowTarget(window({ scope: "global", scope_id: null }), names), "All managed endpoints");
});
