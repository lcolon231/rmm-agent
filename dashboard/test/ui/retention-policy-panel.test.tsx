// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";

import { RetentionPolicyPanel } from "@/components/retention-policy-panel";
import { retentionPolicyFromUnknown, type RetentionPolicy } from "@/lib/retention-policy-core";
import { category, policyPayload } from "../support/retention-policy-fixture";

function policy(overrides: Record<string, unknown> = {}): RetentionPolicy {
  const parsed = retentionPolicyFromUnknown(policyPayload(overrides));
  assert.ok(parsed);
  return parsed;
}

type Call = { url: string; method: string; body: unknown };

function stubFetch(t: { mock: { method: typeof import("node:test").mock.method } }, responses: Response[]) {
  const calls: Call[] = [];
  t.mock.method(globalThis, "fetch", async (url: RequestInfo | URL, init?: RequestInit) => {
    calls.push({
      url: String(url),
      method: init?.method ?? "GET",
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
    });
    const next = responses.shift();
    assert.ok(next, `unexpected request ${init?.method} ${String(url)}`);
    return next;
  });
  return calls;
}

function row(label: string) {
  return within(screen.getByRole("row", { name: new RegExp(`^${label}`) }));
}

function openEditor() {
  fireEvent.click(screen.getByRole("button", { name: "Edit retention" }));
}

function setCustom(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(`${label} retention`), { target: { value: "custom" } });
  fireEvent.change(screen.getByLabelText(`${label} value`), { target: { value } });
}

/** Bring the fixture's two clamped overrides back inside the bounds. */
function fixClamped() {
  setCustom("Inventory history", "1000");
  fireEvent.change(screen.getByLabelText("Notification deliveries retention"), { target: { value: "inherit" } });
}

test("each category shows its effective value, source, override and bounds", () => {
  render(<RetentionPolicyPanel clientId="client-1" initialPolicy={policy()} />);
  const inventory = row("Inventory history");
  assert.ok(inventory.getByText("1000 snapshots"));
  assert.ok(inventory.getByText("Lowered to platform maximum"));
  assert.ok(inventory.getByText("5000 snapshots"));
  assert.ok(inventory.getByText("50 snapshots"));
  const notifications = row("Notification deliveries");
  assert.ok(notifications.getByText("Raised to platform minimum"));
  assert.ok(notifications.getByText("3 days"));
  const telemetry = row("Telemetry");
  assert.ok(telemetry.getByText("Platform default"));
  assert.ok(telemetry.getByText("Not set"));
  assert.ok(telemetry.getByText("1 day – 3650 days"));
  assert.ok(row("Evidence default").getByText("At least 2555 days"));
  assert.ok(row("Resolved alerts").getAllByText("Keep forever").length >= 1);
});

test("a read-only member sees the policy with no edit control at all", () => {
  render(<RetentionPolicyPanel clientId="client-1" initialPolicy={policy({ can_edit: false })} />);
  assert.ok(screen.getByRole("heading", { name: "Retention" }));
  assert.equal(screen.queryByRole("button", { name: /Edit retention|Reset|Save/ }), null);
  assert.equal(screen.queryByRole("combobox"), null);
  assert.equal(screen.queryByRole("textbox"), null);
});

test("an active tenant-wide legal hold is announced", () => {
  render(<RetentionPolicyPanel clientId="client-1" initialPolicy={policy({ pruning_suspended: true })} />);
  const banner = screen.getByRole("status", { name: "Pruning suspended" });
  assert.match(banner.textContent ?? "", /legal hold/i);
  assert.ok(within(banner).getByRole("link", { name: /evidence vault holds/i }));
});

test("keep forever is offered only where the platform allows it", () => {
  render(<RetentionPolicyPanel clientId="client-1" initialPolicy={policy()} />);
  openEditor();
  const options = (label: string) => within(screen.getByLabelText(`${label} retention`))
    .getAllByRole("option").map((option) => option.textContent);
  assert.ok(options("Resolved alerts").includes("Keep forever"));
  assert.ok(!options("Telemetry").includes("Keep forever"));
  assert.ok(!options("Evidence default").includes("Keep forever"));
});

test("an out-of-bounds value is caught on its field before any request", (t) => {
  const calls = stubFetch(t, []);
  render(<RetentionPolicyPanel clientId="client-1" initialPolicy={policy()} />);
  openEditor();
  fixClamped();
  setCustom("Command records", "10");
  assert.match(screen.getByLabelText("Command records value").getAttribute("aria-describedby") ?? "", /hint|error/);
  fireEvent.click(screen.getByRole("button", { name: "Save retention" }));
  assert.equal(screen.getByLabelText("Command records value").getAttribute("aria-invalid"), "true");
  assert.ok(screen.getByText("Must be at least 30 days."));
  assert.equal(calls.length, 0);
});

test("shortening asks for confirmation that pruned data is unrecoverable, then saves with the version", async (t) => {
  const saved = policyPayload({ version: 4 });
  const calls = stubFetch(t, [Response.json({ policy: retentionPolicyFromUnknown(saved) })]);
  render(<RetentionPolicyPanel clientId="client-1" initialPolicy={policy()} />);
  openEditor();
  fixClamped();
  setCustom("Telemetry", "7");
  fireEvent.click(screen.getByRole("button", { name: "Save retention" }));
  const dialog = within(screen.getByRole("alertdialog"));
  assert.match(dialog.getByRole("heading").textContent ?? "", /Shorten retention/);
  assert.ok(dialog.getByText(/cannot be recovered/));
  assert.ok(dialog.getByText(/Telemetry/));
  assert.equal(calls.length, 0);

  fireEvent.click(dialog.getByRole("button", { name: "Shorten and save" }));
  await waitFor(() => assert.equal(calls.length, 1));
  assert.equal(calls[0].url, "/api/clients/client-1/retention-policy");
  assert.equal(calls[0].method, "PUT");
  assert.deepEqual(calls[0].body, {
    expected_version: 3,
    telemetry_days: 7,
    command_output_days: null,
    command_record_days: 400,
    inventory_history_per_section: 1000,
    alert_days: 0,
    notification_days: null,
    evidence_default_days: null,
  });
  await waitFor(() => assert.ok(screen.getByText("Retention policy saved.")));
});

test("a save that only lengthens goes straight through", async (t) => {
  const calls = stubFetch(t, [Response.json({ policy: policy({ version: 4 }) })]);
  render(<RetentionPolicyPanel clientId="client-1" initialPolicy={policy()} />);
  openEditor();
  fixClamped();
  setCustom("Telemetry", "60");
  fireEvent.click(screen.getByRole("button", { name: "Save retention" }));
  assert.equal(screen.queryByRole("alertdialog"), null);
  await waitFor(() => assert.equal(calls.length, 1));
});

test("a 409 reloads the policy and shows what changed instead of overwriting", async (t) => {
  const theirs = policy({
    version: 5,
    set_by: "other@example.test",
    categories: {
      ...policyPayload().categories,
      telemetry_days: category({ effective: 14, source: "tenant", override: 14 }),
    },
  });
  const calls = stubFetch(t, [
    Response.json({ error: "conflict", code: "retention_policy_conflict", category: null }, { status: 409 }),
    Response.json({ policy: theirs }),
  ]);
  render(<RetentionPolicyPanel clientId="client-1" initialPolicy={policy()} />);
  openEditor();
  fixClamped();
  setCustom("Telemetry", "60");
  fireEvent.click(screen.getByRole("button", { name: "Save retention" }));
  const alert = await screen.findByRole("alert", { name: "Policy changed by another administrator" });
  assert.match(alert.textContent ?? "", /other@example\.test/);
  assert.match(alert.textContent ?? "", /Telemetry: Not set → 14 days/);
  assert.deepEqual(calls.map((call) => call.method), ["PUT", "GET"]);
  // The table now reflects the other administrator's saved value.
  assert.ok(row("Telemetry").getAllByText("14 days").length >= 1);
});

test("a 422 is shown on the field the server named", async (t) => {
  stubFetch(t, [Response.json(
    { error: "below", code: "retention_below_minimum", category: "alert_days" },
    { status: 422 },
  )]);
  render(<RetentionPolicyPanel clientId="client-1" initialPolicy={policy()} />);
  openEditor();
  fixClamped();
  setCustom("Telemetry", "60");
  fireEvent.click(screen.getByRole("button", { name: "Save retention" }));
  await waitFor(() => assert.equal(
    screen.getByLabelText("Resolved alerts retention").getAttribute("aria-invalid"),
    "true",
  ));
  assert.ok(screen.getByText("This value is below the platform minimum."));
});

test("step-up is prompted on request and the save is retried once confirmed", async (t) => {
  const calls = stubFetch(t, [
    Response.json({ error: "step up", code: "step_up_required", category: null }, { status: 403 }),
    Response.json({ policy: policy({ version: 4 }) }),
  ]);
  let stepUps = 0;
  render(
    <RetentionPolicyPanel
      clientId="client-1"
      initialPolicy={policy()}
      performStepUp={async () => { stepUps += 1; return { ok: true }; }}
    />,
  );
  openEditor();
  fixClamped();
  setCustom("Telemetry", "60");
  fireEvent.click(screen.getByRole("button", { name: "Save retention" }));
  const prompt = await screen.findByRole("button", { name: "Confirm with security key" });
  // The key prompt only appears after the operator asks for it.
  assert.equal(stepUps, 0);
  fireEvent.click(prompt);
  await waitFor(() => assert.ok(screen.getByText("Retention policy saved.")));
  assert.equal(stepUps, 1);
  assert.deepEqual(calls.map((call) => call.method), ["PUT", "PUT"]);
  assert.deepEqual(calls[1].body, calls[0].body);
});

test("a failed step-up does not retry the save", async (t) => {
  const calls = stubFetch(t, [
    Response.json({ error: "step up", code: "step_up_required", category: null }, { status: 403 }),
  ]);
  render(
    <RetentionPolicyPanel
      clientId="client-1"
      initialPolicy={policy()}
      performStepUp={async () => ({ ok: false, error: "The security key prompt was cancelled." })}
    />,
  );
  openEditor();
  fixClamped();
  setCustom("Telemetry", "60");
  fireEvent.click(screen.getByRole("button", { name: "Save retention" }));
  fireEvent.click(await screen.findByRole("button", { name: "Confirm with security key" }));
  await waitFor(() => assert.ok(screen.getByText("The security key prompt was cancelled.")));
  assert.equal(calls.length, 1);
});

test("reset to platform defaults confirms the shortening and sends DELETE with the version", async (t) => {
  const calls = stubFetch(t, [Response.json({ policy: policy({ version: 4 }) })]);
  render(<RetentionPolicyPanel clientId="client-1" initialPolicy={policy()} />);
  openEditor();
  fireEvent.click(screen.getByRole("button", { name: "Reset to platform defaults" }));
  const dialog = within(screen.getByRole("alertdialog"));
  // Inventory drops from an effective 1000 to the platform default of 50.
  assert.ok(dialog.getByText(/Inventory history/));
  fireEvent.click(dialog.getByRole("button", { name: "Reset and save" }));
  await waitFor(() => assert.equal(calls.length, 1));
  assert.equal(calls[0].method, "DELETE");
  assert.deepEqual(calls[0].body, { expected_version: 3 });
});

test("reset is not offered when the client already inherits everything", () => {
  const inherited = Object.fromEntries(Object.entries(policyPayload().categories).map(
    ([name, entry]) => [name, { ...entry, override: null, source: "default" }],
  ));
  render(<RetentionPolicyPanel clientId="client-1" initialPolicy={policy({ categories: inherited })} />);
  openEditor();
  assert.equal(screen.queryByRole("button", { name: "Reset to platform defaults" }), null);
});
