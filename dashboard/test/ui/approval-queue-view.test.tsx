// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { fireEvent, render, screen, within } from "@testing-library/react";

import { ApprovalQueueView } from "@/components/approval-queue-view";
import type { ApprovalPolicy, ApprovalRequestDetail } from "@/lib/approvals-core";

const requester = "op-requester";
const reviewer = "op-reviewer";
const REASON_LABEL = "Reason (kept in the audit record)";

const pending: ApprovalRequestDetail = {
  id: "req-1",
  agent_id: "agent-1234567890",
  client_id: null,
  site_id: null,
  kind: "powershell",
  status: "pending",
  payload_sha256: "a".repeat(64),
  policy_id: "policy-1",
  required_approvals: 2,
  approvals_recorded: 0,
  requested_by_email: "requester@example.com",
  requested_by_operator_id: requester,
  reason: "Rotate the local admin password",
  created_at: "2026-10-21T12:00:00Z",
  expires_at: "2099-10-21T13:00:00Z",
  decided_at: null,
  consumed_at: null,
  payload_keys: ["script"],
  decisions: [],
  closed_at: null,
  closed_by_email: null,
  consumed_command_id: null,
};

function renderQueue(
  viewerOperatorId: string | null,
  request = pending,
  viewerCanDecide = true,
  policies: ApprovalPolicy[] | null = null,
) {
  render(
    <ApprovalQueueView
      initialDetails={[request]}
      initialError=""
      initialPolicies={policies}
      initialRequests={[request]}
      viewerCanDecide={viewerCanDecide}
      viewerOperatorId={viewerOperatorId}
    />,
  );
}

function openRequest() {
  fireEvent.click(screen.getByRole("row", { name: /Review powershell request/ }));
  return screen.getByRole("dialog");
}

const button = (name: string) => screen.queryByRole("button", { name: new RegExp(name) });

test("the page follows the template with a breadcrumb and no primary action", () => {
  renderQueue(reviewer);
  const crumbs = screen.getByRole("navigation", { name: "Breadcrumb" });
  assert.ok(within(crumbs).getByText("Compliance"));
  assert.ok(screen.getByRole("heading", { level: 1, name: "Approvals" }));
  // Decisions live in the drawer; nothing on the page itself acts.
  assert.equal(button("Approve"), null);
  assert.equal(button("Reject"), null);
});

test("the requester gets no approve or reject control on their own request", () => {
  renderQueue(requester);
  openRequest();
  assert.equal(button("Approve"), null);
  assert.equal(button("Reject"), null);
  assert.ok(button("Withdraw"));
  assert.ok(screen.getByText("You raised this request, so you cannot approve it."));
});

test("an operator who already decided gets no second decision", () => {
  renderQueue(reviewer, {
    ...pending,
    approvals_recorded: 1,
    decisions: [{ id: "d1", operator_id: reviewer, operator_email: "reviewer@example.com", decision: "approve", reason: null, created_at: "2026-10-21T12:05:00Z" }],
  });
  openRequest();
  assert.equal(button("Approve"), null);
  assert.ok(screen.getByText("You have already recorded a decision on this request."));
});

test("an unresolved viewer identity hides the decision controls", () => {
  renderQueue(null);
  openRequest();
  assert.equal(button("Approve"), null);
  assert.ok(screen.getByText("Your identity could not be resolved."));
});

test("a role without decide rights sees the request but no decision controls", () => {
  renderQueue(reviewer, pending, false);
  openRequest();
  assert.equal(button("Approve"), null);
  assert.equal(button("Reject"), null);
  assert.equal(screen.queryByLabelText(REASON_LABEL), null);
});

test("the drawer shows what will run, the fingerprint and that approval is bound to it", () => {
  renderQueue(reviewer);
  const drawer = openRequest();
  assert.ok(within(drawer).getByRole("heading", { name: "Exactly what will run" }));
  assert.match(within(drawer).getByLabelText("Fingerprint").textContent ?? "", new RegExp("a".repeat(64)));
  assert.match(within(drawer).getByRole("note").textContent ?? "", /tied to this exact command/);
  assert.ok(within(drawer).getByText("script"));
});

test("a second identity must give a reason before the approval is sent", async (t) => {
  const fetchMock = t.mock.method(globalThis, "fetch", async () =>
    new Response(JSON.stringify({ request: { ...pending, approvals_recorded: 1 } }), { status: 200 }));
  renderQueue(reviewer);
  openRequest();

  fireEvent.click(button("Approve")!);
  assert.equal(screen.getByRole("alert").textContent, "Enter a printable reason of 10 to 512 characters.");
  assert.equal(fetchMock.mock.callCount(), 0);

  fireEvent.change(screen.getByLabelText(REASON_LABEL), { target: { value: "Reviewed the script body" } });
  fireEvent.click(button("Approve")!);
  assert.ok(await screen.findByText("Approval recorded. It still needs another identity."));
  const [url, init] = fetchMock.mock.calls[0].arguments as [string, RequestInit];
  assert.equal(url, "/api/approval-requests/req-1/approve");
  assert.deepEqual(JSON.parse(String(init.body)), { reason: "Reviewed the script body" });
});

test("rejecting goes through a confirmation that still enforces the decision-reason rules", async (t) => {
  const fetchMock = t.mock.method(globalThis, "fetch", async () =>
    new Response(JSON.stringify({ request: { ...pending, status: "rejected" } }), { status: 200 }));
  renderQueue(reviewer);
  openRequest();
  fireEvent.click(button("Reject request")!);

  const dialog = screen.getByRole("alertdialog", { name: "Reject this request?" });
  const confirm = within(dialog).getByRole("button", { name: "Reject request" }) as HTMLButtonElement;
  assert.equal(confirm.disabled, true, "confirm stays disabled until a reason is typed");

  // Non-blank but shorter than the server's minimum: refused locally, nothing sent.
  fireEvent.change(within(dialog).getByLabelText(REASON_LABEL), { target: { value: "too short" } });
  fireEvent.click(confirm);
  assert.ok(within(dialog).getByText("Enter a printable reason of 10 to 512 characters."));
  assert.equal(fetchMock.mock.callCount(), 0);

  fireEvent.change(within(dialog).getByLabelText(REASON_LABEL), { target: { value: "The script targets the wrong host" } });
  fireEvent.click(confirm);
  assert.ok(await screen.findByText("Request rejected."));
  const [url, init] = fetchMock.mock.calls[0].arguments as [string, RequestInit];
  assert.equal(url, "/api/approval-requests/req-1/reject");
  assert.deepEqual(JSON.parse(String(init.body)), { reason: "The script targets the wrong host" });
  assert.equal(screen.queryByRole("alertdialog"), null);
});

test("a refused rejection keeps the dialog open with the server message", async (t) => {
  t.mock.method(globalThis, "fetch", async () => new Response(JSON.stringify({ error: "This request is no longer pending." }), { status: 409 }));
  renderQueue(reviewer);
  openRequest();
  fireEvent.click(button("Reject request")!);
  const dialog = screen.getByRole("alertdialog");
  fireEvent.change(within(dialog).getByLabelText(REASON_LABEL), { target: { value: "The script targets the wrong host" } });
  fireEvent.click(within(dialog).getByRole("button", { name: "Reject request" }));
  assert.ok(await within(dialog).findByText("This request is no longer pending."));
});

test("stat tiles count only what was loaded and do not invent a policy count", () => {
  renderQueue(reviewer);
  const waiting = screen.getByText("Waiting for you").closest("dl")!;
  assert.equal(within(waiting).getByText("1").tagName, "DD");
  const policies = screen.getByText("Policies in force", { selector: "dt" }).closest("dl")!;
  assert.ok(within(policies).getByText("—"));
  assert.ok(within(policies).getByText("Could not be loaded"));
});

test("a failed load is reported instead of an empty queue", () => {
  render(
    <ApprovalQueueView
      initialDetails={[]}
      initialError=""
      initialPolicies={null}
      initialRequests={null}
      viewerCanDecide
      viewerOperatorId={reviewer}
    />,
  );
  const alert = screen.getByRole("alert");
  assert.match(alert.textContent ?? "", /Approval requests could not be loaded/);
  assert.match(alert.textContent ?? "", /Nothing was changed\./);
});

test("requests whose detail failed to load are counted, not silently dropped", () => {
  render(
    <ApprovalQueueView
      initialDetails={[pending]}
      initialError=""
      initialPolicies={[]}
      initialRequests={[pending, { ...pending, id: "req-2" }]}
      viewerCanDecide
      viewerOperatorId={reviewer}
    />,
  );
  assert.ok(screen.getByText("1 request could not be opened and is not listed. Nothing was changed."));
  assert.ok(screen.getByText(/No approval policy is configured/));
});
