// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { fireEvent, render, screen } from "@testing-library/react";

import { ApprovalQueueView } from "@/components/approval-queue-view";
import type { ApprovalRequestDetail } from "@/lib/approvals-core";

const requester = "op-requester";
const reviewer = "op-reviewer";

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

function renderQueue(viewerOperatorId: string | null, request = pending, viewerCanDecide = true) {
  render(
    <ApprovalQueueView
      initialDetails={[request]}
      initialError=""
      initialPolicies={null}
      initialRequests={[request]}
      viewerCanDecide={viewerCanDecide}
      viewerOperatorId={viewerOperatorId}
    />,
  );
}

const button = (name: string) => screen.queryByRole("button", { name: new RegExp(name) });

test("the requester gets no approve or reject control on their own request", () => {
  renderQueue(requester);
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
  assert.equal(button("Approve"), null);
  assert.ok(screen.getByText("You have already recorded a decision on this request."));
});

test("an unresolved viewer identity hides the decision controls", () => {
  renderQueue(null);
  assert.equal(button("Approve"), null);
  assert.ok(screen.getByText("Your identity could not be resolved."));
});

test("a role without decide rights sees the request but no decision controls", () => {
  renderQueue(reviewer, pending, false);
  assert.equal(button("Approve"), null);
  assert.equal(screen.queryByLabelText("Reason"), null);
});

test("a second identity must give a reason before the approval is sent", async (t) => {
  const fetchMock = t.mock.method(globalThis, "fetch", async () =>
    new Response(JSON.stringify({ request: { ...pending, approvals_recorded: 1 } }), { status: 200 }));
  renderQueue(reviewer);

  fireEvent.click(button("Approve")!);
  assert.equal(screen.getByRole("alert").textContent, "Enter a printable reason of 10 to 512 characters.");
  assert.equal(fetchMock.mock.callCount(), 0);

  fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "Reviewed the script body" } });
  fireEvent.click(button("Approve")!);
  assert.ok(await screen.findByText("Approval recorded. It still needs another identity."));
  const [url, init] = fetchMock.mock.calls[0].arguments as [string, RequestInit];
  assert.equal(url, "/api/approval-requests/req-1/approve");
  assert.deepEqual(JSON.parse(String(init.body)), { reason: "Reviewed the script body" });
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
  assert.match(screen.getByRole("alert").textContent ?? "", /Approval requests could not be loaded/);
});
