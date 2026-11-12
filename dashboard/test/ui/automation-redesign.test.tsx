// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { AppRouterContext } from "next/dist/shared/lib/app-router-context.shared-runtime";
import type { ReactNode } from "react";
import { ScriptLibraryView } from "@/components/script-library-view";
import { ScriptDetailView } from "@/components/script-detail-view";
import { SchedulesView } from "@/components/schedules/schedules-view";
import { CommunityRepositoryView } from "@/components/community-repository-view";
import { TaskRunsView } from "@/components/automation/task-runs-view";
import { scheduledTaskFromUnknown } from "@/lib/scheduled-tasks-core";
import type { ScriptItem } from "@/lib/script-library-core";

function visit(node: ReactNode) { return render(<AppRouterContext.Provider value={{ refresh() {}, push() {} } as never}>{node}</AppRouterContext.Provider>); }
const script: ScriptItem = { id: "s1", name: "Inventory", latest_version: 1, record_version: 1, deprecated_at: null, deprecated_by: null, created_by: "author", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z", latest: { id: "v1", version: 1, language: "shell", content_sha256: "a".repeat(64), content_bytes: 4, description: null, tags: [], supported_platforms: ["linux"], parameters: [], created_by: "author", created_at: "2026-01-01T00:00:00Z", review: null } };

test("readonly library and script detail expose no authoring or review actions", () => {
  const view = visit(<ScriptLibraryView initialList={{ items: [script], total: 1, page: 1, page_size: 25 }} initialError="" role="readonly" />);
  assert.equal(screen.queryByRole("button", { name: "New script" }), null);
  view.unmount();
  visit(<ScriptDetailView initialScript={script} latestContent="<script>literal text</script>" role="readonly" />);
  assert.equal(screen.queryByRole("button", { name: /Approve version|Reject|Retire script|New version/ }), null);
  assert.ok(screen.getByText("<script>literal text</script>"));
});

test("script rejection sends the required reason and retains a refused review", async (t) => {
  let body: unknown;
  t.mock.method(globalThis, "fetch", async (_url: RequestInfo | URL, init?: RequestInit) => { body = JSON.parse(init?.body as string); return Response.json({ error: "Review refused" }, { status: 403 }); });
  visit(<ScriptDetailView initialScript={script} latestContent="echo" role="admin" />);
  fireEvent.click(screen.getByRole("button", { name: "Reject" }));
  const dialog = within(screen.getByRole("alertdialog"));
  assert.equal((dialog.getByRole("button", { name: "Reject version" }) as HTMLButtonElement).disabled, true);
  fireEvent.change(dialog.getByRole("textbox"), { target: { value: "Unsafe command" } });
  fireEvent.click(dialog.getByRole("button", { name: "Reject version" }));
  await waitFor(() => assert.match(screen.getByRole("alertdialog").textContent ?? "", /Review refused/));
  assert.deepEqual(body, { state: "rejected", reason: "Unsafe command" });
});

test("schedule deletion requires a reason and readonly schedules have no mutation controls", () => {
  const task = scheduledTaskFromUnknown({ id: "q1", name: "Daily", enabled: true, target_type: "agent", target_id: "a1", cron_expression: "0 0 * * *", timezone: "UTC", kind: "shell", next_run_at: "2026-12-01T00:00:00Z" })!;
  const schedules = { items: [task], total: 1, page: 1, page_size: 50 };
  const view = visit(<SchedulesView schedules={schedules} role="readonly" />);
  fireEvent.click(screen.getByRole("row", { name: "Preview Daily" }));
  assert.equal(screen.queryByRole("button", { name: /Delete|New schedule|Run now|Pause schedule/ }), null);
  view.unmount();
  visit(<SchedulesView schedules={schedules} role="admin" />);
  fireEvent.click(screen.getByRole("row", { name: "Preview Daily" }));
  fireEvent.click(screen.getByRole("button", { name: "Delete" }));
  assert.equal((within(screen.getByRole("alertdialog")).getByRole("button", { name: "Delete schedule" }) as HTMLButtonElement).disabled, true);
});

test("unavailable community and task records are errors, not empty or successful counts", () => {
  const view = visit(<CommunityRepositoryView publishers={null} packages={null} installs={null} initialError="Unavailable" role="readonly" />);
  assert.match(screen.getByRole("alert").textContent ?? "", /Nothing was changed/);
  assert.equal(screen.queryByRole("button", { name: /Submit|Register|Revoke/ }), null);
  view.unmount();
  visit(<TaskRunsView history={null} filters={{}} filtered={false} pageSize={25} pageCount={1} />);
  assert.match(screen.getByRole("alert").textContent ?? "", /Nothing was changed/);
  assert.equal(screen.queryByRole("table"), null);
});

