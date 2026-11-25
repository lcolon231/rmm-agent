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
import type { ScheduleSources } from "@/lib/schedule-form-core";

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


const approved = { state: "approved" as const, reviewed_by: "reviewer", reason_sha256: "b".repeat(64), reason_bytes: 2, created_at: "2026-01-02T00:00:00Z" };
function libraryScript(id: string, name: string, language: "powershell" | "shell", review: typeof approved | null = approved): ScriptItem {
  return { ...script, id, name, latest_version: 3, latest: { ...script.latest, id: `${id}-v3`, version: 3, language, review } };
}
const sources: ScheduleSources = {
  scripts: [libraryScript("s-disk", "Disk cleanup", "powershell"), libraryScript("s-draft", "Draft fix", "powershell", null), libraryScript("s-logs", "Rotate logs", "shell")],
  sites: [{ client: "Acme", options: [{ id: "site-hq", label: "Acme — HQ" }] }, { client: "Globex", options: [{ id: "site-g", label: "Globex — HQ" }] }],
  endpoints: [{ id: "dev-1", label: "web-01" }, { id: "dev-2", label: "db-01" }],
};
const noSchedules = { items: [], total: 0, page: 1, page_size: 50 };

function stubScheduleApi(t: { mock: { method: (...args: never[]) => unknown } }, onCreate: (body: Record<string, unknown>) => Response = () => Response.json({}, { status: 201 })) {
  const sent: Array<Record<string, unknown>> = [];
  (t.mock.method as (o: object, m: string, f: unknown) => unknown)(globalThis, "fetch", async (url: RequestInfo | URL, init?: RequestInit) => {
    const path = String(url);
    if (path === "/api/schedules/script-source/s-disk/3") {
      return Response.json({ ...script.latest, id: "s-disk-v3", version: 3, language: "powershell", review: approved, content: "Clear-RecycleBin -Force" });
    }
    if (path === "/api/schedules" && init?.method === "POST") {
      const body = JSON.parse(init.body as string);
      sent.push(body);
      return onCreate(body);
    }
    throw new Error(`unexpected request ${path}`);
  });
  return sent;
}

test("a library schedule is pinned to the picked approved version and carries its body", async (t) => {
  const sent = stubScheduleApi(t);
  visit(<SchedulesView schedules={noSchedules} role="operator" sources={sources} />);
  fireEvent.click(screen.getByRole("button", { name: "New schedule" }));
  assert.equal((screen.getByRole("radio", { name: "From script library" }) as HTMLInputElement).checked, true);
  const picker = screen.getByRole("combobox", { name: "Library script" });
  assert.deepEqual(within(picker).getAllByRole("option").map((option) => option.textContent), ["Choose a script", "Disk cleanup"]);

  fireEvent.change(picker, { target: { value: "s-disk" } });
  await waitFor(() => assert.ok(screen.getByText("Clear-RecycleBin -Force")));
  assert.match(screen.getByText(/^Version 3/).textContent ?? "", /Approved/);
  assert.equal((screen.getByRole("textbox", { name: "Name" }) as HTMLInputElement).value, "Disk cleanup");
  assert.equal(screen.queryByRole("textbox", { name: "Command or script" }), null);

  fireEvent.change(screen.getByRole("combobox", { name: "Endpoint" }), { target: { value: "dev-2" } });
  fireEvent.click(screen.getByRole("button", { name: "Save schedule" }));
  await waitFor(() => assert.equal(sent.length, 1));
  assert.equal(sent[0].script_version_id, "s-disk-v3");
  assert.equal(sent[0].kind, "powershell");
  assert.deepEqual(sent[0].payload, { script: "Clear-RecycleBin -Force" });
  assert.equal(sent[0].target_type, "agent");
  assert.equal(sent[0].target_id, "dev-2");
  assert.equal(sent[0].name, "Disk cleanup");
});

test("a written-by-hand schedule sends free text to a site chosen from a grouped list", async (t) => {
  const sent = stubScheduleApi(t);
  visit(<SchedulesView schedules={noSchedules} role="operator" sources={sources} />);
  fireEvent.click(screen.getByRole("button", { name: "New schedule" }));
  fireEvent.change(screen.getByRole("textbox", { name: "Name" }), { target: { value: "Hourly ping" } });
  fireEvent.change(screen.getByRole("combobox", { name: "Endpoint" }), { target: { value: "dev-1" } });
  fireEvent.change(screen.getByRole("combobox", { name: "Applies to" }), { target: { value: "site" } });
  fireEvent.change(screen.getByRole("combobox", { name: "Applies to" }), { target: { value: "agent" } });
  // Switching away and back must not resurrect the earlier endpoint.
  assert.equal((screen.getByRole("combobox", { name: "Endpoint" }) as HTMLSelectElement).value, "");
  fireEvent.change(screen.getByRole("combobox", { name: "Applies to" }), { target: { value: "site" } });
  const sites = screen.getByRole("combobox", { name: "Site" }) as HTMLSelectElement;
  assert.deepEqual([...sites.querySelectorAll("optgroup")].map((group) => group.label), ["Acme", "Globex"]);
  assert.ok(within(sites).getByRole("option", { name: "Globex — HQ" }));
  fireEvent.change(sites, { target: { value: "site-g" } });
  fireEvent.change(screen.getByRole("combobox", { name: "Kind" }), { target: { value: "shell" } });
  fireEvent.click(screen.getByRole("radio", { name: "Write my own" }));
  fireEvent.change(screen.getByRole("textbox", { name: "Command or script" }), { target: { value: "uptime" } });
  fireEvent.click(screen.getByRole("button", { name: "Save schedule" }));
  await waitFor(() => assert.equal(sent.length, 1));
  assert.equal(sent[0].target_type, "site");
  assert.equal(sent[0].target_id, "site-g");
  assert.equal(sent[0].kind, "shell");
  assert.deepEqual(sent[0].payload, { command: "uptime" });
  assert.equal("script_version_id" in sent[0], false);
});

test("a server refusal of an unapproved version is shown in the drawer and nothing is saved", async (t) => {
  stubScheduleApi(t, () => Response.json({ error: "The chosen library script version is no longer approved, or its script was retired. Pick another script." }, { status: 409 }));
  visit(<SchedulesView schedules={noSchedules} role="operator" sources={sources} />);
  fireEvent.click(screen.getByRole("button", { name: "New schedule" }));
  fireEvent.change(screen.getByRole("combobox", { name: "Library script" }), { target: { value: "s-disk" } });
  await waitFor(() => assert.ok(screen.getByText("Clear-RecycleBin -Force")));
  fireEvent.change(screen.getByRole("combobox", { name: "Endpoint" }), { target: { value: "dev-1" } });
  fireEvent.click(screen.getByRole("button", { name: "Save schedule" }));
  await waitFor(() => assert.match(screen.getByRole("alert").textContent ?? "", /no longer approved.*Nothing was saved/));
});

test("missing scripts, sites or devices are explained instead of an empty dropdown", () => {
  const view = visit(<SchedulesView schedules={noSchedules} role="operator" sources={{ ...sources, scripts: [libraryScript("s-logs", "Rotate logs", "shell")], endpoints: null }} />);
  fireEvent.click(screen.getByRole("button", { name: "New schedule" }));
  assert.match(screen.getByText(/No approved PowerShell scripts can be scheduled/).textContent ?? "", /Write my own/);
  assert.match(screen.getByRole("alert").textContent ?? "", /Endpoints could not be loaded/);
  assert.equal(screen.queryByRole("combobox", { name: "Endpoint" }), null);
  view.unmount();
  visit(<SchedulesView schedules={noSchedules} role="operator" sources={{ ...sources, sites: null }} />);
  fireEvent.click(screen.getByRole("button", { name: "New schedule" }));
  fireEvent.change(screen.getByRole("combobox", { name: "Applies to" }), { target: { value: "site" } });
  assert.match(screen.getByRole("alert").textContent ?? "", /Sites could not be loaded/);
});

test("schedules show targets and library scripts by name, with the raw ID beneath or as the fallback", () => {
  const named = scheduledTaskFromUnknown({ id: "q-site", name: "Site cleanup", enabled: true, target_type: "site", target_id: "site-hq", cron_expression: "0 0 * * *", timezone: "UTC", kind: "powershell", script_version_id: "s-disk-v3", next_run_at: "2026-12-01T00:00:00Z" })!;
  const orphan = scheduledTaskFromUnknown({ id: "q-gone", name: "Old device job", enabled: true, target_type: "agent", target_id: "dev-gone-123456789", cron_expression: "0 0 * * *", timezone: "UTC", kind: "shell", script_version_id: "old-version-id", next_run_at: "2026-12-01T00:00:00Z" })!;
  visit(<SchedulesView schedules={{ items: [named, orphan], total: 2, page: 1, page_size: 50 }} role="readonly" sources={sources} />);
  assert.ok(within(screen.getByRole("row", { name: "Preview Site cleanup" })).getByText("Acme — HQ"));
  assert.ok(within(screen.getByRole("row", { name: "Preview Site cleanup" })).getByText("Disk cleanup · v3"));
  const orphanRow = within(screen.getByRole("row", { name: "Preview Old device job" }));
  assert.ok(orphanRow.getByText("dev-gone-123456789"));
  assert.ok(orphanRow.getByText("old-version-id"));

  fireEvent.click(screen.getByRole("row", { name: "Preview Site cleanup" }));
  const drawer = within(screen.getByRole("dialog"));
  assert.ok(drawer.getByText("Acme — HQ"));
  assert.ok(drawer.getByText("site-hq"));
  assert.ok(drawer.getByText("Disk cleanup · v3"));
  assert.ok(drawer.getByText("s-disk-v3"));
  fireEvent.click(drawer.getByRole("button", { name: /Close/ }));

  fireEvent.click(screen.getByRole("row", { name: "Preview Old device job" }));
  const fallback = within(screen.getByRole("dialog"));
  assert.ok(fallback.getByText("dev-gone-123456789"));
  assert.ok(fallback.getByText("old-version-id"));
});

test("changing the kind re-filters the library and drops a script that no longer matches", async (t) => {
  const sent = stubScheduleApi(t);
  visit(<SchedulesView schedules={noSchedules} role="operator" sources={sources} />);
  fireEvent.click(screen.getByRole("button", { name: "New schedule" }));
  fireEvent.change(screen.getByRole("combobox", { name: "Library script" }), { target: { value: "s-disk" } });
  await waitFor(() => assert.ok(screen.getByText("Clear-RecycleBin -Force")));

  fireEvent.change(screen.getByRole("combobox", { name: "Kind" }), { target: { value: "shell" } });
  const picker = screen.getByRole("combobox", { name: "Library script" }) as HTMLSelectElement;
  assert.deepEqual(within(picker).getAllByRole("option").map((option) => option.textContent), ["Choose a script", "Rotate logs"]);
  assert.equal(screen.queryByText(/^Version 3/), null);

  // Back to PowerShell: the earlier pick must not come back on its own.
  fireEvent.change(screen.getByRole("combobox", { name: "Kind" }), { target: { value: "powershell" } });
  const cleared = screen.getByRole("combobox", { name: "Library script" }) as HTMLSelectElement;
  assert.equal(cleared.value, "");
  fireEvent.change(screen.getByRole("combobox", { name: "Endpoint" }), { target: { value: "dev-1" } });
  assert.equal(cleared.checkValidity(), false);
  fireEvent.click(screen.getByRole("button", { name: "Save schedule" }));
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(sent.length, 0);
});
