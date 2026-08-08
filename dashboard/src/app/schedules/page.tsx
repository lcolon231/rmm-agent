// SPDX-License-Identifier: AGPL-3.0-only

import { Clock, Layers, PlayCircle, ShieldCheck } from "lucide-react";
import { redirect } from "next/navigation";

import { CreateScheduleButton, ScheduleRowActions } from "@/components/schedules/schedule-actions";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getScheduledTasks } from "@/lib/scheduled-tasks";
import { formatScheduleDateTime, type ScheduledTaskListData } from "@/lib/scheduled-tasks-core";

export const dynamic = "force-dynamic";

export default async function SchedulesPage() {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");

  let schedules: ScheduledTaskListData | null = null;
  try {
    schedules = await getScheduledTasks(session.sessionToken);
  } catch {
    schedules = null;
  }

  const items = schedules?.items ?? [];
  const total = schedules?.total ?? 0;
  const activeCount = items.filter((i) => i.enabled).length;

  return (
    <>
      <header className="enrollment-page-head">
        <div>
          <span>Timezone-aware task automation</span>
          <h1>Recurring task scheduling</h1>
          <p>
            Configure cron-scheduled script execution for individual endpoints or entire organization sites with
            concurrency safety, misfire protection, and full audit provenance.
          </p>
        </div>
        {session.operator.role !== "readonly" ? <CreateScheduleButton /> : null}
      </header>

      <section className="agent-identity-grid">
        <article>
          <Clock size={20} />
          <span>Total schedules</span>
          <strong>{total}</strong>
          <small>Configured cron tasks</small>
        </article>
        <article>
          <PlayCircle size={20} />
          <span>Active schedules</span>
          <strong>{activeCount}</strong>
          <small>Enabled and scheduling</small>
        </article>
        <article>
          <ShieldCheck size={20} />
          <span>Audit posture</span>
          <strong>Fail-closed</strong>
          <small>All dispatches cryptographically signed</small>
        </article>
      </section>

      <section className="enrollment-panel">
        <header>
          <div>
            <span>Automated dispatches</span>
            <h2>{total} Schedule{total === 1 ? "" : "s"}</h2>
          </div>
          <Layers size={18} />
        </header>

        {items.length === 0 ? (
          <div className="enrollment-empty">
            <p>No recurring task schedules have been created yet.</p>
          </div>
        ) : (
          <div className="enrollment-table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Schedule name</th>
                  <th>Target scope</th>
                  <th>Cron / Timezone</th>
                  <th>Kind</th>
                  <th>Next run</th>
                  <th>Last run</th>
                  <th>Last status</th>
                  <th className="text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {items.map((task) => (
                  <tr key={task.id}>
                    <td>
                      <strong>{task.name}</strong>
                      {task.description ? <small>{task.description}</small> : null}
                    </td>
                    <td>
                      <span className="badge-target">{task.target_type}</span>
                      <small><code>{task.target_id.slice(0, 12)}…</code></small>
                    </td>
                    <td>
                      <code>{task.cron_expression}</code>
                      <small>{task.timezone}</small>
                    </td>
                    <td>
                      <span className="badge-kind">{task.kind}</span>
                    </td>
                    <td>
                      <small>{formatScheduleDateTime(task.next_run_at)}</small>
                    </td>
                    <td>
                      <small>{formatScheduleDateTime(task.last_run_at, "Never")}</small>
                    </td>
                    <td>
                      <span className={`status-tag ${task.last_status || "pending"}`}>
                        {task.last_status || "Scheduled"}
                      </span>
                    </td>
                    <td className="text-right">
                      {session.operator.role !== "readonly" ? (
                        <ScheduleRowActions task={task} />
                      ) : (
                        <span className="read-only-badge">Read-only</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
