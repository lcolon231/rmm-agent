// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { useState } from "react";
import { fireEvent, render, screen, within } from "@testing-library/react";

import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { DataTable, TableFooter, type Column } from "@/components/ui/data-table";
import { Drawer } from "@/components/ui/drawer";
import { Input } from "@/components/ui/field";
import { FilterChip } from "@/components/ui/filter-bar";
import { Meter, meterLevel } from "@/components/ui/meter";
import { sortByRisk } from "@/components/ui/risk";
import { ErrorState } from "@/components/ui/states";
import { StatusBadge, type StatusTone } from "@/components/ui/status-badge";
import { Tabs } from "@/components/ui/tabs";

test("a status badge always carries an icon and a word, not colour alone", () => {
  const tones: StatusTone[] = ["ok", "warn", "crit", "off", "info"];
  for (const tone of tones) {
    const { container, unmount } = render(<StatusBadge tone={tone}>Label</StatusBadge>);
    const badge = container.querySelector(`[data-tone="${tone}"]`)!;
    assert.equal(badge.textContent, "Label");
    assert.ok(badge.querySelector("svg[aria-hidden='true']"), `${tone} badge has an icon`);
    unmount();
  }
});

test("lists sort critical, offline, warning, then healthy, keeping ties stable", () => {
  const rows = [
    { id: "a", tone: "ok" as const },
    { id: "b", tone: "warn" as const },
    { id: "c", tone: "crit" as const },
    { id: "d", tone: "off" as const },
    { id: "e", tone: "crit" as const },
    { id: "f", tone: "info" as const },
  ];
  const sorted = sortByRisk(rows, (row) => row.tone).map((row) => row.id);
  assert.deepEqual(sorted, ["c", "e", "d", "b", "f", "a"]);
  assert.equal(rows[0].id, "a", "input is not mutated");
});

test("meters keep today's 68% and 90% thresholds and expose the exact value", () => {
  assert.equal(meterLevel(67), "normal");
  assert.equal(meterLevel(68), "warn");
  assert.equal(meterLevel(89), "warn");
  assert.equal(meterLevel(90), "crit");

  render(<Meter value={93.4} label="Disk" />);
  const meter = screen.getByRole("meter", { name: "Disk" });
  assert.equal(meter.getAttribute("aria-valuenow"), "93");
  assert.equal(meter.getAttribute("data-level"), "crit");
});

test("a missing reading is announced as no reading, not as 0%", () => {
  render(<Meter value={null} label="Memory" />);
  assert.ok(screen.getByLabelText("Memory: no reading"));
  assert.equal(screen.queryByRole("meter"), null);
});

function DialogHarness({ onConfirm }: { onConfirm: (reason: string) => void }) {
  const [open, setOpen] = useState(true);
  return (
    <>
      <p>{open ? "dialog open" : "dialog closed"}</p>
      <ConfirmDialog
        open={open}
        onCancel={() => setOpen(false)}
        onConfirm={onConfirm}
        title="Restart PHX-FD-02?"
        consequence="Anyone signed in will lose unsaved work."
        confirmLabel="Restart device"
      />
    </>
  );
}

test("a high-risk action cannot be confirmed without a reason for the audit record", () => {
  const reasons: string[] = [];
  render(<DialogHarness onConfirm={(reason) => reasons.push(reason)} />);
  const dialog = screen.getByRole("alertdialog", { name: "Restart PHX-FD-02?" });
  const confirm = within(dialog).getByRole("button", { name: "Restart device" }) as HTMLButtonElement;
  const reason = within(dialog).getByLabelText("Reason (required)");

  assert.equal(document.activeElement, reason, "focus starts in the reason box");
  assert.equal(confirm.disabled, true);
  fireEvent.change(reason, { target: { value: "   " } });
  assert.equal(confirm.disabled, true, "whitespace is not a reason");
  fireEvent.submit(confirm.closest("form")!);
  assert.deepEqual(reasons, [], "submitting with Enter is also refused");

  fireEvent.change(reason, { target: { value: "  Frozen after update  " } });
  assert.equal(confirm.disabled, false);
  fireEvent.click(confirm);
  assert.deepEqual(reasons, ["Frozen after update"]);
});

test("Escape cancels a confirm dialog and nothing is confirmed", () => {
  const reasons: string[] = [];
  render(<DialogHarness onConfirm={(reason) => reasons.push(reason)} />);
  fireEvent.keyDown(document, { key: "Escape" });
  assert.ok(screen.getByText("dialog closed"));
  assert.equal(screen.queryByRole("alertdialog"), null);
  assert.deepEqual(reasons, []);
});

test("a confirm dialog opens with an empty reason every time", () => {
  const { rerender } = render(
    <ConfirmDialog open onCancel={() => {}} onConfirm={() => {}} title="Revoke token?" consequence="It stops working." confirmLabel="Revoke token" />,
  );
  fireEvent.change(screen.getByLabelText("Reason (required)"), { target: { value: "Leaked" } });
  rerender(<ConfirmDialog open={false} onCancel={() => {}} onConfirm={() => {}} title="Revoke token?" consequence="It stops working." confirmLabel="Revoke token" />);
  rerender(<ConfirmDialog open onCancel={() => {}} onConfirm={() => {}} title="Revoke token?" consequence="It stops working." confirmLabel="Revoke token" />);
  assert.equal((screen.getByLabelText("Reason (required)") as HTMLTextAreaElement).value, "");
});

function DrawerHarness() {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>
        Preview device
      </button>
      <Drawer open={open} onClose={() => setOpen(false)} title="PHX-FD-02" context="Phoenix front desk" record="Restarted by A. Rivera">
        <button type="button">Open device</button>
      </Drawer>
    </>
  );
}

test("the drawer closes on Escape and on the scrim, returning focus to its opener", () => {
  render(<DrawerHarness />);
  const opener = screen.getByRole("button", { name: "Preview device" });
  opener.focus();
  fireEvent.click(opener);
  const dialog = screen.getByRole("dialog", { name: "PHX-FD-02" });
  assert.ok(dialog.contains(document.activeElement), "focus moves into the drawer");
  assert.match(dialog.textContent ?? "", /Record · Restarted by A\. Rivera/);

  fireEvent.keyDown(document, { key: "Escape" });
  assert.equal(screen.queryByRole("dialog"), null);
  assert.equal(document.activeElement, opener);

  fireEvent.click(opener);
  fireEvent.click(screen.getByTestId("drawer-scrim"));
  assert.equal(screen.queryByRole("dialog"), null);
});

test("Tab is trapped inside the open drawer", () => {
  render(<DrawerHarness />);
  fireEvent.click(screen.getByRole("button", { name: "Preview device" }));
  const close = screen.getByRole("button", { name: "Close" });
  const last = screen.getByRole("button", { name: "Open device" });
  last.focus();
  fireEvent.keyDown(document, { key: "Tab" });
  assert.equal(document.activeElement, close, "Tab from the last control wraps to the first");
  fireEvent.keyDown(document, { key: "Tab", shiftKey: true });
  assert.equal(document.activeElement, last, "Shift+Tab from the first wraps to the last");
});

type Device = { id: string; host: string };
const columns: Column<Device>[] = [{ key: "host", header: "Device", cell: (row) => row.host }];

test("table rows open by click and by keyboard, and the footer states the sort", () => {
  const opened: string[] = [];
  render(
    <DataTable
      caption="Devices"
      columns={columns}
      rows={[{ id: "1", host: "PHX-FD-02" }, { id: "2", host: "PHX-LAB-01" }]}
      rowKey={(row) => row.id}
      rowLabel={(row) => `Open ${row.host}`}
      onRowSelect={(row) => opened.push(row.host)}
      footer={<TableFooter shown={2} total={42} />}
    />,
  );
  fireEvent.click(screen.getByRole("row", { name: "Open PHX-FD-02" }));
  fireEvent.keyDown(screen.getByRole("row", { name: "Open PHX-LAB-01" }), { key: "Enter" });
  assert.deepEqual(opened, ["PHX-FD-02", "PHX-LAB-01"]);
  assert.ok(screen.getByText("Showing 2 of 42 · most urgent first"));
});

test("a table in a loading or error state renders the state, not stale rows", () => {
  render(
    <DataTable
      caption="Devices"
      columns={columns}
      rows={[{ id: "1", host: "PHX-FD-02" }]}
      rowKey={(row) => row.id}
      state={<ErrorState body="The device list could not be reached" />}
    />,
  );
  assert.equal(screen.queryByText("PHX-FD-02"), null);
  assert.equal(screen.getByRole("alert").querySelector("p")?.textContent, "The device list could not be reached. Nothing was changed.");
});

test("arrow keys move between tabs and only the selected tab is tabbable", () => {
  function Harness() {
    const [value, setValue] = useState("summary");
    return (
      <Tabs
        label="Device sections"
        tabs={[{ id: "summary", label: "Summary" }, { id: "inventory", label: "Inventory" }, { id: "patches", label: "Patches" }]}
        value={value}
        onChange={setValue}
      >
        <p>Panel {value}</p>
      </Tabs>
    );
  }
  render(<Harness />);
  const summary = screen.getByRole("tab", { name: "Summary" });
  assert.equal(summary.getAttribute("aria-selected"), "true");
  assert.equal(screen.getByRole("tab", { name: "Inventory" }).tabIndex, -1);

  fireEvent.keyDown(summary, { key: "ArrowLeft" });
  const patches = screen.getByRole("tab", { name: "Patches" });
  assert.equal(patches.getAttribute("aria-selected"), "true", "ArrowLeft wraps to the last tab");
  assert.equal(document.activeElement, patches);
  assert.ok(screen.getByText("Panel patches"));
  assert.equal(screen.getByRole("tabpanel").getAttribute("aria-labelledby"), patches.id);
});

test("URL-driven filter chips are links that mark the current filter", () => {
  render(
    <>
      <FilterChip href="/endpoints?status=offline" selected count={3}>
        Offline
      </FilterChip>
      <FilterChip href="/endpoints" selected={false}>
        All
      </FilterChip>
    </>,
  );
  const offline = screen.getByRole("link", { name: /Offline/ });
  assert.equal(offline.getAttribute("href"), "/endpoints?status=offline");
  assert.equal(offline.getAttribute("aria-current"), "true");
  assert.equal(screen.getByRole("link", { name: "All" }).getAttribute("aria-current"), null);
});

test("a field error is announced with the control, not only shown in red", () => {
  render(<Input label="Work email" error="Enter a work email address" />);
  const input = screen.getByLabelText("Work email");
  assert.equal(input.getAttribute("aria-invalid"), "true");
  const describedBy = input.getAttribute("aria-describedby")!;
  assert.equal(document.getElementById(describedBy)?.textContent, "Enter a work email address");
});
