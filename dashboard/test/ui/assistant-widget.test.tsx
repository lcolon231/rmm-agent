// SPDX-License-Identifier: AGPL-3.0-only
// The floating assistant (issue #301): launcher, panel, focus and persistence.
import assert from "node:assert/strict";
import { beforeEach, test, type TestContext } from "node:test";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";

import { ASSISTANT_OPEN_KEY, AssistantWidget } from "@/components/assistant/assistant-widget";

const CLIENT = "55555555-5555-4555-8555-555555555555";
const OTHER = "66666666-6666-4666-8666-666666666666";
const ENDPOINT = "77777777-7777-4777-8777-777777777777";
const one = [{ id: CLIENT, name: "Lakeshore" }];
const two = [...one, { id: OTHER, name: "Harbor Dental" }];

function stubFetch(t: TestContext) {
  return t.mock.method(globalThis, "fetch", async () => Response.json({ items: [] }));
}

function renderWidget(props: Partial<Parameters<typeof AssistantWidget>[0]> = {}) {
  return render(<AssistantWidget clients={one} state="available" pathname="/alerts" {...props} />);
}

const launcher = () => screen.getByRole("button", { name: "AI assistant" });
const panel = () => screen.queryByRole("dialog", { name: "AI assistant" });
const composer = () => screen.getByLabelText("Ask about the selected client") as HTMLTextAreaElement;

beforeEach(() => {
  window.localStorage.clear();
});

test("the panel is hidden by default and the launcher describes it", (t) => {
  const fetch = stubFetch(t);
  renderWidget();

  assert.equal(panel(), null, "a hidden panel is not exposed as a dialog");
  assert.equal(launcher().getAttribute("aria-expanded"), "false");
  const controlled = document.getElementById(launcher().getAttribute("aria-controls") ?? "");
  assert.equal(controlled?.getAttribute("role"), "dialog");
  assert.equal(controlled?.hidden, true);
  assert.equal(fetch.mock.callCount(), 0, "nothing is requested until the assistant is opened");
});

test("the launcher opens the panel and a second click closes it", (t) => {
  stubFetch(t);
  renderWidget();

  fireEvent.click(launcher());
  assert.ok(panel());
  assert.equal(launcher().getAttribute("aria-expanded"), "true");

  fireEvent.click(launcher());
  assert.equal(panel(), null);
  assert.equal(launcher().getAttribute("aria-expanded"), "false");
});

test("Escape closes the panel, but not from under a modal", (t) => {
  stubFetch(t);
  renderWidget();
  fireEvent.click(launcher());

  const modal = document.body.appendChild(document.createElement("div"));
  modal.setAttribute("aria-modal", "true");
  fireEvent.keyDown(document, { key: "Escape" });
  assert.ok(panel(), "a modal on top owns Escape");
  modal.remove();

  fireEvent.keyDown(document, { key: "Escape" });
  assert.equal(panel(), null);
});

test("focus moves to the composer on open and back to the launcher on close", (t) => {
  stubFetch(t);
  renderWidget();

  fireEvent.click(launcher());
  assert.equal(document.activeElement, composer());

  fireEvent.keyDown(document, { key: "Escape" });
  assert.equal(document.activeElement, launcher());

  fireEvent.click(launcher());
  fireEvent.click(screen.getByRole("button", { name: "Close assistant" }));
  assert.equal(document.activeElement, launcher());
});

test("with several clients focus lands on the client choice, since the composer is disabled", (t) => {
  stubFetch(t);
  renderWidget({ clients: two });

  fireEvent.click(launcher());
  assert.equal(composer().disabled, true);
  assert.equal(document.activeElement, screen.getByLabelText("Client"));
});

test("the open state is stored and restored after navigation", async (t) => {
  stubFetch(t);
  const first = renderWidget();
  fireEvent.click(launcher());
  assert.equal(window.localStorage.getItem(ASSISTANT_OPEN_KEY), "1");
  first.unmount();

  renderWidget({ pathname: "/monitoring" });
  await waitFor(() => assert.ok(panel()));
  assert.notEqual(document.activeElement, composer(), "restoring does not take focus from the new page");

  fireEvent.click(launcher());
  assert.equal(window.localStorage.getItem(ASSISTANT_OPEN_KEY), "0");
});

test("blocked storage degrades to closed, and the launcher still works", async (t) => {
  stubFetch(t);
  const blocked = () => { throw new DOMException("denied", "SecurityError"); };
  t.mock.method(Storage.prototype, "getItem", blocked);
  t.mock.method(Storage.prototype, "setItem", blocked);
  renderWidget();

  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(panel(), null);

  fireEvent.click(launcher());
  assert.ok(panel());
  fireEvent.click(launcher());
  assert.equal(panel(), null);
});

test("on an endpoint page the composer carries the endpoint prompt once a client is selected", (t) => {
  stubFetch(t);
  renderWidget({ clients: two, pathname: `/endpoints/${ENDPOINT}` });
  fireEvent.click(launcher());

  fireEvent.change(screen.getByLabelText("Client"), { target: { value: OTHER } });
  assert.equal(composer().disabled, false);
  assert.equal(composer().value, `Investigate endpoint ${ENDPOINT}: show its status and telemetry.`);
});

test("moving to another endpoint updates the suggested prompt but keeps a typed question", (t) => {
  stubFetch(t);
  const next = "88888888-8888-4888-8888-888888888888";
  const view = renderWidget({ pathname: `/endpoints/${ENDPOINT}` });
  fireEvent.click(launcher());
  assert.match(composer().value, new RegExp(ENDPOINT));

  view.rerender(<AssistantWidget clients={one} state="available" pathname={`/endpoints/${next}`} />);
  assert.match(composer().value, new RegExp(next));

  fireEvent.change(composer(), { target: { value: "Why is this device offline?" } });
  view.rerender(<AssistantWidget clients={one} state="available" pathname="/endpoints" />);
  assert.equal(composer().value, "Why is this device offline?");
});

test("the conversation survives closing and reopening the panel", (t) => {
  stubFetch(t);
  renderWidget();
  fireEvent.click(launcher());
  fireEvent.change(composer(), { target: { value: "Half-typed question" } });

  fireEvent.click(launcher());
  fireEvent.click(launcher());
  assert.equal(composer().value, "Half-typed question");
});

test("Open full page keeps the selected client and the endpoint", (t) => {
  stubFetch(t);
  renderWidget({ clients: two, pathname: `/endpoints/${ENDPOINT}` });
  fireEvent.click(launcher());

  const link = () => within(panel()!).getByRole("link", { name: "Open full page" }).getAttribute("href");
  assert.equal(link(), `/assistant?endpoint_id=${ENDPOINT}`);
  fireEvent.change(screen.getByLabelText("Client"), { target: { value: OTHER } });
  assert.equal(link(), `/assistant?client_id=${OTHER}&endpoint_id=${ENDPOINT}`);
});

test("disabled, unconfigured and unavailable states show the existing messages in the panel", (t) => {
  const fetch = stubFetch(t);
  for (const [state, copy] of [
    ["disabled", "The assistant is not enabled for this operator."],
    ["unconfigured", "The assistant is awaiting server configuration."],
    ["unavailable", "The assistant is temporarily unavailable."],
  ] as const) {
    const view = renderWidget({ state });
    fireEvent.click(launcher());
    assert.ok(within(panel()!).getByText(copy));
    assert.equal(screen.queryByLabelText("Ask about the selected client"), null);
    assert.equal(document.activeElement, panel(), "with no composer the panel itself takes focus");
    fireEvent.keyDown(document, { key: "Escape" });
    assert.equal(panel(), null);
    view.unmount();
  }
  assert.equal(fetch.mock.callCount(), 0);
});
