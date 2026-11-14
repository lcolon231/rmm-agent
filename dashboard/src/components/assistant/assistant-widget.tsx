// SPDX-License-Identifier: AGPL-3.0-only
"use client";

import { Bot, X } from "lucide-react";
import { useSearchParams } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { assistantPrefill } from "@/lib/assistant-context-core";

import { cx, focusRing } from "../ui/cx";
import { AssistantChat } from "./assistant-chat";

export const ASSISTANT_OPEN_KEY = "nodelink.assistant.open";
const PANEL_ID = "assistant-panel";

function remember(open: boolean) {
  try {
    window.localStorage.setItem(ASSISTANT_OPEN_KEY, open ? "1" : "0");
  } catch {
    /* storage blocked: the choice lasts this page only */
  }
}

/**
 * The assistant as a launcher and panel in the corner of every dashboard
 * shell, so the page being investigated stays on screen. The panel is not
 * modal: the page behind it stays usable.
 */
export function AssistantWidget({ clients, state, pathname }: {
  clients: { id: string; name: string }[];
  state: string;
  pathname: string;
}) {
  const searchParams = useSearchParams();
  const [open, setOpen] = useState(false);
  // The conversation mounts on first open and then stays, so closing keeps it.
  const [started, setStarted] = useState(false);
  const launcher = useRef<HTMLButtonElement>(null);
  const panel = useRef<HTMLDivElement>(null);
  const focusOnOpen = useRef(false);

  useEffect(() => {
    queueMicrotask(() => {
      try {
        if (window.localStorage.getItem(ASSISTANT_OPEN_KEY) !== "1") return;
      } catch {
        return; /* storage blocked: stay closed */
      }
      setStarted(true);
      setOpen(true);
    });
  }, []);

  useEffect(() => {
    if (!open) return;
    if (focusOnOpen.current) {
      focusOnOpen.current = false;
      const root = panel.current;
      // The composer is disabled until a client is chosen; land on the next useful control.
      const target = root?.querySelector<HTMLElement>("#assistant-message:not(:disabled)")
        ?? root?.querySelector<HTMLElement>("select:not(:disabled)") ?? root;
      target?.focus();
    }
    function onKeyDown(event: KeyboardEvent) {
      // A modal on top (drawer, confirmation) owns Escape.
      if (event.key !== "Escape" || document.querySelector('[aria-modal="true"]')) return;
      close();
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [open]);

  function close() {
    setOpen(false);
    remember(false);
    launcher.current?.focus();
  }

  function toggle() {
    if (open) return close();
    focusOnOpen.current = true;
    setStarted(true);
    setOpen(true);
    remember(true);
  }

  const prefill = assistantPrefill(
    pathname,
    { client_id: searchParams?.get("client_id"), endpoint_id: searchParams?.get("endpoint_id") },
    clients.map((client) => client.id),
  );
  // With a single client there is nothing to choose.
  const clientId = prefill.clientId ?? (clients.length === 1 ? clients[0].id : undefined);

  return (
    <>
      <button
        ref={launcher}
        type="button"
        aria-label="AI assistant"
        aria-expanded={open}
        aria-controls={PANEL_ID}
        title="AI assistant"
        onClick={toggle}
        className={cx(
          "fixed right-4 bottom-4 z-40 inline-flex h-14 w-14 items-center justify-center rounded-full bg-(--primary-strong) text-white shadow-[0_8px_24px_rgb(24_16_46/22%)] hover:bg-(--primary-press) min-[850px]:right-6 min-[850px]:bottom-6",
          focusRing,
        )}
      >
        {open ? <X size={24} aria-hidden="true" /> : <Bot size={24} aria-hidden="true" />}
      </button>
      <div
        ref={panel}
        id={PANEL_ID}
        role="dialog"
        aria-label="AI assistant"
        tabIndex={-1}
        hidden={!open}
        className={cx(
          "fixed inset-0 z-40 overflow-hidden bg-(--paper) outline-none motion-safe:animate-[assistant-panel-in_160ms_ease-out]",
          "min-[850px]:inset-auto min-[850px]:right-6 min-[850px]:bottom-24 min-[850px]:h-[min(680px,calc(100vh-7.5rem))] min-[850px]:w-[400px] min-[850px]:rounded-xl min-[850px]:border min-[850px]:border-(--line-strong) min-[850px]:shadow-[0_18px_48px_rgb(24_16_46/22%)]",
          open ? "block" : "hidden",
        )}
      >
        {started ? (
          <AssistantChat
            variant="panel"
            clients={clients}
            initialClientId={clientId}
            endpointId={prefill.endpointId}
            state={state}
            panelActions={
              <button
                type="button"
                aria-label="Close assistant"
                title="Close"
                onClick={close}
                className={cx("inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-(--slate) hover:bg-(--primary-tint)", focusRing)}
              >
                <X size={16} aria-hidden="true" />
              </button>
            }
          />
        ) : null}
      </div>
    </>
  );
}
