// SPDX-License-Identifier: AGPL-3.0-only

"use client";

/**
 * Small building blocks the Administration screens share that the ui/
 * primitives do not provide: a plain action dialog (for changes whose API
 * takes no reason, or takes a note rather than a reason), a modal-layer
 * signal so a dialog opened from a Drawer does not also close the Drawer on
 * Escape, and a status note.
 */

import { CircleAlert, CircleCheck, TriangleAlert, type LucideIcon } from "lucide-react";
import { createContext, useContext, useEffect, useId, useState, type FormEvent, type ReactNode } from "react";

import { Button } from "../ui/button";
import { cx } from "../ui/cx";
import { useModal } from "../ui/use-modal";

/** Lets a dialog tell the surrounding Drawer that it is open on top of it. */
const ModalLayerContext = createContext<(open: boolean) => void>(() => {});

export function ModalLayerProvider({ onChange, children }: { onChange: (open: boolean) => void; children: ReactNode }) {
  return <ModalLayerContext.Provider value={onChange}>{children}</ModalLayerContext.Provider>;
}

export function useReportModal(open: boolean) {
  const report = useContext(ModalLayerContext);
  useEffect(() => {
    if (!open) return;
    report(true);
    return () => report(false);
  }, [open, report]);
}

/** Drawer state that ignores Escape/scrim while a dialog sits on top of it. */
export function useLayeredDrawer<T>() {
  const [selected, setSelected] = useState<T | null>(null);
  const [layerOpen, setLayerOpen] = useState(false);
  return {
    selected,
    open: setSelected,
    close: () => {
      if (!layerOpen) setSelected(null);
    },
    forceClose: () => setSelected(null),
    setLayerOpen,
  };
}

type ActionDialogProps = {
  open: boolean;
  onClose: () => void;
  title: string;
  /** One or two plain sentences. */
  description?: ReactNode;
  children?: ReactNode;
  confirmLabel: string;
  confirmVariant?: "primary" | "danger";
  confirmDisabled?: boolean;
  onConfirm: () => void | Promise<void>;
  busy?: boolean;
  error?: string;
  icon?: LucideIcon;
};

export function ActionDialog(props: ActionDialogProps) {
  useReportModal(props.open);
  if (!props.open) return null;
  return <ActionDialogPanel {...props} />;
}

function ActionDialogPanel({
  onClose,
  title,
  description,
  children,
  confirmLabel,
  confirmVariant = "primary",
  confirmDisabled = false,
  onConfirm,
  busy = false,
  error,
  icon: Icon,
}: ActionDialogProps) {
  const panelRef = useModal(true, busy ? () => {} : onClose);
  const titleId = useId();
  const bodyId = useId();

  function submit(event: FormEvent) {
    event.preventDefault();
    if (busy || confirmDisabled) return;
    void onConfirm();
  }

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center p-4">
      <div aria-hidden="true" className="absolute inset-0 bg-[rgb(23_19_42/45%)]" onClick={busy ? undefined : onClose} />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description ? bodyId : undefined}
        className="relative max-h-[calc(100vh-32px)] w-[min(480px,100%)] overflow-y-auto rounded-[10px] bg-(--paper) shadow-[0_14px_34px_rgb(24_16_46/12%)]"
      >
        <form onSubmit={submit}>
          <div className="grid gap-4 p-6">
            {Icon ? (
              <span className="flex size-10 items-center justify-center rounded-full bg-(--primary-tint) text-(--primary-press)">
                <Icon size={20} aria-hidden="true" />
              </span>
            ) : null}
            <div className="grid gap-2">
              <h2 id={titleId} className="m-0 text-lg leading-[1.3] font-semibold text-(--ink)">
                {title}
              </h2>
              {description ? (
                <div id={bodyId} className="m-0 grid gap-2 text-sm leading-normal text-(--slate)">
                  {description}
                </div>
              ) : null}
            </div>
            {children}
            {error ? (
              <p role="alert" className="m-0 flex items-start gap-2 rounded-lg bg-(--red-soft) px-3 py-2.5 text-sm text-(--red)">
                <CircleAlert size={16} aria-hidden="true" className="mt-0.5 shrink-0" />
                {error}
              </p>
            ) : null}
          </div>
          <footer className="flex flex-wrap justify-end gap-2 border-t border-(--line) px-6 py-4">
            <Button onClick={onClose} disabled={busy}>
              Cancel
            </Button>
            <Button type="submit" variant={confirmVariant} disabled={busy || confirmDisabled} aria-busy={busy || undefined}>
              {confirmLabel}
            </Button>
          </footer>
        </form>
      </div>
    </div>
  );
}

const NOTE_TONES = {
  ok: { className: "bg-(--success-soft) text-(--success)", icon: CircleCheck },
  warn: { className: "bg-(--amber-soft) text-[#89500b]", icon: TriangleAlert },
  crit: { className: "bg-(--red-soft) text-(--red)", icon: CircleAlert },
  info: { className: "bg-(--primary-tint) text-(--primary-press)", icon: CircleAlert },
} as const;

/** Tone background, icon, bold line and one sentence. */
export function StatusNote({
  tone,
  title,
  children,
  action,
  role,
}: {
  tone: keyof typeof NOTE_TONES;
  title?: string;
  children?: ReactNode;
  action?: ReactNode;
  role?: "status" | "alert";
}) {
  const { className, icon: Icon } = NOTE_TONES[tone];
  return (
    <div role={role} className={cx("flex flex-wrap items-start gap-3 rounded-lg px-4 py-3 text-sm", className)}>
      <Icon size={18} aria-hidden="true" className="mt-0.5 shrink-0" />
      <div className="grid min-w-0 flex-1 gap-0.5">
        {title ? <span className="font-semibold">{title}</span> : null}
        {children ? <span className="text-(--slate)">{children}</span> : null}
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  );
}
