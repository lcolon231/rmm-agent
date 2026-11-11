// SPDX-License-Identifier: AGPL-3.0-only

import { CircleAlert } from "lucide-react";
import { useId, type ComponentPropsWithRef, type ReactNode } from "react";

import { cx, focusRing } from "./cx";

const controlBase = cx(
  "w-full rounded-lg border bg-(--paper) px-3 text-sm text-(--ink) disabled:bg-(--fog) disabled:text-(--muted)",
  focusRing,
);

function controlClass(error: boolean, extra?: string) {
  return cx(controlBase, error ? "border-(--red)" : "border-(--line-strong)", extra);
}

type FieldShellProps = {
  id: string;
  label: string;
  hint?: string;
  error?: string;
  children: ReactNode;
};

function FieldShell({ id, label, hint, error, children }: FieldShellProps) {
  return (
    <div className="grid gap-1.5">
      <label htmlFor={id} className="text-[13px] font-semibold text-(--slate)">
        {label}
      </label>
      {children}
      {hint && !error ? (
        <p id={`${id}-hint`} className="m-0 text-xs text-(--muted)">
          {hint}
        </p>
      ) : null}
      {error ? (
        <p id={`${id}-error`} className="m-0 flex items-center gap-1.5 text-xs text-(--red)">
          <CircleAlert size={14} aria-hidden="true" />
          {error}
        </p>
      ) : null}
    </div>
  );
}

function describedBy(id: string, hint?: string, error?: string) {
  if (error) return `${id}-error`;
  if (hint) return `${id}-hint`;
  return undefined;
}

type CommonProps = { label: string; hint?: string; error?: string };

export function Input({ label, hint, error, id, className, ...rest }: CommonProps & ComponentPropsWithRef<"input">) {
  const autoId = useId();
  const fieldId = id ?? autoId;
  return (
    <FieldShell id={fieldId} label={label} hint={hint} error={error}>
      <input
        id={fieldId}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy(fieldId, hint, error)}
        className={controlClass(Boolean(error), cx("h-10", className))}
        {...rest}
      />
    </FieldShell>
  );
}

export function Select({ label, hint, error, id, className, children, ...rest }: CommonProps & ComponentPropsWithRef<"select">) {
  const autoId = useId();
  const fieldId = id ?? autoId;
  return (
    <FieldShell id={fieldId} label={label} hint={hint} error={error}>
      <select
        id={fieldId}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy(fieldId, hint, error)}
        className={controlClass(Boolean(error), cx("h-10", className))}
        {...rest}
      >
        {children}
      </select>
    </FieldShell>
  );
}

export function Textarea({ label, hint, error, id, className, ...rest }: CommonProps & ComponentPropsWithRef<"textarea">) {
  const autoId = useId();
  const fieldId = id ?? autoId;
  return (
    <FieldShell id={fieldId} label={label} hint={hint} error={error}>
      <textarea
        id={fieldId}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy(fieldId, hint, error)}
        className={controlClass(Boolean(error), cx("min-h-24 py-2.5 leading-normal", className))}
        {...rest}
      />
    </FieldShell>
  );
}
