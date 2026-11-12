// SPDX-License-Identifier: AGPL-3.0-only
"use client";

import { KeyRound, Plus, Trash2 } from "lucide-react";
import type { ScriptParameter, ScriptParameterKind } from "@/lib/script-library-core";

import { Button } from "./ui/button";
import { cx, focusRing } from "./ui/cx";
import { Input, Select } from "./ui/field";

export type ParameterDraft = {
  id: string; key: string; label: string; description: string; kind: ScriptParameterKind;
  required: boolean; defaultEnabled: boolean; defaultValue: string;
  minLength: string; maxLength: string; minimum: string; maximum: string; choices: string;
};

export function newParameterDraft(): ParameterDraft {
  return { id: crypto.randomUUID(), key: "", label: "", description: "", kind: "string",
    required: false, defaultEnabled: false, defaultValue: "", minLength: "", maxLength: "",
    minimum: "", maximum: "", choices: "" };
}

export function draftsFromParameters(parameters: ScriptParameter[]): ParameterDraft[] {
  return parameters.map((parameter) => ({ id: crypto.randomUUID(), key: parameter.key,
    label: parameter.label, description: parameter.description ?? "", kind: parameter.kind,
    required: parameter.required, defaultEnabled: parameter.has_default,
    defaultValue: parameter.default_value === null ? "" : String(parameter.default_value),
    minLength: parameter.min_length === null ? "" : String(parameter.min_length),
    maxLength: parameter.max_length === null ? "" : String(parameter.max_length),
    minimum: parameter.minimum === null ? "" : String(parameter.minimum),
    maximum: parameter.maximum === null ? "" : String(parameter.maximum),
    choices: parameter.choices?.join(", ") ?? "" }));
}

function optionalNumber(value: string): number | undefined {
  if (!value.trim()) return undefined;
  const parsed = Number(value); if (!Number.isFinite(parsed)) throw new Error("Parameter bounds must be numbers.");
  return parsed;
}

export function parameterPayload(drafts: ParameterDraft[]) {
  const keys = new Set<string>();
  return drafts.map((draft) => {
    const key = draft.key.trim(); const label = draft.label.trim();
    if (!/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(key)) throw new Error("Parameter keys must start with a letter and use only letters, numbers, or underscore.");
    if (!label) throw new Error(`Add a label for ${key}.`);
    if (keys.has(key.toLowerCase())) throw new Error("Parameter keys must be unique."); keys.add(key.toLowerCase());
    const result: Record<string, unknown> = { key, label, kind: draft.kind,
      required: draft.defaultEnabled ? false : draft.required };
    if (draft.description.trim()) result.description = draft.description.trim();
    if (draft.kind === "string" || draft.kind === "secret") {
      const minimum = optionalNumber(draft.minLength); const maximum = optionalNumber(draft.maxLength);
      if (minimum !== undefined) result.min_length = minimum;
      if (maximum !== undefined) result.max_length = maximum;
    } else if (draft.kind === "number") {
      const minimum = optionalNumber(draft.minimum); const maximum = optionalNumber(draft.maximum);
      if (minimum !== undefined) result.minimum = minimum;
      if (maximum !== undefined) result.maximum = maximum;
    } else if (draft.kind === "choice") {
      const choices = draft.choices.split(",").map((item) => item.trim()).filter(Boolean);
      if (!choices.length) throw new Error(`Add at least one choice for ${key}.`);
      result.choices = choices;
    }
    if (draft.defaultEnabled && draft.kind !== "secret") {
      if (draft.kind === "number") {
        const parsed = Number(draft.defaultValue); if (!Number.isFinite(parsed)) throw new Error(`Default for ${key} must be a number.`);
        result.default_value = parsed;
      } else if (draft.kind === "boolean") result.default_value = draft.defaultValue === "true";
      else result.default_value = draft.defaultValue;
    }
    return result;
  });
}

const checkClass = "flex items-center gap-2 text-[13px] text-(--slate)";

export function ScriptParameterEditor({ value, onChange }: { value: ParameterDraft[]; onChange: (next: ParameterDraft[]) => void }) {
  function update(id: string, patch: Partial<ParameterDraft>) { onChange(value.map((item) => item.id === id ? { ...item, ...patch } : item)); }
  return (
    <fieldset className="m-0 grid gap-3 rounded-lg border border-(--line) p-4">
      <legend className="px-1 text-[13px] font-semibold text-(--slate)">Parameters</legend>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <p className="m-0 flex items-start gap-2 text-xs text-(--muted)">
          <KeyRound size={16} aria-hidden="true" className="mt-0.5 shrink-0" />
          <span>Values the script asks for each time it runs. They are saved with this version and cannot be changed later. In the script, read them as <code className="font-(family-name:--font-data)">NL_PARAM_Key</code>.</span>
        </p>
        <Button size="compact" icon={Plus} disabled={value.length >= 32} onClick={() => onChange([...value, newParameterDraft()])}>Add parameter</Button>
      </div>
      {value.length === 0 ? <p className="m-0 text-sm text-(--muted)">No parameters. The script runs without asking for values.</p> : (
        <ol className="m-0 grid list-none gap-3 p-0">
          {value.map((parameter, index) => (
            <li key={parameter.id} className="grid gap-3 rounded-lg bg-(--fog) p-4">
              <div className="flex items-center justify-between gap-3">
                <span className="text-[13px] font-semibold text-(--slate)">Parameter {index + 1}</span>
                <button type="button" aria-label={`Remove ${parameter.label || "parameter"}`} onClick={() => onChange(value.filter((item) => item.id !== parameter.id))}
                  className={cx("flex size-9 items-center justify-center rounded-lg text-(--red) hover:bg-(--red-soft)", focusRing)}>
                  <Trash2 size={16} aria-hidden="true" />
                </button>
              </div>
              <div className="grid gap-3 min-[720px]:grid-cols-3">
                <Input label="Key" value={parameter.key} maxLength={64} placeholder="ServiceName" onChange={(event) => update(parameter.id, { key: event.target.value })} />
                <Input label="Label" value={parameter.label} maxLength={100} placeholder="Service name" onChange={(event) => update(parameter.id, { label: event.target.value })} />
                <Select label="Type" value={parameter.kind} onChange={(event) => update(parameter.id, { kind: event.target.value as ScriptParameterKind, defaultEnabled: false, defaultValue: "" })}>
                  <option value="string">Text</option><option value="number">Number</option><option value="boolean">Yes or no</option><option value="choice">Choice</option><option value="secret">Secret</option>
                </Select>
              </div>
              <Input label="Description" value={parameter.description} maxLength={500} onChange={(event) => update(parameter.id, { description: event.target.value })} />
              {parameter.kind === "choice" ? <Input label="Choices" hint="Separate with commas" value={parameter.choices} placeholder="safe, force" onChange={(event) => update(parameter.id, { choices: event.target.value })} /> : null}
              {parameter.kind === "string" || parameter.kind === "secret" ? (
                <div className="grid gap-3 min-[720px]:grid-cols-2">
                  <Input label="Minimum length" type="number" min={0} max={16384} value={parameter.minLength} onChange={(event) => update(parameter.id, { minLength: event.target.value })} />
                  <Input label="Maximum length" type="number" min={1} max={16384} value={parameter.maxLength} onChange={(event) => update(parameter.id, { maxLength: event.target.value })} />
                </div>
              ) : null}
              {parameter.kind === "number" ? (
                <div className="grid gap-3 min-[720px]:grid-cols-2">
                  <Input label="Minimum" type="number" value={parameter.minimum} onChange={(event) => update(parameter.id, { minimum: event.target.value })} />
                  <Input label="Maximum" type="number" value={parameter.maximum} onChange={(event) => update(parameter.id, { maximum: event.target.value })} />
                </div>
              ) : null}
              <div className="flex flex-wrap gap-x-6 gap-y-2">
                <label className={checkClass}><input type="checkbox" checked={parameter.required && !parameter.defaultEnabled} disabled={parameter.defaultEnabled} onChange={(event) => update(parameter.id, { required: event.target.checked })} />Required each run</label>
                {parameter.kind !== "secret"
                  ? <label className={checkClass}><input type="checkbox" checked={parameter.defaultEnabled} onChange={(event) => update(parameter.id, { defaultEnabled: event.target.checked, required: event.target.checked ? false : parameter.required })} />Use a default</label>
                  : <span className="text-xs text-(--muted)">Secrets never have a saved default.</span>}
              </div>
              {parameter.defaultEnabled && parameter.kind !== "secret" ? (
                parameter.kind === "boolean"
                  ? <Select label="Default" value={parameter.defaultValue || "false"} onChange={(event) => update(parameter.id, { defaultValue: event.target.value })}><option value="false">No</option><option value="true">Yes</option></Select>
                  : <Input label="Default" value={parameter.defaultValue} onChange={(event) => update(parameter.id, { defaultValue: event.target.value })} />
              ) : null}
            </li>
          ))}
        </ol>
      )}
    </fieldset>
  );
}
