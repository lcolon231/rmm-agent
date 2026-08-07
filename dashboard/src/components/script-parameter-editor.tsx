// SPDX-License-Identifier: AGPL-3.0-only
"use client";

import { KeyRound, Plus, Trash2 } from "lucide-react";
import type { ScriptParameter, ScriptParameterKind } from "@/lib/script-library-core";

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

export function ScriptParameterEditor({ value, onChange }: { value: ParameterDraft[]; onChange: (next: ParameterDraft[]) => void }) {
  function update(id: string, patch: Partial<ParameterDraft>) { onChange(value.map((item) => item.id === id ? { ...item, ...patch } : item)); }
  return <section className="script-parameter-editor wide"><header><div><KeyRound size={17} /><span><strong>Typed parameters</strong><small>Immutable with this version · referenced as NL_PARAM_Key</small></span></div>
    <button type="button" disabled={value.length >= 32} onClick={() => onChange([...value, newParameterDraft()])}><Plus size={14} />Add parameter</button></header>
    {value.length === 0 ? <p>No runtime values. This version executes with source-only inputs.</p> : <div className="script-parameter-list">{value.map((parameter, index) => <article key={parameter.id}>
      <div className="script-parameter-sequence"><span>{String(index + 1).padStart(2, "0")}</span><button type="button" aria-label={`Remove ${parameter.label || "parameter"}`} onClick={() => onChange(value.filter((item) => item.id !== parameter.id))}><Trash2 size={14} /></button></div>
      <label>Key<input value={parameter.key} maxLength={64} placeholder="ServiceName" onChange={(event) => update(parameter.id, { key: event.target.value })} /></label>
      <label>Label<input value={parameter.label} maxLength={100} placeholder="Service name" onChange={(event) => update(parameter.id, { label: event.target.value })} /></label>
      <label>Type<select value={parameter.kind} onChange={(event) => update(parameter.id, { kind: event.target.value as ScriptParameterKind, defaultEnabled: false, defaultValue: "" })}><option value="string">String</option><option value="number">Number</option><option value="boolean">Boolean</option><option value="choice">Choice</option><option value="secret">Secret</option></select></label>
      <label className="wide">Description<input value={parameter.description} maxLength={500} onChange={(event) => update(parameter.id, { description: event.target.value })} /></label>
      {parameter.kind === "choice" ? <label className="wide">Choices <small>comma-separated</small><input value={parameter.choices} placeholder="safe, force" onChange={(event) => update(parameter.id, { choices: event.target.value })} /></label> : null}
      {parameter.kind === "string" || parameter.kind === "secret" ? <><label>Minimum length<input type="number" min={0} max={16384} value={parameter.minLength} onChange={(event) => update(parameter.id, { minLength: event.target.value })} /></label><label>Maximum length<input type="number" min={1} max={16384} value={parameter.maxLength} onChange={(event) => update(parameter.id, { maxLength: event.target.value })} /></label></> : null}
      {parameter.kind === "number" ? <><label>Minimum<input type="number" value={parameter.minimum} onChange={(event) => update(parameter.id, { minimum: event.target.value })} /></label><label>Maximum<input type="number" value={parameter.maximum} onChange={(event) => update(parameter.id, { maximum: event.target.value })} /></label></> : null}
      <label className="script-check"><input type="checkbox" checked={parameter.required && !parameter.defaultEnabled} disabled={parameter.defaultEnabled} onChange={(event) => update(parameter.id, { required: event.target.checked })} />Required each run</label>
      {parameter.kind !== "secret" ? <label className="script-check"><input type="checkbox" checked={parameter.defaultEnabled} onChange={(event) => update(parameter.id, { defaultEnabled: event.target.checked, required: event.target.checked ? false : parameter.required })} />Use a default</label> : <small className="script-secret-note">Secret defaults are never stored.</small>}
      {parameter.defaultEnabled && parameter.kind !== "secret" ? <label className="wide">Default {parameter.kind === "boolean" ? <select value={parameter.defaultValue || "false"} onChange={(event) => update(parameter.id, { defaultValue: event.target.value })}><option value="false">False</option><option value="true">True</option></select> : <input value={parameter.defaultValue} onChange={(event) => update(parameter.id, { defaultValue: event.target.value })} />}</label> : null}
    </article>)}</div>}
  </section>;
}
