// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import {
  ArrowLeft,
  CheckCircle2,
  KeyRound,
  ShieldCheck,
  UserCog,
  Wrench,
} from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import {
  createOperatorInputFromForm,
  operatorKindLabel,
  operatorKindToRole,
  type OperatorKind,
  type OperatorRecord,
} from "@/lib/operator-management-core";

type OperatorResponse = {
  error?: string;
  operator?: OperatorRecord;
};

export function CreateOperatorForm({ kind }: { kind: OperatorKind }) {
  const [created, setCreated] = useState<OperatorRecord | null>(null);
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);
  const label = operatorKindLabel(kind);
  const role = operatorKindToRole(kind);
  const RoleIcon = kind === "administrator" ? ShieldCheck : Wrench;

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    const form = event.currentTarget;
    const input = createOperatorInputFromForm(new FormData(form), kind);
    if (!input) {
      setError("Enter a valid email address and a non-empty password.");
      return;
    }

    setPending(true);
    try {
      const response = await fetch("/api/operators", {
        body: JSON.stringify(input),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      const body = await response.json().catch(() => null) as OperatorResponse | null;
      if (!response.ok || !body?.operator) {
        setError(body?.error ?? `The ${label.toLowerCase()} could not be created.`);
        return;
      }
      form.reset();
      setCreated(body.operator);
    } catch {
      setError("Operator creation is unavailable. Check the management service and try again.");
    } finally {
      setPending(false);
    }
  }

  if (created) {
    return (
      <section className="operator-created" aria-labelledby="operator-created-title">
        <CheckCircle2 aria-hidden="true" size={34} />
        <div>
          <span>Identity created</span>
          <h2 id="operator-created-title">{label} ready for sign-in</h2>
          <p><strong>{created.email}</strong> was created as {label.toLowerCase()}.</p>
        </div>
        <div className="operator-default-deny">
          <ShieldCheck aria-hidden="true" size={19} />
          <div>
            <strong>No script permission</strong>
            <span>Creating any role, including an administrator, never grants arbitrary-script execution.</span>
          </div>
        </div>
        <footer>
          <button type="button" onClick={() => setCreated(null)}>
            <UserCog aria-hidden="true" size={16} /> Create another {label.toLowerCase()}
          </button>
          <Link href="/operators">Return to operators</Link>
        </footer>
      </section>
    );
  }

  return (
    <form className="operator-create-form" onSubmit={submit}>
      <Link className="operator-back-link" href="/operators">
        <ArrowLeft aria-hidden="true" size={15} /> Operators
      </Link>

      <section className="operator-role-lock" aria-labelledby="operator-role-title">
        <span className="operator-role-icon"><RoleIcon aria-hidden="true" size={22} /></span>
        <div>
          <span>Preselected role</span>
          <h2 id="operator-role-title">{label}</h2>
          <p>
            This flow sends the API role <code>{role}</code>. The role is fixed for this entry point.
          </p>
        </div>
      </section>

      <section className="operator-identity-fields">
        <div>
          <span>Operator identity</span>
          <h2>Initial sign-in credentials</h2>
          <p>The password is sent once through NodeLink&apos;s same-origin session boundary and is never returned.</p>
        </div>
        <label htmlFor="operator-email">
          Email address
          <input
            autoComplete="off"
            id="operator-email"
            maxLength={320}
            name="email"
            placeholder="technician@example.com"
            required
            type="email"
          />
        </label>
        <label htmlFor="operator-password">
          Initial password
          <input
            autoComplete="new-password"
            id="operator-password"
            maxLength={1024}
            name="password"
            required
            type="password"
          />
          <small>
            NodeLink does not yet enforce password complexity, forced rotation, or administrator-initiated reset.
            Choose and deliver the initial password through a secure channel.
          </small>
        </label>
      </section>

      <aside className="operator-create-boundary">
        <ShieldCheck aria-hidden="true" size={20} />
        <div>
          <strong>Script execution starts denied</strong>
          <span>
            After creation, an administrator must separately compose and confirm a global, site, or agent grant with an audit reason.
          </span>
        </div>
      </aside>

      {error ? (
        <section className="operator-error-summary" role="alert" aria-labelledby="create-error-title">
          <strong id="create-error-title">Operator was not created</strong>
          <p>{error}</p>
        </section>
      ) : null}

      <footer>
        <span><KeyRound aria-hidden="true" size={16} /> Passwords are never logged or echoed back.</span>
        <button disabled={pending} type="submit">
          <RoleIcon aria-hidden="true" size={16} />
          {pending ? "Creating…" : `Create ${label.toLowerCase()}`}
        </button>
      </footer>
    </form>
  );
}
