// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import {
  AlertTriangle,
  RefreshCw,
  ShieldCheck,
  UserCog,
  Users,
  Wrench,
} from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import {
  formatOperatorCreatedAtUtc,
  operatorRoleLabel,
  scriptPermissionScopeLabel,
  type OperatorRecord,
} from "@/lib/operator-management-core";
import {
  ScriptPermissionAction,
  SignOutEverywhereAction,
} from "@/components/operator-actions";

type OperatorListResponse = {
  error?: string;
  operators?: OperatorRecord[];
};

async function requestOperatorRecords(): Promise<{
  error: string;
  operators: OperatorRecord[] | null;
}> {
  try {
    const response = await fetch("/api/operators", {
      cache: "no-store",
      headers: { Accept: "application/json" },
    });
    const body = await response.json().catch(() => null) as OperatorListResponse | null;
    if (!response.ok || !body?.operators) {
      return {
        error: body?.error ?? "Operator records are unavailable.",
        operators: null,
      };
    }
    return { error: "", operators: body.operators };
  } catch {
    return {
      error: "Operator records are unavailable. Check the management service and try again.",
      operators: null,
    };
  }
}

export function OperatorManagementView({
  currentOperatorId,
  initialError,
  initialOperators,
}: {
  currentOperatorId: string;
  initialError: string;
  initialOperators: OperatorRecord[] | null;
}) {
  const [operators, setOperators] = useState<OperatorRecord[] | null>(initialOperators);
  const [error, setError] = useState(initialError);
  const [loading, setLoading] = useState(false);

  async function loadOperators() {
    setLoading(true);
    setError("");
    const result = await requestOperatorRecords();
    setOperators(result.operators);
    setError(result.error);
    setLoading(false);
  }

  function updateOperator(updated: OperatorRecord) {
    setOperators((current) => current?.map((operator) => (
      operator.id === updated.id ? updated : operator
    )) ?? [updated]);
  }

  return (
    <>
      <header className="operator-page-head">
        <div>
          <span>Identity and privilege administration</span>
          <h1>Operators</h1>
          <p>
            Create administrators and technicians, review explicit script scope, and invalidate sessions.
            Role never implies arbitrary-script permission.
          </p>
        </div>
        <div className="operator-create-links">
          <Link href="/operators/new/technician"><Wrench aria-hidden="true" size={16} /> Create technician</Link>
          <Link className="primary" href="/operators/new/administrator"><ShieldCheck aria-hidden="true" size={16} /> Create administrator</Link>
        </div>
      </header>

      <section className="operator-boundary-banner">
        <ShieldCheck aria-hidden="true" size={23} />
        <div>
          <strong>Arbitrary scripts are default-deny</strong>
          <span>
            Every operator needs a separate, audited global, site, or agent grant. Administrators have no implicit bypass.
          </span>
        </div>
      </section>

      {error ? (
        <section className="operator-error-summary" role="alert" aria-labelledby="operator-list-error">
          <strong id="operator-list-error">Operator records could not be loaded</strong>
          <p>{error}</p>
          <button onClick={loadOperators} type="button"><RefreshCw aria-hidden="true" size={14} /> Try again</button>
        </section>
      ) : null}

      <section className="operator-register" aria-busy={loading}>
        <header>
          <div>
            <span>Access register</span>
            <h2>{operators ? `${operators.length} operator${operators.length === 1 ? "" : "s"}` : "Operators"}</h2>
          </div>
          <button disabled={loading} onClick={loadOperators} type="button">
            <RefreshCw aria-hidden="true" size={14} /> Refresh
          </button>
        </header>

        {loading && !operators ? (
          <div className="operator-empty" role="status">
            <RefreshCw aria-hidden="true" className="operator-loading-icon" size={24} />
            <strong>Loading operator records</strong>
          </div>
        ) : operators?.length === 0 ? (
          <div className="operator-empty">
            <Users aria-hidden="true" size={25} />
            <strong>No operators found</strong>
            <span>Create an administrator or technician to begin.</span>
          </div>
        ) : operators ? (
          <div className="operator-table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Operator</th>
                  <th>Role</th>
                  <th>Script permission</th>
                  <th>Created (UTC)</th>
                  <th><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {operators.map((operator) => (
                  <tr key={operator.id}>
                    <td>
                      <strong>{operator.email}</strong>
                      <span className={`operator-account-state ${operator.disabled ? "disabled" : "active"}`}>
                        {operator.disabled ? "Disabled" : "Active"}
                      </span>
                    </td>
                    <td>
                      <span className={`operator-role role-${operator.role}`}>
                        {operatorRoleLabel(operator.role)}
                      </span>
                      {operator.id === currentOperatorId ? <small>Current operator</small> : null}
                    </td>
                    <td>
                      {operator.script_execution_scope ? (
                        <div className="operator-permission granted">
                          <ShieldCheck aria-hidden="true" size={17} />
                          <div>
                            <strong>{scriptPermissionScopeLabel(operator.script_execution_scope)} permission</strong>
                            <span>
                              {operator.script_execution_scope === "global"
                                ? "All managed endpoints"
                                : <code>{operator.script_execution_scope_id}</code>}
                            </span>
                          </div>
                        </div>
                      ) : (
                        <div className="operator-permission denied">
                          <AlertTriangle aria-hidden="true" size={17} />
                          <div><strong>No script permission</strong><span>Default deny</span></div>
                        </div>
                      )}
                    </td>
                    <td><time dateTime={operator.created_at}>{formatOperatorCreatedAtUtc(operator.created_at)}</time></td>
                    <td>
                      <div className="operator-row-actions">
                        <ScriptPermissionAction mode="grant" onUpdated={updateOperator} operator={operator} />
                        {operator.script_execution_scope ? (
                          <ScriptPermissionAction mode="revoke" onUpdated={updateOperator} operator={operator} />
                        ) : null}
                        <SignOutEverywhereAction
                          isCurrentOperator={operator.id === currentOperatorId}
                          operator={operator}
                        />
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </section>

      <aside className="operator-limitations">
        <UserCog aria-hidden="true" size={19} />
        <div>
          <strong>Current administration boundary</strong>
          <span>
            Disabling, deleting, password reset/change, forced rotation, and pagination are not implemented by the server, so this page does not present those controls.
          </span>
        </div>
      </aside>
    </>
  );
}
