// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Route core for the patch-compliance export download (issue #280).
 *
 * The CSV carries agent-reported hostnames and operator-entered client and
 * site names. A spreadsheet treats a cell that starts with `=`, `+`, `-`, `@`
 * (or a tab/CR that hides one) as a formula, so a hostile hostname could run
 * in the operator's spreadsheet when they open the file. The export is
 * therefore re-written cell by cell before it reaches the browser.
 */

import { authorizeSession, json, type GetSession } from "./bff-route-core.ts";
import type { ComplianceState } from "./patch-compliance-core.ts";

const states = new Set<ComplianceState>(["compliant", "non_compliant", "stale", "unknown", "exempt"]);

/**
 * Make one CSV cell inert for spreadsheet applications.
 *
 * OWASP's recommendation: prefix a single quote, which spreadsheets treat as
 * "text" and hide. Leading whitespace is looked through because `" =1"` and
 * `"\t=1"` are still evaluated. `-` is included even though it also catches a
 * negative number: every numeric column in this export is a non-negative count.
 */
export function neutralizeCsvCell(cell: string): string {
  return /^[\s]*[=+\-@]/.test(cell) || /^[\t\r]/.test(cell) ? `'${cell}` : cell;
}

/** Parse RFC 4180 CSV into rows of cells. Tolerates a missing final newline. */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quoted) {
      if (char === '"' && text[index + 1] === '"') {
        cell += '"';
        index += 1;
      } else if (char === '"') {
        quoted = false;
      } else {
        cell += char;
      }
    } else if (char === '"') {
      quoted = true;
    } else if (char === ",") {
      row.push(cell);
      cell = "";
    } else if (char === "\n" || char === "\r") {
      if (char === "\r" && text[index + 1] === "\n") index += 1;
      row.push(cell);
      rows.push(row);
      row = [];
      cell = "";
    } else {
      cell += char;
    }
  }
  if (cell !== "" || row.length > 0) {
    row.push(cell);
    rows.push(row);
  }
  return rows;
}

function serializeCell(cell: string): string {
  return /[",\r\n]/.test(cell) ? `"${cell.replaceAll('"', '""')}"` : cell;
}

/** Re-emit the CSV with every cell neutralized; the header row included. */
export function neutralizeCsv(text: string): string {
  return parseCsv(text)
    .map((row) => row.map((cell) => serializeCell(neutralizeCsvCell(cell))).join(","))
    .map((line) => `${line}\r\n`)
    .join("");
}

export function exportQueryFromUrl(url: string): { format: "csv" | "json"; query: URLSearchParams } | null {
  const incoming = new URL(url).searchParams;
  const format = incoming.get("format") ?? "csv";
  const state = incoming.get("state");
  if ((format !== "csv" && format !== "json") || (state !== null && !states.has(state as ComplianceState))) {
    return null;
  }
  const query = new URLSearchParams({ format });
  for (const field of ["client_id", "site_id"] as const) {
    const value = incoming.get(field);
    if (value) query.set(field, value.slice(0, 36));
  }
  if (state) query.set("state", state);
  return { format, query };
}

export async function handlePatchComplianceExport(
  request: Request,
  deps: {
    getSession: GetSession;
    requestExport: (sessionToken: string, query: URLSearchParams) => Promise<Response>;
  },
): Promise<Response> {
  const auth = await authorizeSession(deps.getSession, {
    minRole: "readonly",
    signedOut: "Sign in again to continue.",
    forbidden: "Your role cannot export patch compliance.",
  });
  if (auth instanceof Response) return auth;

  const parsed = exportQueryFromUrl(request.url);
  if (!parsed) return json({ error: "The export request is invalid." }, 400);

  let upstream: Response;
  try {
    upstream = await deps.requestExport(auth.sessionToken, parsed.query);
  } catch {
    return json({ error: "The patch compliance export is unavailable right now." }, 503);
  }
  if (!upstream.ok) {
    const status = upstream.status >= 400 && upstream.status < 600 ? upstream.status : 502;
    return json({ error: "The patch compliance export failed." }, status);
  }

  const filenameMatch = /filename="([A-Za-z0-9._-]+)"/.exec(upstream.headers.get("content-disposition") ?? "");
  const filename = filenameMatch?.[1] ?? `patch-compliance.${parsed.format}`;
  const body = parsed.format === "csv" ? neutralizeCsv(await upstream.text()) : await upstream.arrayBuffer();
  return new Response(body, {
    status: 200,
    headers: {
      "Content-Type": parsed.format === "csv" ? "text/csv; charset=utf-8" : "application/json",
      "Content-Disposition": `attachment; filename="${filename}"`,
      "Cache-Control": "no-store",
    },
  });
}
