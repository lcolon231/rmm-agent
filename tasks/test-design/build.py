# SPDX-License-Identifier: AGPL-3.0-only
"""Build tasks/test-design-plan.{html,json} from data.py + evidence.json.

    python tasks/test-design/build.py

Both outputs come from the same in-memory row list, so the summary strip and
the JSON row count cannot disagree. The build refuses to write if any
dashboard route handler is unaccounted for or if the rubric does not produce a
total order.
"""

from __future__ import annotations

import html
import inspect
import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
TASKS = HERE.parent
sys.path.insert(0, str(HERE))

from data import ROWS, RUNNER_CHANGES, SEAMS  # noqa: E402

PRIORITIES = ("P0", "P1", "P2", "P3")


# ───────────────────────────── §4 prioritization rubric ─────────────────────────────
def rubric(row: dict) -> tuple[str, tuple]:
    """Return (priority label, sort key) for one row. Smaller sort key = do first.

    Inputs available on every row (see data.py docstring):
      row["plane"]         "trust" | "operations" | "product"
      row["coverage"]      "zero" | "thin"
      row["visibility"]    "silent" | "visible"
      row["fixture_cost"]  "low" | "medium" | "high"
      row["expected_fail"] bool
      row["id"]            unique string, usable as a last-resort tie-breaker

    The label must be one of PRIORITIES. The sort key must differ for every
    row (the build checks this), so the rule itself has to say how ties break.
    """
    # TODO(human): implement the scoring rule (2-10 lines).
    raise NotImplementedError("rubric() is the §4 decision left to a human")


WORKED_EXAMPLE_ID = "SRV-10"


# ───────────────────────────── assembly ─────────────────────────────
def load_evidence() -> dict:
    return json.loads((HERE / "evidence.json").read_text(encoding="utf-8"))


def apply_rubric(rows: list[dict]) -> list[dict]:
    keyed = []
    for row in rows:
        label, key = rubric(row)
        if label not in PRIORITIES:
            raise SystemExit(f"rubric returned {label!r} for {row['id']}; expected one of {PRIORITIES}")
        row["priority"] = label
        keyed.append((key, row))
    dupes = [k for k, n in Counter(k for k, _ in keyed).items() if n > 1]
    if dupes:
        clash = [r["id"] for k, r in keyed if k in dupes]
        raise SystemExit(f"rubric is not a total order; equal keys for {clash}. Add a tie-breaker.")
    keyed.sort(key=lambda kr: kr[0])
    for rank, (_, row) in enumerate(keyed, start=1):
        row["rank"] = rank
    return [r for _, r in keyed]


def handler_coverage(evidence: dict, rows: list[dict]) -> list[dict]:
    by_handler = {}
    for row in rows:
        for h in row["handlers"]:
            by_handler.setdefault(h, []).append(row["id"])
    out, missing = [], []
    for h in evidence["dashboard_handlers"]:
        key = f'{h["method"]} {h["path"]}'
        test = h.get("route_core_test") or ""
        proposed = by_handler.get(key, [])
        if proposed:
            status = "proposed: " + ", ".join(proposed)
        elif test and "ORPHAN" not in test and test.endswith(".test.ts"):
            status = f"covered by test/{test}"
        else:
            missing.append(key)
            status = "UNACCOUNTED"
        out.append(dict(handler=key, route_core=h.get("route_core_fn") or "(inline)",
                        status=status,
                        session_revalidation=h.get("session_revalidation"),
                        role_gating=h.get("role_gating"),
                        allowlisting=h.get("allowlisting")))
    if missing:
        raise SystemExit("dashboard handlers with neither a covering test nor a proposed row:\n  " + "\n  ".join(missing))
    return out


def summary(rows: list[dict]) -> dict:
    return dict(
        total=len(rows),
        by_layer=dict(Counter(r["layer"] for r in rows)),
        by_tier=dict(Counter(r["tier"] for r in rows)),
        by_priority={p: sum(1 for r in rows if r["priority"] == p) for p in PRIORITIES},
        expected_fail=sum(1 for r in rows if r["expected_fail"]),
    )


# ───────────────────────────── HTML ─────────────────────────────
CSS = """
:root{--bg:#fbfaf8;--panel:#fff;--ink:#1d1d1b;--muted:#5f5e5a;--line:#e3e1dc;--accent:#2d5bd7;
--p0:#b42318;--p1:#b54708;--p2:#2d5bd7;--p3:#5f5e5a;--fail-bg:#fdecea;--chip:#f1efea;--code:#f4f2ee}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#141413;--panel:#1c1c1a;--ink:#ecebe7;
--muted:#a3a19b;--line:#2f2e2b;--accent:#8aa8ff;--p0:#ff8a80;--p1:#ffb86b;--p2:#8aa8ff;--p3:#a3a19b;
--fail-bg:#3a1f1c;--chip:#262624;--code:#22221f}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:1.6rem;margin:0 0 4px}h2{font-size:1.2rem;margin:40px 0 12px;padding-top:8px;border-top:1px solid var(--line)}
h3{font-size:1rem;margin:20px 0 8px}p,li{max-width:80ch}.muted{color:var(--muted)}
code,pre{font:12.5px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace;background:var(--code);border-radius:4px}
code{padding:1px 4px}pre{padding:12px;overflow-x:auto;white-space:pre}
.strip{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:20px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.card .big{font-size:1.8rem;font-weight:650;line-height:1.1}.card dl{margin:6px 0 0;display:grid;grid-template-columns:1fr auto;gap:2px 10px;font-size:13px}
.card dd{margin:0;text-align:right;font-variant-numeric:tabular-nums}
.tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px;background:var(--panel)}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top;text-align:left}
th{position:sticky;top:0;background:var(--panel);font-weight:600;white-space:nowrap}
th[data-sort]{cursor:pointer;color:var(--accent)}th[data-sort]::after{content:" ⇅";color:var(--muted)}
td.wide{min-width:260px}td.mid{min-width:170px}tr.fail td{background:var(--fail-bg)}
.pri{display:inline-block;font-weight:700;padding:1px 7px;border-radius:10px;background:var(--chip)}
.P0{color:var(--p0)}.P1{color:var(--p1)}.P2{color:var(--p2)}.P3{color:var(--p3)}
.chip{display:inline-block;background:var(--chip);border-radius:10px;padding:0 7px;margin:1px 2px 1px 0;font-size:12px;white-space:nowrap}
.seam{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px 16px;margin:12px 0}
.seam dl{display:grid;grid-template-columns:minmax(90px,140px) 1fr;gap:4px 12px;margin:0}.seam dt{color:var(--muted)}.seam dd{margin:0}
details{margin:8px 0}summary{cursor:pointer;font-weight:600}
nav a{color:var(--accent);margin-right:12px;white-space:nowrap}
@media (max-width:520px){.seam dl{grid-template-columns:1fr}.seam dt{margin-top:6px}}
"""

JS = """
document.querySelectorAll('table[data-sortable]').forEach(t=>{
  t.querySelectorAll('th[data-sort]').forEach(th=>{
    let asc=true;th.addEventListener('click',()=>{
      const col=th.cellIndex,body=t.tBodies[0],rows=[...body.rows];
      rows.sort((a,b)=>{const x=a.cells[col].dataset.v??a.cells[col].textContent,y=b.cells[col].dataset.v??b.cells[col].textContent;
        const nx=+x,ny=+y;const c=(!isNaN(nx)&&!isNaN(ny))?nx-ny:x.localeCompare(y);return asc?c:-c});
      asc=!asc;rows.forEach(r=>body.appendChild(r));});});});
"""

FIELDS = ("rank", "priority", "id", "tier", "target", "behavior", "boundary", "fixture_strategy",
          "existing_pattern_to_copy", "rationale", "plane", "coverage", "visibility", "fixture_cost", "notes")


def e(s) -> str:
    return html.escape(str(s))


def row_html(r: dict) -> str:
    cells = []
    for f in FIELDS:
        v = r.get(f)
        if f == "priority":
            cells.append(f'<td data-v="{r["rank"]}"><span class="pri {v}">{v}</span></td>')
        elif f == "rank":
            cells.append(f'<td data-v="{v}">{v}</td>')
        elif f == "notes":
            items = list(v) + (["handlers: " + "; ".join(r["handlers"])] if r["handlers"] else [])
            cells.append('<td class="mid">' + "".join(f'<div class="chip">{e(n)}</div><br>' for n in items) + "</td>")
        elif f in ("behavior", "rationale", "fixture_strategy"):
            cells.append(f'<td class="wide">{e(v)}</td>')
        elif f in ("target", "boundary", "existing_pattern_to_copy"):
            cells.append(f'<td class="mid">{e(v)}</td>')
        else:
            cells.append(f"<td>{e(v)}</td>")
    cls = ' class="fail"' if r["expected_fail"] else ""
    return f"<tr{cls}>" + "".join(cells) + "</tr>"


def layer_table(layer: str, rows: list[dict]) -> str:
    head = "".join(f'<th data-sort>{f}</th>' if f in ("rank", "priority", "id", "tier", "plane", "coverage", "fixture_cost") else f"<th>{f}</th>" for f in FIELDS)
    body = "".join(row_html(r) for r in rows if r["layer"] == layer)
    n = sum(1 for r in rows if r["layer"] == layer)
    return (f'<h3 id="layer-{layer}">{e(layer)} <span class="muted">({n} rows)</span></h3>'
            f'<div class="tablewrap"><table data-sortable><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>')


def card(title: str, big, items: dict) -> str:
    dl = "".join(f"<dt>{e(k)}</dt><dd>{e(v)}</dd>" for k, v in items.items())
    return f'<div class="card"><div class="muted">{e(title)}</div><div class="big">{e(big)}</div><dl>{dl}</dl></div>'


def build_html(rows, summ, ev, handlers, worked) -> str:
    layers = ["server", "dashboard", "agent", "contracts", "installer", "cross-layer"]
    strip = (card("Rows proposed", summ["total"], {"expected to fail": summ["expected_fail"]})
             + card("Per layer", "", {k: summ["by_layer"].get(k, 0) for k in layers})
             + card("Per tier", "", summ["by_tier"])
             + card("Per priority", "", summ["by_priority"]))
    evid = "".join(
        f"<details><summary>{e(c['title'])}</summary><pre>$ {e(c['cmd'])}</pre><pre>{e(c['output'])}</pre>"
        + (f"<p class='muted'>{e(c['caveat'])}</p>" if c.get("caveat") else "") + "</details>"
        for c in ev["commands"])
    zh = "".join(f"<tr><td>{e(m['module'])}</td><td>{e(m['classification'])}</td><td>{e(str(m.get('evidence'))[:400])}</td></tr>" for m in ev["zero_hit_modules"])
    tot = ev["http_exception_totals"]
    exc = "".join(f"<tr><td>{e(x['router'])}:{x['line']}</td><td>{e(x['method'])}</td><td>{e(x['path'])}</td><td>{e(x['status'])}</td><td>{e(str(x['detail'])[:80])}</td></tr>" for x in ev["http_exceptions_untriggered"])
    hcov = "".join(f"<tr><td>{e(h['handler'])}</td><td>{e(h['route_core'])}</td><td>{e(h['status'])}</td><td>{e(h['session_revalidation'])}</td><td>{e(h['role_gating'])}</td><td>{e(h['allowlisting'])}</td></tr>" for h in handlers)
    seams = "".join(
        f'<div class="seam" id="seam-{s["n"]}"><h3>{s["n"]}. {e(s["name"])}</h3><dl>'
        f"<dt>Parties</dt><dd>{e(s['parties'])}</dd><dt>Transport</dt><dd>{e(s['transport'])}</dd>"
        f"<dt>Test dependency</dt><dd>{e(s['dependency'])}</dd><dt>Happy path</dt><dd>{e(s['happy'])}</dd>"
        f"<dt>Failure modes</dt><dd><ul>{''.join(f'<li>{e(x)}</li>' for x in s['failures'])}</ul></dd>"
        + (f"<dt>Go-side only</dt><dd>{e(s['go_only'])}</dd>" if s["go_only"] else "")
        + f"<dt>Rows</dt><dd>{''.join(f'<span class=chip>{e(x)}</span>' for x in s['rows'])}</dd></dl></div>"
        for s in SEAMS)
    runner = "".join(f"<tr><td>{e(c['name'])}</td><td>{e(c['need'])}</td><td>{e(c['change'])}</td><td>{e(c['asks'])}</td></tr>" for c in RUNNER_CHANGES)
    w_row, w_label, w_key = worked
    w_inputs = {k: w_row[k] for k in ("plane", "coverage", "visibility", "fixture_cost", "expected_fail", "id")}
    tables = "".join(layer_table(l, rows) for l in layers)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>NodeLink Test Matrix</title>
<style>{CSS}</style></head><body><main>
<h1>NodeLink Test Matrix</h1>
<p class="muted">Unit and integration test design (design only, nothing added or run). Generated from commit <code>{e(ev['generated_from_commit'])}</code> by <code>tasks/test-design/build.py</code>. Rows highlighted are <b>expected to fail</b> on current code, per code reading.</p>
<nav><a href="#summary">Summary</a><a href="#evidence">Survey evidence</a><a href="#tables">Tables</a><a href="#handlers">Route handlers</a><a href="#seams">Seams</a><a href="#runner">Runner changes</a><a href="#rubric">Rubric</a></nav>
<h2 id="summary">Summary</h2><div class="strip">{strip}</div>
<h2 id="evidence">Survey evidence</h2>
<p>Exact commands and their output, re-runnable from the repo root. A missing same-named test was only classed as a gap after the import-graph check and the HTTP-path check.</p>
{evid}
<details><summary>Zero-import modules: import graph + HTTP check</summary><div class="tablewrap"><table><thead><tr><th>module</th><th>classification</th><th>evidence</th></tr></thead><tbody>{zh}</tbody></table></div></details>
<details><summary>HTTPException branches: {tot['sites']} sites, {tot['triggered']} triggered, {tot['not_triggered']} untriggered, {tot['unknown']} unknown (untriggered listed)</summary><div class="tablewrap"><table><thead><tr><th>site</th><th>method</th><th>path</th><th>status</th><th>detail</th></tr></thead><tbody>{exc}</tbody></table></div></details>
<h2 id="tables">Proposed tests by layer</h2><p class="muted">Click a header with ⇅ to sort; <code>priority</code> sorts by rubric rank.</p>{tables}
<h2 id="handlers">Every dashboard route handler ({len(handlers)})</h2>
<p>Each <code>src/app/api/**/route.ts</code> method handler is either covered by a route-core test in <code>npm test</code> or mapped to a proposed row. The three columns are the survey's reading of current code.</p>
<div class="tablewrap"><table data-sortable><thead><tr><th data-sort>handler</th><th>route-core</th><th data-sort>status</th><th>session revalidation</th><th>role gating</th><th>allowlisting</th></tr></thead><tbody>{hcov}</tbody></table></div>
<h2 id="seams">Integration seams</h2>{seams}
<h2 id="runner">Runner changes</h2><p>Smallest change that unblocks each part of the matrix. Anything touching package.json, go.mod, requirements, or CI is marked "ask first".</p>
<div class="tablewrap"><table><thead><tr><th>change</th><th>needed by</th><th>smallest change</th><th>approval</th></tr></thead><tbody>{runner}</tbody></table></div>
<h2 id="rubric">Prioritization rubric</h2><p>Verbatim from <code>build.py</code>; it is the code that ordered every row above.</p>
<pre>{e(inspect.getsource(rubric))}</pre>
<h3>Worked example: {e(w_row['id'])}</h3><p>{e(w_row['behavior'])}</p>
<pre>inputs  = {e(json.dumps(w_inputs))}
output  = ({e(w_label)!s}, {e(repr(w_key))})
rank    = {w_row['rank']} of {len(rows)}</pre>
</main><script>{JS}</script></body></html>"""


def main() -> None:
    ev = load_evidence()
    rows = apply_rubric([dict(r) for r in ROWS])
    handlers = handler_coverage(ev, rows)
    summ = summary(rows)
    assert summ["total"] == len(rows) == sum(summ["by_priority"].values())
    w_row = next(r for r in rows if r["id"] == WORKED_EXAMPLE_ID)
    w_label, w_key = rubric(w_row)
    (TASKS / "test-design-plan.html").write_text(build_html(rows, summ, ev, handlers, (w_row, w_label, w_key)), encoding="utf-8")
    (TASKS / "test-design-plan.json").write_text(json.dumps(dict(
        generated_from_commit=ev["generated_from_commit"],
        rubric_source=inspect.getsource(rubric),
        summary=summ, rows=rows, seams=SEAMS, runner_changes=RUNNER_CHANGES,
        dashboard_handler_coverage=handlers,
    ), indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {summ['total']} rows; per priority {summ['by_priority']}; handlers {len(handlers)}")


if __name__ == "__main__":
    main()
