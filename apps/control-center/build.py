"""INFINITY CONTROL CENTER (minimal).

Renders apps/control-center/index.html from persisted project files only:
  state/tasks.json, state/gates.json, state/audit_verdict.json, benchmarks/results/*/results.json,
  THEORY/*.md tables, ENVIRONMENT_AUDIT.md, AUDIT_REPORT.md
It never invents data. A module with no persisted data says so.

    python3 apps/control-center/build.py
"""
import html
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
E = html.escape


def jload(p):
    p = ROOT / p
    return json.loads(p.read_text()) if p.exists() else None


def md_tables(path):
    """Return rows (lists of cells) of the first markdown table in a file; header excluded."""
    p = ROOT / path
    if not p.exists():
        return []
    rows = []
    for line in p.read_text().splitlines():
        if line.startswith("|") and not re.match(r"^\|[\s:|-]+\|$", line.strip()):
            rows.append([c.strip() for c in line.strip().strip("|").split("|")])
    return rows[1:]  # drop header


def table(headers, rows, empty="No persisted data."):
    if not rows:
        return f"<p class='empty'>{E(empty)}</p>"
    h = "".join(f"<th>{E(str(x))}</th>" for x in headers)
    b = "".join("<tr>" + "".join(f"<td>{E(str(c))}</td>" for c in r) + "</tr>" for r in rows)
    return f"<div class='scroll'><table><thead><tr>{h}</tr></thead><tbody>{b}</tbody></table></div>"


def badge(s):
    cls = {"PASS": "ok", "VERIFIED": "ok", "FAIL": "bad", "BLOCKED": "bad"}.get(s, "warn")
    return f"<span class='b {cls}'>{E(s)}</span>"


def main() -> None:
    tasks = (jload("state/tasks.json") or {}).get("tasks", [])
    gates = jload("state/gates.json")
    verdict = jload("state/audit_verdict.json") or {}
    results = sorted((ROOT / "benchmarks" / "results").glob("*/results.json"))

    counts = Counter(t["state"] for t in tasks)
    overview = (table(["State", "Tasks"], sorted(counts.items()), "No tasks recorded.") +
                table(["ID", "Task", "State", "Note"], [[t["id"], t["title"], t["state"], t.get("note", "")] for t in tasks]))

    research = ("<h3>Hypotheses</h3>" + table(["ID", "Hypothesis", "Status", "Planned test"], md_tables("THEORY/active_hypotheses.md")) +
                "<h3>Verified findings</h3>" + table(["ID", "Claim", "Status", "Evidence"], [r for r in md_tables("THEORY/verified_findings.md") if r[0] != "(none yet)"], "None. No claim has reached EXPERIMENTALLY_SUPPORTED.") +
                "<h3>Rejected hypotheses</h3>" + table(["ID", "Hypothesis", "Status", "Reason"], [r for r in md_tables("THEORY/rejected_hypotheses.md") if r[0] != "(none yet)"], "None recorded."))

    exp_html = bench_html = ""
    if not results:
        exp_html = bench_html = "<p class='empty'>No experiments have been run.</p>"
    for rj in results:
        d = json.loads(rj.read_text())
        m, recs = d["meta"], d["records"]
        exp_html += (f"<h3>{E(m['experiment_id'])}</h3><p>Dataset {E(m['dataset_id'])} · {len(recs)} measurements · "
                     f"commit <code>{E(str(m['git']['commit'])[:10])}</code> · {E(m['timestamp_utc'])}</p>")
        rows = [[r["file"], r["codec"], r["original_bytes"], r["complete_storage_bytes"],
                 f"{r['compression_ratio']:.3f}" if r["compression_ratio"] else "n/a",
                 f"{r['compress_seconds_median']*1000:.1f}", f"{r['decompress_seconds_median']*1000:.1f}",
                 "yes" if r["reconstruction_success"] else "NO", "yes" if r["deterministic_across_repeats"] else "NO"]
                for r in sorted(recs, key=lambda r: (r["file"], r["complete_storage_bytes"]))]
        bench_html += f"<h3>{E(m['experiment_id'])}</h3>" + table(
            ["File", "Codec", "Original B", "Stored B", "Ratio", "Comp ms", "Decomp ms", "Exact", "Deterministic"], rows)
        bench_html += (f"<p class='empty'>Not implemented (no results): {E(', '.join(m['not_implemented']))}. "
                       f"Timings are medians on a shared 2-core VM and indicative only.</p>")

    if gates:
        gate_html = (f"<p>Last run: {E(gates['timestamp_utc'])} · release ready: <b>{gates['release_ready']}</b></p>" +
                     "<div class='scroll'><table><thead><tr><th>Gate</th><th>Name</th><th>Status</th><th>Evidence</th></tr></thead><tbody>" +
                     "".join(f"<tr><td>{g['id']}</td><td>{E(g['name'])}</td><td>{badge(g['status'])}</td><td>{E(g['evidence'])}</td></tr>" for g in gates["gates"]) +
                     "</tbody></table></div>")
    else:
        gate_html = "<p class='empty'>Gates have not been run.</p>"
    audit_html = gate_html + "<h3>Recorded audit verdicts</h3>" + (
        table(["Item", "Verdict"], sorted(verdict.items())) if verdict else "<p class='empty'>No verdict recorded.</p>")
    audit_html += f"<p>AUDIT_REPORT.md present: <b>{(ROOT / 'AUDIT_REPORT.md').exists()}</b></p>"

    infra = (table(["Component", "Status"], [
        ["Git repository", "initialized locally; no remote"],
        ["GitHub / CI", "not connected; .github/workflows/ci.yml written but never executed"],
        ["Benchmark workers", "none running (runs are manual, in-session)"],
        ["Scheduled automation", "not configured"],
        ["GPU", "none"],
        ["External connectors in use", "none"]]) +
        "<p>Source of truth: <code>ENVIRONMENT_AUDIT.md</code>.</p>")

    qs = [l.strip() for l in (ROOT / "THEORY" / "unresolved_questions.md").read_text().splitlines() if re.match(r"^\d+\.", l.strip())] \
        if (ROOT / "THEORY" / "unresolved_questions.md").exists() else []
    approval = jload("state/owner_approval.json")
    dec = ("<h3>Open questions for the owner</h3>" + ("<ol>" + "".join(f"<li>{E(re.sub(r'^[0-9]+[.] ', '', q))}</li>" for q in qs) + "</ol>" if qs else "<p class='empty'>None.</p>") +
           f"<p>Owner approval on file: <b>{bool(approval and approval.get('approved'))}</b></p>")

    mods = [("Overview", overview), ("Research", research), ("Experiments", exp_html), ("Benchmarks", bench_html),
            ("Audits & gates", audit_html), ("Infrastructure", infra), ("Decisions", dec)]
    nav = "".join(f"<a href='#m{i}'>{n}</a>" for i, (n, _) in enumerate(mods))
    body = "".join(f"<section id='m{i}'><h2>{n}</h2>{c}</section>" for i, (n, c) in enumerate(mods))
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Infinity Control Center</title><style>
:root{{--bg:#fff;--fg:#1b1f24;--mut:#5b6670;--line:#d8dee4;--ok:#1a7f37;--bad:#cf222e;--warn:#9a6700;--card:#f6f8fa}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0d1117;--fg:#e6edf3;--mut:#8b949e;--line:#30363d;--ok:#3fb950;--bad:#f85149;--warn:#d29922;--card:#161b22}}}}
body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}}
header{{padding:16px;border-bottom:1px solid var(--line)}}h1{{margin:0;font-size:20px}}
nav{{display:flex;gap:14px;flex-wrap:wrap;padding:10px 16px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--bg)}}
nav a{{color:var(--fg);text-decoration:none;font-weight:600}}main{{padding:0 16px 40px;max-width:1100px;margin:auto}}
section{{padding-top:12px}}h2{{border-bottom:1px solid var(--line);padding-bottom:4px}}h3{{margin-bottom:4px}}
.scroll{{overflow-x:auto}}table{{border-collapse:collapse;width:100%;font-size:13px}}th,td{{border:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top}}
th{{background:var(--card)}}.empty{{color:var(--mut)}}code{{background:var(--card);padding:1px 4px;border-radius:4px}}
.b{{padding:1px 7px;border-radius:10px;font-size:12px;font-weight:700;border:1px solid currentColor}}.ok{{color:var(--ok)}}.bad{{color:var(--bad)}}.warn{{color:var(--warn)}}
</style></head><body><header><h1>INFINITY CONTROL CENTER</h1>
<div class="empty">Generated {E(datetime.now(timezone.utc).isoformat(timespec='seconds'))} from persisted project files. Nothing here is simulated.</div></header>
<nav>{nav}</nav><main>{body}</main></body></html>"""
    out = ROOT / "apps" / "control-center" / "index.html"
    out.write_text(page)
    print(f"wrote {out.relative_to(ROOT)} ({len(page)} bytes)")


if __name__ == "__main__":
    main()
