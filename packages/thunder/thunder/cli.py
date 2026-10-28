"""thunder: scan | graph | blast | why | snapshot | diff | init"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import config as C
from .extract import build
from .graph import Graph, diff
from .rules import SEV, run_all

INIT_CONFIG = {
    "comment": "Thunder config. Edit paths for your project; run `python -m thunder scan`.",
    "source_roots": ["."],
    "critical": [{"name": "core", "paths": ["src"], "forbid_imports": ["socket", "subprocess", "pickle", "random"], "require_tests": True}],
    "layers": [],
    "baseline": {},
}


def _load(args):
    root = Path(args.root).resolve()
    cfg = C.load(root, args.config)
    return root, cfg, build(root, cfg)


def _baseline(cfg):
    return cfg.get("baseline", {})


def cmd_scan(args) -> int:
    root, cfg, g = _load(args)
    findings = run_all(g, cfg, root)
    base = _baseline(cfg)
    fresh = [f for f in findings if f.fingerprint() not in base]
    accepted = [f for f in findings if f.fingerprint() in base]
    if args.json:
        print(json.dumps({"nodes": len(g.nodes), "edges": len(g.edges), "new": [f.to_json() for f in fresh],
                          "accepted": [dict(f.to_json(), reason=base[f.fingerprint()]) for f in accepted]}, indent=1))
    else:
        kinds = {}
        for d in g.nodes.values():
            kinds[d["kind"]] = kinds.get(d["kind"], 0) + 1
        print(f"THUNDER scan of {root}\n  graph: {len(g.nodes)} nodes, {len(g.edges)} edges  {dict(sorted(kinds.items()))}")
        print("  limits: static, name-based call resolution; dynamic dispatch, reflection and runtime behaviour are not seen.")
        for f in fresh:
            print(f"\n[{f.severity.upper()}] {f.rule}  {f.node}\n  {f.message}")
            for e in f.evidence[:6]:
                print(f"    - {e}")
            print(f"  fingerprint: {f.fingerprint()}")
        print(f"\n{len(fresh)} new finding(s), {len(accepted)} accepted in baseline.")
    worst = max((SEV[f.severity] for f in fresh), default=-1)
    return 1 if worst >= SEV[args.fail_on] else 0


def cmd_graph(args) -> int:
    _, _, g = _load(args)
    sys.stdout.write(g.to_dot({"imports"}) if args.dot else g.dumps())
    return 0


def _resolve_node(g: Graph, name: str) -> list[str]:
    if name in g.nodes:
        return [name]
    return sorted(n for n in g.nodes if n.endswith(name) or n.split("::")[0].endswith(name))


def cmd_blast(args) -> int:
    """What can be affected if this node changes (reverse reachability), and which tests sit on that path."""
    _, _, g = _load(args)
    hits = _resolve_node(g, args.node)
    if not hits:
        print("no such node"); return 2
    for h in hits:
        mod = h.split("::")[0]
        affected = g.reachable([h, mod], kinds={"imports", "calls", "calls_by_name", "contains"}, reverse=True)
        tests = sorted(n for n in affected if g.nodes[n]["kind"] == "test")
        mods = sorted(n for n in affected if g.nodes[n]["kind"] == "module")
        print(f"{h}\n  modules that depend on it: {len(mods)}\n" + "".join(f"    {m}\n" for m in mods[:25]) + f"  tests on the path: {len(tests)}\n" + "".join(f"    {t}\n" for t in tests[:25]))
    return 0


def cmd_why(args) -> int:
    _, _, g = _load(args)
    a, b = _resolve_node(g, args.a), _resolve_node(g, args.b)
    if not a or not b:
        print("node not found"); return 2
    p = g.path(a[0], b[0], kinds={"imports", "calls", "calls_by_name", "contains"})
    print(" -> ".join(p) if p else "no path")
    return 0 if p else 1


def cmd_snapshot(args) -> int:
    _, _, g = _load(args)
    Path(args.out).write_text(g.dumps())
    print(f"snapshot: {len(g.nodes)} nodes, {len(g.edges)} edges -> {args.out}")
    return 0


RISKY = ("external:", "stdlib:subprocess", "stdlib:socket", "stdlib:pickle", "stdlib:urllib", "stdlib:http", "stdlib:ctypes")


def cmd_diff(args) -> int:
    root, cfg, new = _load(args)
    old = Graph.from_json(json.loads(Path(args.old).read_text()))
    d = diff(old, new)
    crit = [p for c in cfg["critical"] for p in c["paths"]]
    alerts = []
    for s, t, k in d["edges_added"]:
        if k == "imports" and t.startswith(RISKY) and any(s == p or s.startswith(p.rstrip("/") + "/") for p in crit):
            alerts.append(f"critical module {s} now imports {t}")
    print(f"nodes +{len(d['nodes_added'])} -{len(d['nodes_removed'])}, edges +{len(d['edges_added'])} -{len(d['edges_removed'])}")
    for a in alerts:
        print(f"ALERT {a}")
    return 1 if alerts else 0


def cmd_init(args) -> int:
    p = Path(args.root) / "thunder.json"
    if p.exists():
        print("thunder.json already exists; not overwriting"); return 1
    p.write_text(json.dumps(INIT_CONFIG, indent=2) + "\n")
    print(f"wrote {p}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="thunder")
    ap.add_argument("--root", default=".")
    ap.add_argument("--config")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan"); s.add_argument("--json", action="store_true"); s.add_argument("--fail-on", choices=list(SEV), default="high"); s.set_defaults(fn=cmd_scan)
    s = sub.add_parser("graph"); s.add_argument("--dot", action="store_true"); s.set_defaults(fn=cmd_graph)
    s = sub.add_parser("blast"); s.add_argument("node"); s.set_defaults(fn=cmd_blast)
    s = sub.add_parser("why"); s.add_argument("a"); s.add_argument("b"); s.set_defaults(fn=cmd_why)
    s = sub.add_parser("snapshot"); s.add_argument("out"); s.set_defaults(fn=cmd_snapshot)
    s = sub.add_parser("diff"); s.add_argument("old"); s.set_defaults(fn=cmd_diff)
    s = sub.add_parser("init"); s.set_defaults(fn=cmd_init)
    args = ap.parse_args(argv)
    return args.fn(args)
