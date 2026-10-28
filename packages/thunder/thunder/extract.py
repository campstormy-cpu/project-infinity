"""Build the project graph from source. Static analysis, best effort: calls are resolved by NAME through the
import tables, not by types, so dynamic dispatch is invisible. Thunder says so in its reports."""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

from .graph import Graph

STDLIB = set(sys.stdlib_module_names)
DOC_REF = re.compile(r"`([A-Za-z0-9_./\-]+(?:\.[A-Za-z0-9]{1,5}|/))`")


def _skip(rel: Path, cfg) -> bool:
    return any(part in cfg["exclude"] for part in rel.parts)


def _is_test(rel: str, cfg) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return any(g in rel if g.endswith("/") else name.startswith(g) for g in cfg["test_globs"])


def _dotted(rel: str, cfg) -> str | None:
    """Longest matching source root decides the module's dotted name."""
    best = None
    for r in cfg["source_roots"]:
        r = r.strip("./") if r != "." else ""
        if r == "" or rel == r or rel.startswith(r + "/"):
            sub = rel[len(r):].lstrip("/") if r else rel
            if best is None or len(r) > best[0]:
                best = (len(r), sub)
    if best is None:
        return None
    sub = best[1][:-3]
    parts = sub.split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) if parts and parts != [""] else None


def build(root: Path, cfg: dict) -> Graph:
    g = Graph()
    root = root.resolve()
    py_files = []
    for p in sorted(root.rglob("*.py")):
        rel = p.relative_to(root)
        if not _skip(rel, cfg):
            py_files.append(rel.as_posix())
    by_dotted: dict[str, str] = {}
    for rel in py_files:
        d = _dotted(rel, cfg)
        if d:
            by_dotted[d] = rel
    infos: dict[str, dict] = {}
    infos_paths = set(py_files)

    # pass 1: modules, symbols, import tables
    for rel in py_files:
        src = (root / rel).read_text(encoding="utf-8", errors="replace")
        try:
            tree = ast.parse(src)
        except SyntaxError as e:
            g.add_node(rel, "module", test=_is_test(rel, cfg), syntax_error=str(e))
            continue
        kind = "test" if _is_test(rel, cfg) else "module"
        g.add_node(rel, kind, dotted=_dotted(rel, cfg), loc=src.count("\n") + 1)
        syms, alias, danger = {}, {}, []
        pkg = (_dotted(rel, cfg) or "")
        is_init = rel.endswith("__init__.py")
        base_pkg = pkg if is_init else pkg.rpartition(".")[0]

        here = rel.rsplit("/", 1)[0] if "/" in rel else ""

        def resolve_mod(name: str) -> str | None:
            if name in by_dotted:
                return by_dotted[name]
            sib = (here + "/" if here else "") + name.replace(".", "/") + ".py"  # script-directory import (e.g. conftest)
            return sib if sib in infos_paths else None

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                sid = f"{rel}::{node.name}"
                g.add_node(sid, "class" if isinstance(node, ast.ClassDef) else "func", public=not node.name.startswith("_"), line=node.lineno)
                g.add_edge(rel, sid, "runs" if kind == "test" else "contains")  # the test runner executes test functions
                syms[node.name] = sid
                if isinstance(node, ast.ClassDef):
                    for sub in node.body:
                        if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            mid = f"{rel}::{node.name}.{sub.name}"
                            g.add_node(mid, "method", public=not sub.name.startswith("_") and not node.name.startswith("_"), line=sub.lineno)
                            g.add_edge(sid, mid, "runs" if kind == "test" else "contains")
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    top = a.name.split(".")[0]
                    tgt = resolve_mod(a.name) or resolve_mod(top)
                    alias[a.asname or top] = ("mod", tgt, a.name if a.asname else top)
                    _imp(g, rel, a.name, tgt)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    parts = base_pkg.split(".") if base_pkg else []
                    parts = parts[: len(parts) - (node.level - 1)] if node.level > 1 else parts
                    modname = ".".join(parts + ([node.module] if node.module else []))
                else:
                    modname = node.module or ""
                tgt = resolve_mod(modname)
                _imp(g, rel, modname, tgt)
                for a in node.names:
                    sub = resolve_mod(f"{modname}.{a.name}")
                    if sub:
                        g.add_edge(rel, sub, "imports")
                        alias[a.asname or a.name] = ("mod", sub, a.name)
                    else:
                        alias[a.asname or a.name] = ("sym", tgt, a.name, modname)
            elif isinstance(node, ast.Call):
                n = _dotted_name(node.func)
                if n and n in cfg["dangerous_calls"]:
                    danger.append((node.lineno, n))
                if n and n.startswith("subprocess.") and any(k.arg == "shell" and getattr(k.value, "value", None) is True for k in node.keywords):
                    danger.append((node.lineno, "subprocess(shell=True)"))
        g.nodes[rel]["danger"] = sorted(set(danger))
        infos[rel] = {"tree": tree, "syms": syms, "alias": alias}

    # pass 2: references / calls
    def lookup(rel: str, name: str, seen=None):
        seen = seen or set()
        if (rel, name) in seen:
            return None
        seen.add((rel, name))
        info = infos.get(rel)
        if not info:
            return None
        if name in info["syms"]:
            return info["syms"][name]
        a = info["alias"].get(name)
        if a and a[0] == "sym" and a[1]:
            return lookup(a[1], a[2], seen)
        return None

    method_index: dict[str, list[str]] = {}
    for nid, nd in g.nodes.items():
        if nd["kind"] == "method":
            method_index.setdefault(nid.rsplit(".", 1)[1], []).append(nid)

    for rel, info in infos.items():
        scopes = []
        for node in info["tree"].body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scopes.append((f"{rel}::{node.name}", node))
            elif isinstance(node, ast.ClassDef):
                scopes.append((f"{rel}::{node.name}", node))
                for sub in node.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        scopes.append((f"{rel}::{node.name}.{sub.name}", sub))
        scoped_ids = {id(n) for _, n in scopes}
        module_level = [n for n in info["tree"].body if id(n) not in scoped_ids and not isinstance(n, ast.ClassDef)]
        for owner, body in [(s, n) for s, n in scopes] + [(rel, ast.Module(body=module_level, type_ignores=[]))]:
            for node in ast.walk(body):
                target = None
                if isinstance(node, ast.Name):
                    target = lookup(rel, node.id)
                elif isinstance(node, ast.Attribute):
                    base = node.value
                    if isinstance(base, ast.Name) and base.id in info["alias"] and info["alias"][base.id][0] == "mod" and info["alias"][base.id][1]:
                        target = lookup(info["alias"][base.id][1], node.attr)
                    if target is None and node.attr in method_index:  # name-based heuristic for obj.method()
                        for m in method_index[node.attr]:
                            g.add_edge(owner, m, "calls_by_name")
                if target:
                    g.add_edge(owner, target, "runs" if owner == rel else "calls")  # module-level code runs at import

    # external dependency nodes already added by _imp; docs and workflows
    for md in sorted(root.rglob("*.md")):
        rel = md.relative_to(root)
        if _skip(rel, cfg):
            continue
        r = rel.as_posix()
        g.add_node(r, "doc")
        dangling = []
        for ref in sorted(set(DOC_REF.findall(md.read_text(encoding="utf-8", errors="replace")))):
            if "/" not in ref or any(ig in ref for ig in cfg["dangling_ignore"]):
                continue
            if ref.startswith("/") or ".." in ref.split("/"):
                continue  # absolute or escaping references are never followed
            tgt = (root / ref.rstrip("/"))
            if tgt.exists():
                key = tgt.relative_to(root).as_posix()
                if key in g.nodes:
                    g.add_edge(r, key, "mentions")
            else:
                dangling.append(ref)
        g.nodes[r]["dangling"] = dangling
    wf = root / ".github" / "workflows"
    if cfg["check_workflows"] and wf.is_dir():
        for y in sorted(wf.glob("*.y*ml")):
            r = y.relative_to(root).as_posix()
            uses = re.findall(r"uses:\s*([^\s#]+)", y.read_text())
            g.add_node(r, "workflow", unpinned=sorted(u for u in uses if not re.search(r"@[0-9a-f]{40}$", u) and not u.startswith("./")))
    return g


def _imp(g: Graph, rel: str, name: str, tgt: str | None) -> None:
    if tgt:
        g.add_edge(rel, tgt, "imports")
        return
    top = name.split(".")[0]
    if not top:
        return
    kind = "stdlib" if top in STDLIB else "external"
    nid = f"{kind}:{top}"
    g.add_node(nid, kind)
    g.add_edge(rel, nid, "imports")
    # keep the dotted name too: forbidding `os.system` or `urllib.request` needs more than the top level
    if "." in name:
        did = f"{kind}:{name}"
        g.add_node(did, kind)
        g.add_edge(rel, did, "imports")
        g.add_edge(did, nid, "part_of")


def _dotted_name(n: ast.AST) -> str | None:
    parts = []
    while isinstance(n, ast.Attribute):
        parts.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        parts.append(n.id)
        return ".".join(reversed(parts))
    return None
