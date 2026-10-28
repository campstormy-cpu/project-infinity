"""Guard rules. Each rule reads the graph and returns Findings. A finding always carries evidence
(a graph path or a source location) so a human can check it; Thunder never reports a bare opinion."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from .graph import Graph

SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    rule: str
    severity: str
    node: str
    message: str
    evidence: list[str] = field(default_factory=list)

    def fingerprint(self) -> str:
        return hashlib.sha256(f"{self.rule}|{self.node}|{self.message}".encode()).hexdigest()[:16]

    def to_json(self) -> dict:
        return {"rule": self.rule, "severity": self.severity, "node": self.node, "message": self.message,
                "evidence": self.evidence, "fingerprint": self.fingerprint()}


def _under(node: str, paths: list[str]) -> bool:
    n = node.split("::")[0]
    return any(n == p.rstrip("/") or n.startswith(p.rstrip("/") + "/") for p in paths)


def _modules(g: Graph, paths: list[str]) -> list[str]:
    return sorted(n for n, d in g.nodes.items() if d["kind"] in ("module", "test") and _under(n, paths))


def r_forbidden_imports(g: Graph, cfg: dict, root: Path):
    """Trust boundary: critical code must not reach forbidden libraries, directly OR through its own imports."""
    for c in cfg["critical"]:
        mods = _modules(g, c["paths"])
        forbid = {f"stdlib:{x}" for x in c.get("forbid_imports", [])} | {f"external:{x}" for x in c.get("forbid_imports", [])}
        for m in mods:
            reach = g.reachable(m, kinds={"imports"})
            for bad in sorted(forbid & reach):
                p = g.path(m, bad, kinds={"imports"})
                direct = len(p) == 2
                yield Finding("trust-boundary", "high" if direct else "medium", m,
                              f"critical package '{c['name']}' {'imports' if direct else 'transitively reaches'} forbidden '{bad.split(':',1)[1]}'",
                              [" -> ".join(p)])


def r_layers(g: Graph, cfg: dict, root: Path):
    for layer in cfg["layers"]:
        for m in _modules(g, layer["from"]):
            reach = g.reachable(m, kinds={"imports"})
            for t in sorted(x for x in reach if _under(x, layer["must_not_reach"]) and g.nodes[x]["kind"] in ("module", "test")):
                yield Finding("layering", "high", m, f"layer '{layer['name']}' violated: reaches {t}", [" -> ".join(g.path(m, t, kinds={"imports"}))])


def r_cycles(g: Graph, cfg: dict, root: Path):
    sub = Graph()
    for n, d in g.nodes.items():
        if d["kind"] in ("module", "test"):
            sub.add_node(n, d["kind"])
    for s, t, k in g.edges:
        if k == "imports" and s in sub.nodes and t in sub.nodes:
            sub.add_edge(s, t, k)
    for comp in sub.cycles({"imports"}):
        yield Finding("import-cycle", "medium", comp[0], f"import cycle among {len(comp)} modules", comp)


def r_dangerous_calls(g: Graph, cfg: dict, root: Path):
    crit = [p for c in cfg["critical"] for p in c["paths"]]
    for n, d in sorted(g.nodes.items()):
        for line, call in d.get("danger", []):
            if f"{n}::{call}" in cfg["danger_allow"]:
                continue
            yield Finding("dangerous-call", "high" if _under(n, crit) else "medium", n, f"call to {call} at line {line}", [f"{n}:{line}"])


def r_untested_public(g: Graph, cfg: dict, root: Path):
    tests = [n for n, d in g.nodes.items() if d["kind"] == "test"]
    covered = g.reachable(tests, kinds={"calls", "calls_by_name", "runs", "imports"})
    for c in cfg["critical"]:
        if not c.get("require_tests", True):
            continue
        for n, d in sorted(g.nodes.items()):
            if d["kind"] in ("func", "class", "method") and d.get("public") and _under(n, c["paths"]) and n not in covered:
                yield Finding("untested-public", "medium", n, f"public {d['kind']} in '{c['name']}' is not reachable from any test (name-based static analysis; may miss dynamic use)")


def _parse_reqs(root: Path, cfg: dict):
    for f in cfg["requirements_files"]:
        p = root / f
        if p.exists():
            for i, line in enumerate(p.read_text().splitlines(), 1):
                line = line.split("#")[0].strip()
                if line and not line.startswith("-"):
                    yield f, i, line


def r_dependencies(g: Graph, cfg: dict, root: Path):
    declared = {}
    for f, i, line in _parse_reqs(root, cfg):
        m = re.match(r"([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|!=|<|>)?\s*(\S*)", line)
        name, op = m.group(1), m.group(2)
        declared[cfg["import_name_map"].get(name.lower(), name.lower().replace("-", "_"))] = f
        if op != "==":
            yield Finding("dependency-pin", "medium", f"{f}:{i}", f"'{line}' is not pinned with ==", [f"{f}:{i}"])
    ext = {n.split(":", 1)[1] for n, d in g.nodes.items() if d["kind"] == "external" and "." not in n}
    for e in sorted(ext):
        if e.lower() not in declared:
            users = sorted(g.inc(f"external:{e}", {"imports"}))
            yield Finding("undeclared-dependency", "medium", f"external:{e}", f"'{e}' is imported but not in any requirements file", users[:5])
    for name, f in sorted(declared.items()):
        if name not in {e.lower() for e in ext} and name not in {"pytest"}:
            yield Finding("unused-dependency", "low", f"{f}", f"'{name}' is declared but never imported (heuristic: dev tools and plugins can look unused)")


def r_dangling_docs(g: Graph, cfg: dict, root: Path):
    for n, d in sorted(g.nodes.items()):
        if d["kind"] == "doc" and d.get("dangling"):
            yield Finding("dangling-doc-reference", "low", n, f"documentation references {len(d['dangling'])} path(s) that do not exist", d["dangling"][:10])


def r_workflows(g: Graph, cfg: dict, root: Path):
    for n, d in sorted(g.nodes.items()):
        if d["kind"] == "workflow" and d.get("unpinned"):
            yield Finding("workflow-supply-chain", "low", n, "GitHub Actions not pinned to a commit SHA (a moved tag can change what runs in CI)", d["unpinned"])


SECRET_PATTERNS = [
    ("private-key-block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("generic-assignment", re.compile(r"""(?i)\b(?:api[_-]?key|secret|passwd|password|token)\b\s*[:=]\s*['"][A-Za-z0-9/+_\-]{20,}['"]""")),
]


def r_secrets(g: Graph, cfg: dict, root: Path):
    if not cfg["secret_scan"]:
        return
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix in {".pyc", ".png", ".jpg", ".zip", ".gz", ".bin", ".parquet"} or p.stat().st_size > 2_000_000:
            continue
        rel = p.relative_to(root)
        if any(part in cfg["exclude"] for part in rel.parts) or any(x in rel.as_posix() for x in cfg["secret_scan_exclude"]):
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for name, rx in SECRET_PATTERNS:
            for m in rx.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                yield Finding("secret", "critical", rel.as_posix(), f"possible secret ({name}) at line {line}", [f"{rel.as_posix()}:{line}"])


RULES = [r_forbidden_imports, r_layers, r_cycles, r_dangerous_calls, r_untested_public, r_dependencies,
         r_dangling_docs, r_workflows, r_secrets]


def run_all(g: Graph, cfg: dict, root: Path) -> list[Finding]:
    out: list[Finding] = []
    for rule in RULES:
        out.extend(rule(g, cfg, root))
    return sorted(out, key=lambda f: (-SEV[f.severity], f.rule, f.node, f.message))
