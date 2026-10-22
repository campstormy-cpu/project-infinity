"""Release gate runner (Directive 009).

Every gate gets a status computed from real checks:
  PASS | FAIL | PARTIAL | PENDING | NOT_EVALUATED | APPROVAL_REQUIRED
Only PASS counts. A gate with no check implemented is NOT_EVALUATED, never PASS.
Writes state/gates.json. Exit code 0 only if every gate is PASS.
"""
import json
import py_compile
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "compression-core"))
STATE = ROOT / "state"
STATE.mkdir(exist_ok=True)


def sh(cmd, **kw):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, **kw)


def py_files():
    skip = {".git", "__pycache__", ".pytest_cache", "scratch"}
    return [p for p in ROOT.rglob("*.py") if not (set(p.relative_to(ROOT).parts) & skip)]


def gate_build():
    errs = []
    for p in py_files():
        try:
            py_compile.compile(str(p), doraise=True, cfile="/dev/null")
        except py_compile.PyCompileError as e:
            errs.append(str(e))
    deps = []
    for mod in ("zstandard", "brotli", "lzma", "zlib", "bz2", "pyarrow", "pytest"):
        try:
            __import__(mod)
        except ImportError:
            deps.append(mod)
    ok = not errs and not deps
    return ("PASS" if ok else "FAIL", f"{len(py_files())} python files compiled; missing deps: {deps or 'none'}; errors: {errs or 'none'}")


def gate_unit():
    r = sh([sys.executable, "-m", "pytest", "-q", "tests"])
    tail = (r.stdout.strip().splitlines() or [""])[-1]
    return ("PASS" if r.returncode == 0 else "FAIL", f"pytest exit {r.returncode}: {tail}")


def gate_integration():
    t = ROOT / "tests" / "integration"
    if not t.exists() or not list(t.glob("test_*.py")):
        return ("NOT_EVALUATED", "no integration tests exist yet")
    r = sh([sys.executable, "-m", "pytest", "-q", "tests/integration"])
    tail = (r.stdout.strip().splitlines() or [""])[-1]
    return ("PASS" if r.returncode == 0 else "FAIL", f"pytest exit {r.returncode}: {tail}")


def sha256sum_ok(manifest: Path, commit=None):
    """Evidence files are checked as they are now. Code files are checked against the
    commit the experiment ran at, so later (audited) code changes do not invalidate old evidence."""
    import hashlib
    from infinity_core import sha256_file
    bad = []
    for line in manifest.read_text().splitlines():
        h, rel = line.split("  ", 1)
        is_code = rel.endswith(".py")
        if is_code and commit:
            r = subprocess.run(["git", "show", f"{commit}:{rel}"], cwd=ROOT, capture_output=True)
            ok = r.returncode == 0 and hashlib.sha256(r.stdout).hexdigest() == h
        else:
            p = ROOT / rel
            ok = p.exists() and sha256_file(p) == h
        if not ok:
            bad.append(rel)
    return bad


def gate_integrity():
    results = sorted((ROOT / "benchmarks" / "results").glob("*/results.json"))
    if not results:
        return ("NOT_EVALUATED", "no benchmark results")
    problems, n = [], 0
    for rj in results:
        data = json.loads(rj.read_text())
        for r in data["records"]:
            n += 1
            if not (r["reconstruction_success"] and r["original_unmodified"]
                    and r["recovery"]["hash_match"] and r["recovery"]["byte_identical"]):
                problems.append(f"{rj.parent.name}:{r['file']}:{r['codec']}")
        bad = sha256sum_ok(rj.parent / "MANIFEST.sha256", data["meta"]["git"].get("commit"))
        problems += [f"{rj.parent.name}:manifest mismatch {b}" for b in bad]
    return ("PASS" if not problems else "FAIL", f"{n} records in {len(results)} experiment(s) re-checked; problems: {problems or 'none'}")


SECRET_PATTERNS = [r"AKIA[0-9A-Z]{16}", r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", r"ghp_[A-Za-z0-9]{36}",
                   r"sk-[A-Za-z0-9]{20,}", r"(?i)(api[_-]?key|secret|password)\s*[=:]\s*['\"][^'\"]{8,}['\"]"]


def gate_security():
    hits = []
    for p in ROOT.rglob("*"):
        if not p.is_file() or ".git" in p.parts or "data" in p.parts or p.suffix in {".parquet", ".inf", ".xz"}:
            continue
        if p.name == "run_gates.py":
            continue
        try:
            text = p.read_text(errors="ignore")
        except OSError:
            continue
        for pat in SECRET_PATTERNS:
            if re.search(pat, text):
                hits.append(f"{p.relative_to(ROOT)}: {pat}")
    verdict = load_verdict()
    review = verdict.get("security_review")
    if hits:
        return ("FAIL", f"secret scan hits: {hits}")
    if review == "PASS":
        return ("PASS", "secret scan clean; independent security review recorded as PASS")
    return ("PARTIAL", f"secret scan clean (regex-based, limited); independent security review: {review or 'not recorded'}")


def load_verdict():
    p = STATE / "audit_verdict.json"
    return json.loads(p.read_text()) if p.exists() else {}


def gate_scientific():
    v = load_verdict().get("scientific_validity")
    if v == "PASS":
        return ("PASS", "scientific audit verdict recorded as PASS (see AUDIT_REPORT.md)")
    return ("PENDING" if v is None else "FAIL", f"scientific audit verdict: {v or 'not recorded'}")


def gate_audit():
    v = load_verdict().get("independent_audit")
    if v == "PASS":
        return ("PASS", "independent audit verdict recorded as PASS with evidence in AUDIT_REPORT.md")
    return ("PENDING" if v is None else "FAIL", f"independent audit verdict: {v or 'not recorded'}")


def gate_owner():
    a = STATE / "owner_approval.json"
    if a.exists() and json.loads(a.read_text()).get("approved") is True:
        return ("PASS", "owner approval file present")
    return ("APPROVAL_REQUIRED", "no owner approval recorded")


GATES = [("GATE_01", "BUILD", gate_build), ("GATE_02", "UNIT_TESTS", gate_unit),
         ("GATE_03", "INTEGRATION_TESTS", gate_integration), ("GATE_04", "DATA_INTEGRITY", gate_integrity),
         ("GATE_05", "SECURITY", gate_security), ("GATE_06", "SCIENTIFIC_VALIDITY", gate_scientific),
         ("GATE_07", "INDEPENDENT_AUDIT", gate_audit), ("GATE_08", "STRATEGIC_APPROVAL", gate_owner)]


def main() -> int:
    out = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "gates": []}
    for gid, name, fn in GATES:
        status, evidence = fn()
        out["gates"].append({"id": gid, "name": name, "status": status, "evidence": evidence})
        print(f"{gid} {name:20s} {status:18s} {evidence}")
    out["release_ready"] = all(g["status"] == "PASS" for g in out["gates"])
    (STATE / "gates.json").write_text(json.dumps(out, indent=2) + "\n")
    print("release_ready:", out["release_ready"])
    return 0 if out["release_ready"] else 1


if __name__ == "__main__":
    sys.exit(main())
