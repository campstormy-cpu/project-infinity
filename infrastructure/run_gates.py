"""Release gate runner (Directive 009).

    python3 infrastructure/run_gates.py [--only GATE_04,GATE_08]
    INFINITY_ROOT=/path/to/copy python3 infrastructure/run_gates.py   (used by tests)

Status values: PASS | FAIL | PARTIAL | PENDING | NOT_EVALUATED | APPROVAL_REQUIRED
Only PASS counts. A gate with no implemented check is NOT_EVALUATED, never PASS.

HONEST LIMITS (read before trusting a PASS):
  * This runner re-checks recorded evidence; it does not re-run experiments.
  * Audit verdicts and owner approval live in local JSON files. The audit verdict is bound to
    the SHA-256 of the audit document it cites, so editing the document invalidates the verdict,
    but anyone with write access to this repo can still forge both. Real enforcement needs CI on a
    remote with protected branches and signed approvals (not configured; see ENVIRONMENT_AUDIT.md).

Writes state/gates.json atomically; any stale copy is removed first, so a crash cannot leave an
old result in place.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parents[1]
ROOT = Path(os.environ.get("INFINITY_ROOT") or DEFAULT_ROOT).resolve()
sys.path.insert(0, str(ROOT / "packages" / "compression-core"))
STATE = ROOT / "state"


def sh(cmd):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)


def sha256_path(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def inside_root(rel: str):
    """Resolve a manifest path; return None unless it stays inside ROOT (no absolute, .., or symlink escape)."""
    if os.path.isabs(rel) or ".." in Path(rel).parts:
        return None
    p = ROOT / rel
    try:
        p.resolve(strict=False).relative_to(ROOT)
    except ValueError:
        return None
    return p


def py_files():
    skip = {".git", "__pycache__", ".pytest_cache", "scratch"}
    return [p for p in ROOT.rglob("*.py") if not (set(p.relative_to(ROOT).parts) & skip)]


# ---------------------------------------------------------------- gates
def gate_build():
    errs = []
    for p in py_files():
        try:
            compile(p.read_text(), str(p), "exec")  # syntax check, no bytecode written
        except SyntaxError as e:
            errs.append(f"{p.relative_to(ROOT)}: {e}")
    missing = []
    for mod in ("zstandard", "brotli", "lzma", "zlib", "bz2", "pyarrow", "pytest", "cryptography"):
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    ok = not errs and not missing and bool(py_files())
    return ("PASS" if ok else "FAIL",
            f"{len(py_files())} python files compiled; missing deps: {missing or 'none'}; errors: {errs or 'none'}")


def _pytest(path):
    r = sh([sys.executable, "-m", "pytest", "-q", path])
    tail = (r.stdout.strip().splitlines() or [""])[-1]
    passed = re.search(r"(\d+) passed", tail)
    ok = r.returncode == 0 and passed and int(passed.group(1)) > 0
    return ("PASS" if ok else "FAIL"), f"pytest exit {r.returncode}: {tail}"


def gate_unit():
    if not list((ROOT / "tests").rglob("test_*.py")):
        return ("NOT_EVALUATED", "no tests found")
    return _pytest("tests")


def gate_integration():
    t = ROOT / "tests" / "integration"
    if not list(t.glob("test_*.py")):
        return ("NOT_EVALUATED", "no integration tests exist")
    return _pytest("tests/integration")


def verify_manifest(manifest: Path, commit, required=()):
    """Return list of problems. Code (.py) lines are checked against the commit the experiment ran at;
    everything else against the working tree. Paths outside the repo are rejected."""
    problems = []
    lines = [l for l in manifest.read_text().splitlines() if l.strip()]
    if not lines:
        return ["manifest is empty"]
    seen = set()
    for line in lines:
        if "  " not in line:
            problems.append(f"malformed manifest line: {line[:60]!r}")
            continue
        h, rel = line.split("  ", 1)
        seen.add(rel)
        p = inside_root(rel)
        if p is None:
            problems.append(f"path outside repository: {rel}")
            continue
        if rel.endswith(".py"):
            if not commit:
                problems.append(f"no commit recorded to check {rel}")
                continue
            r = subprocess.run(["git", "show", f"{commit}:{rel}"], cwd=ROOT, capture_output=True)
            ok = r.returncode == 0 and hashlib.sha256(r.stdout).hexdigest() == h
        else:
            ok = p.is_file() and sha256_path(p) == h
        if not ok:
            problems.append(f"hash mismatch: {rel}")
    problems += [f"manifest does not cover {r}" for r in sorted(set(required) - seen)]
    return problems


_RECOMPUTED = {}


def recompute(dataset_dir: Path, name: str, codec: str):
    """Re-compress a dataset file with the CURRENT code. Returns (container_bytes, container_sha256)."""
    key = (name, codec)
    if key not in _RECOMPUTED:
        from infinity_core import compress_bytes
        blob = compress_bytes(codec, (dataset_dir / name).read_bytes())
        _RECOMPUTED[key] = (len(blob), hashlib.sha256(blob).hexdigest())
    return _RECOMPUTED[key]


def gate_integrity():
    results = sorted((ROOT / "benchmarks" / "results").glob("*/results.json"))
    if not results:
        return ("NOT_EVALUATED", "no benchmark results")
    problems, notes, n = [], [], 0
    dm_path = ROOT / "benchmarks" / "data" / "MANIFEST.json"
    if not dm_path.is_file():
        return ("FAIL", "dataset manifest missing")
    dm = json.loads(dm_path.read_text())
    for name, meta in dm["files"].items():
        f = ROOT / "benchmarks" / "data" / name
        if not f.is_file() or sha256_path(f) != meta["sha256"]:
            problems.append(f"dataset file changed or missing: {name}")
    for rj in results:
        exp = rj.parent.name
        data = json.loads(rj.read_text())
        recs, meta = data["records"], data["meta"]
        from infinity_core import CODECS
        registry = set(CODECS)
        codecs = meta.get("baselines_run", [])
        if not registry <= set(codecs):  # the experiment cannot choose a weaker codec set for itself
            problems.append(f"{exp}: baselines_run misses registered codecs {sorted(registry - set(codecs))}")
        expected = {(f, c) for f in dm["files"] for c in registry}
        got = [(r["file"], r["codec"]) for r in recs]
        if not codecs or set(got) != expected or len(got) != len(expected):
            problems.append(f"{exp}: records do not match dataset x baselines ({len(got)} vs {len(expected)})")
        if meta.get("dataset_id") != dm.get("dataset_id"):
            problems.append(f"{exp}: dataset id mismatch")
        for r in recs:
            n += 1
            m = dm["files"].get(r["file"])
            if not m or r["recovery"]["sha256_original"] != m["sha256"] or r["original_bytes"] != m["bytes"]:
                problems.append(f"{exp}:{r['file']}:{r['codec']}: original does not match dataset manifest")
            if not (r["reconstruction_success"] is True and r["original_unmodified"] is True
                    and r["recovery"]["hash_match"] is True and r["recovery"]["byte_identical"] is True
                    and r["recovery"]["sha256_reconstructed"] == r["recovery"]["sha256_original"]):
                problems.append(f"{exp}:{r['file']}:{r['codec']}: recovery not verified")
        mp = rj.parent / "MANIFEST.sha256"
        if not mp.is_file():
            problems.append(f"{exp}: MANIFEST.sha256 missing")
        else:
            req = [f"benchmarks/results/{exp}/results.json", f"benchmarks/results/{exp}/report.md"]
            problems += [f"{exp}: {x}" for x in verify_manifest(mp, meta.get("git", {}).get("commit"), req)]
        # Re-execution: recompute every stored size and container hash from the dataset.
        env = meta.get("environment", {})
        import brotli, zstandard
        same_libs = env.get("zstandard") == zstandard.__version__ and env.get("brotli") == brotli.__version__
        for r in recs:
            if r["file"] not in dm["files"] or r["codec"] not in registry:
                continue
            size, h = recompute(ROOT / "benchmarks" / "data", r["file"], r["codec"])
            if (size, h) != (r.get("complete_storage_bytes"), r.get("container_sha256")):
                (problems if same_libs else notes).append(
                    f"{exp}:{r['file']}:{r['codec']}: recomputed size/hash differ from recorded"
                    + ("" if same_libs else " (library versions differ, so not conclusive)"))
    status = "FAIL" if problems else ("PARTIAL" if notes else "PASS")
    return (status,
            f"{n} records in {len(results)} experiment(s) checked against the dataset manifest and the codec registry; "
            f"sizes and container hashes recomputed from the dataset with the current code; "
            f"problems: {problems or 'none'}; inconclusive: {notes or 'none'}")


SECRET_PATTERNS = [r"AKIA[0-9A-Z]{16}", r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", r"ghp_[A-Za-z0-9]{36}",
                   r"sk-[A-Za-z0-9]{20,}", r"(?i)(api[_-]?key|secret|password)\s*[=:]\s*['\"][^'\"]{8,}['\"]"]


def load_verdicts():
    p = STATE / "audit_verdict.json"
    return json.loads(p.read_text()) if p.exists() else {}


def check_verdict(key):
    """PASS only if the verdict is PASS AND cites an existing document under audits/ whose SHA-256
    matches the one recorded."""
    v = load_verdicts().get(key)
    if v is None:
        return ("PENDING", f"{key}: no verdict recorded")
    if not isinstance(v, dict):
        return ("FAIL", f"{key}: verdict must be an object with audit_file and audit_sha256")
    verdict, rel, want = v.get("verdict"), v.get("audit_file"), v.get("audit_sha256")
    p = inside_root(rel) if isinstance(rel, str) else None
    if p is None or not rel.startswith("audits/") or not p.is_file():
        return ("FAIL", f"{key}: cited audit document missing or outside audits/: {rel}")
    if sha256_path(p) != want:
        return ("FAIL", f"{key}: audit document changed since the verdict was recorded ({rel})")
    if verdict != "PASS":
        return (verdict if verdict in ("PENDING", "FAIL") else "FAIL",
                f"{key}: recorded verdict {verdict} in {rel}")
    return ("PASS", f"{key}: PASS recorded against {rel} (sha256 {want[:12]}...); verdict file is local and unauthenticated")


def gate_security():
    hits = []
    for p in ROOT.rglob("*"):
        if not p.is_file() or {".git", "data", "__pycache__", ".pytest_cache"} & set(p.parts) \
                or p.suffix in {".parquet", ".inf", ".xz", ".pyc"}:
            continue
        if p.name == "run_gates.py":
            continue
        try:
            text = p.read_text(errors="ignore")
        except OSError:
            continue
        hits += [f"{p.relative_to(ROOT)}: {pat}" for pat in SECRET_PATTERNS if re.search(pat, text)]
    if hits:
        return ("FAIL", f"secret scan hits: {hits}")
    st, txt = check_verdict("security_review")
    if st == "PASS":
        return ("PASS", f"secret scan clean (regex-based); {txt}")
    return ("PARTIAL", f"secret scan clean (regex-based, limited); {txt}")


def gate_scientific():
    return check_verdict("scientific_validity")


def gate_audit():
    return check_verdict("independent_audit")


def gate_owner():
    a = STATE / "owner_approval.json"
    if not a.exists():
        return ("APPROVAL_REQUIRED", "no owner approval recorded")
    d = json.loads(a.read_text())
    if d.get("approved") is True and isinstance(d.get("approved_by"), str) and d["approved_by"].strip() \
            and isinstance(d.get("scope"), str) and d["scope"].strip():
        return ("PASS", f"owner approval file names {d['approved_by']!r} for scope {d['scope']!r}; "
                        "file is local and unauthenticated")
    return ("APPROVAL_REQUIRED", "approval file present but incomplete (needs approved=true, approved_by, scope)")


GATES = [("GATE_01", "BUILD", gate_build), ("GATE_02", "UNIT_TESTS", gate_unit),
         ("GATE_03", "INTEGRATION_TESTS", gate_integration), ("GATE_04", "DATA_INTEGRITY", gate_integrity),
         ("GATE_05", "SECURITY", gate_security), ("GATE_06", "SCIENTIFIC_VALIDITY", gate_scientific),
         ("GATE_07", "INDEPENDENT_AUDIT", gate_audit), ("GATE_08", "STRATEGIC_APPROVAL", gate_owner)]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="comma-separated gate ids; release_ready is then always False")
    args = ap.parse_args(argv)
    only = set(args.only.split(",")) if args.only else None

    STATE.mkdir(exist_ok=True)
    out_path = STATE / "gates.json"
    if out_path.exists():
        out_path.unlink()  # a crash must never leave an old result behind

    out = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "partial_run": bool(only), "gates": []}
    for gid, name, fn in GATES:
        if only and gid not in only:
            continue
        try:
            status, evidence = fn()
        except Exception:  # a crashing check is a FAIL, never a silent skip
            status, evidence = "FAIL", "gate crashed: " + traceback.format_exc().strip().splitlines()[-1]
        out["gates"].append({"id": gid, "name": name, "status": status, "evidence": evidence})
        print(f"{gid} {name:20s} {status:18s} {evidence}")
    out["caveat"] = ("Gates 05-08 depend on local, unauthenticated files (state/audit_verdict.json, state/owner_approval.json). "
                     "A verdict is bound to the hash of the audit document it cites, not to that document's conclusion.")
    out["release_ready"] = (not only) and len(out["gates"]) == len(GATES) and all(g["status"] == "PASS" for g in out["gates"])
    tmp = out_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(out, indent=2) + "\n")
    os.replace(tmp, out_path)
    print("release_ready:", out["release_ready"])
    return 0 if out["release_ready"] else 1


if __name__ == "__main__":
    sys.exit(main())
