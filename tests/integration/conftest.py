import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture
def repo_copy(tmp_path):
    """A disposable copy of the repository (including .git, which gate checks need)."""
    dst = tmp_path / "repo"
    shutil.copytree(REPO, dst, ignore=shutil.ignore_patterns("scratch", "__pycache__", ".pytest_cache"),
                    symlinks=True)
    # data files are read-only in the original; make the copy writable so tests can tamper with it
    for p in dst.rglob("*"):
        if p.is_file() and ".git" not in p.parts:
            p.chmod(0o644)
    return dst


def run_gates(root: Path, *gates: str):
    """Run the COPY's gate runner against the copy. Always restricted with --only so a test never
    recurses into pytest. Returns {gate_id: (status, evidence)} and the full json."""
    import json
    import os
    env = {**os.environ, "INFINITY_ROOT": str(root)}
    args = [sys.executable, str(root / "infrastructure" / "run_gates.py")]
    if gates:
        args += ["--only", ",".join(gates)]
    r = subprocess.run(args, cwd=root, env=env, capture_output=True, text=True)
    gj = root / "state" / "gates.json"
    data = json.loads(gj.read_text()) if gj.exists() else None
    status = {g["id"]: (g["status"], g["evidence"]) for g in data["gates"]} if data else {}
    return status, data, r
