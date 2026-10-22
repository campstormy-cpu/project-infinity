"""Unit/integration tests for run_benchmark.git_state, report generation and worker failure paths
(AUDIT_002 N25-N35)."""
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "benchmarks" / "run_benchmark.py"
WORKER = ROOT / "benchmarks" / "worker.py"
PKG = ROOT / "packages" / "compression-core"


def load_runner():
    spec = importlib.util.spec_from_file_location("run_benchmark_under_test", RUNNER)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def git(cwd, *a):
    subprocess.run(["git", *a], cwd=cwd, check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                        "GIT_COMMITTER_EMAIL": "t@t", "PATH": "/usr/bin:/bin"})


@pytest.fixture
def tmp_git(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "a.txt").write_text("a")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "x")
    return tmp_path


def state_in(monkeypatch, path):
    rb = load_runner()
    monkeypatch.setattr(rb, "ROOT", path)
    return rb.git_state()


def test_git_state_clean(monkeypatch, tmp_git):
    s = state_in(monkeypatch, tmp_git)
    assert s["dirty"] is False and s["dirty_files"] == [] and len(s["commit"]) == 40


def test_git_state_modified_tracked_file_is_dirty(monkeypatch, tmp_git):
    (tmp_git / "a.txt").write_text("changed")
    s = state_in(monkeypatch, tmp_git)
    assert s["dirty"] is True and s["dirty_files"] == ["a.txt"]


def test_git_state_untracked_file_is_dirty(monkeypatch, tmp_git):
    (tmp_git / "new.py").write_text("x")
    s = state_in(monkeypatch, tmp_git)
    assert s["dirty"] is True and "new.py" in s["dirty_files"]


def test_git_state_ignores_only_benchmark_outputs(monkeypatch, tmp_git):
    (tmp_git / "benchmarks" / "results" / "E").mkdir(parents=True)
    (tmp_git / "benchmarks" / "results" / "E" / "r.json").write_text("{}")
    (tmp_git / "benchmarks" / "scratch").mkdir()
    (tmp_git / "benchmarks" / "scratch" / "s").write_text("x")
    assert state_in(monkeypatch, tmp_git)["dirty"] is False
    (tmp_git / "benchmarks" / "other.py").write_text("x")
    assert state_in(monkeypatch, tmp_git)["dirty"] is True


def test_git_state_fails_closed_without_git(monkeypatch, tmp_path):
    s = state_in(monkeypatch, tmp_path)  # a directory that is not a git repository
    assert s["dirty"] is True and s["commit"] is None and s["dirty_files"] == ["<git unavailable>"]


def make_dataset(d: Path):
    d.mkdir()
    files = {"a.txt": b"report test data " * 500, "r.bin": __import__("random").Random(1).randbytes(3000), "e.bin": b""}
    man = {"dataset_id": "DS-T", "files": {}}
    for n, b in files.items():
        (d / n).write_bytes(b)
        man["files"][n] = {"bytes": len(b), "sha256": hashlib.sha256(b).hexdigest()}
    (d / "MANIFEST.json").write_text(json.dumps(man))


def run_runner(tmp, data):
    r = subprocess.run([sys.executable, str(RUNNER), "--experiment-id", "EXP-T", "--data", str(data), "--repeats", "1",
                        "--results-root", str(tmp / "res"), "--scratch-root", str(tmp / "scr")], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    out = tmp / "res" / "EXP-T"
    return json.loads((out / "results.json").read_text()), (out / "report.md").read_text()


def test_report_is_generated_from_data_and_flags_brotli(tmp_path):
    make_dataset(tmp_path / "d")
    res, report = run_runner(tmp_path, tmp_path / "d")
    recs = res["records"]
    rows = [l for l in report.splitlines() if l.startswith("| ") and not l.startswith("| file") and "---" not in l]
    assert len(rows) == 3
    for row in rows:
        cells = [c.strip() for c in row.strip("|").split("|")]
        name, headline_codec, headline_bytes = cells[0], cells[2], int(cells[3])
        assert headline_codec != "brotli-11", "headline column must exclude the codec with an external dictionary"
        clean = min(r["complete_storage_bytes"] for r in recs if r["file"] == name and not r["external_dependency"])
        assert headline_bytes == clean
        allmin = min(r["complete_storage_bytes"] for r in recs if r["file"] == name)
        assert int(cells[7]) == allmin
        sav = cells[5]
        if cells[4] != "n/a":
            assert sav[0] in "+-" and sav.endswith("%")  # signed, never a bare unsigned or rounded-away value
            o = next(r["original_bytes"] for r in recs if r["file"] == name)
            assert float(sav[:-1]) == pytest.approx((1 - clean / o) * 100, abs=0.0006)
    wins = sum(1 for n in {r["file"] for r in recs}
               if min(r["complete_storage_bytes"] for r in recs if r["file"] == n)
               < min(r["complete_storage_bytes"] for r in recs if r["file"] == n and not r["external_dependency"]))
    m = re.search(r"smaller than every dictionary-free codec on (\d+) of 3 files", report)
    assert m and int(m.group(1)) == wins
    assert "Limitations" in report and "no** claim of a new compression method" in report
    assert "122784" in report  # dependency size disclosed


def test_dirty_flag_in_runner_output_matches_git(tmp_path):
    make_dataset(tmp_path / "d")
    res, _ = run_runner(tmp_path, tmp_path / "d")
    out = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT, capture_output=True, text=True).stdout
    expected = [l[3:] for l in out.splitlines() if not l[3:].startswith(("benchmarks/results/", "benchmarks/scratch/"))]
    assert res["meta"]["git"]["dirty"] is bool(expected)
    assert sorted(res["meta"]["git"]["dirty_files"]) == sorted(expected)


# ---------------------------------------------------------------- worker failure paths
def run_worker_patched(tmp_path, patch_code: str):
    """Run worker.py in a subprocess after applying a deliberate bug, return its JSON."""
    f = tmp_path / "orig.bin"
    f.write_bytes(b"worker failure path test " * 200)
    code = f"""
import sys, runpy
sys.path.insert(0, {str(PKG)!r})
import infinity_core
{patch_code}
sys.argv = ['worker.py', 'zlib-9', {str(f)!r}, {str(tmp_path / 'scr')!r}, '2']
runpy.run_path({str(WORKER)!r}, run_name='__main__')
"""
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_worker_good_path(tmp_path):
    r = run_worker_patched(tmp_path, "")
    assert r["reconstruction_success"] and r["original_unmodified"] and r["deterministic_across_repeats"]


def test_worker_detects_wrong_reconstruction(tmp_path):
    r = run_worker_patched(tmp_path, """
real = infinity_core.decompress_bytes
infinity_core.decompress_bytes = lambda b, *a, **k: real(b, *a, **k)[:-1] + b'X'
""")
    assert r["reconstruction_success"] is False
    assert r["recovery"]["byte_identical"] is False and r["recovery"]["hash_match"] is False


def test_worker_detects_modified_original(tmp_path):
    r = run_worker_patched(tmp_path, f"""
real = infinity_core.compress_bytes
def evil(codec, data):
    open({str(tmp_path / 'orig.bin')!r}, 'ab').write(b'!')
    return real(codec, data)
infinity_core.compress_bytes = evil
""")
    assert r["original_unmodified"] is False


def test_worker_detects_nondeterminism(tmp_path):
    r = run_worker_patched(tmp_path, """
import itertools
c = itertools.count()
infinity_core.sha256_bytes = lambda b: str(next(c))
""")
    assert r["deterministic_across_repeats"] is False
