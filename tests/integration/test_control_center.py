"""Control center: escaping, honesty about missing data, Brotli caveat (AUDIT_002 N-06, N-08..N-10, N42)."""
import json
import os
import subprocess
import sys

from conftest import REPO  # noqa: F401

HOSTILE = "<script>alert(1)</script>"
IMG = "<img src=x onerror=alert(2)>"


def build(root):
    env = {**os.environ, "INFINITY_ROOT": str(root)}
    r = subprocess.run([sys.executable, str(root / "apps" / "control-center" / "build.py")],
                       cwd=root, env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return (root / "apps" / "control-center" / "index.html").read_text()


def test_hostile_values_are_escaped_everywhere(repo_copy):
    st = repo_copy / "state"
    tasks = json.loads((st / "tasks.json").read_text())
    tasks["tasks"][0].update(title=HOSTILE, note=IMG, id=IMG, state=HOSTILE)
    (st / "tasks.json").write_text(json.dumps(tasks))
    gates = {"timestamp_utc": HOSTILE, "release_ready": IMG,
             "gates": [{"id": IMG, "name": HOSTILE, "status": HOSTILE, "evidence": IMG}]}
    (st / "gates.json").write_text(json.dumps(gates))
    (st / "audit_verdict.json").write_text(json.dumps({HOSTILE: {"verdict": IMG, "audit_file": HOSTILE}}))
    (repo_copy / "THEORY" / "active_hypotheses.md").write_text(
        f"# x\n\n| ID | H | S | P |\n|---|---|---|---|\n| {HOSTILE} | {IMG} | {HOSTILE} | {IMG} |\n")
    (repo_copy / "THEORY" / "unresolved_questions.md").write_text(f"1. {HOSTILE}\n")
    html = build(repo_copy)
    assert "<script>alert" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_missing_state_is_stated_not_invented(repo_copy):
    for f in ("gates.json", "audit_verdict.json", "tasks.json"):
        p = repo_copy / "state" / f
        if p.exists():
            p.unlink()
    import shutil
    shutil.rmtree(repo_copy / "benchmarks" / "results")
    html = build(repo_copy)
    assert "Gates have not been run" in html
    assert "No experiments have been run" in html
    assert "No tasks recorded" in html
    assert "No verdict recorded" in html


def test_gate_status_shown_when_present(repo_copy):
    (repo_copy / "state" / "gates.json").write_text(json.dumps(
        {"timestamp_utc": "T", "release_ready": False,
         "gates": [{"id": "GATE_01", "name": "BUILD", "status": "PASS", "evidence": "e"}]}))
    html = build(repo_copy)
    assert "Gates have not been run" not in html and "GATE_01" in html


def test_brotli_dependency_caveat_is_visible(repo_copy):
    html = build(repo_copy)
    assert "embedded data, 122784 B, not counted" in html or "embedded data" in html
    assert "not directly comparable" in html


def test_experiment_numbers_come_from_results_json(repo_copy):
    p = repo_copy / "benchmarks" / "results" / "EXP-0002" / "results.json"
    d = json.loads(p.read_text())
    d["records"][0]["complete_storage_bytes"] = 987654321
    p.write_text(json.dumps(d))
    assert "987654321" in build(repo_copy)


def test_infrastructure_text_is_labelled_static(repo_copy):
    html = build(repo_copy)
    assert "not live telemetry" in html


def test_audit_documents_are_listed_from_disk(repo_copy):
    (repo_copy / "audits" / "AUDIT_999_TEST.md").write_text("x")
    assert "AUDIT_999_TEST.md" in build(repo_copy)
