"""The release-gate runner must be hard to fool (AUDIT_002 N-01..N-04, mutants N36-N41)."""
import hashlib
import json
import shutil
from pathlib import Path

import pytest

from conftest import run_gates

pytestmark = pytest.mark.filterwarnings("ignore")


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def exp_dir(root: Path) -> Path:
    return root / "benchmarks" / "results" / "EXP-0002"


def write_manifest_for(d: Path, root: Path):
    """Rewrite MANIFEST.sha256 so that it is self-consistent with a tampered results.json (forger's move)."""
    lines = []
    for line in (d / "MANIFEST.sha256").read_text().splitlines():
        h, rel = line.split("  ", 1)
        p = root / rel
        if p.is_file() and not rel.endswith(".py"):
            h = sha(p)
        lines.append(f"{h}  {rel}")
    (d / "MANIFEST.sha256").write_text("\n".join(lines) + "\n")


def test_integrity_gate_passes_on_untouched_copy(repo_copy):
    st, _, _ = run_gates(repo_copy, "GATE_04")
    assert st["GATE_04"][0] == "PASS", st["GATE_04"]


def test_no_results_is_not_a_pass(repo_copy):
    shutil.rmtree(repo_copy / "benchmarks" / "results")
    st, _, _ = run_gates(repo_copy, "GATE_04")
    assert st["GATE_04"][0] == "NOT_EVALUATED"


def test_dataset_file_change_fails(repo_copy):
    with open(repo_copy / "benchmarks" / "data" / "empty.bin", "ab") as fh:
        fh.write(b"x")
    assert run_gates(repo_copy, "GATE_04")[0]["GATE_04"][0] == "FAIL"


def test_flipped_recovery_flag_fails(repo_copy):
    p = exp_dir(repo_copy) / "results.json"
    d = json.loads(p.read_text())
    d["records"][3]["reconstruction_success"] = False
    p.write_text(json.dumps(d))
    write_manifest_for(exp_dir(repo_copy), repo_copy)  # forger also fixes the manifest
    assert run_gates(repo_copy, "GATE_04")[0]["GATE_04"][0] == "FAIL"


def test_forged_self_consistent_one_record_experiment_fails(repo_copy):
    shutil.rmtree(repo_copy / "benchmarks" / "results")
    d = repo_copy / "benchmarks" / "results" / "EXP-FAKE"
    d.mkdir(parents=True)
    rec = {"file": "empty.bin", "codec": "zlib-9", "original_bytes": 0, "reconstruction_success": True,
           "original_unmodified": True,
           "recovery": {"sha256_original": hashlib.sha256(b"").hexdigest(),
                        "sha256_reconstructed": hashlib.sha256(b"").hexdigest(),
                        "hash_match": True, "byte_identical": True}}
    (d / "results.json").write_text(json.dumps({"meta": {"dataset_id": "DS-0001", "baselines_run": ["zlib-9"],
                                                           "git": {"commit": None}}, "records": [rec]}))
    (d / "report.md").write_text("fake")
    (d / "MANIFEST.sha256").write_text(f"{sha(d / 'results.json')}  benchmarks/results/EXP-FAKE/results.json\n"
                                       f"{sha(d / 'report.md')}  benchmarks/results/EXP-FAKE/report.md\n")
    st = run_gates(repo_copy, "GATE_04")[0]["GATE_04"]
    assert st[0] == "FAIL" and "do not match dataset" in st[1]


@pytest.mark.parametrize("bad_path", ["../../etc/passwd", "/etc/passwd"])
def test_manifest_path_outside_repo_fails(repo_copy, bad_path):
    m = exp_dir(repo_copy) / "MANIFEST.sha256"
    m.write_text(m.read_text() + f"{hashlib.sha256(Path('/etc/passwd').read_bytes()).hexdigest()}  {bad_path}\n")
    st = run_gates(repo_copy, "GATE_04")[0]["GATE_04"]
    assert st[0] == "FAIL" and "outside repository" in st[1]


def test_symlink_escape_in_manifest_fails(repo_copy, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    link = repo_copy / "benchmarks" / "results" / "EXP-0002" / "link.txt"
    link.symlink_to(outside)
    m = exp_dir(repo_copy) / "MANIFEST.sha256"
    m.write_text(m.read_text() + f"{sha(outside)}  benchmarks/results/EXP-0002/link.txt\n")
    st = run_gates(repo_copy, "GATE_04")[0]["GATE_04"]
    assert st[0] == "FAIL" and "outside repository" in st[1]


def test_empty_or_truncated_manifest_fails(repo_copy):
    (exp_dir(repo_copy) / "MANIFEST.sha256").write_text("")
    assert run_gates(repo_copy, "GATE_04")[0]["GATE_04"][0] == "FAIL"


def test_manifest_must_cover_results_and_report(repo_copy):
    m = exp_dir(repo_copy) / "MANIFEST.sha256"
    m.write_text("".join(l + "\n" for l in m.read_text().splitlines() if "results.json" not in l))
    st = run_gates(repo_copy, "GATE_04")[0]["GATE_04"]
    assert st[0] == "FAIL" and "does not cover" in st[1]


def test_crash_never_leaves_a_stale_result(repo_copy):
    gj = repo_copy / "state" / "gates.json"
    gj.write_text(json.dumps({"release_ready": True, "gates": []}))
    (exp_dir(repo_copy) / "results.json").write_text("{ not json")
    st, data, r = run_gates(repo_copy, "GATE_04")
    assert data is not None and data["release_ready"] is False
    assert st["GATE_04"][0] == "FAIL" and "crashed" in st["GATE_04"][1]


def test_only_flag_can_never_report_release_ready(repo_copy):
    _, data, r = run_gates(repo_copy, "GATE_01")
    assert data["partial_run"] is True and data["release_ready"] is False and r.returncode == 1


# ---------------------------------------------------------------- audit verdicts / owner approval
def set_verdict(root: Path, key: str, **entry):
    p = root / "state" / "audit_verdict.json"
    d = json.loads(p.read_text()) if p.exists() else {}
    d[key] = entry
    p.parent.mkdir(exist_ok=True)
    p.write_text(json.dumps(d))


def test_verdict_without_document_fails(repo_copy):
    set_verdict(repo_copy, "independent_audit", verdict="PASS", audit_file="audits/DOES_NOT_EXIST.md", audit_sha256="0" * 64)
    assert run_gates(repo_copy, "GATE_07")[0]["GATE_07"][0] == "FAIL"


def test_verdict_with_wrong_hash_fails(repo_copy):
    set_verdict(repo_copy, "independent_audit", verdict="PASS", audit_file="audits/AUDIT_002_FIXES.md", audit_sha256="0" * 64)
    st = run_gates(repo_copy, "GATE_07")[0]["GATE_07"]
    assert st[0] == "FAIL" and "changed since" in st[1]


def test_verdict_pass_with_matching_hash_passes_and_edit_invalidates(repo_copy):
    doc = repo_copy / "audits" / "AUDIT_002_FIXES.md"
    set_verdict(repo_copy, "independent_audit", verdict="PASS", audit_file="audits/AUDIT_002_FIXES.md", audit_sha256=sha(doc))
    assert run_gates(repo_copy, "GATE_07")[0]["GATE_07"][0] == "PASS"
    doc.write_text(doc.read_text() + "\nedited after the verdict\n")
    assert run_gates(repo_copy, "GATE_07")[0]["GATE_07"][0] == "FAIL"


def test_verdict_outside_audits_dir_fails(repo_copy):
    doc = repo_copy / "README_FAKE.md"
    doc.write_text("I approve")
    set_verdict(repo_copy, "independent_audit", verdict="PASS", audit_file="README_FAKE.md", audit_sha256=sha(doc))
    assert run_gates(repo_copy, "GATE_07")[0]["GATE_07"][0] == "FAIL"


def test_non_pass_verdict_never_passes(repo_copy):
    doc = repo_copy / "audits" / "AUDIT_002_FIXES.md"
    set_verdict(repo_copy, "scientific_validity", verdict="REVISE", audit_file="audits/AUDIT_002_FIXES.md", audit_sha256=sha(doc))
    assert run_gates(repo_copy, "GATE_06")[0]["GATE_06"][0] != "PASS"


def test_missing_verdict_is_pending(repo_copy):
    p = repo_copy / "state" / "audit_verdict.json"
    if p.exists():
        p.unlink()
    st = run_gates(repo_copy, "GATE_06", "GATE_07")[0]
    assert st["GATE_06"][0] == "PENDING" and st["GATE_07"][0] == "PENDING"


def test_security_gate_is_partial_without_review_and_fails_on_secret(repo_copy):
    p = repo_copy / "state" / "audit_verdict.json"
    if p.exists():
        p.unlink()
    assert run_gates(repo_copy, "GATE_05")[0]["GATE_05"][0] == "PARTIAL"
    (repo_copy / "oops.py").write_text("pass" + "word = " + '"' + "hunter2" * 2 + '"\n')  # built at runtime so this file itself is clean
    assert run_gates(repo_copy, "GATE_05")[0]["GATE_05"][0] == "FAIL"


@pytest.mark.parametrize("content,expected", [
    ({"approved": True}, "APPROVAL_REQUIRED"),
    ({"approved": True, "approved_by": "", "scope": "x"}, "APPROVAL_REQUIRED"),
    ({"approved": "yes", "approved_by": "Esteban", "scope": "x"}, "APPROVAL_REQUIRED"),
    ({"approved": True, "approved_by": "Esteban", "scope": "release 0.1"}, "PASS"),
])
def test_owner_approval_requires_complete_record(repo_copy, content, expected):
    (repo_copy / "state").mkdir(exist_ok=True)
    (repo_copy / "state" / "owner_approval.json").write_text(json.dumps(content))
    assert run_gates(repo_copy, "GATE_08")[0]["GATE_08"][0] == expected


def test_no_owner_approval_file_means_approval_required(repo_copy):
    p = repo_copy / "state" / "owner_approval.json"
    if p.exists():
        p.unlink()
    assert run_gates(repo_copy, "GATE_08")[0]["GATE_08"][0] == "APPROVAL_REQUIRED"


def test_build_gate_fails_on_syntax_error(repo_copy):
    (repo_copy / "broken.py").write_text("def x(:\n")
    assert run_gates(repo_copy, "GATE_01")[0]["GATE_01"][0] == "FAIL"


def test_hard_abort_mid_run_leaves_no_stale_result(repo_copy):
    """A gate that raises BaseException (as a killed or interrupted run would) must not leave the old file."""
    import os
    import subprocess
    import sys
    gj = repo_copy / "state" / "gates.json"
    gj.write_text(json.dumps({"release_ready": True, "gates": []}))
    code = (
        "import sys; sys.path.insert(0, 'infrastructure'); import run_gates as g\n"
        "def boom(): raise KeyboardInterrupt\n"
        "g.GATES = [('GATE_X', 'X', boom)]\n"
        "try:\n    g.main([])\nexcept KeyboardInterrupt:\n    pass\n"
    )
    subprocess.run([sys.executable, "-c", code], cwd=repo_copy, env={**os.environ, "INFINITY_ROOT": str(repo_copy)})
    assert not gj.exists(), "stale gates.json survived an aborted run"


def test_symlink_check_is_what_blocks_escapes_not_just_dotdot(repo_copy, tmp_path):
    """Guards the resolve() leg of inside_root independently of the '..' / absolute-path leg."""
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    (repo_copy / "benchmarks" / "results" / "EXP-0002" / "l2.txt").symlink_to(outside)
    m = exp_dir(repo_copy) / "MANIFEST.sha256"
    m.write_text(m.read_text() + f"{sha(outside)}  benchmarks/results/EXP-0002/l2.txt\n")
    st = run_gates(repo_copy, "GATE_04")[0]["GATE_04"]
    assert st[0] == "FAIL" and "outside repository" in st[1]
