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


# ---------------------------------------------------------------- AUDIT_003 A3-02 and test gaps
def tamper_results(root: Path, fn):
    p = exp_dir(root) / "results.json"
    d = json.loads(p.read_text())
    fn(d)
    p.write_text(json.dumps(d))
    write_manifest_for(exp_dir(root), root)  # a forger re-hashes the manifest so the files agree


def gate4(root):
    return run_gates(root, "GATE_04")[0]["GATE_04"]


def test_manifest_listing_another_experiments_results_does_not_count(repo_copy):
    """Coverage is by full relative path, not basename (A3-02)."""
    m = exp_dir(repo_copy) / "MANIFEST.sha256"
    other = repo_copy / "benchmarks" / "results" / "EXP-0001" / "results.json"
    keep = [l for l in m.read_text().splitlines() if not l.endswith("EXP-0002/results.json")]
    keep.append(f"{sha(other)}  benchmarks/results/EXP-0001/results.json")
    m.write_text("\n".join(keep) + "\n")
    st = gate4(repo_copy)
    assert st[0] == "FAIL" and "does not cover benchmarks/results/EXP-0002/results.json" in st[1]


def test_one_codec_experiment_cannot_define_its_own_baseline_set(repo_copy):
    def only_zlib(d):
        d["meta"]["baselines_run"] = ["zlib-9"]
        d["records"] = [r for r in d["records"] if r["codec"] == "zlib-9"]
    tamper_results(repo_copy, only_zlib)
    st = gate4(repo_copy)
    assert st[0] == "FAIL" and "misses registered codecs" in st[1]


def test_fabricated_sizes_are_caught_by_recomputation(repo_copy):
    def fake(d):
        d["records"][0]["complete_storage_bytes"] -= 1000
    tamper_results(repo_copy, fake)
    st = gate4(repo_copy)
    assert st[0] == "FAIL" and "recomputed size/hash differ" in st[1]


def test_fabricated_container_hash_is_caught(repo_copy):
    def fake(d):
        d["records"][5]["container_sha256"] = "0" * 64
    tamper_results(repo_copy, fake)
    assert gate4(repo_copy)[0] == "FAIL"


def test_duplicate_record_fails(repo_copy):
    tamper_results(repo_copy, lambda d: d["records"].append(dict(d["records"][0])))
    assert gate4(repo_copy)[0] == "FAIL"


def test_extra_unknown_record_fails(repo_copy):
    def extra(d):
        r = dict(d["records"][0])
        r["file"] = "ghost.bin"
        d["records"].append(r)
    tamper_results(repo_copy, extra)
    assert gate4(repo_copy)[0] == "FAIL"


@pytest.mark.parametrize("field,value", [("reconstruction_success", "yes"), ("original_unmodified", 1)])
def test_non_boolean_flags_do_not_count_as_true(repo_copy, field, value):
    tamper_results(repo_copy, lambda d: d["records"][2].__setitem__(field, value))
    st = gate4(repo_copy)
    assert st[0] == "FAIL" and "recovery not verified" in st[1]


def test_dataset_id_mismatch_fails(repo_copy):
    tamper_results(repo_copy, lambda d: d["meta"].__setitem__("dataset_id", "DS-OTHER"))
    st = gate4(repo_copy)
    assert st[0] == "FAIL" and "dataset id mismatch" in st[1]


def test_differing_library_versions_make_recompute_inconclusive_not_pass(repo_copy):
    def other_versions(d):
        d["meta"]["environment"]["zstandard"] = "0.0.1"
        d["records"][0]["container_sha256"] = "0" * 64
    tamper_results(repo_copy, other_versions)
    st = gate4(repo_copy)
    assert st[0] == "PARTIAL" and "not conclusive" in st[1]


def test_blank_owner_scope_is_not_approval(repo_copy):
    (repo_copy / "state").mkdir(exist_ok=True)
    (repo_copy / "state" / "owner_approval.json").write_text(
        json.dumps({"approved": True, "approved_by": "Esteban", "scope": "   "}))
    assert run_gates(repo_copy, "GATE_08")[0]["GATE_08"][0] == "APPROVAL_REQUIRED"


def test_unit_and_integration_gates_fail_when_tests_fail(repo_copy):
    shutil.rmtree(repo_copy / "tests")
    (repo_copy / "tests" / "integration").mkdir(parents=True)
    (repo_copy / "tests" / "integration" / "test_fail.py").write_text("def test_x():\n    assert False\n")
    st = run_gates(repo_copy, "GATE_02", "GATE_03")[0]
    assert st["GATE_02"][0] == "FAIL" and st["GATE_03"][0] == "FAIL"


def test_unit_gate_is_not_evaluated_without_tests_and_zero_passed_is_not_pass(repo_copy):
    shutil.rmtree(repo_copy / "tests")
    st = run_gates(repo_copy, "GATE_02", "GATE_03")[0]
    assert st["GATE_02"][0] == "NOT_EVALUATED" and st["GATE_03"][0] == "NOT_EVALUATED"
    (repo_copy / "tests").mkdir()
    (repo_copy / "tests" / "test_skip.py").write_text("import pytest\n@pytest.mark.skip\ndef test_x():\n    pass\n")
    assert run_gates(repo_copy, "GATE_02")[0]["GATE_02"][0] == "FAIL"  # nothing passed


def test_gates_json_carries_attestation_caveat(repo_copy):
    _, data, _ = run_gates(repo_copy, "GATE_01")
    assert "unauthenticated" in data["caveat"]
