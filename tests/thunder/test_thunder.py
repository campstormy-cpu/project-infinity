"""Thunder is tested by planting known violations in throwaway projects: every rule must fire on the planted
fault, and must stay silent on a clean project."""
import json
from pathlib import Path

import pytest

from thunder import config as C
from thunder.cli import main
from thunder.extract import build
from thunder.graph import Graph, diff
from thunder.rules import run_all

CFG = {
    "source_roots": ["src", "."],
    "critical": [{"name": "core", "paths": ["src/core"], "forbid_imports": ["socket", "subprocess", "random"], "require_tests": True}],
    "layers": [{"name": "core is independent", "from": ["src/core"], "must_not_reach": ["src/app"]}],
}


def project(tmp_path: Path, files: dict, cfg=None) -> Path:
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    (tmp_path / "thunder.json").write_text(json.dumps(cfg or CFG))
    return tmp_path


CLEAN = {
    "src/core/__init__.py": "from .lib import add\n",
    "src/core/lib.py": "def add(a, b):\n    return a + b\n",
    "src/app/main.py": "from core import add\nprint(add(1, 2))\n",
    "tests/test_lib.py": "from core import add\n\ndef test_add():\n    assert add(1, 2) == 3\n",
    "requirements.txt": "pytest==9.1.1\n",
}


def scan(root: Path):
    cfg = C.load(root)
    return run_all(build(root, cfg), cfg, root)


def rules_of(fs):
    return {f.rule for f in fs}


def test_clean_project_has_no_findings(tmp_path):
    assert scan(project(tmp_path, CLEAN)) == []


def test_direct_forbidden_import_is_high(tmp_path):
    files = {**CLEAN, "src/core/lib.py": "import socket\ndef add(a, b):\n    return a + b\n"}
    fs = scan(project(tmp_path, files))
    f = [x for x in fs if x.rule == "trust-boundary"]
    assert f and f[0].severity == "high" and "socket" in f[0].message


def test_transitive_forbidden_import_shows_the_path(tmp_path):
    files = {**CLEAN, "src/core/lib.py": "from . import helper\ndef add(a, b):\n    return a + b\n",
             "src/core/helper.py": "import subprocess\n"}
    fs = [x for x in scan(project(tmp_path, files)) if x.rule == "trust-boundary"]
    assert any("transitively" in x.message and "helper.py" in x.evidence[0] and "subprocess" in x.evidence[0] for x in fs)


def test_dotted_forbidden_import_is_seen(tmp_path):
    cfg = {**CFG, "critical": [{"name": "core", "paths": ["src/core"], "forbid_imports": ["urllib.request"]}]}
    files = {**CLEAN, "src/core/lib.py": "import urllib.request\ndef add(a, b):\n    return a + b\n"}
    assert "trust-boundary" in rules_of(scan(project(tmp_path, files, cfg)))


def test_layer_violation_detected(tmp_path):
    files = {**CLEAN, "src/core/lib.py": "from app import main\ndef add(a, b):\n    return a + b\n"}
    assert "layering" in rules_of(scan(project(tmp_path, files)))


def test_import_cycle_detected(tmp_path):
    files = {**CLEAN, "src/core/a.py": "from . import b\n", "src/core/b.py": "from . import a\n"}
    assert "import-cycle" in rules_of(scan(project(tmp_path, files)))


@pytest.mark.parametrize("code", ["eval('1')", "exec('x=1')", "import os\nos.system('ls')", "import pickle\npickle.loads(b'')",
                                  "import subprocess\nsubprocess.run('ls', shell=True)"])
def test_dangerous_calls_detected(tmp_path, code):
    files = {**CLEAN, "src/app/main.py": code + "\n"}
    assert "dangerous-call" in rules_of(scan(project(tmp_path, files)))


def test_untested_public_function_detected_and_test_fixes_it(tmp_path):
    files = {**CLEAN, "src/core/lib.py": "def add(a, b):\n    return a + b\n\ndef mul(a, b):\n    return a * b\n",
             "src/core/__init__.py": "from .lib import add, mul\n"}
    fs = scan(project(tmp_path, files))
    assert [f.node for f in fs if f.rule == "untested-public"] == ["src/core/lib.py::mul"]
    files["tests/test_lib.py"] += "\ndef test_mul():\n    from core import mul\n    assert mul(2, 3) == 6\n"
    assert scan(project(tmp_path, files)) == []


def test_import_alone_does_not_count_as_coverage(tmp_path):
    files = {**CLEAN, "tests/test_lib.py": "from core import add\n\ndef test_nothing():\n    assert True\n"}
    assert "untested-public" in rules_of(scan(project(tmp_path, files)))


def test_method_covered_by_name(tmp_path):
    files = {**CLEAN, "src/core/lib.py": "class Box:\n    def open(self):\n        return 1\n",
             "src/core/__init__.py": "from .lib import Box\n",
             "tests/test_lib.py": "from core import Box\n\ndef test_box():\n    assert Box().open() == 1\n"}
    assert scan(project(tmp_path, files)) == []


def test_unpinned_and_undeclared_dependencies(tmp_path):
    files = {**CLEAN, "requirements.txt": "pytest>=9\nleftpad\n", "src/app/main.py": "import requests\n"}
    r = rules_of(scan(project(tmp_path, files)))
    assert {"dependency-pin", "undeclared-dependency"} <= r


def test_dangling_doc_reference_and_escape_is_not_followed(tmp_path):
    files = {**CLEAN, "README.md": "see `docs/missing.md` and `../outside/file.md` and `/etc/passwd.txt`\n"}
    fs = [f for f in scan(project(tmp_path, files)) if f.rule == "dangling-doc-reference"]
    assert fs and fs[0].evidence == ["docs/missing.md"]


def test_secret_detected(tmp_path):
    key = "gh" + "p_" + "A" * 36  # built at runtime so this file does not trip scanners
    files = {**CLEAN, "src/app/main.py": f'TOKEN = "{key}"\n'}
    assert "secret" in rules_of(scan(project(tmp_path, files)))


def test_workflow_unpinned_action(tmp_path):
    files = {**CLEAN, ".github/workflows/ci.yml": "steps:\n  - uses: actions/checkout@v4\n"}
    assert "workflow-supply-chain" in rules_of(scan(project(tmp_path, files)))


def test_pinned_workflow_is_quiet(tmp_path):
    files = {**CLEAN, ".github/workflows/ci.yml": "steps:\n  - uses: actions/checkout@" + "a" * 40 + "\n"}
    assert scan(project(tmp_path, files)) == []


def test_baseline_silences_only_the_exact_finding(tmp_path):
    files = {**CLEAN, "src/app/main.py": "eval('1')\n"}
    root = project(tmp_path, files)
    f = scan(root)[0]
    cfg = {**CFG, "baseline": {f.fingerprint(): "reviewed"}}
    (root / "thunder.json").write_text(json.dumps(cfg))
    assert main(["--root", str(root), "scan", "--fail-on", "medium"]) == 0
    (root / "src/app/other.py").write_text("exec('1')\n")
    assert main(["--root", str(root), "scan", "--fail-on", "medium"]) == 1


def test_fail_on_threshold(tmp_path):
    root = project(tmp_path, {**CLEAN, "requirements.txt": "pytest>=9\n"})  # medium finding only
    assert main(["--root", str(root), "scan", "--fail-on", "high"]) == 0
    assert main(["--root", str(root), "scan", "--fail-on", "medium"]) == 1


def test_unknown_config_key_is_refused(tmp_path):
    root = project(tmp_path, CLEAN, {**CFG, "typo_key": 1})
    with pytest.raises(SystemExit):
        C.load(root)


def test_graph_algorithms():
    g = Graph()
    for n in "abcd":
        g.add_node(n, "module")
    for s, t in [("a", "b"), ("b", "c"), ("c", "b"), ("c", "d")]:
        g.add_edge(s, t, "imports")
    assert g.path("a", "d") == ["a", "b", "c", "d"]
    assert g.path("d", "a") is None
    assert g.reachable("a") == {"b", "c", "d"}
    assert g.reachable("d", reverse=True) == {"a", "b", "c"}
    assert g.cycles() == [["b", "c"]]
    assert Graph.from_json(g.to_json()).edges == g.edges


def test_diff_alerts_when_critical_module_gains_risky_import(tmp_path, capsys):
    root = project(tmp_path, CLEAN)
    snap = tmp_path / "snap.json"
    assert main(["--root", str(root), "snapshot", str(snap)]) == 0
    assert main(["--root", str(root), "diff", str(snap)]) == 0
    (root / "src/core/lib.py").write_text("import subprocess\ndef add(a, b):\n    return a + b\n")
    assert main(["--root", str(root), "diff", str(snap)]) == 1
    assert "ALERT" in capsys.readouterr().out


def test_blast_lists_dependent_modules_and_tests(tmp_path, capsys):
    root = project(tmp_path, CLEAN)
    assert main(["--root", str(root), "blast", "src/core/lib.py"]) == 0
    out = capsys.readouterr().out
    assert "src/app/main.py" in out and "tests/test_lib.py" in out


def test_why_finds_path(tmp_path, capsys):
    root = project(tmp_path, CLEAN)
    assert main(["--root", str(root), "why", "src/app/main.py", "src/core/lib.py"]) == 0
    assert "src/core/lib.py" in capsys.readouterr().out


def test_syntax_error_file_does_not_crash_scan(tmp_path):
    files = {**CLEAN, "src/app/broken.py": "def (:\n"}
    assert scan(project(tmp_path, files)) is not None
