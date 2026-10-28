"""Thunder configuration. A project teaches Thunder what to guard through one JSON file (thunder.json)."""
from __future__ import annotations

import json
from pathlib import Path

DEFAULTS = {
    "source_roots": ["."],            # directories that act as import roots (for resolving imports)
    "exclude": [".git", "__pycache__", ".venv", "venv", "node_modules", ".pytest_cache", ".mypy_cache", "build", "dist"],
    "test_globs": ["tests/", "test_"],  # a python file is a test if its path starts with / contains one of these
    "doc_dirs_extensions": [".md"],
    "critical": [],                   # [{name, paths:[...], forbid_imports:[...], require_tests:true}]
    "layers": [],                     # [{name, from:[paths], must_not_reach:[paths]}]
    "dangerous_calls": ["eval", "exec", "pickle.loads", "pickle.load", "marshal.loads", "os.system",
                        "yaml.load", "__import__"],
    "danger_allow": [],               # ["path::call"]
    "requirements_files": ["requirements.txt", "requirements-dev.txt"],
    "import_name_map": {},            # pip name -> import name when they differ
    "dangling_ignore": [],            # substrings of doc references to ignore
    "check_workflows": True,
    "secret_scan": True,
    "secret_scan_exclude": [],
}


def load(root: Path, path: str | None = None) -> dict:
    cfg = json.loads(json.dumps(DEFAULTS))
    p = Path(path) if path else root / "thunder.json"
    if p.exists():
        user = json.loads(p.read_text())
        unknown = set(user) - set(DEFAULTS) - {"baseline", "comment"}
        if unknown:
            raise SystemExit(f"thunder: unknown config keys: {sorted(unknown)}")
        cfg.update(user)
    return cfg
