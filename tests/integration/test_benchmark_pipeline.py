"""Integration test of the real benchmark runner + worker on a tiny temporary dataset."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "benchmarks" / "run_benchmark.py"


def make_dataset(d: Path) -> dict:
    d.mkdir()
    files = {"a.txt": b"integration test data " * 400, "b.bin": bytes(range(256)) * 20, "empty.bin": b""}
    manifest = {"dataset_id": "DS-TEST", "files": {}}
    for name, data in files.items():
        (d / name).write_bytes(data)
        manifest["files"][name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    (d / "MANIFEST.json").write_text(json.dumps(manifest))
    return files


def run(tmp: Path, data: Path, exp="EXP-TEST"):
    return subprocess.run(
        [sys.executable, str(RUNNER), "--experiment-id", exp, "--data", str(data), "--repeats", "1",
         "--results-root", str(tmp / "res"), "--scratch-root", str(tmp / "scr")],
        capture_output=True, text=True)


def test_pipeline_end_to_end(tmp_path):
    data = tmp_path / "data"
    files = make_dataset(data)
    r = run(tmp_path, data)
    assert r.returncode == 0, r.stderr
    out = tmp_path / "res" / "EXP-TEST"
    res = json.loads((out / "results.json").read_text())
    recs = res["records"]
    assert len(recs) == len(files) * 5
    for rec in recs:
        raw = files[rec["file"]]
        assert rec["original_bytes"] == len(raw)
        assert rec["reconstruction_success"] is True and rec["original_unmodified"] is True
        assert rec["recovery"]["sha256_original"] == hashlib.sha256(raw).hexdigest()
        assert rec["recovery"]["sha256_reconstructed"] == rec["recovery"]["sha256_original"]
        assert rec["complete_storage_bytes"] == rec["compressed_bytes"] + 45
        # the stored container on disk really has the reported size and hash
        blob = (tmp_path / "scr" / "EXP-TEST" / f"{rec['file']}.{rec['codec']}.inf").read_bytes()
        assert len(blob) == rec["complete_storage_bytes"]
        assert hashlib.sha256(blob).hexdigest() == rec["container_sha256"]
    assert (out / "results.csv").exists() and (out / "report.md").exists()
    brotli_rec = next(x for x in recs if x["codec"] == "brotli-11")
    assert brotli_rec["external_dependency"]
    assert res["meta"]["git"]["dirty"] in (True, False)
    # manifest lines verify
    for line in (out / "MANIFEST.sha256").read_text().splitlines():
        h, path = line.split("  ", 1)
        assert hashlib.sha256(Path(path if Path(path).is_absolute() else ROOT / path).read_bytes()).hexdigest() == h


def test_runner_aborts_if_original_changed(tmp_path):
    data = tmp_path / "data"
    make_dataset(data)
    (data / "a.txt").write_bytes(b"tampered")
    r = run(tmp_path, data)
    assert r.returncode != 0 and "ABORT" in (r.stdout + r.stderr)
    assert not (tmp_path / "res" / "EXP-TEST" / "results.json").exists()
