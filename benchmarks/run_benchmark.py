"""Benchmark runner.

    python3 benchmarks/run_benchmark.py --experiment-id EXP-0001

Writes benchmarks/results/<id>/{results.json,results.csv,results.parquet,report.md,MANIFEST.sha256}
Every number in report.md is generated from results.json; nothing is hand-typed.
Algorithms that are configured but not implemented are recorded as such, with no numbers.
"""
import argparse
import csv
import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "compression-core"))

from infinity_core import CODECS, sha256_file  # noqa: E402

BASELINES = ["zstd-19", "lzma-9e", "brotli-11", "zlib-9", "bz2-9"]
NOT_IMPLEMENTED = ["infinity_adaptive", "infinity_predictive", "infinity_neural"]
NOT_APPLICABLE = {
    "ffv1": "video codec; the dataset contains no video, so no valid comparison exists",
    "flac": "audio codec; the dataset contains no audio, so no valid comparison exists",
}
HEADER_BYTES = 45


def git_state() -> dict:
    def run(*a):
        r = subprocess.run(["git", *a], cwd=ROOT, capture_output=True, text=True)
        return r.stdout.strip() if r.returncode == 0 else None
    return {"commit": run("rev-parse", "HEAD"), "dirty": bool(run("status", "--porcelain"))}


def versions() -> dict:
    import brotli, zstandard, pyarrow  # noqa: E401
    return {"python": platform.python_version(), "zstandard": zstandard.__version__,
            "brotli": brotli.__version__, "pyarrow": pyarrow.__version__,
            "platform": platform.platform(), "cpu_count": __import__("os").cpu_count()}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--experiment-id", required=True)
    ap.add_argument("--data", default=str(ROOT / "benchmarks" / "data"))
    ap.add_argument("--repeats", type=int, default=3)
    args = ap.parse_args()

    data_dir = Path(args.data)
    manifest = json.loads((data_dir / "MANIFEST.json").read_text())
    out_dir = ROOT / "benchmarks" / "results" / args.experiment_id
    out_dir.mkdir(parents=True, exist_ok=True)
    scratch = ROOT / "benchmarks" / "scratch" / args.experiment_id

    # Originals must match the manifest before we start.
    for name, meta in manifest["files"].items():
        got = sha256_file(data_dir / name)
        if got != meta["sha256"]:
            sys.exit(f"ABORT: {name} does not match the dataset manifest")

    records = []
    for name in sorted(manifest["files"]):
        for codec in BASELINES:
            proc = subprocess.run(
                [sys.executable, str(ROOT / "benchmarks" / "worker.py"), codec,
                 str(data_dir / name), str(scratch), str(args.repeats)],
                capture_output=True, text=True)
            if proc.returncode != 0:
                sys.exit(f"worker failed for {codec} {name}:\n{proc.stderr}")
            r = json.loads(proc.stdout)
            n = r["original_bytes"]
            stor = r["complete_storage_bytes"]
            r["compressed_bytes"] = stor - HEADER_BYTES  # raw codec payload
            r["model_overhead_bytes"] = 0
            r["compression_ratio"] = (n / stor) if stor else None
            r["space_savings"] = (1 - stor / n) if n else None
            r["gpu_usage"] = None  # no GPU in this environment
            records.append(r)

    # Verify every record against the manifest again (immutability) before writing.
    for name, meta in manifest["files"].items():
        assert sha256_file(data_dir / name) == meta["sha256"], f"{name} changed during the run"

    meta = {
        "experiment_id": args.experiment_id,
        "dataset_id": manifest["dataset_id"],
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "repeats": args.repeats,
        "git": git_state(),
        "environment": versions(),
        "container_header_bytes": HEADER_BYTES,
        "baselines_run": BASELINES,
        "not_implemented": NOT_IMPLEMENTED,
        "not_applicable": NOT_APPLICABLE,
        "metric_notes": {
            "complete_storage_bytes": "container header (45 B) + codec payload + model overhead (0 for baselines)",
            "peak_rss_kb": "peak resident memory of a fresh worker process; includes interpreter baseline (see baseline_rss_kb)",
            "timing": "median of N repeats on a shared 2-core VM; indicative only, not a rigorous timing study",
            "gpu_usage": "null: no GPU available",
        },
    }
    (out_dir / "results.json").write_text(json.dumps({"meta": meta, "records": records}, indent=2) + "\n")

    flat_cols = ["file", "codec", "original_bytes", "compressed_bytes", "complete_storage_bytes",
                 "compression_ratio", "space_savings", "compress_seconds_median", "decompress_seconds_median",
                 "compress_cpu_seconds_median", "decompress_cpu_seconds_median", "peak_rss_kb", "baseline_rss_kb",
                 "model_overhead_bytes", "gpu_usage", "reconstruction_success", "original_unmodified",
                 "deterministic_across_repeats", "container_sha256"]
    with open(out_dir / "results.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=flat_cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(records)
    try:
        import pyarrow as pa, pyarrow.parquet as pq  # noqa: E401
        pq.write_table(pa.Table.from_pylist([{k: r.get(k) for k in flat_cols} for r in records]),
                       out_dir / "results.parquet")
    except Exception as exc:  # parquet is optional; csv/json remain authoritative
        print("parquet skipped:", exc)

    # ---- report.md, generated from data ----
    lines = [f"# {args.experiment_id} report (generated)", "",
             f"Dataset {manifest['dataset_id']}, {len(manifest['files'])} files. Repeats per measurement: {args.repeats}.",
             f"Git: commit `{meta['git']['commit']}`, dirty working tree: {meta['git']['dirty']}.", "",
             "Smallest complete stored size per file (baselines only). `x` = ratio original/stored; negative savings mean expansion.", "",
             "| file | original B | best codec | stored B | ratio | savings | runner-up |",
             "|---|---:|---|---:|---:|---:|---|"]
    for name in sorted(manifest["files"]):
        rs = sorted([r for r in records if r["file"] == name], key=lambda r: r["complete_storage_bytes"])
        b, ru = rs[0], rs[1]
        ratio = f"{b['compression_ratio']:.3f}" if b["compression_ratio"] else "n/a"
        sav = f"{b['space_savings']*100:.1f}%" if b["space_savings"] is not None else "n/a"
        lines.append(f"| {name} | {b['original_bytes']} | {b['codec']} | {b['complete_storage_bytes']} | {ratio} | {sav} | {ru['codec']} ({ru['complete_storage_bytes']} B) |")
    ok = all(r["reconstruction_success"] and r["original_unmodified"] for r in records)
    det = all(r["deterministic_across_repeats"] for r in records)
    lines += ["", f"- Measurements: {len(records)}. All reconstructions byte-exact (hash + byte compare) and originals unmodified: **{ok}**.",
              f"- Container output identical across repeats for every measurement: **{det}**.",
              f"- Not implemented, no results recorded: {', '.join(NOT_IMPLEMENTED)}.",
              "- Not applicable to this dataset: " + "; ".join(f"{k} ({v})" for k, v in NOT_APPLICABLE.items()) + ".",
              "- This experiment checks the pipeline. It makes **no** claim of a new compression method."]
    (out_dir / "report.md").write_text("\n".join(lines) + "\n")

    # ---- SHA-256 manifest of evidence ----
    evidence = [out_dir / n for n in ("results.json", "results.csv", "results.parquet", "report.md") if (out_dir / n).exists()]
    evidence += sorted((ROOT / "benchmarks" / "data").iterdir())
    evidence += [ROOT / "benchmarks" / "run_benchmark.py", ROOT / "benchmarks" / "worker.py"]
    evidence += sorted((ROOT / "packages" / "compression-core" / "infinity_core").glob("*.py"))
    with open(out_dir / "MANIFEST.sha256", "w") as fh:
        for p in evidence:
            fh.write(f"{sha256_file(p)}  {p.relative_to(ROOT)}\n")
    print(f"{args.experiment_id}: {len(records)} measurements, all_ok={ok}, deterministic={det}")


if __name__ == "__main__":
    main()
