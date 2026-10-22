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
import zlib  # noqa: E402

BASELINES = ["zstd-19", "lzma-9e", "brotli-11", "zlib-9", "bz2-9"]
NOT_IMPLEMENTED = ["infinity_adaptive", "infinity_predictive", "infinity_neural"]
NOT_APPLICABLE = {
    "ffv1": "video codec; the dataset contains no video, so no valid comparison exists",
    "flac": "audio codec; the dataset contains no audio, so no valid comparison exists",
}
HEADER_BYTES = 45


def git_state() -> dict:
    """Fail-closed: any git error means dirty=True. Only benchmark outputs are ignored."""
    def run(*a):
        r = subprocess.run(["git", *a], cwd=ROOT, capture_output=True, text=True)
        return r.stdout if r.returncode == 0 else None
    commit = run("rev-parse", "HEAD")
    status = run("status", "--porcelain", "--untracked-files=all")
    if commit is None or status is None:
        return {"commit": None, "dirty": True, "dirty_files": ["<git unavailable>"]}
    files = [l[3:] for l in status.splitlines()
             if not l[3:].startswith(("benchmarks/results/", "benchmarks/scratch/"))]
    return {"commit": commit.strip(), "dirty": bool(files), "dirty_files": files}


def versions() -> dict:
    import brotli, zstandard, pyarrow  # noqa: E401
    return {"python": platform.python_version(), "zstandard": zstandard.__version__,
            "brotli": brotli.__version__, "zlib_runtime": zlib.ZLIB_VERSION, "pyarrow": pyarrow.__version__,
            "platform": platform.platform(), "cpu_count": __import__("os").cpu_count()}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--experiment-id", required=True)
    ap.add_argument("--data", default=str(ROOT / "benchmarks" / "data"))
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--results-root", default=str(ROOT / "benchmarks" / "results"))
    ap.add_argument("--scratch-root", default=str(ROOT / "benchmarks" / "scratch"))
    args = ap.parse_args()

    git = git_state()  # captured BEFORE any output is created
    data_dir = Path(args.data)
    manifest = json.loads((data_dir / "MANIFEST.json").read_text())
    out_dir = Path(args.results_root) / args.experiment_id
    out_dir.mkdir(parents=True, exist_ok=True)
    scratch = Path(args.scratch_root) / args.experiment_id

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
            r["external_dependency"] = CODECS[codec].external_dependency
            records.append(r)

    # Verify every record against the manifest again (immutability) before writing.
    for name, meta in manifest["files"].items():
        assert sha256_file(data_dir / name) == meta["sha256"], f"{name} changed during the run"

    meta = {
        "experiment_id": args.experiment_id,
        "dataset_id": manifest["dataset_id"],
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "repeats": args.repeats,
        "git": git,
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
                 "compress_cpu_seconds_median", "decompress_cpu_seconds_median", "peak_rss_kb", "baseline_rss_kb", "external_dependency",
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
    def fmt_ratio(r):
        return f"{r['compression_ratio']:.4f}" if r["compression_ratio"] else "n/a"

    def fmt_sav(r):
        if r["space_savings"] is None:
            return "n/a"
        return f"{r['space_savings']*100:+.3f}%"  # signed; negative = expansion

    def best(rs):
        return sorted(rs, key=lambda r: r["complete_storage_bytes"])

    lines = [f"# {args.experiment_id} report (generated)", "",
             f"Dataset {manifest['dataset_id']}, {len(manifest['files'])} files. Repeats per measurement: {args.repeats}.",
             f"Git: commit `{git['commit']}`, dirty working tree: {git['dirty']}"
             + (f" ({', '.join(git['dirty_files'])})" if git["dirty"] else "") + ".", "",
             "Smallest complete stored size per file. Savings are signed (negative = the stored form is larger than the original).",
             "Brotli needs a built-in static dictionary that is **not** counted in its stored bytes (THEORY FP-07), so the "
             "headline column excludes it and the all-codecs column shows what changes if it is included.", "",
             "| file | original B | best (no external dependency) | stored B | ratio | savings | best incl. brotli | stored B |",
             "|---|---:|---|---:|---:|---:|---|---:|"]
    brotli_wins = 0
    for name in sorted(manifest["files"]):
        rs = [r for r in records if r["file"] == name]
        clean = best([r for r in rs if not r["external_dependency"]])[0]
        allb = best(rs)[0]
        brotli_wins += allb["external_dependency"] is not None and allb["complete_storage_bytes"] < clean["complete_storage_bytes"]
        lines.append(f"| {name} | {clean['original_bytes']} | {clean['codec']} | {clean['complete_storage_bytes']} | "
                     f"{fmt_ratio(clean)} | {fmt_sav(clean)} | {allb['codec']} | {allb['complete_storage_bytes']} |")
    ok = all(r["reconstruction_success"] and r["original_unmodified"] for r in records)
    det = all(r["deterministic_across_repeats"] for r in records)
    lines += ["", f"- Measurements: {len(records)}. All reconstructions byte-exact (hash + byte compare) and originals unmodified: **{ok}**.",
              f"- Container output identical across repeats for every measurement: **{det}**.",
              f"- Brotli (external static dictionary) is smaller than every dictionary-free codec on {brotli_wins} of {len(manifest['files'])} files.",
              f"- Not implemented, no results recorded: {', '.join(NOT_IMPLEMENTED)}.",
              "- Not applicable to this dataset: " + "; ".join(f"{k} ({v})" for k, v in NOT_APPLICABLE.items()) + ".",
              "",
              "## Limitations (read before using any number)",
              "- This experiment checks the pipeline. It makes **no** claim of a new compression method.",
              "- The dataset is small and mostly synthetic: empty, one-byte, zeros, random, repetitive text and a generated CSV are "
              "degenerate or artificial. Only the Python source corpus is real text, and `already_compressed.xz` is the same content re-encoded.",
              "- Ratios on degenerate files (zeros, repetitive text) are dominated by the 45-byte header and say nothing about real data.",
              "- Results depend on library versions (see results.json meta.environment); other builds may give different bytes.",
              "- Timings are medians of a few repeats on a shared 2-core VM; differences under about 30% are noise. "
              "Peak RSS covers compress and decompress together and includes the interpreter baseline.",
              "- Reproducibility was shown on this machine only; the evidence manifest is self-attested, not independently signed."]
    (out_dir / "report.md").write_text("\n".join(lines) + "\n")

    # ---- SHA-256 manifest of evidence ----
    evidence = [out_dir / n for n in ("results.json", "results.csv", "results.parquet", "report.md") if (out_dir / n).exists()]
    evidence += sorted(data_dir.iterdir())
    evidence += [ROOT / "benchmarks" / "run_benchmark.py", ROOT / "benchmarks" / "worker.py"]
    evidence += sorted((ROOT / "packages" / "compression-core" / "infinity_core").glob("*.py"))
    with open(out_dir / "MANIFEST.sha256", "w") as fh:
        for p in evidence:
            try:
                shown = p.relative_to(ROOT)
            except ValueError:
                shown = p  # outside the repo (tests): absolute path
            fh.write(f"{sha256_file(p)}  {shown}\n")
    print(f"{args.experiment_id}: {len(records)} measurements, all_ok={ok}, deterministic={det}")


if __name__ == "__main__":
    main()
