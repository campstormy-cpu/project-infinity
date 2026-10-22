"""Runs ONE (codec, file) measurement in a fresh process and prints JSON.

A fresh process gives a meaningful peak-RSS figure. Steps:
  1. hash the original (before)
  2. compress N times (timing, determinism check via hash of each output)
  3. write the container to disk, then decode FROM DISK N times
  4. write reconstructed file, verify with hash AND direct byte comparison
  5. hash the original again (immutability check)
"""
import json
import os
import resource
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "compression-core"))

from infinity_core import check_recovery, compress_bytes, decompress_bytes, sha256_bytes, sha256_file  # noqa: E402


def main() -> None:
    codec, original, scratch, repeats = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]), int(sys.argv[4])
    baseline_rss_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    sha_before = sha256_file(original)
    data = original.read_bytes()

    c_wall, c_cpu, blob_hashes = [], [], []
    blob = b""
    for _ in range(repeats):
        w0, c0 = time.perf_counter(), time.process_time()
        blob = compress_bytes(codec, data)
        c_wall.append(time.perf_counter() - w0)
        c_cpu.append(time.process_time() - c0)
        blob_hashes.append(sha256_bytes(blob))

    scratch.mkdir(parents=True, exist_ok=True)
    blob_path = scratch / f"{original.name}.{codec}.inf"
    out_path = scratch / f"{original.name}.{codec}.recovered"
    blob_path.write_bytes(blob)

    d_wall, d_cpu = [], []
    recovered = b""
    for _ in range(repeats):
        stored = blob_path.read_bytes()
        w0, c0 = time.perf_counter(), time.process_time()
        recovered = decompress_bytes(stored)
        d_wall.append(time.perf_counter() - w0)
        d_cpu.append(time.process_time() - c0)
    out_path.write_bytes(recovered)

    rec = check_recovery(original, out_path)
    sha_after = sha256_file(original)
    peak_rss_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    result = {
        "codec": codec,
        "file": original.name,
        "original_bytes": len(data),
        "complete_storage_bytes": os.path.getsize(blob_path),
        "compress_seconds_median": statistics.median(c_wall),
        "decompress_seconds_median": statistics.median(d_wall),
        "compress_cpu_seconds_median": statistics.median(c_cpu),
        "decompress_cpu_seconds_median": statistics.median(d_cpu),
        "peak_rss_kb": peak_rss_kb,
        "baseline_rss_kb": baseline_rss_kb,
        "container_sha256": blob_hashes[0],
        "deterministic_across_repeats": len(set(blob_hashes)) == 1,
        "repeats": repeats,
        "reconstruction_success": rec.ok,
        "recovery": rec.as_dict(),
        "original_unmodified": sha_before == sha_after,
    }
    print(json.dumps(result))
    out_path.unlink()  # scratch cleanup; the container stays for audit


if __name__ == "__main__":
    main()
