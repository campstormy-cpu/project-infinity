"""Builds the small nonsensitive dataset DS-0001 used by EXP-0001.

Synthetic files use fixed seeds. The real-text file is a fixed list of Python
standard-library source files (public, nonsensitive). Output files are made
read-only and listed in benchmarks/data/MANIFEST.json with SHA-256 hashes, so a
later run can prove the originals were not modified.
"""
import json
import lzma
import os
import random
import stat
import sys
import sysconfig
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "data"

STDLIB_FILES = ["argparse.py", "textwrap.py", "json/decoder.py", "csv.py", "heapq.py",
                "shutil.py", "statistics.py", "fractions.py", "difflib.py", "configparser.py"]


def write(name: str, data: bytes) -> None:
    p = OUT / name
    if p.exists():
        p.chmod(0o644)
    p.write_bytes(data)
    p.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)  # originals are immutable


def main() -> None:
    OUT.mkdir(exist_ok=True)
    rng = random.Random(1337)

    write("empty.bin", b"")
    write("one_byte.bin", b"\x41")
    write("zeros_256KiB.bin", bytes(256 * 1024))
    write("random_256KiB.bin", rng.randbytes(256 * 1024))

    line = b"The quick brown fox jumps over the lazy dog. "
    write("repetitive_text_256KiB.txt", (line * (256 * 1024 // len(line) + 1))[: 256 * 1024])

    rows = ["id,name,city,amount,flag"]
    cities = ["Mexico City", "Guadalajara", "Monterrey", "Puebla", "Tijuana", "Merida"]
    for i in range(12000):
        rows.append(f"{i},user{rng.randrange(5000)},{rng.choice(cities)},{rng.randrange(100000)/100:.2f},{rng.randrange(2)}")
    write("synthetic_table_csv.csv", ("\n".join(rows) + "\n").encode())

    stdlib = Path(sysconfig.get_paths()["stdlib"])
    parts = []
    for rel in STDLIB_FILES:
        parts.append((stdlib / rel).read_bytes())
    corpus = b"\n".join(parts)
    write("python_source_corpus.txt", corpus)

    # Already-compressed input (expected: no further gain; see THEORY FP-03)
    write("already_compressed.xz", lzma.compress(corpus, preset=9))

    manifest = {"dataset_id": "DS-0001", "files": {}}
    import hashlib
    for p in sorted(OUT.iterdir()):
        if p.name == "MANIFEST.json":
            continue
        b = p.read_bytes()
        manifest["files"][p.name] = {"bytes": len(b), "sha256": hashlib.sha256(b).hexdigest()}
    manifest["note"] = (
        "python_source_corpus.txt was built from the stdlib files listed in make_dataset.py "
        f"on Python {sys.version.split()[0]}; regenerating on another Python version may give different bytes. "
        "Use the committed files and this manifest as ground truth."
    )
    mp = OUT / "MANIFEST.json"
    if mp.exists():
        mp.chmod(0o644)
    mp.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: v["bytes"] for k, v in manifest["files"].items()}, indent=2))


if __name__ == "__main__":
    main()
