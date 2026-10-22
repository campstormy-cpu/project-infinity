# EXP-0003 report (generated)

Dataset DS-0001, 8 files. Repeats per measurement: 3.
Git: commit `98acddc53c07bd9d971a91ddc2879542ce0175f0`, dirty working tree: False.

Smallest complete stored size per file. Savings are signed (negative = the stored form is larger than the original).
Brotli needs a built-in static dictionary that is **not** counted in its stored bytes (THEORY FP-07), so the headline column excludes it and the all-codecs column shows what changes if it is included.

| file | original B | best (no external dependency) | stored B | ratio | savings | best incl. brotli | stored B |
|---|---:|---|---:|---:|---:|---|---:|
| already_compressed.xz | 106680 | zstd-19 | 106737 | 0.9995 | -0.053% | brotli-11 | 106730 |
| empty.bin | 0 | zlib-9 | 53 | n/a | n/a | brotli-11 | 46 |
| one_byte.bin | 1 | zlib-9 | 54 | 0.0185 | -5300.000% | brotli-11 | 50 |
| python_source_corpus.txt | 476341 | bz2-9 | 106714 | 4.4637 | +77.597% | brotli-11 | 103785 |
| random_256KiB.bin | 262144 | zstd-19 | 262204 | 0.9998 | -0.023% | brotli-11 | 262194 |
| repetitive_text_256KiB.txt | 262144 | zstd-19 | 125 | 2097.1520 | +99.952% | brotli-11 | 106 |
| synthetic_table_csv.csv | 384887 | bz2-9 | 83475 | 4.6108 | +78.312% | bz2-9 | 83475 |
| zeros_256KiB.bin | 262144 | zstd-19 | 70 | 3744.9143 | +99.973% | brotli-11 | 59 |

- Measurements: 40. All reconstructions byte-exact (hash + byte compare) and originals unmodified: **True**.
- Container output identical across repeats for every measurement: **True**.
- Brotli (external static dictionary, 122784 bytes, shared by all files and not counted above) is smaller than every dictionary-free codec on 7 of 8 files.
- Not implemented, no results recorded: infinity_adaptive, infinity_predictive, infinity_neural.
- Not applicable to this dataset: ffv1 (video codec; the dataset contains no video, so no valid comparison exists); flac (audio codec; the dataset contains no audio, so no valid comparison exists).

## Limitations (read before using any number)
- This experiment checks the pipeline. It makes **no** claim of a new compression method.
- The dataset is small and mostly synthetic: empty, one-byte, zeros, random, repetitive text and a generated CSV are degenerate or artificial. Only the Python source corpus is real text, and `already_compressed.xz` is the same content re-encoded.
- Ratios on degenerate files (zeros, repetitive text) are dominated by the 45-byte header and say nothing about real data.
- Results depend on library versions (see results.json meta.environment); other builds may give different bytes.
- Timings are medians of a few repeats on a shared 2-core VM. Comparing two identical runs of this suite, individual timings differed by more than 30% in a large share of cases, so use timings only for order of magnitude. Peak RSS covers compress and decompress together and includes the interpreter baseline.
- Reproducibility was shown on this machine only; the evidence manifest is self-attested, not independently signed.
