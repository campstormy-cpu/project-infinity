# EXP-0001 report (generated)

Dataset DS-0001, 8 files. Repeats per measurement: 3.
Git: commit `aed8f04696a97fbbfdd8ea5070199ddd562fecd4`, dirty working tree: False.

Smallest complete stored size per file (baselines only). `x` = ratio original/stored; negative savings mean expansion.

| file | original B | best codec | stored B | ratio | savings | runner-up |
|---|---:|---|---:|---:|---:|---|
| already_compressed.xz | 106680 | brotli-11 | 106730 | 1.000 | -0.0% | zstd-19 (106737 B) |
| empty.bin | 0 | brotli-11 | 46 | n/a | n/a | zlib-9 (53 B) |
| one_byte.bin | 1 | brotli-11 | 50 | 0.020 | -4900.0% | zlib-9 (54 B) |
| python_source_corpus.txt | 476341 | brotli-11 | 103785 | 4.590 | 78.2% | bz2-9 (106714 B) |
| random_256KiB.bin | 262144 | brotli-11 | 262194 | 1.000 | -0.0% | zstd-19 (262204 B) |
| repetitive_text_256KiB.txt | 262144 | brotli-11 | 106 | 2473.057 | 100.0% | zstd-19 (125 B) |
| synthetic_table_csv.csv | 384887 | bz2-9 | 83475 | 4.611 | 78.3% | lzma-9e (93145 B) |
| zeros_256KiB.bin | 262144 | brotli-11 | 59 | 4443.119 | 100.0% | zstd-19 (70 B) |

- Measurements: 40. All reconstructions byte-exact (hash + byte compare) and originals unmodified: **True**.
- Container output identical across repeats for every measurement: **True**.
- Not implemented, no results recorded: infinity_adaptive, infinity_predictive, infinity_neural.
- Not applicable to this dataset: ffv1 (video codec; the dataset contains no video, so no valid comparison exists); flac (audio codec; the dataset contains no audio, so no valid comparison exists).
- This experiment checks the pipeline. It makes **no** claim of a new compression method.
