# Mathematical constraints

1. Counting bound: of the 2^n strings of length n, at most 2^n - 1 strings are shorter, so a lossless code that shortens some inputs must lengthen others (or leave them equal).
2. Container overhead: every real format adds a header. Even a perfect codec expands incompressible input by at least a small constant. The benchmark must report `complete_storage_bytes`, not only payload bytes.
3. Entropy floor: for a stationary source, expected code length is at least its entropy rate. A claimed ratio beyond what the data's structure allows indicates a measurement error, leakage or a lossy step.
4. Model cost: if a decoder needs a model or dictionary of size M, total stored size is payload + M (amortised only if the same model serves many files, and that amortisation must be stated explicitly).
5. Reproducibility: timing varies by machine; byte counts of deterministic codecs must be identical across runs.
