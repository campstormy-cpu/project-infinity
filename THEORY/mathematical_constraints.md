# Mathematical constraints

1. Counting bound: of the 2^n strings of length n, at most 2^n - 1 strings are shorter, so a lossless code that shortens some inputs must lengthen others (or leave them equal).
2. Container overhead: the INF1 container adds a fixed 45-byte header. By constraint 1, a codec that shrinks some inputs must expand others; the amount is codec-dependent (measured, not assumed). The benchmark reports `complete_storage_bytes`, not only payload bytes.
3. Entropy floor: for a stationary source, expected code length is at least its entropy rate. A claimed ratio beyond what the data's structure allows indicates a measurement error, leakage or a lossy step.
4. Model cost: if a decoder needs a model or dictionary of size M, total stored size is payload + M (amortised only if the same model serves many files, and that amortisation must be stated explicitly).
5. Reproducibility: timing varies by machine. For a fixed codec, parameters and library version, output bytes are expected to be identical across runs (checked per run); a different library build may legitimately produce different bytes.
6. Library-embedded data: a decoder may rely on data compiled into its library (for example Brotli's static dictionary). Such data is a reconstruction dependency (FP-07) even though it is not in the stored stream.
