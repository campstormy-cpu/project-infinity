# AUDIT REPORT: EXP-0001 and compression-core

Auditor role: SCIENTIFIC_AUDITOR + SYSTEM_AUDITOR (independent; did not write the code).
Date: 2026-10-22. Repo HEAD audited: `aed8f04696a97fbbfdd8ea5070199ddd562fecd4`.
All audit scripts are in `/tmp/audit/` (not in the repo): `sizes.py`, `dict.py`, `dict2.py`, `mutate.py`, `sec.py`, `sec2.py`, `trail.py`. The mutation sandbox is `/tmp/audit/mut`.
No existing repo file was modified. `benchmarks/results/AUDIT-RERUN` and `benchmarks/scratch/AUDIT-RERUN` were deleted after use.

## 1. Verdicts

| Claim | Verdict | One-line reason |
|---|---|---|
| (a) Byte-exact reconstruction and correct SHA-256 verification | **ACCEPT** (with test-suite caveats, see F-04) | All 40 records re-verified; all independent recomputations match; tampering is rejected. Test suite has real gaps but they do not invalidate EXP-0001. |
| (b) Reported storage sizes and ratios are correct and fairly measured | **REVISE** | Numbers are correct (0 discrepancies in 40/40). "Fairly measured" is not fully true: Brotli uses an embedded static dictionary that is not counted and not disclosed (F-01); report rounding hides expansion (F-05). |
| (c) The report makes no unsupported scientific claim | **REVISE** | The report is mostly restrained and says "no claim of a new method", but it omits material caveats (Brotli dictionary, synthetic and degenerate dataset, library-version dependence), the `dirty` flag is unreliable (F-03), and THEORY files contain stale or overstated text (F-11). |

Overall: EXP-0001 is a valid pipeline check. It is not yet an acceptable baseline reference until F-01, F-03 and F-05 are fixed or disclosed. No CRITICAL or HIGH findings.

## 2. Evidence per required check

### Check 1. Test suite
Command: `cd /home/claude/project-infinity && python3 -m pytest -q`
Result: `61 passed in 1.13s` (re-run at the end of the audit: `61 passed in 1.10s`).
Note: other untracked directories (`.github/`, `apps/`, `infrastructure/`, `state/`, `docs/`) appeared in the repo during the audit. They are outside the audit scope and were not reviewed, except that `infrastructure/run_gates.py` was grepped for secrets (only regex patterns of a scanner; no secrets).

### Check 2. Independent size recomputation
Command: `python3 /tmp/audit/sizes.py` (stdlib `zlib`/`bz2`/`lzma`, `zstandard`, `brotli`; no `infinity_core` import).
- Header size: `4+1+8+32 = 45`, and `struct.calcsize(">4sBQ32s") = 45`. Matches `container.py` and `HEADER_BYTES`.
- For all 40 (file, codec) records I recompressed the file with the documented parameters (zlib 9, bz2 9, xz preset 9|extreme, zstd 19, brotli q11) and compared `45 + len(payload)` to `complete_storage_bytes`, `len(payload)` to `compressed_bytes`, and the file length to `original_bytes`: **0 discrepancies**.
- `compression_ratio` and `space_savings` recomputed from the stored bytes: 0 discrepancies.
- I rebuilt each container byte-for-byte with my own code (`INF1` + id + BE length + SHA-256 + payload) and compared its SHA-256 to `container_sha256`: **0 of 40 differ**.
- I compared the 40 container files in `benchmarks/scratch/EXP-0001/*.inf` with `container_sha256` and `complete_storage_bytes`: 0 bad.
- `results.csv` (40 rows) and `results.parquet` (40 rows) agree with `results.json` on size, hash and ratio fields.
- The `recovery` block of every record agrees with `MANIFEST.json` (original hash == reconstructed hash == manifest hash, sizes equal, `byte_identical`, `original_unmodified`): 0 of 40 fail.
- The "best codec" and "runner-up" columns in `report.md` match my own ranking of the sizes.

### Check 3. Hashes
- `benchmarks/data/*` against `MANIFEST.json` (own script, checks hash and byte length, and checks for extra or missing files): 8 of 8 match, no extra or missing files. Files are mode `0444`.
- `cd /home/claude/project-infinity && sha256sum -c benchmarks/results/EXP-0001/MANIFEST.sha256`: all 19 lines `OK`.
- The evidence manifest is self-attested. It lists neither itself, the tests, nor `container` outputs, and anyone can regenerate it (F-12).
- Tracked files have no diff against HEAD (`git diff --stat` empty). The code hashes in the manifest match the current files, so the run used the audited code.

### Check 4. Mutation testing
Sandbox copy of `packages/`, `tests/`, `pyproject.toml` in `/tmp/audit/mut`; baseline there: 61 passed. Each mutant applied alone, `pytest -x`, then restored. Script: `/tmp/audit/mutate.py`.

| ID | Mutation | Result | Note |
|---|---|---|---|
| M01 | decompress returns `data[:-1]` | KILLED | |
| M02 | skip SHA-256 check in `decompress_bytes` | KILLED | |
| M03 | skip length check | **SURVIVED** | Practically equivalent: the SHA check that follows catches any length change. Defence in depth is untested. |
| M04 | `verify` compares only sizes | KILLED | |
| M05 | `verify` ignores byte compare (hash + size only) | **SURVIVED** | Redundant leg; no test isolates it. |
| M06 | `verify` ignores hash (bytes + size only) | **SURVIVED** | Redundant leg; no test isolates it. |
| M07 | `files_byte_identical` returns True after first chunk | **SURVIVED** | Real weakness: no test with a file larger than 1 MiB that differs after the first chunk. Only the hash leg would protect. |
| M08 | header stores 32 zero bytes instead of the SHA | KILLED | |
| M09 | wrong codec_id written | KILLED | |
| M10 | lzma id remapped to 4 | KILLED | |
| M11 | zstd level 19 changed to 3 | **SURVIVED** | Real weakness: codec parameters are not pinned by any test. A baseline labelled `zstd-19` could silently be level 3. |
| M12 | brotli quality 11 changed to 1 | **SURVIVED** | Same weakness as M11. |
| M13 | orig_length written as len+1 | KILLED | |
| M14 | magic check removed | KILLED | |
| M15 | `sha256_bytes` replaced by padded MD5 | KILLED | |
| M16 | `sha256_file` hashes only the first chunk | KILLED | |
| M17 | `decompress_file` writes truncated output | KILLED | |
| M18 | `compress_file` writes truncated container | KILLED | |
| M19 | decode exceptions swallowed, returns `b""` | **SURVIVED** | Equivalent in effect: the length check still raises `IntegrityError`, only the message differs. |
| M20 | header struct changed to 31-byte hash (HEADER_SIZE 44) | KILLED | |

Totals: 20 mutants, 14 killed, 6 survived. Of the survivors, 2 are effectively equivalent (M03, M19), 2 are redundant-leg gaps (M05, M06), and 2 are real test weaknesses (M07; M11+M12 as one class). The three mutants requested in the brief (drop last byte, size-only verify, skip SHA check) were all killed.
The tests cover only `infinity_core`. `benchmarks/worker.py`, `run_benchmark.py` and the report generator have no tests.

### Check 5. Scientific checklist

**Baseline relevance.** zstd-19, xz 9e, brotli-11, zlib-9, bz2-9 are the standard general-purpose baselines named in H-001. Relevant. Missing for later phases (not for EXP-0001): zstd `--ultra -22` with long-range matching, `zstd --train` dictionaries, and `paq`/`cmix`-class context mixers, which matter for H-001 claims. `ffv1`/`flac` are correctly declared N/A.

**Full storage overhead.** The 45-byte header is counted for every codec equally, and I verified it. The header contains a 32-byte SHA-256 that the codecs do not need to decode, so it is a project policy cost, not a codec cost. It is applied to all codecs, so the comparison is consistent. `model_overhead_bytes = 0` is correct for xz, zlib, bz2 and zstd (no embedded dictionary by default). It is **not** correct for Brotli (next item). The decoder software itself is not counted, which is standard but should be stated.

**External dictionary or model dependency (important).**
- zlib, bz2, xz and zstd (without `--dict`) have no built-in dictionary.
- Brotli (RFC 7932) embeds a fixed static dictionary of 122,784 bytes (figure from the RFC; not re-measured locally) of English, HTML and code words in the decoder. The decoder needs it to reconstruct data. Under FP-07 and mathematical constraint 4 ("any dictionary ... needed to decode belongs in the measured stored size"), it is a dependency that is not counted, and `model_overhead_bytes: 0` and the report do not disclose it.
- I measured the effect. `/tmp/audit/dict2.py`: a 120-byte English sentence compresses to **40 B** with brotli-11 versus 98 B for zlib-9 and zstd-19; the same bytes under a fixed byte permutation (same structure, no dictionary hits) compress to **96 B** with brotli. That 40 vs 96 gap can only come from information held outside the stream.
- `/tmp/audit/dict.py` (byte-permuted copies of the dataset files): on `python_source_corpus.txt`, brotli-11 gets 5.0% worse (103,740 to 108,916 B) while zstd gets 0.03% worse. On `repetitive_text_256KiB.txt`, brotli gets 36% worse (61 to 83 B). Brotli's text context modelling also depends on ASCII, so the permutation is a confounded test; it shows dependence on text-specific priors and does not isolate the dictionary alone.
- Consequence: Brotli "wins" 6 of 8 files in the report, including `python_source_corpus.txt` (103,785 B vs bz2 106,714 B, a 2.7% margin that the permutation test suggests is largely due to built-in text priors). Excluding Brotli's dictionary from the byte count is conservative for any later "beats the baseline" claim, but it contradicts FP-07 as written and should be an explicit, documented exception (amortised shared prior, size 122,784 B).

**Cache, dedup, leakage.** Each measurement is a fresh subprocess; no cross-file state, no dedup, no shared dictionary or model. Compression is deterministic and the originals are read-only and hash-checked before and after. No leakage in EXP-0001. Note for the future: `already_compressed.xz` is the xz of `python_source_corpus.txt`, so the two files share content. Any later shared-model or dedup experiment (H-002) must not train on one and test on the other.

**Accidental lossy steps.** None found. The path is bytes in, bytes out; the reconstructed file is written to disk and compared with the original by size, SHA-256 and direct byte comparison. Decoding reads the container from disk (not from memory). I also decoded every payload independently with the stdlib codecs and got identical bytes.

**Reproducibility.** `python3 benchmarks/run_benchmark.py --experiment-id AUDIT-RERUN` gave 40 measurements, `all_ok=True`, `deterministic=True`. Against EXP-0001: **0 differences** in `container_sha256`, `complete_storage_bytes`, `compressed_bytes`, `original_bytes`. The report body is identical except one line: `dirty working tree: False` (EXP-0001) versus `True` (rerun) with identical code, see F-03. Reproducibility is shown only on the same machine with the same library builds (zstd 1.5.7 as bundled in zstandard 0.25.0, brotli 1.2.1, Python 3.13.16 zlib 1.3 / liblzma; xz CLI 5.4.5 per ENVIRONMENT_AUDIT). Compressed bytes of zlib, xz, zstd and brotli can change across library versions. `pyproject.toml` does not pin versions and has no lockfile.

**Resource measurement validity.**
- `peak_rss_kb` uses `ru_maxrss` of a fresh process, which is a meaningful relative indicator (zlib about +0 to 1 MB, xz about +65 MB, brotli up to +25 MB over the 20.8 MB interpreter baseline). It is the high-water mark over compress plus decompress plus hashing plus the in-memory copies (`data`, `blob`, `recovered`), so it cannot be attributed to either direction. RSS counts touched pages only, so fixed-size structures (the xz 64 MiB dictionary) are understated on small inputs.
- Timings: median of 3 on a shared 2-core VM; sub-millisecond values are at the noise floor. Between EXP-0001 and my rerun, 5 compress timings above 10 ms differed by more than 20% (for example zstd on `already_compressed.xz` 0.020 s vs 0.033 s). The first of 3 repeats is a cold run. The JSON states "indicative only"; `report.md` does not repeat this and does not report timings at all, which is the safer choice.
- GPU is correctly `null`.

**Limitations disclosed?** Partly. The report discloses: baselines only, N/A codecs, no new-method claim, negative savings mean expansion. It does not disclose: Brotli's dictionary, that all but one file are synthetic and 4 of 8 are degenerate (empty, 1 byte, all zeros, one repeated sentence), the single-environment/version basis of reproducibility, or that the evidence directory is untracked in git.

**`dirty` flag logic.** `git_state()` runs `git status --porcelain` after `out_dir.mkdir(...)`. An empty untracked directory is invisible to git, so the run reported `dirty: False`; once EXP-0001 contained files, an identical rerun reported `True`. In addition, `bool(run(...))` returns `False` when git fails (`None`), so the flag fails open; and ignored files (`scratch/`, `__pycache__`) are never considered. The flag therefore does not reliably mean "the code equals the commit". In this case the conclusion is nevertheless true, because I verified independently that tracked files have no diff and that the manifest code hashes match.

**"Negative savings" wording.** The sentence "negative savings mean expansion" is correct, and the `one_byte.bin` figure -4900.0% is arithmetically right (50 B stored for 1 B). But the table prints `-0.0%` for `already_compressed.xz` (true -0.0469%) and `random_256KiB.bin` (true -0.0191%), which reads like "no change" and hides that both expanded. It prints `100.0%` for `repetitive_text_256KiB.txt` (true 99.9596%) and `zeros_256KiB.bin` (true 99.9775%), which reads like complete elimination. Ratios of 2473 and 4443 on synthetic degenerate files are dominated by the 45-byte header and say nothing about real data.

**THEORY files.**
- `experimental_evidence.md` still lists EXP-0001 as "(pending) not run yet" although it has run (stale).
- `foundational_principles.md` is introduced as "established results from information theory and cryptography. They are not claims of this project", but FP-04 to FP-07 are labelled "Project definition", not established results (mislabel).
- `mathematical_constraints.md` #2: "Even a perfect codec expands incompressible input by at least a small constant" is a property of a format with a mandatory header, not a theorem; the counting bound only says some inputs must not shrink.
- `mathematical_constraints.md` #5: "byte counts of deterministic codecs must be identical across runs" is true only for the same codec build and parameters; it is not guaranteed across library versions or machines.
- FP-01, FP-02, FP-03, FP-08 are correct as stated. `verified_findings.md` is correctly empty.

### Check 6. Security
- Secrets: grep for key/token/password/private-key patterns over the repo (excluding `.git`, scratch, caches): no secrets. Only hits are the scanner patterns in `infrastructure/run_gates.py`, and the words "token" in docs. No `eval`, `exec`, `pickle`, `shell=True`, `os.system` in scoped code. `.gitignore` excludes `.env`, `*.key`.
- Subprocess use in `run_benchmark.py` is a list (no shell), with paths taken from a local manifest.
- **Allocation from header fields** (`/tmp/audit/sec.py`, `sec2.py`, run with `python3 -I` and `ulimit -v 3 GB`):
  - zstd with huge `orig_length` (2^30, 2^33, 2^40, 2^50, 2^62, 2^64-1): rejected with `IntegrityError`, no crash. The mechanism is a pre-allocation of `max_output_size`: 2^30 allocates 1 GiB of virtual memory lazily (RSS stayed 17.7 MB) and fails the length check; 2^33 and above raise `MemoryError`, which is converted to `IntegrityError("payload failed to decode: ")` with an empty message. Behaviour depends on the OS overcommit setting (`vm.overcommit_memory=0` here), so on other hosts a large claimed length could commit real memory.
  - `orig_length` is **not used as a bound** for zlib, bz2, lzma or brotli. A 382-byte bz2 container claiming `orig_length = 1` inflated to 400 MiB (peak RSS 820 MB, 6.0 s) before the length check rejected it; a 407,730-byte zlib container did the same (819 MB, 3.9 s). Output scales linearly with the attacker's input ratio, so a few tens of KB could exhaust 8 GB. This is a decompression-bomb DoS in `decompress_bytes`.
  - The check order (decode first, then compare to header) means the header never protects memory.
- **Non-canonical containers** (`/tmp/audit/trail.py`): trailing bytes appended after a valid container are ACCEPTED for zlib, bz2, zstd (zeros and junk) and xz (junk; zeros are rejected). Brotli rejects both. So several different byte strings decode to the same, correctly hashed data. Not a confidentiality problem, but it breaks canonical-form assumptions needed for content addressing, dedup and "complete storage" accounting.
- The SHA-256 in the header protects against accidental corruption only. Anyone who alters the payload can recompute the hash; it is not authentication. Acceptable for Phase 0; it must not be described as tamper-proofing once encryption and decentralized storage are added (needs an AEAD or MAC).
- File handling: `compress_file` and `decompress_file` read whole files into memory (documented), overwrite the destination, follow symlinks, and write non-atomically. `decompress_file` writes only after verification succeeded (good). `run_benchmark.py` joins manifest names onto `data_dir` without normalising, so a malicious manifest could point at other files; manifests are trusted local input, so this is INFO only. The worker uses `original.name` for scratch paths, so scratch writes cannot escape `scratch/`.

## 3. Findings

| ID | Severity | Finding | Where | Recommended correction |
|---|---|---|---|---|
| F-01 | MEDIUM | Brotli's embedded static dictionary (about 122 KB) is required to decode but is not counted and not disclosed; `model_overhead_bytes = 0` and "brotli-11 best codec" on 6/8 files are therefore not fully consistent with FP-07. | `codecs.py`, `run_benchmark.py` (`model_overhead_bytes`), `report.md` | Document the dictionary as an explicit, amortised shared prior (size 122,784 B) in the report and in `metric_notes`; either record it as a separate field or state the exception to FP-07. Add a footnote beside every "best codec" claim. |
| F-02 | MEDIUM | Decompression bomb and header-driven allocation: non-zstd codecs are unbounded; 382 B container produced 820 MB RSS. zstd pre-allocates `orig_length` bytes (virtual). MemoryError is relabelled as `IntegrityError` with an empty message. | `container.py` `decompress_bytes`, `codecs.py` | Enforce a maximum `orig_length` (configurable) before decoding; use streaming decompressors with `max_length = orig_len` (and stop at `orig_len + 1`); reject when output exceeds the header length; keep MemoryError distinct. Add tests with a crafted bomb. |
| F-03 | LOW | `dirty` flag is unreliable: false-clean when the results directory was empty, fails open when git errors, ignores ignored files. Identical code produced `False` then `True`. | `run_benchmark.py` `git_state()` | Compute `dirty` before creating the output directory; use `git status --porcelain --untracked-files=all` excluding only the output directory; treat git errors as `null`/"unknown"; also record `git diff` hash or the code hashes (already in MANIFEST.sha256). |
| F-04 | MEDIUM | Test-suite weaknesses: 4 non-equivalent surviving mutants (M05/M06 redundant legs untested, M07 multi-chunk byte comparison untested, M11/M12 codec parameters unpinned). No tests for `worker.py`, `run_benchmark.py` or report generation. | `tests/integrity/test_integrity.py` | Add a >1 MiB differing-after-first-chunk test; pin each codec's parameters (for example decode the frame/header level or compare to known-answer sizes for a fixed input); test each leg of `check_recovery` in isolation (monkeypatch); add known-answer container tests; add a small end-to-end test of the benchmark runner on a tiny dataset. |
| F-05 | LOW | Report rounding misleads: `-0.0%` for real expansion of 0.019% and 0.047%; `100.0%` for 99.96% and 99.98%; ratios of 2473 and 4443 are header-dominated and not informative. | `run_benchmark.py` report section | Print stored-minus-original in bytes for expansions, use 2 to 3 decimals or explicit "expanded by N B", and mark degenerate synthetic files as such. |
| F-06 | LOW | Timing and RSS are only indicative: 3 repeats, cold first repeat, 2-core shared VM, run-to-run differences above 20% observed; RSS is a joint compress/decompress high-water mark and understates lazily committed memory. `report.md` does not state this (only `results.json` does). | `worker.py`, `report.md` | Keep the caveat in the report; for any speed claim use more repeats, drop the first, and report min/IQR; measure compress and decompress RSS in separate processes. |
| F-07 | LOW | Container is malleable: trailing bytes accepted for zlib, bz2, zstd and (junk) xz. | `container.py` / `codecs.py` | Reject trailing data (use `decompressobj` and check `unused_data`/`eof`), or define the container length in the header. |
| F-08 | INFO | Header SHA-256 is an integrity check, not authentication. | `container.py` | State this in the format spec; use AEAD/MAC when encryption is added. |
| F-09 | LOW | Reproducibility depends on unpinned libraries (zstandard, brotli, system zlib/liblzma). No lockfile; `pytest` is listed as a runtime dependency. Library versions are in `results.json`, not in `report.md`. THEORY constraint 5 overstates cross-environment determinism. | `pyproject.toml`, `THEORY/mathematical_constraints.md` | Pin versions or add a lockfile; print versions in the report; qualify constraint 5 ("same codec build and parameters"); move `pytest` to dev dependencies. |
| F-10 | LOW | Dataset is small and mostly synthetic: 4/8 files are degenerate; random data comes from Mersenne Twister (`random.Random.randbytes`, fine for incompressibility here); the stdlib corpus is 10 files of one Python version; `already_compressed.xz` duplicates the content of the corpus. Fine for a pipeline check, not for rankings. | `benchmarks/make_dataset.py` | State in the report that rankings are not evidence about real data; for H-001 choose a real, documented dataset with a train/test split that keeps related files on one side. |
| F-11 | LOW | THEORY text issues: `experimental_evidence.md` stale ("not run yet"), `foundational_principles.md` heading mislabels project definitions as established results, `mathematical_constraints.md` #2 and #5 overstated. | `THEORY/*.md` | Update the EXP-0001 row with the verdict from this report; relabel FP-04..FP-07 as definitions; qualify constraints #2 and #5. |
| F-12 | INFO | The evidence is self-attested and unversioned: `MANIFEST.sha256` is not signed, does not list itself, tests or containers, and `benchmarks/results/` is untracked in git (the commit does not contain the evidence). | `run_benchmark.py`, repo state | Commit the results with the experiment, tag the commit, and include test files in the manifest. |
| F-13 | INFO | Repo changed during the audit (new untracked `.github/`, `apps/`, `infrastructure/`, `state/`, `docs/`). Not audited. `pytest` still 61 passed. | repo root | Audit these separately before relying on them (`infrastructure/run_gates.py` in particular, since it asserts gates such as "independent security review recorded as PASS"). |
| F-14 | INFO | Whole-file memory use, non-atomic overwrites, and no path normalisation of manifest names (trusted input). | `container.py`, `run_benchmark.py` | Streaming API and atomic writes before handling untrusted or large files. |

No CRITICAL or HIGH findings. No secrets found. No evidence of an accidental lossy step, leakage, cache effects or mismeasured size.

## 4. What was verified as correct (clean results)

- 40 of 40 reconstructions are byte-exact against the manifest hash and sizes; originals are unmodified (read-only, hashed before and after).
- 40 of 40 `complete_storage_bytes`, `compressed_bytes` and `container_sha256` values reproduced independently, and again by a full rerun. 0 discrepancies, 0 differences.
- 8 of 8 dataset hashes and 19 of 19 evidence-manifest lines verified.
- Header is exactly 45 bytes.
- Tampered payload, tampered header hash, bad magic and short blobs are rejected.
- Report numbers are generated from `results.json`; table values match the data.

## 5. Limitations of this audit

- Reproduction was done on the same VM, Python and library builds as the original run; cross-machine and cross-version determinism was not tested.
- The Brotli dictionary size (122,784 B) comes from RFC 7932; I demonstrated its effect by experiment but did not measure the size inside the installed library. The byte-permutation experiment is confounded by Brotli's ASCII-based context modelling.
- Timing and memory claims were assessed for validity, not re-measured with a rigorous method.
- The mutation set is hand-picked (20 mutants), not exhaustive; only `infinity_core` was mutated, not the benchmark scripts.
- The memory-safety tests were bounded (`ulimit -v 3 GB`, 400 MiB bombs); I did not run an actual OOM.
- Files added to the repo during the audit were not reviewed.

## 6. Recommended corrections (priority order)

1. Disclose and account for Brotli's static dictionary (F-01); add the caveat next to every "best codec" statement.
2. Bound decompression by header `orig_length` and a configurable maximum; reject trailing data (F-02, F-07).
3. Fix `git_state()` and compute dirtiness before creating output (F-03).
4. Close the mutation gaps: multi-chunk compare, pinned codec parameters, isolated verification legs, a runner end-to-end test (F-04).
5. Fix report formatting of tiny negative and near-100% savings (F-05) and add the environment/caveat lines to `report.md` (F-06, F-09, F-10).
6. Update THEORY text and the EXP-0001 evidence row; commit and tag the results (F-11, F-12).

After 1, 3 and 5 are done (they change only reporting or metadata, not measured bytes), claims (b) and (c) could move to ACCEPT.
