# AUDIT 002: re-audit of the AUDIT_001 fixes, EXP-0002, gate runner and control center

Auditor role: SCIENTIFIC_AUDITOR + SYSTEM_AUDITOR (independent; did not write this code).
Date: 2026-10-22. Repo HEAD audited: `1bcfd8a9a8b130013dbaabc275c5103df68e94c3` (fix commit `d3471b2`).
All scripts and artefacts are under `/tmp/audit2/` (outside the repo). The only write inside the repo is this file. `git status --short` was empty before and after the audit. Mutation, gate and XSS experiments ran on copies (`/tmp/audit2/mut`, `/tmp/audit2/g_*`, `/tmp/audit2/xss`, `/tmp/audit2/cc`, `/tmp/audit2/copy`).
Environment: Python 3.13.16, zstandard 0.25.0, brotli 1.2.1, pyarrow 26.0.0, pytest 9.1.1, 2 cores, 8 GB RAM (same VM image as AUDIT_001).

## 1. Verdicts

| Subject | Verdict | One-line reason |
|---|---|---|
| (a) Fixes of AUDIT_001 findings | **REVISE** (minor) | The code fixes that matter (F-01, F-02, F-03, F-05, F-07, F-12) are real and survived my attacks. Several new tests are vacuous or too small (memlimit, zstd window, zstd bomb, chunk-aligned trailing), F-08 wording is still wrong, F-06 gained a noise claim the data contradicts, and F-11 left dangling references. No security regression found. |
| (b) EXP-0002 as a valid pipeline baseline | **ACCEPT** (with 2 LOW corrections) | All 40 records, container hashes, CSV and Parquet recomputed independently with 0 discrepancies. `report.md` is accurate against `results.json` (every row, "7 of 8", signed savings). The "differences under about 30% are noise" sentence is contradicted by the data and should be corrected. It is a pipeline baseline only, not evidence about any method or real data. |
| (c) Release-gate runner honesty | **REVISE** | Today's output is truthful (`release_ready=false`, each evidence string matches what was done). But the runner can print PASS without real evidence: GATE_04 passes with 0 records, a forged one-record file, or a manifest listing only `/etc/passwd`; GATES 05-08 flip to PASS from two unauthenticated JSON files, with evidence text citing a file (`AUDIT_REPORT.md`) that does not exist. A crash leaves a stale `gates.json`. The CI file would fail GATE_04 on a shallow checkout. |
| (d) Control center honesty and safety | **REVISE** | It renders persisted data and escapes almost everything, but: two fields are not escaped (stored XSS, reproduced as a string), the checked-in `index.html` is stale and says "Gates have not been run" while `state/gates.json` exists, the benchmark table shows Brotli as smallest with no dependency caveat, and the Infrastructure module is hard-coded text, not persisted data. |

No CRITICAL or HIGH findings. Counts of new findings: 0 CRITICAL, 0 HIGH, 6 MEDIUM, 9 LOW, 8 INFO.

## 2. Check 1: tests and gate runner

- `cd /home/claude/project-infinity && python3 -m pytest -q` : **111 passed in 6.33s** (re-run again later: 111 passed). 
- `python3 infrastructure/run_gates.py` on a copy (`/tmp/audit2/copy`), exit 1 (expected, not release-ready):

| Gate | Status | Evidence text (verbatim, abbreviated) | Truthful? |
|---|---|---|---|
| GATE_01 BUILD | PASS | 12 python files compiled; missing deps: none | Yes. 12 = 4 core + run_benchmark + worker + make_dataset + run_gates + build.py + 3 test files. Syntax check plus import check only. |
| GATE_02 UNIT_TESTS | PASS | pytest exit 0: 111 passed in 6.25s | Yes. Note: `pytest tests` also contains the 2 integration tests, so GATE_03 re-runs them. |
| GATE_03 INTEGRATION_TESTS | PASS | pytest exit 0: 2 passed in 2.69s | Yes. |
| GATE_04 DATA_INTEGRITY | PASS | 80 records in 2 experiment(s) re-checked; problems: none | Partly. It re-reads the self-reported booleans in `results.json` and checks the evidence manifest hashes. It does not recompute any size or hash from the data ("re-checked" overstates). See section 5. |
| GATE_05 SECURITY | PARTIAL | secret scan clean (regex-based, limited); independent security review: not recorded | Yes. |
| GATE_06 SCIENTIFIC_VALIDITY | PENDING | scientific audit verdict: not recorded | Yes (this audit is not recorded in `state/`). |
| GATE_07 INDEPENDENT_AUDIT | PENDING | independent audit verdict: not recorded | Yes. |
| GATE_08 STRATEGIC_APPROVAL | APPROVAL_REQUIRED | no owner approval recorded | Yes. |

`release_ready: False`. The only diff against the committed `state/gates.json` is the timestamp and two pytest durations. The committed `gates.json` is a genuine output of this runner.

## 3. Check 2: status of F-01 .. F-14

Decoder attack method: my own generators `gen.py`, `gen2.py`, `gen3.py`, `aligned.py`; each case is decoded in a fresh subprocess (`child.py`) and peak RSS taken from `resource.getrusage(RUSAGE_SELF).ru_maxrss` (C-library allocations included; `/usr/bin/time` is not installed). 459 structured cases (all 5 codecs x small/large/empty/1-byte payloads x trailing/truncated/bit-flip/cross-codec/forged-header variants) plus the bomb and huge-claim cases below.

| ID | AUDIT_001 sev | Status | Evidence |
|---|---|---|---|
| F-01 Brotli dictionary | MEDIUM | **RESOLVED** (residual LOW, see N-14) | `codecs.py` carries `external_dependency` for brotli only; every record in `results.json` and `results.csv` has the field (brotli non-null, the other 4 null; `test_brotli_external_dependency_is_disclosed_FP07`). `report.md` splits the headline column (dictionary-free codecs) from "best incl. brotli" and states the exception to FP-07. THEORY constraint 6 added. Mutant N21 (drop disclosure) is killed. I measured the dictionary in the installed library: `_brotli.cpython-313-x86_64-linux-gnu.so` contains the dictionary starting at file offset 438112 ("timedownlifeleftback..."); the 122,784 bytes from there have SHA-256 prefix `20e42eb1b511c218`, and the span ends exactly at a UTF-8 word end followed by unrelated table data. So the "about 122 KB" figure is now measured (the code comment still says "size not measured here"). |
| F-02 Decompression bomb | MEDIUM | **RESOLVED** (code); residual accepted risk LOW; tests weak (N-05, N-06) | Experiments, all in fresh processes. (1) 256 MiB-of-zeros bomb with header claiming 1000 B: zlib 18.1 MB, bz2 20.6 MB, lzma 17.3 MB, brotli 21.3 MB, zstd 88.6 MB peak RSS (base 17.2 MB), all `IntegrityError`; before the fix a 382 B bz2 blob took 820 MB. (2) forged `orig_length` = 1 GiB / 2^40 / 2^64-1 with a tiny payload: all rejected, all codecs, peak RSS 17.2-17.4 MB (limit `max_output`, default 1 GiB, is checked before decoding). (3) `max_output=1 MiB` on an honest 256 MiB container: rejected in 0.0 s for all five. (4) xz requesting a dictionary: 64-96 MiB accepted, 100/200/1500 MiB refused ("Memory usage limit exceeded"; note the effective ceiling is about 97 MiB, not the 128 MiB in the comment). (5) zstd requesting a window: window_log 23 accepted, 26/27/28/30 refused ("Frame requires too much memory"). (6) zstd frame with forged 2^60 content size: rejected. Residual: the default cap still allows an honest-looking or forged-to-1-GiB container: a 1,662 B brotli or 32,832 B zstd or 1.04 MB zlib container decoding to exactly 1 GiB peaks at about **2.07-2.10 GB RSS** (roughly 2x output: bytearray plus bytes copy), 6.6-9.1 s. That is bounded and documented as a parameter (`max_output`), but `decompress_file` does not expose it. The docstring "never produce more than n+1 bytes" is false for zstd: the decoder is fed 1024 B at a time and one chunk can expand to about 32 MiB (RLE blocks), so overshoot is bounded by roughly 70 MB, not by n. |
| F-03 `dirty` flag | LOW | **RESOLVED** (code); untested (N-07) | `git_state()` is called before `out_dir.mkdir`, uses `--untracked-files=all`, fails closed. Direct probes on a copy: clean tree False; modified tracked code True; any untracked file True; no `.git` -> `{"commit": None, "dirty": True, "dirty_files": ["<git unavailable>"]}`. Residual: everything under `benchmarks/results/` and `benchmarks/scratch/` is exempt, including modified tracked result files and an untracked `.py` placed there (both reported clean). The code-hash manifest covers this, so it is acceptable. Mutants N25/N26/N27 survive: no test exercises `git_state`. |
| F-04 Test weaknesses | MEDIUM | **PARTIALLY** | The five real survivors of AUDIT_001 (M05, M06, M07, M11, M12) are now all KILLED. M03 still survives (practically equivalent: the SHA-256 check that follows catches any length change). Also the new hardening tests do fail on the pre-fix code: I ran `tests/integrity/test_hardening.py` from HEAD against `packages/` from `aed8f04`: 19 failed, 29 passed (the 29 include the lzma-dictionary, zstd-window and zstd-bomb tests, which therefore do not test anything new; see section 6). Still no tests for report generation, worker flags, `git_state`, gates, or the control center (survivors N25-N42). |
| F-05 Report rounding | LOW | **RESOLVED** | EXP-0002 uses signed `%+.3f%%` (`-0.053%`, `-0.023%`, `+99.952%`, `-5300.000%`), 4-decimal ratios, an explicit degenerate-file warning. Mutant N31 (drop the sign) survives only because the report generator is untested. |
| F-06 Timing/RSS caveat | LOW | **PARTIALLY** | The caveat is now in `report.md` and in `metric_notes`. But it adds "differences under about 30% are noise", which the data contradicts: comparing EXP-0001 and EXP-0002 (same code and machine) for the 30 timings above 10 ms, **12 differ by more than 30%** (up to 66%: zstd-19 on random 0.0428 s vs 0.0712 s; bz2-9 on repetitive 0.0652 s vs 0.1028 s). Compress and decompress RSS are still one joint high-water mark (stated). |
| F-07 Trailing bytes | LOW | **RESOLVED** | Every codec rejects: 1 junk byte, 1 zero byte, 5000 junk, 5000 zeros, a second valid stream, the same stream twice, a zstd skippable frame appended, leading zeros, a leading skippable frame, an empty frame followed by a data frame. For small, large, empty and 1-byte payloads: 0 of 459 cases accepted a malformed input (script `runcases_inproc.py`). I also built payloads whose length is an exact multiple of the 1024-byte FEED (brotli 2048 B, zstd 2048 B), the boundary where the `p[pos:]` / `p[i:]` branches are the only protection: all trailing variants rejected (`aligned.py`). Truncation at 1, 2, 4, half and len-1 bytes, and payload removed: all rejected. Residual malleability that is not trailing data: xz with other check types or a delta filter, brotli with other quality/lgwin/mode, two encodings of the empty brotli stream (`0x06` and `0x3b`), zstd with checksum/no content size, and two flipped bits in a zlib stream's ignored padding all decode to the right bytes (INFO N-20). |
| F-08 SHA is not authentication | INFO | **NOT RESOLVED** | `container.py` still says "so a corrupted or tampered container can never be returned as if it were the original". Experiment: a container carrying `b"attacker data"` with a recomputed SHA-256 and zlib payload is accepted and returned. Wording only (LOW, N-15). |
| F-09 Unpinned deps | LOW | **PARTIALLY** | `pyproject.toml` and `requirements.txt` pin `zstandard==0.25.0`, `brotli==1.2.1`, `pyarrow==26.0.0`; `pytest==9.1.1` moved to dev; THEORY constraint 5 qualified. Not done: no lockfile or hashes, system zlib/liblzma/libbz2 versions not pinned (bytes of those codecs depend on them), library versions not in `report.md` (only pointer to `results.json`), `pyarrow` is listed as a runtime dependency although the code treats Parquet as optional. |
| F-10 Dataset small/synthetic | LOW | **ACCEPTED-RISK (disclosed)** | Limitations section of `report.md` states it. Dataset unchanged. I confirmed `already_compressed.xz` decodes exactly to `python_source_corpus.txt` (it is the same content; any shared-model experiment must keep both on one side of a split). |
| F-11 THEORY text | LOW | **PARTIALLY** | Fixed: stale EXP-0001 row, FP-04..FP-08 relabelled, constraints 2 and 5 qualified, new constraint 6. New problems: `experimental_evidence.md` cites `AUDIT_REPORT.md`, which does not exist (the file is `audits/AUDIT_001_EXP-0001.md`); the EXP-0002 row says "see below" and nothing follows; FP-03 says "Follows from FP-02" (encrypted data being incompressible is not a consequence of the entropy bound alone) and FP-06 and FP-08 sit under a header that calls them "project definitions" though FP-08 is a consequence of FP-01. `verified_findings.md` is correctly empty; `rejected_hypotheses.md` correctly empty; no hypothesis is presented as a result. |
| F-12 Evidence untracked/self-attested | INFO | **RESOLVED** (partially) | `benchmarks/results/EXP-0001` and `EXP-0002` are tracked in git (`git ls-files`). EXP-0002 manifest verifies (below). Still self-attested; no tag (`git tag` empty); tests are not in the manifest. |
| F-13 Unreviewed files | INFO | **ADDRESSED by this audit** | Findings in sections 5 and 7. |
| F-14 Whole-file memory, non-atomic writes, manifest paths | INFO | **ACCEPTED-RISK** | Unchanged; the module docstring documents the whole-file reads. `run_benchmark.py` still joins manifest names onto `data_dir` unnormalised (trusted local input). |

## 4. Check 4: EXP-0002 independent recomputation (no `infinity_core` import)

Script `/tmp/audit2/recompute.py`, run with `python3 -I`. It reads `benchmarks/data/*`, recompresses with stdlib `zlib`/`bz2`/`lzma` and `zstandard`/`brotli` with the documented parameters, builds the 45-byte `INF1` header with `struct`, and compares.

- Dataset: 8 of 8 files match `benchmarks/data/MANIFEST.json` (hash and byte length); no extra or missing files; originals mode `0444`.
- EXP-0002: 40 records; `original_bytes`, `compressed_bytes`, `complete_storage_bytes`, `container_sha256`, `compression_ratio`, `space_savings`, and the `recovery` block (original hash == reconstructed hash == manifest hash, byte_identical, sizes): **0 discrepancies**. The 40 on-disk containers in `benchmarks/scratch/EXP-0002/*.inf` are byte-identical to my rebuilt containers. `results.csv` and `results.parquet` agree with `results.json` (40 rows each, 0 field differences).
- EXP-0001 recomputed the same way: 0 discrepancies, 40 containers byte-identical.
- **`container_sha256` EXP-0001 vs EXP-0002: 40 of 40 identical; sizes identical.** This is expected: the decoder hardening and report changes do not touch the encoder or the container, and the encoders are deterministic. So EXP-0002 changes reporting and metadata, not measured bytes. Neither the report nor THEORY says this plainly; they say "same pipeline after fixes", which is consistent.
- `meta.git` of EXP-0002: commit `d3471b294a1cd4d25f06fd70d73321104fe4313f`, `dirty: false`, `dirty_files: []`. Environment recorded: Python 3.13.16, zstandard 0.25.0, brotli 1.2.1, zlib 1.3, pyarrow 26.0.0.
- `sha256sum -c benchmarks/results/EXP-0002/MANIFEST.sha256` from the repo root: all 19 lines OK (no output besides OK). I also verified every `.py` line of both manifests against `git show <meta.git.commit>:<path>` (own script): EXP-0001 19/19 OK against `aed8f04`, EXP-0002 19/19 OK against `d3471b2`. `sha256sum -c` on the EXP-0001 manifest from today's tree reports 3 FAILED code lines (`run_benchmark.py`, `codecs.py`, `container.py`): expected, the code changed after EXP-0001 ran, and the gate runner handles this by checking code lines at the recorded commit. `git diff d3471b2 HEAD -- packages benchmarks/*.py tests` is empty, so HEAD code equals the code that produced EXP-0002.
- **`report.md` vs `results.json`** (own script, regenerating every row): all 8 table rows match exactly (best dictionary-free codec, stored bytes, 4-decimal ratio, signed savings, best incl. brotli). "Measurements: 40", "byte-exact ... True", "identical across repeats ... True" and "Brotli ... smaller than every dictionary-free codec on 7 of 8 files" are correct (brotli wins `already_compressed.xz`, `empty.bin`, `one_byte.bin`, `python_source_corpus.txt`, `random_256KiB.bin`, `repetitive_text_256KiB.txt`, `zeros_256KiB.bin`; not `synthetic_table_csv.csv`, where bz2-9 wins both columns). Limitations list: each item is true, with one exception: "differences under about 30% are noise" is contradicted (F-06). What the report still omits: the 122,784 B size of the dictionary; that the decoder implementation itself and the 32-byte SHA-256 in the header (an integrity policy cost that duplicates codec checksums) are counted/not counted respectively; that EXP-0002 containers are byte-identical to EXP-0001; the library versions inline. None of these overstates a result.

## 5. Check 5: previously unreviewed files

### 5.1 `infrastructure/run_gates.py` (probes in `/tmp/audit2/gates_probe.py`, each on a fresh copy)

| Scenario | Observed |
|---|---|
| Only an experiment with `records: []` and an empty manifest | GATE_04 **PASS** "0 records in 1 experiment(s) re-checked; problems: none" |
| Real results, manifest replaced by one line `<sha256 of /etc/passwd>  ../../../../../../etc/passwd` | GATE_04 **PASS** (80 records) |
| Same with absolute `/etc/passwd` | GATE_04 **PASS** |
| Forged `results.json` with one record, all flags true, manifest listing only itself | GATE_04 **PASS** "1 records in 1 experiment(s)" |
| Evidence file replaced by a symlink to an outside file with equal bytes | PASS (symlink followed, not rejected) |
| `MANIFEST.sha256` missing | Python traceback, exit 1, `state/gates.json` **left as it was** (a pre-existing file with `release_ready: "STALE"` survived) |
| Blank line appended to a manifest | `ValueError` traceback, exit 1, `gates.json` stale |
| One record with `byte_identical=false` | GATE_04 FAIL (correct) |
| One manifest hash wrong | GATE_04 FAIL (correct) |
| `meta.git.commit = "--output=/tmp/audit2/INJECTED_FILE"` (git option injection attempt) | No file created; GATE_04 FAIL. Not exploitable here. |
| `state/audit_verdict.json` = `{"independent_audit":"PASS","scientific_validity":"PASS","security_review":"PASS"}` plus `state/owner_approval.json` = `{"approved": true}` | **All eight gates PASS, `release_ready: True`, exit 0.** Evidence texts: "see AUDIT_REPORT.md" and "with evidence in AUDIT_REPORT.md"; that file does not exist. |

Mutants N36-N41 (gate_integrity always PASS, manifest check disabled, unit gate always PASS, empty results -> PASS, absent verdict -> PASS, any approval file -> PASS) all survive: the runner has no tests.
Secret scan (GATE_05) skips any file named `run_gates.py`, any path with a `data` directory component, and the suffixes `.parquet .inf .xz`; it is regex-only and honestly labelled PARTIAL.
Conclusion: in the current repo state the runner does not lie, but it checks that records and manifest lines are self-consistent, not that they are complete or independent, and gates 05-08 are attestations by file with no provenance.

### 5.2 `apps/control-center/build.py` and `index.html`

- XSS test (`/tmp/audit2/xss`): I injected `<img src=x onerror=alert(1)>` into task id/title/state/note, gate id/name/status/evidence, `release_ready`, `timestamp_utc`, experiment id, dataset id, commit, timestamps, `not_implemented`, a record's file and codec, `audit_verdict.json` keys and values, `owner_approval.json`, THEORY hypothesis rows and an unresolved question, then ran `build.py`. 23 occurrences were escaped. **2 were emitted raw**: the gate `id` (`<td>{g['id']}</td>`) and `gates['release_ready']` (`<b>{...}</b>`). Verified by string inspection of the generated HTML, not in a browser. Only data from `state/gates.json` reaches them, a file written by `run_gates.py` and committed in the repo, so exploitation needs write access to the repo: LOW. Fix: wrap both in `E(str(...))`.
- Only persisted data? Mostly. Tasks, gates, verdicts, results, THEORY tables and the open questions come from files; absent data renders "No persisted data", "Gates have not been run", "None recorded". Exceptions: the Infrastructure module is a hard-coded list (git initialised locally with no remote, CI never executed, no workers, no scheduled automation, no GPU, no connectors in use). I checked `git remote -v` (empty), but nothing keeps these rows in sync with `ENVIRONMENT_AUDIT.md`, and the page header claims "Nothing here is simulated" and "from persisted project files". Also "Generated <time>" is the build time, not the data time.
- **The checked-in `apps/control-center/index.html` is stale.** Rebuilding on a copy changes the Audits & gates section: the committed page says "Gates have not been run." and "No verdict recorded." although `state/gates.json` (committed in the same commit) holds a run. It was generated at 17:55:36, three seconds before the gate run at 17:55:39. A viewer of the committed page is told gates were never run.
- The Benchmarks table sorts by stored bytes, so Brotli rows appear first per file with no `external_dependency` marker; the words "dictionary" / "external dependency" appear nowhere in the page. This is the omission F-01 was about, reintroduced in the UI.
- `AUDIT_REPORT.md present: False` is computed truthfully but refers to a file name that is not the audit file (`audits/AUDIT_001_EXP-0001.md`), so the page cannot show that an audit exists.
- `state/tasks.json` notes are stale: T-05 "mutation testing by independent auditor in progress", T-06 "independent re-derivation in progress", T-08/T-09 "AUDIT"/"IN_PROGRESS" while AUDIT_001 is finished and this re-audit is the in-progress one. T-11 is honest (BLOCKED, CI unexecuted, no scheduler). All 12 task descriptions about counts check out (10 agent files, 7 THEORY files, local git only).

### 5.3 `.github/workflows/ci.yml`

- The file states in its first two lines that it is "written but NEVER EXECUTED" and not an active gate: honest. `yaml.safe_load` parses it (the `on:` key parses as boolean `True` under YAML 1.1, which GitHub accepts); steps are `actions/checkout@v4`, `actions/setup-python@v5` (3.13), `pip install -r requirements-dev.txt`, `python3 infrastructure/run_gates.py`. Pinned versions exist locally.
- **As written it would fail GATE_04 on a standard runner.** `actions/checkout@v4` defaults to `fetch-depth: 1`, so `git show <commit>:<path>` for the recorded experiment commits fails. I reproduced it with `git clone --depth 1 file:///home/claude/project-infinity` and `run_gates.py`: GATE_04 FAIL ("EXP-0001:manifest mismatch benchmarks/run_benchmark.py ... "). It needs `fetch-depth: 0`. Also the job can never go green by design (`release_ready` is false, exit 1) and no gate result is uploaded. GitHub Actions itself was not available to me; this is a reproduction of the shallow-clone condition, not an Actions run.

### 5.4 Other files

- `state/gates.json`: genuine runner output (section 2). `state/tasks.json`: see above.
- `tests/integration/test_benchmark_pipeline.py`: a real end-to-end run of the runner and worker on a tiny dataset (3 files x 5 codecs); checks sizes, hashes, on-disk containers, manifest lines, brotli disclosure, abort on tampered original. Its `meta.git.dirty in (True, False)` assertion is vacuous. It only checks the all-good path (N33-N35 survive).
- `tests/integrity/test_hardening.py`: see F-04 and section 6.
- `requirements.txt`, `requirements-dev.txt`, `pyproject.toml`: consistent with each other and with installed versions (zstandard 0.25.0, brotli 1.2.1, pyarrow 26.0.0, pytest 9.1.1). `requires-python >=3.11`; only 3.13.16 was exercised.
- `.gitignore` ignores `benchmarks/scratch/`, `.env`, `*.key`; scratch containers are therefore not in git (the manifest records their hashes via `results.json`).
- `benchmarks/make_dataset.py`: deterministic (seed 1337, fixed stdlib file list); the manifest note correctly warns that the corpus depends on the Python version.

## 6. Check 3: mutation testing (48 mutants, `/tmp/audit2/mutate.py`, copy of the whole repo incl. `.git`)

Method: each mutant applied alone to `/tmp/audit2/mut`, `python3 -m pytest -x -q tests`, restored. Baseline 111 passed. Survivors were then re-tested against my own attack suite (`mutprobe.py`, `aligned.py`) to tell equivalent from non-equivalent.

Totals: **48 mutants, 21 killed, 27 survived.** Of the 27: 7 practically equivalent, 20 test weaknesses.

| ID | Mutation | Result | Class / explanation |
|---|---|---|---|
| M03 | skip length check (container) | SURVIVED | Equivalent: the SHA-256 check that follows catches any length change; 0 divergences on my 459 cases. |
| M05 | verify ignores byte compare | KILLED | `test_verify_byte_leg_works_independently_of_hash_F04` |
| M06 | verify ignores hash | KILLED | `test_verify_hash_leg_works_independently_of_bytes_F04` |
| M07 | `files_byte_identical` returns True after first chunk | KILLED | `test_byte_compare_sees_difference_after_first_chunk_F04` |
| M11 | zstd level 19 -> 3 | KILLED | `test_codec_parameters_are_pinned_F04` |
| M12 | brotli quality 11 -> 1 | KILLED | same |
| N01 | `_check_tail` ignores trailing (all codecs) | KILLED | |
| N02 | zlib: drop trailing check | KILLED | |
| N03 | bz2: drop trailing check | KILLED | |
| N04 | lzma: drop trailing check | KILLED | |
| N05 | zstd: drop trailing check (final return) | KILLED | |
| N06 | zstd: drop trailing check (early-eof return) | SURVIVED | **Not equivalent.** With payload an exact multiple of 1024 B and trailing junk/zeros/second stream, the mutant accepts all 9 attack cases. Tests only append `b"JUNK"` to payloads under 1 KiB, never reaching the second chunk. Test weakness (MEDIUM). |
| N07 | brotli: drop trailing check (`p[pos:]`) | SURVIVED | **Not equivalent.** Chunk-aligned brotli payload plus junk is accepted by the mutant (`aligned.py`). Same cause. Test weakness (MEDIUM). |
| N08 | remove `max_output` check | KILLED | |
| N09 | remove lzma memlimit | SURVIVED | **Not equivalent.** Mutant accepts xz with 200 MiB and 1500 MiB dictionaries (RSS unchanged, 17 MB, because the dictionary is allocated lazily). `test_lzma_dictionary_memory_request_is_refused_F02` forges a header with a zero SHA-256, so it raises `IntegrityError` from the hash check whether or not the limit exists: vacuous test. It passed against pre-fix code. |
| N10 | remove zstd `max_window_size` | SURVIVED | **Not equivalent.** Mutant accepts window_log 26 and 27 frames. Same vacuity (zero SHA). Passed against pre-fix code. |
| N11 | brotli: feed whole input at once | SURVIVED | Equivalent: output is still limited by `output_buffer_limit`; 0 divergences. |
| N12 | brotli: `output_buffer_limit` unbounded | KILLED | |
| N13 | brotli: no raise on truncated input (`break`) | SURVIVED | Near-equivalent: differs only for streams whose truncation still decodes to the right bytes, i.e. an empty file with a missing/empty brotli payload (4 attack cases accepted). For non-empty data the length and SHA checks backstop it. Minor weakness. |
| N14 | brotli: remove in-loop "output exceeds" check | SURVIVED | Equivalent: `output_buffer_limit` already caps output and `_check_tail` re-checks; 0 divergences. |
| N15 | `_check_tail` ignores not-eof | KILLED | |
| N16 | `_check_tail` ignores oversize | SURVIVED | Equivalent: container length check (and the loop checks) still reject. |
| N17 | zlib unbounded max_length | KILLED | |
| N18 | bz2 unbounded max_length | KILLED | |
| N19 | lzma unbounded max_length | KILLED | |
| N20 | zstd: remove in-loop oversize check | SURVIVED | **Not equivalent.** Memory for a 256 MiB zeros bomb claiming 1000 B rises from 88.6 MB to 569.8 MB peak RSS. The test bomb is 8 MiB with a 24 MiB allowance, so it can never see the difference. Test weakness (MEDIUM). |
| N21 | drop brotli `external_dependency` | KILLED | |
| N22 | `max_output` boundary `>` -> `>=` | KILLED | |
| N23 | `MemoryError` no longer converted to `IntegrityError` | SURVIVED | Not equivalent but trivial: nothing triggers a `MemoryError` in tests. LOW. |
| N24 | skip SHA check | KILLED | |
| N25 | `git_state`: dirty always False | SURVIVED | Test weakness: the integration test asserts only `dirty in (True, False)`. |
| N26 | `git_state`: git failure -> dirty False | SURVIVED | Test weakness. |
| N27 | `git_state`: dirty_files always empty | SURVIVED | Test weakness. |
| N28 | report headline includes brotli | SURVIVED | Test weakness (report generation untested). |
| N29 | `HEADER_BYTES` 45 -> 44 | KILLED | |
| N30 | skip dataset-hash abort | KILLED | |
| N31 | savings sign dropped in report | SURVIVED | Test weakness. |
| N32 | brotli_wins counter forced to 0 | SURVIVED | Test weakness. |
| N33 | worker: `reconstruction_success` always True | SURVIVED | Test weakness: only the all-good path is tested. |
| N34 | worker: `original_unmodified` always True | SURVIVED | Test weakness. |
| N35 | worker: determinism flag always True | SURVIVED | Test weakness. |
| N36 | `gate_integrity` always PASS | SURVIVED | Test weakness: no tests for `run_gates.py`. |
| N37 | gate manifest check disabled | SURVIVED | Test weakness. |
| N38 | `gate_unit` always PASS | SURVIVED | Test weakness. |
| N39 | no results -> PASS | SURVIVED | Test weakness. |
| N40 | missing audit verdict -> PASS | SURVIVED | Test weakness. |
| N41 | any owner approval file -> PASS | SURVIVED | Test weakness. |
| N42 | `build.py` HTML escaping disabled | SURVIVED | Test weakness: no tests for the control center. |

Practically equivalent survivors: M03, N11, N14, N16 (and near-equivalent N13, N23). Everything else that survived is a missing test, not an equivalence.

## 7. New findings

| ID | Severity | Finding | Where | Recommended correction |
|---|---|---|---|---|
| N-01 | MEDIUM | Gates 05-08 become PASS from unauthenticated JSON files; with two files written, `release_ready` is true and exit code 0. Evidence strings cite `AUDIT_REPORT.md`, which does not exist. | `run_gates.py` `gate_security/gate_scientific/gate_audit/gate_owner`, `load_verdict` | Require the verdict to point at an existing audit file whose hash is recorded, and check the file exists; keep owner approval out of any path an agent session can write, or require a signed/hashed approval; correct the file name in the evidence strings. |
| N-02 | MEDIUM | GATE_04 PASS with zero records, a forged self-consistent one-record file, or a manifest that lists only an arbitrary path (`../../etc/passwd`, absolute paths, symlinks followed). It re-reads self-reported booleans and never recomputes sizes or hashes against `benchmarks/data/MANIFEST.json`. | `gate_integrity`, `sha256sum_ok` | Require `n >= 1`, exact expected record count (files x baselines), manifest entries inside the repo (no `..`, no absolute paths, no symlinks) and covering `results.json`, report, data and code; recompute at least container hashes or the recovery hashes against the dataset manifest; reword "re-checked". |
| N-03 | MEDIUM | A crash (missing or malformed manifest) exits 1 but leaves the previous `state/gates.json`, which can still say whatever it said before. | `run_gates.py` `main` | Write the output file atomically at the end, delete or overwrite it at start with `release_ready: false`, wrap each gate in try/except -> FAIL. |
| N-04 | MEDIUM | The CI workflow as written would fail GATE_04 on a default shallow checkout (reproduced with `git clone --depth 1`) and can never be green by design. | `.github/workflows/ci.yml` | Add `fetch-depth: 0`, upload `state/gates.json` as an artifact, and say whether a red run is expected. Still mark it unexecuted until a run is observed. |
| N-05 | MEDIUM | Several new hardening tests are vacuous or too small: lzma dictionary and zstd window tests forge a zero SHA and pass with or without the limits (N09, N10, passed on pre-fix code); the zstd bomb test is 8 MiB against a 24 MiB allowance (N20); trailing-data tests never reach a second 1024-byte chunk (N06, N07). | `tests/integrity/test_hardening.py` | Use honest headers (real SHA-256 of the decoded bytes) so only the limit can reject; add a bomb larger than the allowance; add chunk-aligned payloads for zstd and brotli. |
| N-06 | MEDIUM | The committed control-center page is stale and states "Gates have not been run" and "No verdict recorded" while `state/gates.json` exists from the same commit. | `apps/control-center/index.html` | Rebuild at commit time (or generate in CI), print the timestamp of the data it renders, and consider not committing generated HTML. |
| N-07 | LOW | Runner/worker/report/gate/control-center code is untested beyond one happy-path integration test: 20 surviving mutants (N25-N42, N13, N23). | `tests/` | Add tests for `git_state` (clean, dirty, no git), negative worker cases (corrupt output, modified original), report formatting, each gate with empty/forged/missing inputs, and `build.py` escaping. |
| N-08 | LOW | Stored XSS-class defect: gate `id` and `release_ready` are interpolated unescaped. Reproduced as raw `<img onerror>` in the generated HTML. | `build.py` gate table and gate header | Escape both. |
| N-09 | LOW | Control center omits the Brotli dependency; Brotli rows sort first as smallest in the Benchmarks table. | `build.py` | Show `external_dependency` in the table and note the headline-vs-incl.-Brotli split. |
| N-10 | LOW | Infrastructure module is hard-coded text although the page claims everything comes from persisted files; "AUDIT_REPORT.md present" checks the wrong file name; task notes are stale (T-05, T-06, T-08, T-09). | `build.py`, `state/tasks.json` | Derive from `ENVIRONMENT_AUDIT.md`/state files or label as hand-maintained; point at `audits/`; update task states. |
| N-11 | LOW | `report.md` claim "differences under about 30% are noise" is contradicted by the project's own data (12 of 30 timing pairs above 10 ms differ by more than 30%, max 66%). | `run_benchmark.py` report text | Remove the number or state the observed spread; report no timing conclusions. |
| N-12 | LOW | Dangling references: `AUDIT_REPORT.md` in `THEORY/experimental_evidence.md`, `run_gates.py`, `build.py`, test docstring; EXP-0002 row says "see below" with nothing below; FP-03/FP-06/FP-08 basis column is looser than the header says. | THEORY, code | Point to `audits/AUDIT_001_EXP-0001.md` and `audits/AUDIT_002_FIXES.md`; fill the EXP-0002 row with the verdict; soften "Follows from FP-02". |
| N-13 | LOW | Decoder docstring "never produce more than n + 1 bytes" is false for zstd (fed 1 KiB at a time, one chunk can expand to about 32 MiB, measured overshoot about 70 MB RSS). Default `max_output` (1 GiB) lets a 1.6 KB brotli or 32 KB zstd container drive about 2.1 GB peak RSS; `decompress_file` cannot pass a smaller cap. | `codecs.py`, `container.py` | Correct the docstring; use smaller feed chunks or `read_to_iter`/`max_length` for zstd; expose `max_output` on `decompress_file` and consider a lower default; avoid the second full copy (`bytes(out)`). |
| N-14 | LOW | `model_overhead_bytes` is still 0 for Brotli in every record and `metric_notes` says "model overhead (0 for baselines)"; the dictionary size is not recorded numerically; the code comment says "size not measured here" although it is 122,784 B in the installed build (measured above). | `run_benchmark.py`, `codecs.py` | Record `external_dependency_bytes: 122784` (with the offset/hash check) beside the string; reword the metric note. |
| N-15 | LOW | F-08 not fixed: container docstring claims a "tampered" container can never be returned as the original; an attacker with a recomputed SHA-256 is accepted. | `container.py` | State that the SHA-256 detects accidental corruption only; AEAD/MAC needed once encryption is added. |
| N-16 | INFO | Misleading error text: a bomb stopped at `n+1` bytes reports "truncated or unterminated stream" for zlib, bz2 and lzma (not "output exceeds declared length"). | `_check_tail` call order | Cosmetic. |
| N-17 | INFO | The lzma memlimit comment says 128 MiB; the effective dictionary ceiling is about 97 MiB (100 MiB dictionary refused). A legitimate xz with a dictionary of 100 MiB or more cannot be read. | `codecs.py` | Document. |
| N-18 | INFO | Non-canonical encodings still decode (other xz check types/filters, brotli parameters, two empty-brotli encodings, zstd checksum variants, ignored zlib padding bits). The SHA-256 makes the data unambiguous but the container bytes are not canonical, so content addressing of containers must hash the decoded data, not the container. | codecs | Document; do not rely on container-byte uniqueness. |
| N-19 | INFO | `gate_unit` (`pytest tests`) already includes the integration tests that GATE_03 runs again; the "111 passed" figure includes them. | `run_gates.py` | Cosmetic. |
| N-20 | INFO | EXP-0001's `report.md` (immutable, hash-listed) still shows "best codec: brotli-11" with no dependency caveat; the superseded status exists only in THEORY. | `benchmarks/results/EXP-0001/report.md` | Keep as is; ensure nothing cites EXP-0001 as a baseline. |
| N-21 | INFO | Baseline strength: brotli at default `lgwin` 22 (not 24), xz in `.xz` container framing (about 60 B fixed overhead, matters only on tiny files), no zstd `--long`/ultra levels, no trained dictionary, no context-mixing baseline. Fine for a pipeline check; H-001 needs stronger baselines. | `codecs.py` | Revisit for Phase 2. |
| N-22 | INFO | No git tag, no lockfile with hashes, `pyarrow` listed as a hard dependency though optional. | repo | Tag the audited commit; add hashes if reproducible installs matter. |
| N-23 | INFO | Positive: the brotli dictionary size and presence in the installed library were confirmed by inspecting the binary (122,784 B at offset 438112). | n/a | none |

## 8. Check 6: scientific checklist

- **Baseline fairness and accounting.** The same 45-byte header is charged to all five codecs; codec payloads are produced with fixed, test-pinned parameters (the new pin test compares against direct library calls and a weaker setting, and fails when zstd or brotli is downgraded). `complete_storage_bytes` equals the on-disk container size, verified. The decoder code is not counted (standard practice; should stay stated). Baseline strength is moderate (N-21).
- **Brotli static dictionary.** Excluding it from the headline column and disclosing it next to every record is adequate for this pipeline-validation experiment, and it is the conservative choice only if later claims are compared with the "best incl. brotli" column too. Recommendation for H-001: a claim of "beats the baseline" must beat both columns, and the dictionary should be shown as an explicit amortised shared prior (122,784 B, measured here), never as zero. Reporting the dependency count as a number would be better than a prose note (N-14).
- **Other embedded data.** zlib/deflate (fixed Huffman code defined by the format), zstd (predefined FSE tables defined by the format, no default dictionary), xz/LZMA2 and bz2 carry no content dictionary; their constants are part of the format specification and are small and non-semantic. Brotli is the only decoder with a large, text-oriented data dependency. xz could use a BCJ/delta filter, but those are code, not data. I did not exhaustively inspect the other four libraries' binaries for embedded tables.
- **Leakage and dedup.** Every measurement is a fresh process, no shared state. The only content overlap in the dataset is `already_compressed.xz` = xz of `python_source_corpus.txt` (verified). It does not affect per-file compression but must be split together in any train/test design.
- **Accidental lossy steps.** None found: bytes in, bytes out; decoding from disk; I decoded and compared independently (0 discrepancies); tampering, truncation, trailing data and bit flips (including 2 harmless flips in zlib padding that still give the right bytes) end in `IntegrityError` or identical output.
- **Reproducibility.** Deterministic on this machine and library build (40/40 containers identical across two experiments, 3 repeats each). Cross-machine and cross-version reproducibility not tested (THEORY constraint 5 now says so correctly).
- **THEORY files.** No hypothesis is presented as a finding; `verified_findings.md` and `rejected_hypotheses.md` are empty and say so; hypothesis status values are all HYPOTHESIS. Remaining issues are in N-12. FP-01 and FP-02 are correct as stated; constraint 2 ("a codec that shrinks some inputs must expand others") is a fair statement of the counting bound.
- **False statements still present.** (1) Committed `index.html`: "Gates have not been run" (false at the commit). (2) `run_gates.py` evidence strings reference `AUDIT_REPORT.md`, which does not exist. (3) `THEORY/experimental_evidence.md` cites `AUDIT_REPORT.md` and an empty "see below". (4) `report.md`: "differences under about 30% are noise". (5) `container.py`: "tampered container can never be returned as if it were the original". (6) `codecs.py`: decoders "never produce more than n + 1 bytes" (zstd overshoots). (7) `tasks.json` audit notes are out of date. Statements about what has not been run (CI, GitHub, schedulers, connectors, GPU) are honest in `ci.yml`, `tasks.json`, `build.py` and `ENVIRONMENT_AUDIT.md`; I did not re-verify the environment facts in `ENVIRONMENT_AUDIT.md` (Docker, `gh`, network) beyond the Python library versions.

## 9. What I could not verify

- Execution of the GitHub Actions workflow (no GitHub access); only the shallow-clone condition and YAML validity were checked.
- Cross-machine, cross-OS or cross-library-version reproducibility; behaviour with `vm.overcommit_memory` other than the VM default; behaviour on Python other than 3.13.16.
- Rendering of the control center in a real browser: XSS was shown by inspecting the generated HTML string, not by executing it.
- The dictionary hash was matched by prefix (`20e42eb1b511c218`) against my recollection of the published RFC 7932 dictionary hash; I could not fetch the RFC offline to compare the full digest. The span length (122,784 B) and its clean ending in the binary are directly observed.
- Memory behaviour at sizes beyond the 1 GiB default cap and actual OOM kills (tests were bounded at 1 GiB output, about 2.1 GB RSS, on an 8 GB machine).
- Exhaustive decoder robustness: 459 structured cases plus targeted bombs, not a coverage-guided fuzz run; library bugs in zstd/brotli/liblzma themselves were out of scope.
- The mutation set is hand-picked (48 mutants), not exhaustive; compress-side code and `make_dataset.py` were not mutated.
- Timing and peak-RSS figures in `results.json` were assessed for plausibility and drift, not re-measured with a rigorous method.
- The contents of `.claude/agents/*.md` and the environment facts in `ENVIRONMENT_AUDIT.md` were only grepped for false claims about execution, not independently re-derived.

## 10. Recommended corrections (priority order)

1. Make the gate runner fail closed: non-empty exact-count evidence, manifest paths inside the repo, atomic output with a reset at start, verdicts bound to an existing audit file; fix `fetch-depth` in CI (N-01 to N-04).
2. Fix the tests that cannot fail: honest-header memlimit/window tests, a bomb above the zstd allowance, chunk-aligned trailing tests for zstd and brotli (N-05); add tests for `git_state`, worker negatives, report formatting and the gates (N-07).
3. Regenerate `index.html`, escape the two fields, add the Brotli marker, stop presenting hard-coded rows as persisted data, update `tasks.json` (N-06, N-08, N-09, N-10).
4. Correct the wording: noise claim, SHA-256 "tampered", decoder docstring, `AUDIT_REPORT.md` references, EXP-0002 row (N-11, N-12, N-13, N-15); record the measured dictionary size as a number (N-14).
5. Record this verdict in `state/` only through a process that cannot be self-written by the developer agent, and tag the audited commit.
