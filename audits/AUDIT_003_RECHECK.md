# AUDIT 003: scoped re-check of the AUDIT_002 fixes, EXP-0003, gate runner, control center

Auditor role: SCIENTIFIC_AUDITOR + SYSTEM_AUDITOR (independent; same auditor as AUDIT_001/002, own scripts, nothing taken from the developer's reports).
Date: 2026-10-22. Repo HEAD audited: `c37bf95` (fixes in `98acddc` and `c37bf95`). `git status --short` was empty before and after; the only write inside the repo is this file.
Scripts and artefacts: `/tmp/audit3/` (`gp.py` gate probes, `gen13.py`/`runcases.py`/`child.py` decoder RSS probes, `recompute3.py`, `mutate3.py`, copies `copy/ mut/ xss/ cc/ g_*`). Environment unchanged: Python 3.13.16, zstandard 0.25.0, brotli 1.2.1, pyarrow 26.0.0, pytest 9.1.1, 2 cores, 8 GB.

## 1. Verdicts

| Subject | Verdict | One-line reason |
|---|---|---|
| (a) Fixes of AUDIT_002 N-01..N-13 | **REVISE (minor)** | 9 of 13 are RESOLVED, 1 is ACCEPTED-RISK (documented), 3 are PARTIALLY. The partial ones: the new RSS-based hardening test is blind when run inside the full suite (a real test defect), the gate's manifest-coverage and record-count checks still have small gaps, and the N-13 RSS range in the docstring is slightly too low. No security regression. |
| (b) EXP-0003 as a pipeline baseline | **ACCEPT** | 40 of 40 sizes and container hashes recomputed without `infinity_core` (0 discrepancies) and byte-identical to EXP-0001; `report.md` matches `results.json` row for row ("7 of 8", "122784 bytes"); manifest verifies at the recorded commit; recorded commit has a clean tree and its code equals HEAD's code. Pipeline baseline only. |
| (c) Release-gate runner honesty | **ACCEPT with caveats** | Output on the real repo is truthful. The AUDIT_002 forgeries (empty, one-record, `/etc/passwd`, string verdicts, missing document, wrong hash, stale file) now fail. What remains is exactly what the runner's own docstring says: PASS for gates 05-08 comes from local unauthenticated files, and I could still obtain a full "PASS" with a forged verdict citing a document that actually says REVISE. That is documented honestly in the code and in every PASS evidence string. Two LOW gaps in GATE_04 (below). |
| (d) Control center honesty and safety | **ACCEPT** | Hostile values in every field I could reach are escaped (0 raw tags, 29 escaped); the committed page is regenerated and consistent with `state/gates.json`; Brotli caveat and dependency column are present; infrastructure text is labelled static. Minor label inaccuracy for EXP-0001/0002 rows (LOW). |

Counts of new findings: 0 CRITICAL, 0 HIGH, 2 MEDIUM, 5 LOW, 5 INFO.

## 2. Check 1: tests and gate runner

- `python3 -m pytest -q` in the repo root: **196 passed in 57.02s** (matches the expectation).
- `python3 infrastructure/run_gates.py` on `/tmp/audit3/copy` (exit 1, as expected):

| Gate | Status | Evidence (abbreviated) | Truthful? |
|---|---|---|---|
| GATE_01 BUILD | PASS | 17 python files compiled; missing deps: none | Yes (syntax and import check only; says so). |
| GATE_02 UNIT_TESTS | PASS | pytest exit 0: 196 passed in 58.73s | Yes. Now requires `N passed` with N > 0. |
| GATE_03 INTEGRATION_TESTS | PASS | pytest exit 0: 47 passed in 18.12s | Yes (these 47 are also inside the 196). |
| GATE_04 DATA_INTEGRITY | PASS | 120 records in 3 experiment(s) re-checked against the dataset manifest (self-attested evidence, no re-execution); problems: none | Yes, and the wording is now honest about what "re-checked" means. |
| GATE_05 SECURITY | PARTIAL | secret scan clean (regex-based, limited); security_review: no verdict recorded | Yes. |
| GATE_06 SCIENTIFIC_VALIDITY | PENDING | scientific_validity: no verdict recorded | Yes (my AUDIT_001/002 are not recorded as verdicts). |
| GATE_07 INDEPENDENT_AUDIT | PENDING | independent_audit: no verdict recorded | Yes. |
| GATE_08 STRATEGIC_APPROVAL | APPROVAL_REQUIRED | no owner approval recorded | Yes. |

`release_ready: False`. The only differences against the committed `state/gates.json` are the timestamp and two pytest durations; the committed file is a genuine output. `state/audit_verdict.json` and `state/owner_approval.json` do not exist.

## 3. Check 2: N-01 .. N-13

| ID | Status | Evidence |
|---|---|---|
| N-01 Gates 05-08 from unauthenticated files | **ACCEPTED-RISK, adequately documented** (the specific AUDIT_002 forgeries are RESOLVED) | Probes (`gp.py n01`, each on a fresh copy, `--only GATE_07`): old-style string verdict `"PASS"` -> FAIL; object verdict citing a missing/outside document -> FAIL (`AUDIT_REPORT.md` at root, `audits/../AUDIT_REPORT.md`, `audits/link.md` -> `/etc/passwd`); wrong or upper-case hash -> FAIL; `REVISE` with valid document -> FAIL; list/null/non-string `audit_file` -> FAIL; owner approval without `approved_by`/`scope`, `"true"` string, blank name -> APPROVAL_REQUIRED. **Still PASS**: (i) a PASS verdict citing `audits/AUDIT_001_EXP-0001.md` with its correct hash, although that document's own verdict is REVISE; (ii) a PASS citing a brand-new junk file `audits/fake.md` with its hash; (iii) a symlink `audits/link2.md -> ../pyproject.toml` (inside the repo, resolves, hash correct). With (i) for gates 05-07 plus a three-field approval file, all eight gates PASS. The binding is to a document's bytes, not to what the document concludes, and nothing authenticates who wrote either file. Honesty: the module docstring states "anyone with write access to this repo can still forge both" and names the real remedy (remote CI with protected branches and signed approvals); every PASS evidence string ends "verdict file is local and unauthenticated". I judge that adequate disclosure for a local agent-driven workflow. Residual LOW: `release_ready: true` in `gates.json` carries no such caveat of its own, and `build.py` shows the badge PASS in green (evidence text is shown beside it). |
| N-02 GATE_04 weaknesses | **PARTIALLY RESOLVED** | Now FAIL (all tested via `gp.py n02` on fresh copies): empty records + empty manifest (FAIL, "manifest is empty"); no results (NOT_EVALUATED); one record dropped, manifest rehashed (39 vs 40); a duplicate in place of the last record (set mismatch); fabricated size without rehash (hash mismatch); fabricated flag value `"yes"` (needs `is True`); manifest `../../etc/passwd` or an appended absolute `/etc/passwd` line (path outside repo, and "does not cover report.md/results.json"); `report.md` replaced by a symlink pointing outside the repo; modified dataset file; commit `null`; missing manifest; malformed `results.json` or a record without `recovery` (crash caught, gate FAIL). Still PASS: (1) **fabricated `complete_storage_bytes` and `container_sha256` with the manifest line rehashed** (the gate never recomputes sizes or container hashes; it says "self-attested evidence, no re-execution"); (2) **self-declared coverage**: setting `meta.baselines_run = ["zlib-9"]` and keeping only the 8 zlib records passes ("88 records"), because expected records are computed from the experiment's own `baselines_run`; (3) **basename coverage hole**: `seen` stores `Path(rel).name`, so a manifest whose `results.json` line points at another experiment's `results.json` satisfies "covers results.json", and an edited EXP-0003 `results.json` then passes (verified: edited size = 1, GATE_04 PASS); (4) a symlink that resolves inside the repo with identical bytes (harmless); (5) blank lines are tolerated (fine). All of 1-3 need write access to the repo and are partly disclosed (1); 2 and 3 are not. |
| N-03 Stale output | **RESOLVED** | `main()` unlinks `state/gates.json` first and writes via temp file + `os.replace`. Experiments: a pre-existing `{"stale":true,"release_ready":"STALE"}`, the runner killed with SIGKILL after 4 s -> `state/` contained no `gates.json`; a malformed `audit_verdict.json` -> gates 05 and 07 report FAIL ("gate crashed: JSONDecodeError"), file rewritten with `partial_run: true, release_ready: false`; an owner file that is a list -> GATE_08 FAIL (crash caught). Each gate runs in try/except -> FAIL. `--only` can never yield `release_ready: true`. |
| N-04 CI checkout depth | **RESOLVED** (still unexecuted, honestly labelled) | `ci.yml` now has `fetch-depth: 0` with a comment naming `git show <commit>:<path>`. Reproduced both conditions: `git clone` (full) -> GATE_04 PASS; `git clone --depth 1` -> GATE_04 FAIL (hash mismatches on code lines). The first two lines still say "written but NEVER EXECUTED"; YAML parses. A red run is expected by design (release_ready false) and the file does not say so (INFO). |
| N-05 Vacuous hardening tests | **PARTIALLY RESOLVED** | `tests/integrity/test_hardening_v2.py` (40 tests) uses true-hash headers for the lzma/zstd limit tests, a 128 MiB bomb with a subprocess RSS measurement, chunk-aligned (2048 B) trailing-data tests for all codecs, and a MemoryError test. Verified they can fail: against `packages/` from `aed8f04` 25 of 40 fail; against `d3471b2` and `1bcfd8a` code 40 of 40 pass, as expected (the earlier code already had the limits; what was missing was a test). Mutants N06, N07, N09, N10, N23 are now KILLED (section 4). **But N20 and F01 survive the full suite**, and the cause is a defect in the new test: `rss_growth_mb` computes `ru_maxrss(after) - ru_maxrss(at child start)`, and a forked/exec'ed child inherits the parent's peak RSS as its starting `ru_maxrss` (measured: child baseline 10.9 MB with a small parent, 611.6 MB with a parent that once held 600 MB, even after it freed it). Inside the full `tests/integrity` run the pytest process has a large historical peak, so growth reads about 0. Evidence: mutant N20 (remove the in-loop zstd output check) fails `test_bomb_rejected_with_bounded_rss[zstd-19]` with 231 MB growth when that test runs alone, with the whole v2 file, or twice in one session (3 of 3 runs), and passes (`149 passed`) when the whole `tests/integrity` directory runs, and passes in the full 196-test run (3 of 3 attempts). Fix: measure RSS inside the child from absolute `VmHWM`/`ru_maxrss` against a fixed limit (e.g. absolute peak < baseline interpreter + 64 MB), or reset by starting the child with `subprocess` via `posix_spawn` from a small helper process. |
| N-06 Stale index.html | **RESOLVED** | I rebuilt on a copy (`/tmp/audit3/cc`): the committed `index.html` is byte-identical except the "Generated" timestamp. It shows the gate table from `state/gates.json` (Last run 2026-10-22T18:54:32, same as the file) and no "Gates have not been run". It will go stale again after any later gate run unless regenerated (INFO). |
| N-07 Untested code | **RESOLVED** | 85 new tests (111 -> 196). Of the 22 AUDIT_002 survivors/new probes in my list, all but the ones in section 4 are now killed. Remaining gaps are listed there. |
| N-08 Unescaped fields | **RESOLVED** | Hostile string `<img src=x onerror=alert(1)>` injected into task id/title/state/note, gate id/name/status/evidence, `release_ready`, timestamps, experiment id, dataset id, commit, `not_implemented`, a record's file/codec, `external_dependency_bytes`, verdict keys/values/audit_file, owner approval, a THEORY hypothesis row, an unresolved question, and a file name `audits/evil<script>x.md`: generated page has **0 raw `<img onerror`, 0 raw `<script>`, 29 escaped occurrences, the script-named file escaped**. (Verified by inspecting the generated HTML, not in a browser.) Mutants C03 and C04 (unescape gate id / release_ready) are killed. |
| N-09 Brotli caveat in UI | **RESOLVED** (LOW residual) | Benchmarks section has an "External dependency" column and one caveat paragraph per experiment (3 of 3). EXP-0003 brotli rows read "embedded data, 122784 B, not counted"; EXP-0002 rows read "embedded data, ? B, not counted"; **EXP-0001 brotli rows read "none"** because that experiment's JSON predates the field. The paragraph under the table covers it, but the cell is wrong for EXP-0001 (LOW, N-A3). Mutants C02, C06 killed. |
| N-10 Static labels, stale notes | **RESOLVED** | Infrastructure module now says "Static text transcribed from ENVIRONMENT_AUDIT.md on 2026-10-22. It is not live telemetry" (the test checks for "not live telemetry"). Audit documents are listed from disk (9 mentions of `AUDIT_00`); the wrong "AUDIT_REPORT.md present" row is gone. `state/tasks.json` notes were updated and are consistent with the repository (T-05 "being strengthened", T-09 "re-check pending", T-11 BLOCKED, T-02 VERIFIED with "local git only, no remote": `git remote -v` is empty). I did not re-verify the infrastructure rows against the environment. Mutant C05 (change the label text) survives: the test only asserts a substring that the mutation leaves untouched (trivial). |
| N-11 "30% noise" wording | **RESOLVED** | `report.md` and `metric_notes.timing` now say identical runs differed by more than 30% in a large share of cases and timings are order-of-magnitude only. This matches the earlier measurement (12 of 30 pairs above 10 ms differed by more than 30%). |
| N-12 Dangling references | **RESOLVED** (LOW residual) | `AUDIT_REPORT.md` now exists as an index and says audit 003 verdict is "pending"; gates cite `audits/` documents only. `THEORY/experimental_evidence.md` rows for EXP-0002 and EXP-0003 are filled, the EXP-0003 row says "pending AUDIT_003" and "identical to EXP-0001". FP-03/FP-06/FP-08 basis text corrected (FP-03 now says the empirical check is on one random file and one xz file, not a proof). Residual: the `build.py` module docstring still lists `AUDIT_REPORT.md` as a data source it no longer reads (INFO); the EXP-0001 row still cites `AUDIT_REPORT.md` for AUDIT_001 content (acceptable, the index points to the document). |
| N-13 Docstrings vs measurement | **PARTIALLY RESOLVED** | `DEFAULT_MAX_OUTPUT` is 268,435,456 (256 MiB), as documented. My measurements (`gen13.py`, fresh process per case, peak `ru_maxrss`, base 17 MB), container declaring exactly 256 MiB with true hash: zlib **530.0**, bz2 **532.8**, lzma **593.3**, zstd **539.9** (569.7 in an earlier run), brotli **533.5** MB; i.e. about 2.0-2.2x the cap. With the true hash all accept; with a zero hash all reject at the SHA-256 step after full decode (same RSS); payload producing 256 MiB + 1 bytes rejected at n+1: zlib/bz2/lzma/brotli same RSS, zstd **284 MB**; declaring 256 MiB + 1: rejected in 0.0 s at 17 MB (cap check works). Bomb declaring 1000 B: zlib 18.3, bz2 20.8, lzma 17.3, **zstd 21.8** (was 88.6 MB with FEED 1024), brotli 21.4 MB. The docstring's "measured 250-534 MB" is therefore slightly low at the top (lzma 593, zstd up to 570) and the lower end (250) only appears for the zstd n+1 case; the "roughly twice max_output" statement is right. `codecs.py` docstring is now accurate: n + 1 bytes for zlib/bz2/lzma/brotli; zstd overshoot bounded by one chunk's expansion (measured with a crafted frame of RLE blocks: 64 B input gave up to 2 MiB output in one call, 1024 B gave up to 5 MiB; the old docstring's "about 32 MiB" claim was an overestimate for this window size). `container.py` says the hash is not authentication and what is needed (F-08/N-15 fixed; test `test_container_hash_is_integrity_not_authentication` documents it). |

## 4. Check 3: focused mutation pass (52 mutants, `/tmp/audit3/mutate3.py`, copy of whole repo, `pytest -x -q tests` per mutant)

**Totals: 52 mutants, 36 killed, 16 survived** (baseline 196 passed). Survivors: 4 equivalent or practically redundant, 12 test weaknesses (2 MEDIUM-class, rest LOW).

| ID | Mutation | Result | Class / explanation |
|---|---|---|---|
| N06 | zstd: drop trailing check (early-eof return) | KILLED | |
| N07 | brotli: drop trailing check (`p[pos:]`) | KILLED | chunk-aligned tests work |
| N09 | remove lzma memlimit | KILLED | true-hash test works |
| N10 | remove zstd `max_window_size` | KILLED | true-hash test works |
| N20 | zstd: remove in-loop oversize check | **SURVIVED** | **Test weakness (MEDIUM).** Non-equivalent: the bomb costs 278 MB instead of 22 MB. The intended killer test fails when run alone; it is blinded by the inherited-peak-RSS defect (N-05, finding A3-01). |
| N23 | MemoryError not converted | KILLED | |
| N25 | `git_state` dirty always False | KILLED | |
| N26 | `git_state` git failure -> dirty False | KILLED | |
| N27 | `git_state` ignores all files | KILLED | |
| N28 | report headline includes brotli | KILLED | |
| N31 | report savings sign dropped | KILLED | |
| N32 | brotli_wins forced 0 | KILLED | |
| N33 | worker `reconstruction_success` always True | KILLED | |
| N34 | worker `original_unmodified` always True | KILLED | |
| N35 | worker determinism flag always True | KILLED | |
| N36 | `gate_integrity` always PASS | KILLED | |
| N37 | manifest verification disabled | KILLED | |
| N38 | `_pytest` always PASS (gates 02/03) | **SURVIVED** | Test weakness (LOW): the gate tests always pass `--only` to avoid recursing into pytest, so GATE_02/03 status logic is never exercised. |
| N39 | no results -> PASS | KILLED | |
| N40 | absent verdict -> PASS | KILLED | |
| N41 | owner approval ignores `approved` flag | KILLED | |
| N42 | `build.py` escaping disabled | KILLED | |
| G01 | `inside_root`: `resolve()` containment leg removed | KILLED | symlink-escape test |
| G02 | `inside_root`: `..` check removed | SURVIVED | Equivalent in effect: the `resolve()` leg rejects the same inputs (defence in depth). |
| G03 | `inside_root`: `isabs` check removed | SURVIVED | Equivalent in effect: `ROOT / "/etc/passwd"` is `/etc/passwd`, which `resolve()` rejects. |
| G04 | stale `gates.json` deletion removed | KILLED | |
| G05 | record-count `len(got) != len(expected)` removed | SURVIVED | Test weakness (LOW): a 41st duplicate record (all expected pairs present plus one extra) would be accepted; no test builds that case. |
| G06 | record-set comparison removed (length only) | SURVIVED | Test weakness (LOW): replacing a record by a duplicate keeps the length; my own probe shows the real code rejects it, but no committed test does. |
| G07 | verdict hash check removed | KILLED | |
| G08 | verdict must live under `audits/` removed | KILLED | |
| G09 | manifest required coverage removed | KILLED | (the basename hole of N-02 is not covered by any test) |
| G10 | dataset-file hash check removed | SURVIVED | Practically redundant: every data file is also in each experiment manifest, so the manifest leg still fails; the explicit dataset check only adds a clearer message. |
| G11 | `--only` no longer blocks `release_ready` | SURVIVED | Equivalent today: `len(out["gates"]) == len(GATES)` already false for a partial run; the docstring promise is double-guarded. |
| G12 | recovery flags: drop `is True` (truthy accepted) | SURVIVED | Test weakness (LOW): my probe (`byte_identical = "yes"`) is rejected by the real code; no committed test uses a non-bool. |
| G13 | `sha256_reconstructed == sha256_original` removed | KILLED | |
| G14 | dataset_id mismatch check removed | SURVIVED | Test weakness (LOW). |
| G15 | gate crash recorded as PASS | KILLED | |
| G16 | `.py` manifest lines checked against worktree | KILLED | |
| G17 | secret scan disabled | KILLED | |
| G18 | owner `scope` check removed | SURVIVED | Test weakness (LOW): the parametrised cases cover missing `approved_by` and wrong `approved`, never a blank scope. |
| G19 | build gate accepts zero files | KILLED | |
| F01 | `FEED_ZSTD` 64 -> 1 MiB | **SURVIVED** | **Test weakness (MEDIUM).** Same blinding as N20: a 1 MiB feed lets one call expand far beyond n. |
| F02 | brotli feeds whole input at once | SURVIVED | Equivalent (output is capped per call by `output_buffer_limit`); unchanged conclusion since AUDIT_002. |
| F03 | brotli `output_buffer_limit` unbounded | KILLED | |
| F04 | zstd final-return trailing check dropped | KILLED | |
| C01 | `DEFAULT_MAX_OUTPUT` 256 MiB -> 1 GiB | SURVIVED | Test weakness (LOW): the default-cap test uses 2^40, so any default below that passes; the documented number 256 MiB is not pinned. |
| C02 | control center caveat text removed | KILLED | |
| C03 | gate id unescaped | KILLED | |
| C04 | `release_ready` unescaped | KILLED | |
| C05 | static-text label changed | SURVIVED | Test weakness (trivial): the test checks a different substring. |
| C06 | external-dependency column constant "none" | KILLED | |
| R01 | runner does not record `external_dependency_bytes` | SURVIVED | Test weakness (LOW): no test asserts that the runner writes the field, although report text, CSV and the control center depend on it. |

Gate-specific mutants requested by the brief: `resolve()` leg (G01 killed), stale deletion (G04 killed), record-count check (G05 survived, see above), verdict hash (G07 killed), FEED_ZSTD handling (F01 survived, N20 survived), brotli feed (F02 equivalent, F03 killed).

## 5. Check 4: EXP-0003 independent recomputation (no `infinity_core` import)

Script `/tmp/audit3/recompute3.py` (adapted from AUDIT_002, run with `python3 -I`): recompresses every dataset file with stdlib `zlib/bz2/lzma` and `zstandard/brotli` at the documented parameters, builds the 45-byte `INF1` header with `struct`, and compares.

- Dataset: 8 of 8 files match `benchmarks/data/MANIFEST.json` (hash and length), no extra files, mode `0444`.
- **EXP-0003: 40 records, 0 discrepancies** in `original_bytes`, `compressed_bytes`, `complete_storage_bytes`, `container_sha256`, `compression_ratio`, `space_savings`, and the `recovery` block; the 40 containers in `benchmarks/scratch/EXP-0003/` are byte-identical to my rebuilt ones. `results.csv` and `results.parquet` agree with `results.json` (40 rows each, 0 field differences). EXP-0001 again: 0 discrepancies.
- **`container_sha256` EXP-0001 vs EXP-0003: 40 of 40 identical; all sizes identical.** Explanation: between `aed8f04` and `98acddc` the encoder side (`compress_bytes`, the five compressors, parameters, header layout) did not change; the commits changed only decoding limits/strictness (`_check_tail`, feed sizes, `max_output`), reporting, the `external_dependency_bytes` metadata field and tests. Deterministic encoders with identical parameters and library builds give identical bytes. So EXP-0003 changes metadata and report text, not measured sizes.
- `meta.git` of EXP-0003: commit `98acddc53c07bd9d971a91ddc2879542ce0175f0`, `dirty: false`, `dirty_files: []`; environment Python 3.13.16, zstandard 0.25.0, brotli 1.2.1, zlib 1.3, pyarrow 26.0.0. `git diff 98acddc HEAD -- packages benchmarks/*.py` is empty, so the code at HEAD is the code that produced EXP-0003.
- **Manifest:** `sha256sum -c benchmarks/results/EXP-0003/MANIFEST.sha256` from the repo root: no failures (19 OK, no output other than OK lines filtered). My own check against `git show 98acddc:<path>` for the `.py` lines and the working tree for the rest: 19 ok, 0 bad.
- **`report.md` vs `results.json`:** all 8 table rows regenerated and found verbatim (best dictionary-free codec, stored bytes, 4-decimal ratio, signed savings, best incl. brotli). "Brotli ... smaller than every dictionary-free codec on **7 of 8** files" is correct (it loses only on `synthetic_table_csv.csv`, where bz2-9 wins both columns) and the sentence now states "122784 bytes, shared by all files and not counted above". `results.json` records `external_dependency_bytes` = 122784 for the 8 brotli records and null for the other 32; `metric_notes` has the new field. The limitations list is accurate; the 30% sentence is replaced by a statement consistent with the measured variation. Still not stated in the report (unchanged from AUDIT_002, INFO): that EXP-0003 containers equal EXP-0001's byte for byte, and the library versions inline.
- 122784 is the size I measured in `_brotli.cpython-313-x86_64-linux-gnu.so` (AUDIT_002); the code comment now says so. I did not re-measure it in this audit.

## 6. Check 5: new findings

| ID | Severity | Finding | Where | Recommended correction |
|---|---|---|---|---|
| A3-01 | MEDIUM | The RSS-based bomb test is blind in a full test run: the child inherits the parent's historical peak RSS as its `ru_maxrss` starting point (measured 611.6 MB baseline in a child whose parent once held 600 MB), so `growth` is about 0. Mutants N20 and F01, which raise a bomb's RSS from about 22 MB to 278 MB, pass the full suite (3 of 3) but fail the same test when it runs alone (3 of 3). The hardening claim for zstd/brotli memory therefore rests on a test that depends on execution order. | `tests/integrity/test_hardening_v2.py` `rss_growth_mb` | Measure absolute peak inside the child (compare to a fixed ceiling such as 64 MB above an interpreter-only baseline measured in the same way), or launch the child from a tiny fresh helper process; add a test that asserts the baseline measurement itself is small. |
| A3-02 | MEDIUM | GATE_04 manifest coverage is checked by basename, so a manifest line pointing at another experiment's `results.json` satisfies "covers results.json" and leaves the experiment's own `results.json` unbound (verified: edited size passes). Together with self-declared `baselines_run` (a one-codec experiment of 8 records passes) and no recomputation of sizes/container hashes, GATE_04 only proves internal consistency of attacker-controllable files. The first two are not mentioned in the gate's documentation. | `run_gates.py` `verify_manifest`, `gate_integrity` | Match the full relative path `benchmarks/results/<exp>/results.json` and `report.md` for that experiment; take expected baselines from a constant or from the dataset/runner definition, not from the experiment; optionally recompute container hashes for a sample or all records (cheap here); document the remaining limit. |
| A3-03 | LOW | EXP-0001 brotli rows show "none" in the control center's External dependency column (its JSON predates the field); EXP-0002 shows "? B". | `build.py` | Derive the label from the codec name, or print "n/a (field not recorded)" when the key is absent. |
| A3-04 | LOW | Test gaps still open: G05/G06 (duplicate or extra record), G12 (non-bool flag), G14 (dataset id), G18 (blank scope), N38 (gates 02/03 status logic), C01 (default cap value), R01 (runner records `external_dependency_bytes`). | `tests/integration/*` | Add one case each; for C01 assert `DEFAULT_MAX_OUTPUT == 256 * 2**20`. |
| A3-05 | LOW | `container.py` docstring says "measured 250-534 MB RSS across the five codecs"; independent measurement gives 530-593 MB for an honest 256 MiB container (lzma 593, zstd 540-570) and 284 MB for the zstd n+1 rejection. The factor "about twice max_output" is correct. | `container.py` docstring | Say "about 2.0-2.3 x max_output (530-595 MB measured)". |
| A3-06 | LOW | `release_ready: true` in `gates.json` has no marker that gates 05-08 are local attestations; only the per-gate evidence strings say so, and the control center shows a green PASS badge. | `run_gates.py` output schema, `build.py` | Add an `attestation: "local, unauthenticated"` field to the verdict-based gates or to the file, and show it next to the badge. |
| A3-07 | INFO | A verdict is bound to a document's bytes, not to its conclusion: a PASS can cite an audit file whose text says REVISE (shown with AUDIT_001), or a symlink inside `audits/` to any in-repo file. Documented as a limitation; consider requiring a machine-readable verdict line inside the audit document and rejecting symlinks. | `check_verdict` | Optional hardening. |
| A3-08 | INFO | `build.py` module docstring still lists `AUDIT_REPORT.md` as an input; `index.html` becomes stale after any later gate run until rebuilt. | `build.py`, `index.html` | Cosmetic; rebuild in the same step as the gate run. |
| A3-09 | INFO | `ci.yml` remains unexecuted (correctly labelled) and will report red by design while `release_ready` is false; the comment does not say so. | `.github/workflows/ci.yml` | Add a one-line note or upload `state/gates.json` as an artifact. |
| A3-10 | INFO | The EXP-0003 report and THEORY do not state that EXP-0003 containers are byte-identical to EXP-0001 (the THEORY row does say "identical to EXP-0001"; the report does not). | `report.md` | Optional. |
| A3-11 | INFO | Non-canonical but valid encodings still decode (other xz checks/filters, brotli parameters, two empty-brotli encodings, zstd checksum variants); unchanged since AUDIT_002 N-18, accepted. Container bytes are not canonical, hash the decoded data for content addressing. | codecs | Document (partly done in docstrings). |
| A3-12 | INFO | Positive: the new `FEED_ZSTD = 64` reduced the zstd bomb cost from 88.6 MB to 21.8 MB peak RSS (measured), and the 256 MiB cap rejects `n = cap + 1` in 0.0 s at 17 MB for all five codecs. | `codecs.py`, `container.py` | none |

## 7. What I could not verify

- Execution of GitHub Actions (no GitHub access); only YAML validity and the full-versus-shallow clone behaviour were reproduced locally.
- Rendering of the control center in a real browser; XSS escaping was checked by inspecting the generated HTML.
- Cross-machine, cross-OS or cross-library-version reproducibility; behaviour with other `vm.overcommit_memory` settings; other Python versions (only 3.13.16).
- The infrastructure rows in the control center (no remote, no scheduler, no GPU, no connectors in use) beyond `git remote -v` being empty; `ENVIRONMENT_AUDIT.md` facts (Docker, `gh`, network) were not re-derived.
- The 122,784-byte Brotli dictionary size was taken from my AUDIT_002 measurement, not re-measured here.
- Memory behaviour above the 256 MiB default and real OOM conditions; the cap was tested at exactly the limit (about 2.1x RSS) on an 8 GB machine.
- The mutation set is hand-picked (52 mutants), not exhaustive; compress-side code and `make_dataset.py` were not mutated. Survivors were classified from reasoning plus targeted probes (N20/F01 reproduced standalone); G05, G06, G12, G14, G18 and R01 were classified from code reading and my gate probes, not by constructing a failing committed test.
- Timing and peak-RSS fields in `results.json` were assessed for plausibility, not re-measured.
- The `.claude/agents/*.md` role files were not re-read in this round.

## 8. Recommended corrections (priority order)

1. Fix the RSS measurement in `test_hardening_v2.py` so N20/F01 die in the full suite (A3-01).
2. Tighten GATE_04: per-experiment full-path manifest coverage, expected baselines from a constant, optional recomputation of container hashes (A3-02); add tests G05/G06/G12/G14/G18/N38 (A3-04).
3. Small wording/label fixes: container RSS range, EXP-0001/0002 dependency cells, `release_ready` attestation marker (A3-03, A3-05, A3-06).
4. Keep `AUDIT_003` verdicts out of `state/audit_verdict.json` until a person (not the development agent) records them; the current forge-ability is documented but real.
