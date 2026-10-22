# Experimental evidence

Index of experiments. Raw data lives in `benchmarks/results/<experiment_id>/`. Failed or superseded experiments are kept.

| Experiment | Purpose | Status | Result files | Audit |
|---|---|---|---|---|
| EXP-0001 | Verify the pipeline: standard codecs, round trip, SHA-256, benchmark record | RUN 2026-10-22. Numbers confirmed by independent recomputation. **Superseded**, not deleted. | `benchmarks/results/EXP-0001/` | AUDIT_REPORT.md: claim (a) accept; (b) and (c) revise (Brotli static dictionary not disclosed, rounding, dirty flag, caveats missing) |
| EXP-0002 | Same pipeline after fixes for the audit findings | see below | `benchmarks/results/EXP-0002/` | pending re-audit |

Neither experiment supports any claim about a new compression method. No hypothesis in `active_hypotheses.md` has been tested.
