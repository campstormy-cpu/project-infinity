# AUDIT REPORT (index)

This file is an index written by the developer. The audits themselves are written by independent
auditor agents running in separate contexts, and live in `audits/`. Read them, not this summary.
Verdicts below are copied from the auditors' own documents.

| Audit | Scope | Document | Auditor verdict |
|---|---|---|---|
| 001 | EXP-0001, compression-core, benchmark runner | `audits/AUDIT_001_EXP-0001.md` | (a) byte-exact recovery: ACCEPT. (b) sizes/ratios fairly measured: REVISE. (c) no unsupported claim: REVISE. No critical/high findings. |
| 002 | Fixes for 001, EXP-0002, gate runner, control center | `audits/AUDIT_002_FIXES.md` | (a) fixes: REVISE (minor). (b) EXP-0002 as baseline: ACCEPT. (c) gate runner: REVISE. (d) control center: REVISE. No critical/high findings; 6 medium. |
| 003 | Scoped re-check of the fixes for 002 and EXP-0003 | `audits/AUDIT_003_RECHECK.md` | pending |

Release gates are enforced by `infrastructure/run_gates.py` (see its docstring for what a PASS does and does not prove).
No verdict is recorded in `state/audit_verdict.json` until an audit document supports it.
