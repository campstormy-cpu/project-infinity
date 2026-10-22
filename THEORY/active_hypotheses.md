# Active hypotheses

Every hypothesis here is unproven. None has been tested beyond what is listed.

| ID | Hypothesis | Status | Planned test |
|---|---|---|---|
| H-001 | On a specific, documented dataset, a content-aware pipeline (type detection, format-specific transform, context-mixing or adaptive entropy coder) can beat the best general-purpose baseline (zstd -19, xz -9e, brotli -11) in complete storage bytes, with byte-exact recovery. | HYPOTHESIS | Phase 2. Needs a chosen dataset, complete-storage accounting and train/test split. |
| H-002 | A small learned model (counts toward stored size) can improve prediction enough to pay for its own weights on a large homogeneous corpus. | HYPOTHESIS | Phase 3. Blocked on GPU/torch (see ENVIRONMENT_AUDIT.md) for anything beyond tiny CPU models. |
