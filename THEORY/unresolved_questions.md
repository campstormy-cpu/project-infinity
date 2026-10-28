# Unresolved questions (owner input needed)

1. Which real data type should Phase 2 target first (documents, photos, audio, video, scientific data)? The ratio of any method depends on this.
2. Is a trained model allowed to be shared across files (amortised overhead), or must each file be self-contained?
3. Compute budget for Phase 3: GPU access is not available in the current environment.
4. Should GitHub be connected for CI? Not connected today.

5. Vault: who reviews the INV1 composition externally before real secrets are used? (docs/security/THREAT_MODEL.md section 7)
6. Vault: do you need sender signatures (ML-DSA) and signed versions, or is anonymous-sender encryption enough?
