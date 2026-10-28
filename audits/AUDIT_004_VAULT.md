# AUDIT_004 - INV1 vault prototype (independent review)

Scope: commit 08c9176 (vault code unchanged at HEAD 8b5af8e, which only adds tests/vault/test_fuzz.py).
Files read: packages/vault/infinity_vault/vault.py, tests/vault/test_vault.py, docs/adr/ADR-001-vault.md,
docs/security/THREAT_MODEL.md; also infinity_core container/codecs for the compression path.
Auditor did not write the code. No repo file was modified; experiments live in the session scratchpad
(exp.py, exp2.py). Existing tests: `python3 -m pytest -q -p no:cacheprovider tests/vault` -> 54 passed (0.46 s), re-run by me.

This is a prototype review by a single reviewer. It is NOT a substitute for external cryptographic review.

## Summary table

| ID | Sev | Area | Title |
|----|-----|------|-------|
| F1 | Medium | KDF / DoS | 64-byte file forces up to 1 GiB / t=10 / 16-lane Argon2 before any structural check |
| F2 | Low | Passphrase | Minimum length counted before NFKC; 12 raw chars can be 6 effective characters |
| F3 | Low | Passphrase / errors | Lone surrogate passphrase raises raw UnicodeEncodeError, not a VaultError |
| F4 | Low | Key export | Key file has no type/domain separation; any 96-byte mode-1 vault imports as keys; FormatError is a correct-passphrase oracle |
| F5 | Low | Error handling | Encrypt to a low-order/invalid X25519 recipient key raises bare ValueError |
| F6 | Low | Docs | Docstring claim "wrong key and damaged file give the same DecryptError" is false for header damage |
| F7 | Low | Docs/evidence | Mutation-test claim (15/19) has no artifact in the repo; several evidence claims narrower than worded |
| F8 | Low | Metadata | recipient_id (stable SHA-256 of the public key) in every hybrid header is a linkability handle; threat model does not list it |
| F9 | Info | KDF | No lower bound on Argon2 cost on encrypt or decrypt |
| F10 | Info | Commitment | dek_commit is redundant; the real commitment is kek_commit + header-AAD |
| F11 | Info | Combiner | Hybrid combiner is bespoke (not X-Wing / a published design); sound on inspection but needs expert review |
| F12 | Info | Passphrase | NFKC is lossy by design (compat-equivalent passphrases collide) |

No Critical or High findings.

## Findings

### F1 (Medium) Unauthenticated Argon2 cost; structural validation happens after the KDF
Reference: vault.py:62-63 (caps 1<<20 KiB, t<=10, lanes<=16), :234-239 (decrypt_with_passphrase: KDF at :238, `_open` length/truncation checks at :150-160 only afterwards).
The comments/ADR/threat model (adversary D) say header costs are "bounded before expensive work". The bound is applied, but (a) the ceiling is very high and (b) cheap checks (file length, body_len, trailing data) run after the KDF.
Reproduction (scratchpad exp.py): a 64-byte blob = valid base + (random salt, m_kib=1<<20, t=10, lanes=16, zero commit):
`decrypt_with_passphrase(blob, "frase de prueba larga y unica")` -> FormatError("file truncated") after 6.53 s and ~1048 MB peak RSS on this 2-core VM. With default-sized params (256 MiB, t=3) it costs 0.59 s for the same truncated file.
Impact: any party who can hand the application a file can cost ~1 GiB and several CPU-seconds per 64 bytes; concurrent requests exhaust RAM. Test coverage (test_vault.py:193-199) only checks a value above the cap is rejected quickly, not the cost of values inside the cap.
Fix: run all length checks first (a file that is shorter than header+wrap+body fields never reaches the KDF); lower the default decrypt ceiling to a small multiple of the encrypt default (e.g. 2x) and make the larger cap opt-in; document the residual cost.

### F2 (Low) Minimum passphrase length measured before normalization
vault.py:114-119. `len(passphrase)` is checked, then NFKC is applied. `"é"*6` (12 code points) is accepted and normalizes to 6 characters (verified, exp.py E2). Compatibility characters can also expand, so the check is inconsistent in both directions. Fix: normalize, then count. The 12-char floor is weak anyway (threat model already says so).

### F3 (Low) Lone surrogate -> UnicodeEncodeError
vault.py:119. `encrypt_with_passphrase(b"x", "\ud800"*12)` raises UnicodeEncodeError ("'utf-8' codec can't encode characters in position 0-11"). Not a VaultError, and the message includes positions. Fuzz test property "VaultError only" covers file bytes, not passphrases. Fix: catch and raise ValueError without echoing input (or encode with a defined policy).

### F4 (Low) Private-key file: no domain separation, and a correct-passphrase oracle
vault.py:279-289. The key file is an ordinary mode-1 vault whose plaintext is exactly 96 bytes (x25519 32 + ML-KEM seed 64). Consequences verified in exp.py:
- E6: a normal data vault holding 96 random bytes imports successfully as a recipient key (no type label, no AAD tag, no public-key check). Mixing a data file and a key file is silently accepted.
- E6b: `import_private` on a data vault of other length with the CORRECT passphrase raises FormatError("not a recipient key file"); with a wrong passphrase it raises DecryptError. Anyone who can observe which exception surfaces learns whether a guessed passphrase is correct. Impact is small (the caller already holds the file and the attacker needs an interface exposing it), but it contradicts the "same generic error" design rule.
- Key files are recognisable by size (288 bytes with test params), unlike other vaults.
Not found: the seed format itself is fine (from_seed_bytes round-trips; tests cover export/import and plaintext absence). Fix: collapse the size mismatch into DecryptError; add a key-file label (e.g. a distinct flag or AAD context) and a magic inside the plaintext.

### F5 (Low) Bad recipient key on encrypt leaks a raw library error
vault.py:297. `RecipientPublic(bytes(32), mlkem_pk)` passes `__post_init__` (length only) and `encrypt_for_recipient` raises ValueError("Error computing shared key.") (exp.py E3). Fail-closed, so not a security break, but the contract is unclear. A random 1184-byte ML-KEM key is rejected by the library (E4), good. Fix: validate on construction and wrap errors.

### F6 (Low, docs) False statement in module docstring
vault.py:31 "Wrong key and damaged file give the same DecryptError". Damage to magic, version, mode, flags, KDF fields, or length fields yields FormatError (vault.py:215-225, 157-160; also tests at test_vault.py:92-96 accept either). Only damage in the authenticated region yields DecryptError. The ADR (line 21) is more careful. No secret leaks (these fields are public), but the docstring overstates. Hybrid damage to the X25519 value or ML-KEM ciphertext gives DecryptError; recipient_id mismatch also DecryptError (vault.py:312).

### F7 (Low, docs/evidence) Claims not reproducible from the repo
- THREAT_MODEL.md:62 "mutation test (19 changes, 15 detected)": no script, config or output in the repo (grepped tests/, packages/, audits/). Unverifiable as written.
- THREAT_MODEL.md:61 "cada bit de la cabecera": the exhaustive bit-flip test (test_vault.py:99-104) covers passphrase mode only; hybrid is sampled every 13th byte (test_vault.py:107-112). I ran an exhaustive bit-flip over all 1419 bytes of a hybrid file: no tampered file was accepted (exp2.py), so the property holds, but the repo does not demonstrate it.
- "punto X25519 de orden bajo": only the all-zero point is tested (test_vault.py:304-308). I tried seven low-order encodings (0, 1, the order-8 points, p-1, p, p+1): all give DecryptError (exp.py E5). Holds, but via the library, and is untested in the repo.
- Test count "54" is stale at HEAD (fuzz tests added).
- test_compression_bomb_inside_a_valid_file_is_bounded (test_vault.py:231) actually triggers the declared-length check (50 MiB declared vs 1 MiB cap), not the in-decoder cap; the decoder cap (codecs.py zlib/bz2/lzma/zstd with n+1 limits) looks correct on reading, but a lying-header bomb is not tested at the vault layer.
- Expectation of unit test "hybrid_needs_both_halves" monkeypatches `public()` to keep recipient_id valid; fine, and it does prove each half matters.

### F8 (Low) Linkable recipient identifier
vault.py:262, :301. Every hybrid file carries SHA-256("INV1 recipient id"||pubkey). Anyone holding files can group them by recipient. The threat model's metadata list (line 22) mentions size, mode, flags only. Document it or drop recipient_id (AEAD failure already identifies wrong recipient).

### F9 (Info) No cost floor
KdfParams.check (vault.py:99-102) enforces only upper bounds and 8*lanes <= m_kib. `KdfParams(8,1,1)` encrypts successfully (exp.py E8). Decrypt accepts any file-supplied cost above the floor, so a file made by a malicious sender with trivial cost is accepted (harmless for confidentiality of the receiver but relevant if the app ever treats the KDF cost as a security property of stored files). Consider a minimum for non-test callers.

### F10 (Info) Key commitment analysis
Checked (vault.py:106-111, 132-143, 146-174). Header (including kek_commit = HKDF(KEK,"INV1 commit kek")) is AAD of the key-wrap GCM, so a (header, wrapped) pair can open under at most one KEK unless HKDF-SHA256 collides; the wrap holds exactly one DEK, and the body is decrypted only under that DEK. So the file is committing for both keys. The in-wrap dek_commit does not add a property (the DEK is already uniquely determined by the KEK-authenticated wrap); it is harmless defense in depth. test_dek_commitment_is_enforced shows it is checked, not that it is needed. Domain separation: labels "INV1 commit kek"/"INV1 commit dek" are distinct (verified), hybrid uses a different salt/info; KEK is used both as an AES key and as HKDF input (acceptable via HKDF). kek_commit gives an offline passphrase-check value as cheap as the GCM tag, so no extra attack surface. Nonces: wrap nonce is unique per fresh KEK; body nonce per fresh DEK; one message per key; random 96-bit reuse risk is negligible. No issue found.

### F11 (Info) Hybrid combiner
vault.py:126-128, 292-321. HKDF-SHA256(salt="INV1", IKM = ss_x||ss_k, info = "INV1 hybrid KEK"||eph_pub||mlkem_ct||rx_pub||rk_pub). All shared secrets and all public values are bound; all fields are fixed length so no concatenation ambiguity; recipient_id is bound indirectly through the two recipient public keys and is AAD in the header. ML-KEM uses implicit rejection (decapsulation never errors; wrong ciphertext -> wrong KEK -> commitment mismatch, DecryptError). X25519: the library rejects all low-order outputs (all seven tested encodings -> DecryptError), which is the contributory check, but this is delegated to OpenSSL behaviour and not asserted by the code or pinned by tests beyond one point. Sender is anonymous and the recipient public key is unauthenticated (documented). No flaw found; the design is a custom combiner and is exactly the "composition" the docs say needs expert review.

### F12 (Info) NFKC
Compatibility collisions: fullwidth "１２３４５６７８９０ab" and "1234567890ab" derive the same key (verified). That is the intended normalization trade-off; ensure users are told. Normalization form is fixed (not versioned in the header), so any change needs a new version byte.

## Areas checked with no defect found
1. AAD coverage, both modes: every byte before each ciphertext is AAD (wrap: header; body: header||wrap_nonce||wrapped||body_nonce||length). Exhaustive single-bit flips: passphrase mode via existing test, hybrid mode via my exp2.py (all 1419*8 mutations rejected). Truncation at every length and trailing bytes are rejected; mode/flags/version checks happen before and are also authenticated.
2. Parser: length arithmetic is exact (`len(blob) != need + body_len`), body_len is bounded before slicing (vault.py:157-160), u64 length cannot overflow Python ints; 3,000 random mutations of a compressed vault produced only VaultError (exp.py E7). bytes-like inputs: str -> FormatError, None/memoryview -> TypeError (Low-grade API inconsistency only).
3. Compression: FLAG_COMPRESSED only triggers the bounded decoder with max_output=max_plaintext after authentication; decoder streams with n+1 caps and a window limit. Compress-then-encrypt length leakage is documented and off by default.
4. Error oracles in file parsing: FormatError conditions depend only on public header bytes; the commitment check and GCM failure return the same exception and message; I measured no usable timing difference by inspection (not benchmarked).

## Overclaim check (docs vs code/tests)
- Supported: AES-256-GCM/Argon2id/HKDF/X25519/ML-KEM-768 composition as described; header authenticated; key commitment present and checked; Argon2 timings (0.59 s at 256 MiB t=3 reproduced: matches the 0.56 s claim).
- Overstated: "bounded before expensive work" (F1); "same error for wrong key and damaged file" (F6); "bit-by-bit" (hybrid, F7); mutation score (F7); ADR "Agilidad ... sin romper lectores antiguos" (only a version byte that readers reject; no negotiation or tested upgrade path); metadata list incomplete (F8).
- Correctly disclaimed: unreviewed status, anonymous sender, no rollback protection, memory not wiped, whole-file in memory.

## Recommendation
Fix F1 before any non-test use that accepts files from others; clean up F2-F5 and the doc corrections (F6-F8); then commission external review of the composition (pending item 1 in THREAT_MODEL section 7).

This is a prototype review by one auditor within a limited session, not a substitute for external cryptographic review.

VERDICT: PASS
