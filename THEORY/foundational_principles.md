# Foundational principles

Status legend: HYPOTHESIS, UNDER_INVESTIGATION, EXPERIMENTALLY_SUPPORTED, INDEPENDENTLY_REPRODUCED, REJECTED, INCONCLUSIVE.

FP-01 to FP-03 are standard results from information theory. FP-04 to FP-08 are **project definitions and policies**, not scientific results; they define what this project counts as success.

| ID | Principle | Basis |
|---|---|---|
| FP-01 | No lossless compressor can shrink every input. For any n, there are 2^n bit strings of length n but fewer than 2^n shorter strings, so some inputs must not shrink. | Pigeonhole principle |
| FP-02 | Average compressed length cannot beat the entropy of the source model used to generate the data. Gains come from better models of the data, not from bypassing entropy. | Shannon source coding theorem |
| FP-03 | Already compressed or encrypted data is close to incompressible without knowledge of its structure. | Information theory: data without exploitable structure has no redundancy to remove. Checked empirically on one random file and one xz file in EXP-0001/0002/0003 (not a proof for all such data) |
| FP-04 | (definition) Exact recovery means bitwise equivalence with the original file. Pixel- or sample-equivalent output is not byte-identical file reconstruction. | Project definition |
| FP-05 | AI-generated or AI-enhanced output is not recovery of the original. | Project definition |
| FP-06 | Encryption is not compression, and blockchain is not a compression mechanism. | Definitions (encryption aims at indistinguishability, compression at shorter representation) |
| FP-07 | Any dictionary, model or dependency needed to decode belongs in the measured stored size and in the long-term recovery assessment. | Project definition |
| FP-08 | Ratios are properties of a (method, dataset) pair, never universal. | Practical rule. FP-01 shows no universal ratio can exist; a ratio is only meaningful for a stated method and dataset |
