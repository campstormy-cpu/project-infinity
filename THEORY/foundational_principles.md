# Foundational principles

Status legend: HYPOTHESIS, UNDER_INVESTIGATION, EXPERIMENTALLY_SUPPORTED, INDEPENDENTLY_REPRODUCED, REJECTED, INCONCLUSIVE.

These are established results from information theory and cryptography. They are not claims of this project.

| ID | Principle | Basis |
|---|---|---|
| FP-01 | No lossless compressor can shrink every input. For any n, there are 2^n bit strings of length n but fewer than 2^n shorter strings, so some inputs must not shrink. | Pigeonhole principle |
| FP-02 | Average compressed length cannot beat the entropy of the source model used to generate the data. Gains come from better models of the data, not from bypassing entropy. | Shannon source coding theorem |
| FP-03 | Already compressed or encrypted data is close to incompressible without knowledge of its structure. | Follows from FP-02 |
| FP-04 | Exact recovery means bitwise equivalence with the original file. Pixel- or sample-equivalent output is not byte-identical file reconstruction. | Project definition |
| FP-05 | AI-generated or AI-enhanced output is not recovery of the original. | Project definition |
| FP-06 | Encryption is not compression, and blockchain is not a compression mechanism. | Definitions |
| FP-07 | Any dictionary, model or dependency needed to decode belongs in the measured stored size and in the long-term recovery assessment. | Project definition |
| FP-08 | Ratios are properties of a (method, dataset) pair, never universal. | Consequence of FP-01 |
