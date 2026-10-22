"""Integrity primitives: SHA-256 hashing and exact-recovery verification.

Exact recovery means bitwise equivalence. A hash match alone is necessary but we
also compare bytes directly, as required for critical benchmarks.
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass

CHUNK = 1024 * 1024


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def files_byte_identical(path_a, path_b) -> bool:
    """Direct byte-for-byte comparison, independent of any hash."""
    with open(path_a, "rb") as fa, open(path_b, "rb") as fb:
        while True:
            ca = fa.read(CHUNK)
            cb = fb.read(CHUNK)
            if ca != cb:
                return False
            if not ca:
                return True


@dataclass(frozen=True)
class RecoveryResult:
    ok: bool
    sha256_original: str
    sha256_reconstructed: str
    hash_match: bool
    byte_identical: bool
    size_original: int
    size_reconstructed: int

    def as_dict(self) -> dict:
        return asdict(self)


def check_recovery(original, reconstructed) -> RecoveryResult:
    """Detailed verification. ok is True only if size, hash AND bytes all agree."""
    import os

    size_o = os.path.getsize(original)
    size_r = os.path.getsize(reconstructed)
    sha_o = sha256_file(original)
    sha_r = sha256_file(reconstructed)
    hash_match = sha_o == sha_r
    byte_identical = files_byte_identical(original, reconstructed)
    return RecoveryResult(
        ok=hash_match and byte_identical and size_o == size_r,
        sha256_original=sha_o,
        sha256_reconstructed=sha_r,
        hash_match=hash_match,
        byte_identical=byte_identical,
        size_original=size_o,
        size_reconstructed=size_r,
    )


def verify_exact_recovery(original, reconstructed) -> bool:
    """Boolean form specified in Directive 007."""
    return check_recovery(original, reconstructed).ok
